package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v2"

	"github.com/skandragon/grpc-bidir/tunnel"
	"github.com/skandragon/grpc-bidir/ulid"
)

var (
	port           = flag.Int("port", tunnel.DefaultPort, "The GRPC port to listen on")
	httpPort       = flag.Int("httpPort", 9002, "The HTTP port to listen for Kubernetes API requests on")
	serverCertFile = flag.String("certFile", "/app/config/cert.pem", "The file containing the certificate for the server")
	serverKeyFile  = flag.String("keyFile", "/app/config/key.pem", "The file containing the certificate for the server")
	caCertFile     = flag.String("caCertFile", "/app/config/ca.pem", "The file containing the CA certificate we will use to verify the client's cert")
	configFile     = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	clients = struct {
		sync.RWMutex
		m map[string]*clientState
	}{m: make(map[string]*clientState)}

	config *controllerConfig

	ulidContext = ulid.NewContext()
)

type controllerConfig struct {
	Clients map[string]*clientConfig `yaml:"clients"`
}

type clientConfig struct {
	Identity string `yaml:"identity"`
}

func loadConfig() *controllerConfig {
	buf, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Unable to load config file: %v", err)
	}

	config := &controllerConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		log.Fatalf("Unable to read config file: %v", err)
	}
	return config
}

type httpMessage struct {
	out chan *tunnel.ASEventWrapper
	cmd *tunnel.HttpRequest
}

type cancelRequest struct {
	id string
}

type clientState struct {
	identity        string
	inHTTPRequest   chan *httpMessage
	inCancelRequest chan *cancelRequest
}

func addClient(identity string, inHTTPRequest chan *httpMessage, inCancelRequest chan *cancelRequest) {
	clients.Lock()
	clients.m[identity] = &clientState{
		identity:        identity,
		inHTTPRequest:   inHTTPRequest,
		inCancelRequest: inCancelRequest,
	}
	clients.Unlock()
}

func removeClient(identity string) {
	clients.Lock()
	client := clients.m[identity]
	delete(clients.m, identity)
	clients.Unlock()

	if client != nil {
		close(client.inHTTPRequest)
		close(client.inCancelRequest)
	}
}

type tunnelServer struct {
	tunnel.UnimplementedTunnelServiceServer
}

func newServer() *tunnelServer {
	s := &tunnelServer{}
	return s
}

func makePingResponse(req *tunnel.PingRequest) *tunnel.SAEventWrapper {
	resp := &tunnel.SAEventWrapper{
		Event: &tunnel.SAEventWrapper_PingResponse{
			PingResponse: &tunnel.PingResponse{Ts: tunnel.Now(), EchoedTs: req.Ts},
		},
	}
	return resp
}

func getClientNameFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer found")
	}
	tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
	}
	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "could not verify peer certificate")
	}
	return tlsAuth.State.VerifiedChains[0][0].Subject.CommonName, nil
}

func (s *tunnelServer) EventTunnel(stream tunnel.TunnelService_EventTunnelServer) error {
	clientIdentity, err := getClientNameFromContext(stream.Context())
	if err != nil {
		return err
	}
	log.Printf("Registered agent: %s", clientIdentity)

	inHTTPRequest := make(chan *httpMessage, 1)
	inCancelRequest := make(chan *cancelRequest, 1)
	httpids := struct {
		sync.RWMutex
		m map[string]chan *tunnel.ASEventWrapper
	}{m: make(map[string]chan *tunnel.ASEventWrapper)}

	addClient(clientIdentity, inHTTPRequest, inCancelRequest)

	go func() {
		for {
			request, more := <-inHTTPRequest
			if !more {
				log.Printf("Request channel closed for %s", clientIdentity)
				return
			}
			httpids.Lock()
			httpids.m[request.cmd.Id] = request.out
			httpids.Unlock()
			resp := &tunnel.SAEventWrapper{
				Event: &tunnel.SAEventWrapper_HttpRequest{
					HttpRequest: request.cmd,
				},
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to client %s for HTTP request %s", clientIdentity, request.cmd.Id)
			}
		}
	}()

	go func() {
		for {
			request, more := <-inCancelRequest
			if !more {
				log.Printf("cancel channel closed for agent %s", clientIdentity)
				return
			}
			httpids.Lock()
			delete(httpids.m, request.id)
			httpids.Unlock()
			resp := &tunnel.SAEventWrapper{
				Event: &tunnel.SAEventWrapper_HttpRequestCancel{
					HttpRequestCancel: &tunnel.HttpRequestCancel{Id: request.id, Target: clientIdentity},
				},
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to client %s for cancel request %s", clientIdentity, request.id)
			}
		}
	}()

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Closing %s", clientIdentity)
			httpids.Lock()
			for _, v := range httpids.m {
				close(v)
			}
			httpids.Unlock()
			removeClient(clientIdentity)
			return nil
		}
		if err != nil {
			log.Printf("Client closed connection: %s", clientIdentity)
			httpids.Lock()
			for _, v := range httpids.m {
				close(v)
			}
			httpids.Unlock()
			removeClient(clientIdentity)
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_PingRequest:
			req := in.GetPingRequest()
			if err := stream.Send(makePingResponse(req)); err != nil {
				log.Printf("Unable to respond to %s with ping response: %v", clientIdentity, err)
				removeClient(clientIdentity)
				return err
			}
		case *tunnel.ASEventWrapper_HttpResponse:
			resp := in.GetHttpResponse()
			httpids.Lock()
			dest := httpids.m[resp.Id]
			if dest != nil {
				dest <- in
				if resp.ContentLength == 0 {
					delete(httpids.m, resp.Id)
				}
			} else {
				log.Printf("Got response to unknown HTTP request id %s from %s", resp.Id, clientIdentity)
			}
			httpids.Unlock()
		case *tunnel.ASEventWrapper_HttpChunkedResponse:
			resp := in.GetHttpChunkedResponse()
			httpids.Lock()
			dest := httpids.m[resp.Id]
			if dest != nil {
				dest <- in
				if len(resp.Body) == 0 {
					delete(httpids.m, resp.Id)
				}
			} else {
				log.Printf("Got response to unknown HTTP request id %s from %s", resp.Id, clientIdentity)
			}
			httpids.Unlock()
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T", clientIdentity, x)
		}
	}
}

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		if name != "Accept-Encoding" {
			ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
		}
	}
	return ret
}

func handler(w http.ResponseWriter, r *http.Request) {
	hostname := r.TLS.ServerName
	clientname := r.TLS.PeerCertificates[0].Subject.CommonName
	target, ok := config.Clients[hostname]
	if !ok {
		log.Printf("No mapping for server name %s", hostname)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Id:      ulidContext.Ulid(),
		Target:  target.Identity,
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: makeHeaders(r.Header),
		Body:    body,
	}
	clients.RLock()
	client, ok := clients.m[req.Target]
	if !ok {
		clients.RUnlock()
		log.Printf("Unknown target: %s", req.Target)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	message := &httpMessage{out: make(chan *tunnel.ASEventWrapper), cmd: req}
	client.inHTTPRequest <- message
	clients.RUnlock()

	cleanClose := false

	notify := r.Context().Done()
	go func() {
		<-notify
		if !cleanClose {
			client.inCancelRequest <- &cancelRequest{id: req.Id}
		}
	}()

	seenHeader := false
	isChunked := false
	flusher := w.(http.Flusher)
	for {
		in, more := <-message.out
		if !more {
			if !seenHeader {
				log.Printf("Request timed out sending to agent %s", req.Target)
				w.WriteHeader(http.StatusBadGateway)
			}
			cleanClose = true
			return
		}

		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_HttpResponse:
			resp := in.GetHttpResponse()
			seenHeader = true
			isChunked = resp.ContentLength < 0
			for name := range w.Header() {
				r.Header.Del(name)
			}
			for _, header := range resp.Headers {
				for _, value := range header.Values {
					w.Header().Add(header.Name, value)
				}
			}
			w.WriteHeader(int(resp.Status))
			if resp.ContentLength == 0 {
				cleanClose = true
				return
			}
		case *tunnel.ASEventWrapper_HttpChunkedResponse:
			resp := in.GetHttpChunkedResponse()
			if !seenHeader {
				log.Printf("Error: got ChunkedResponse before HttpResponse")
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if len(resp.Body) == 0 {
				cleanClose = true
				return
			}
			w.Write(resp.Body)
			if isChunked {
				flusher.Flush()
			}
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T", clientname, x)
		}
	}
}

func main() {
	flag.Parse()

	config = loadConfig()

	//
	// Set up HTTP server
	//
	log.Printf("Running HTTP listener on port %d", *httpPort)

	caCert, _ := ioutil.ReadFile(*caCertFile)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", *httpPort),
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/", handler)
	// Configure the port
	go server.ListenAndServeTLS(*serverCertFile, *serverKeyFile)

	//
	// Set up GRPC server
	//
	log.Printf("Starting GRPC server on port %d...", *port)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	certificate, err := tls.LoadX509KeyPair(*serverCertFile, *serverKeyFile)
	if err != nil {
		log.Fatalf("could not load server key pair: %s", err)
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("could not read ca certificate: %s", err)
	}
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append client certs")
	}
	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS12,
	})
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	tunnel.RegisterTunnelServiceServer(grpcServer, newServer())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start GRPC server: %v", err)
	}
}
