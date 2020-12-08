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
	serverCertFile = flag.String("certFile", "/app/cert.pem", "The file containing the certificate for the server")
	serverKeyFile  = flag.String("keyFile", "/app/key.pem", "The file containing the certificate for the server")
	caCertFile     = flag.String("caCertFile", "/app/ca.pem", "The file containing the CA certificate we will use to verify the client's cert")
	configFile     = flag.String("configFile", "/app/config.yaml", "The file with the controller config")
	clients        = struct {
		sync.RWMutex
		m map[string]*clientState
	}{m: make(map[string]*clientState)}
	config *controllerConfig
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
	out chan *tunnel.HttpResponse
	cmd *tunnel.HttpRequest
}

type clientState struct {
	identity      string
	inHTTPRequest chan *httpMessage
}

func addClient(identity string, inHTTPRequest chan *httpMessage) {
	clients.Lock()
	clients.m[identity] = &clientState{identity: identity, inHTTPRequest: inHTTPRequest}
	clients.Unlock()
}

func removeClient(identity string) {
	clients.Lock()
	client := clients.m[identity]
	delete(clients.m, identity)
	clients.Unlock()

	if client != nil {
		close(client.inHTTPRequest)
	}
}

func forwardHTTP(req *tunnel.HttpRequest) (*tunnel.HttpResponse, error) {
	clients.RLock()
	client, ok := clients.m[req.Target]
	if !ok {
		clients.RUnlock()
		return nil, fmt.Errorf("Unknown target: %s", req.Target)
	}
	message := &httpMessage{out: make(chan *tunnel.HttpResponse), cmd: req}
	client.inHTTPRequest <- message
	clients.RUnlock()
	resp, more := <-message.out
	if !more {
		return nil, fmt.Errorf("Request timed out sending to agent %s", req.Target)
	}
	return resp, nil
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
	httpids := struct {
		sync.RWMutex
		m map[string]chan *tunnel.HttpResponse
	}{m: make(map[string]chan *tunnel.HttpResponse)}

	addClient(clientIdentity, inHTTPRequest)

	go func() {
		ulidContext := ulid.NewContext()

		for {
			request, more := <-inHTTPRequest
			if more {
				requestID := ulid.Ulid(ulidContext)
				request.cmd.Id = requestID
				httpids.Lock()
				httpids.m[requestID] = request.out
				httpids.Unlock()
				resp := &tunnel.SAEventWrapper{
					Event: &tunnel.SAEventWrapper_HttpRequest{
						HttpRequest: request.cmd,
					},
				}
				log.Printf("Sending HTTP request to %s id %s", clientIdentity, requestID)
				if err := stream.Send(resp); err != nil {
					log.Printf("Unable to send to client %s for HTTP request %s", clientIdentity, requestID)
					return
				}
			} else {
				log.Printf("Request channel closed for %s", clientIdentity)
				return
			}
		}
	}()

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Closing %s", clientIdentity)
			removeClient(clientIdentity)
			return nil
		}
		if err != nil {
			log.Printf("Client closed connection: %s", clientIdentity)
			removeClient(clientIdentity)
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_PingRequest:
			req := in.GetPingRequest()
			log.Printf("Received: %s: %v", clientIdentity, in)
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
				dest <- resp
				close(dest)
				delete(httpids.m, resp.Id)
				log.Printf("closed HTTP request id %s from %s", resp.Id, clientIdentity)
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
	log.Printf("Got HTTP request for server name %s", hostname)
	log.Printf("Client: %v", clientname)
	target, ok := config.Clients[hostname]
	if !ok {
		log.Printf("No mapping for server name %s", hostname)
	}
	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Target:  target.Identity,
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: makeHeaders(r.Header),
		Body:    body,
	}

	resp, err := forwardHTTP(req)
	if err != nil {
		log.Print("Got an error from forwardHTTP, responding with Bad Gateway")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte{})
		return
	}

	for name := range w.Header() {
		r.Header.Del(name)
	}

	for _, header := range resp.Headers {
		for _, value := range header.Values {
			w.Header().Add(header.Name, value)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	w.WriteHeader(int(resp.Status))
	w.Write(resp.Body)

	log.Printf("Got %d bytes, content-length reported as %d", len(resp.Body), resp.ContentLength)
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
