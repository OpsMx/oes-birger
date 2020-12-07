package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"

	"google.golang.org/grpc"

	"github.com/rocketlaunchr/https-go"
	"github.com/skandragon/grpc-bidir/tunnel"
	"github.com/skandragon/grpc-bidir/ulid"
)

var (
	port     = flag.Int("port", tunnel.DefaultPort, "The GRPC port to listen on")
	httpPort = flag.Int("httpPort", 9002, "The HTTP port to listen for API requests on")
	clients  = struct {
		sync.RWMutex
		m map[string]*clientState
	}{m: make(map[string]*clientState)}
)

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
	client := clients.m[req.Target]
	if client == nil {
		clients.RUnlock()
		return nil, fmt.Errorf("Unknown target: %s", req.Target)
	}
	message := &httpMessage{out: make(chan *tunnel.HttpResponse), cmd: req}
	client.inHTTPRequest <- message
	clients.RUnlock()
	resp := <-message.out
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

func makeSigninResponse(req *tunnel.SigninRequest, success bool) *tunnel.SAEventWrapper {
	resp := &tunnel.SAEventWrapper{
		Event: &tunnel.SAEventWrapper_SigninResponse{
			SigninResponse: &tunnel.SigninResponse{Success: success},
		},
	}
	return resp
}

func (s *tunnelServer) EventTunnel(stream tunnel.TunnelService_EventTunnelServer) error {
	var clientIdentity string

	inHTTPRequest := make(chan *httpMessage)

	httpids := make(map[string]chan *tunnel.HttpResponse)

	go func() {
		ulidContext := ulid.NewContext()

		for {
			request, more := <-inHTTPRequest
			if more {
				requestID := ulid.Ulid(ulidContext)
				request.cmd.Id = requestID
				httpids[requestID] = request.out
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
		case *tunnel.ASEventWrapper_SigninRequest:
			req := in.GetSigninRequest()
			if err := stream.Send(makeSigninResponse(req, true)); err != nil {
				log.Printf("Unable to respond to %s with signin response: %v", clientIdentity, err)
				removeClient(clientIdentity)
				return err
			}
			clientIdentity = req.Identity
			addClient(clientIdentity, inHTTPRequest)
			log.Printf("Client %s signed in", clientIdentity)
		case *tunnel.ASEventWrapper_HttpResponse:
			resp := in.GetHttpResponse()
			dest := httpids[resp.Id]
			if dest != nil {
				dest <- resp
				close(dest)
				delete(httpids, resp.Id)
				log.Printf("closed HTTP request id %s from %s", resp.Id, clientIdentity)
			} else {
				log.Printf("Got response to unknown HTTP request id %s from %s", resp.Id, clientIdentity)
			}
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
		ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
	}
	return ret
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Got HTTP request for server name %s", r.TLS.ServerName)
	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Target:  "skan1", // TODO: find a way to know where this should be sent...
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: makeHeaders(r.Header),
		Body:    body,
	}

	resp, err := forwardHTTP(req)
	if err != nil {
		log.Printf("Got an error from forwardHTTP, returning HTTP status 500")
		w.WriteHeader(500)
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
	w.WriteHeader(int(resp.Status))
	w.Write(resp.Body)
}

func main() {
	flag.Parse()

	log.Printf("Running HTTP listener on port %d", *httpPort)
	http.HandleFunc("/", handler)
	// Configure the port
	httpServer, _ := https.Server("9002", https.GenerateOptions{Host: "kubernetes.docker.internal"})

	go httpServer.ListenAndServeTLS("", "")

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Starting GRPC server on port %d...", *port)

	grpcServer := grpc.NewServer()

	tunnel.RegisterTunnelServiceServer(grpcServer, newServer())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start GRPC server: %v", err)
	}
}
