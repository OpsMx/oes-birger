package main

import (
	"context"
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

type commandMessage struct {
	out chan *tunnel.CommandResponse
	cmd *tunnel.CommandRequest
}

type httpMessage struct {
	out chan *tunnel.HttpResponse
	cmd *tunnel.HttpRequest
}

type clientState struct {
	identity      string
	inRequest     chan *commandMessage
	inHTTPRequest chan *httpMessage
}

func addClient(identity string, inRequest chan *commandMessage, inHTTPRequest chan *httpMessage) {
	clients.Lock()
	clients.m[identity] = &clientState{identity: identity, inRequest: inRequest, inHTTPRequest: inHTTPRequest}
	clients.Unlock()
}

func removeClient(identity string) {
	clients.Lock()
	client := clients.m[identity]
	delete(clients.m, identity)
	clients.Unlock()

	if client != nil {
		close(client.inRequest)
		close(client.inHTTPRequest)
	}
}

func (s *tunnelServer) SendToClient(ctx context.Context, req *tunnel.CommandRequest) (*tunnel.CommandResponse, error) {
	clients.RLock()
	commandMessage := &commandMessage{out: make(chan *tunnel.CommandResponse), cmd: req}
	client := clients.m[req.Target]
	if client == nil {
		clients.RUnlock()
		return nil, fmt.Errorf("Unknown target: %s", req.Target)
	}
	client.inRequest <- commandMessage
	clients.RUnlock()
	resp := <-commandMessage.out
	return resp, nil
}

func forwardHTTP(req *tunnel.HttpRequest) (*tunnel.HttpResponse, error) {
	log.Printf("Forwarding HTTP request to 'skan1', content: %v", req)
	clients.RLock()
	message := &httpMessage{out: make(chan *tunnel.HttpResponse), cmd: req}
	client := clients.m[req.Target]
	if client == nil {
		clients.RUnlock()
		return nil, fmt.Errorf("Unknown target: %s", req.Target)
	}
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

	inRequest := make(chan *commandMessage)
	inHTTPRequest := make(chan *httpMessage)

	ids := make(map[string]chan *tunnel.CommandResponse)
	httpids := make(map[string]chan *tunnel.HttpResponse)

	go func() {
		ulidContext := ulid.NewContext()

		for {
			request, more := <-inRequest
			if more {
				log.Printf("Got command request: %v", request)
				requestID := ulid.Ulid(ulidContext)
				request.cmd.Id = requestID
				ids[requestID] = request.out
				resp := &tunnel.SAEventWrapper{
					Event: &tunnel.SAEventWrapper_CommandRequest{
						CommandRequest: request.cmd,
					},
				}
				if err := stream.Send(resp); err != nil {
					return
				}
			} else {
				return
			}
		}
	}()

	go func() {
		ulidContext := ulid.NewContext()

		for {
			request, more := <-inHTTPRequest
			if more {
				log.Printf("Got command request: %v", request)
				requestID := ulid.Ulid(ulidContext)
				request.cmd.Id = requestID
				httpids[requestID] = request.out
				resp := &tunnel.SAEventWrapper{
					Event: &tunnel.SAEventWrapper_HttpRequest{
						HttpRequest: request.cmd,
					},
				}
				if err := stream.Send(resp); err != nil {
					return
				}
			} else {
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
			removeClient(clientIdentity)
			log.Printf("Client closed connection: %s", clientIdentity)
			return err
		}

		log.Printf("Received: %s: %v", clientIdentity, in)
		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_PingRequest:
			req := in.GetPingRequest()
			if err := stream.Send(makePingResponse(req)); err != nil {
				removeClient(clientIdentity)
				return err
			}
		case *tunnel.ASEventWrapper_SigninRequest:
			req := in.GetSigninRequest()
			if err := stream.Send(makeSigninResponse(req, true)); err != nil {
				removeClient(clientIdentity)
				return err
			}
			clientIdentity = req.Identity
			addClient(clientIdentity, inRequest, inHTTPRequest)
		case *tunnel.ASEventWrapper_CommandResponse:
			resp := in.GetCommandResponse()
			dest := ids[resp.Id]
			if dest != nil {
				dest <- resp
				close(dest)
				delete(ids, resp.Id)
			}
		case *tunnel.ASEventWrapper_HttpResponse:
			resp := in.GetHttpResponse()
			dest := httpids[resp.Id]
			if dest != nil {
				dest <- resp
				close(dest)
				delete(httpids, resp.Id)
			}
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T: %v", clientIdentity, x, in)
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
	log.Println()

	log.Printf("Method: %s, URI: %v", r.Method, r.RequestURI)
	log.Printf("Protocol: %s", r.Proto)
	for key, element := range r.Header {
		log.Printf("Header: %s -> %v", key, element)
	}

	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Target:   "skan1",
		Protocol: r.Proto,
		Method:   r.Method,
		URI:      r.RequestURI,
		Headers:  makeHeaders(r.Header),
		Body:     string(body),
	}

	resp, err := forwardHTTP(req)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte{})
		return
	}

	log.Printf("HTTP repsonse: %v", resp)

	for name := range w.Header() {
		r.Header.Del(name)
	}

	for _, header := range resp.Headers {
		for _, value := range header.Values {
			w.Header().Add(header.Name, value)
		}
	}
	w.WriteHeader(int(resp.Status))
	fmt.Fprintf(w, resp.Body)
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
