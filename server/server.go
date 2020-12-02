package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"

	"github.com/skandragon/grpc-bidir/tunnel"
	"github.com/skandragon/grpc-bidir/ulid"
)

var (
	port    = flag.Int("port", tunnel.DefaultPort, "The GRPC port to listen on")
	clients = struct {
		sync.RWMutex
		m map[string]*clientState
	}{m: make(map[string]*clientState)}
)

type commandMessage struct {
	out     chan string
	message string
}

type clientState struct {
	identity  string
	inRequest chan *commandMessage
}

func addClient(identity string, inRequest chan *commandMessage) {
	clients.Lock()
	clients.m[identity] = &clientState{identity: identity, inRequest: inRequest}
	clients.Unlock()
}

func removeClient(identity string) {
	clients.Lock()
	client := clients.m[identity]
	delete(clients.m, identity)
	clients.Unlock()

	if client != nil {
		close(client.inRequest)
	}
}

func sendToClient(identity string, message string) (string, error) {
	clients.RLock()
	commandMessage := &commandMessage{out: make(chan string), message: message}
	client := clients.m[identity]
	if client == nil {
		clients.RUnlock()
		return "", fmt.Errorf("Unknown target: %s", identity)
	}
	client.inRequest <- commandMessage
	clients.RUnlock()
	return <-commandMessage.out, nil
}

type tunnelServer struct {
	tunnel.UnimplementedTunnelServiceServer
}

func newServer() *tunnelServer {
	s := &tunnelServer{}
	return s
}

func makePingResponse(req *tunnel.PingRequest) *tunnel.EventWrapper {
	resp := &tunnel.EventWrapper{
		Event: &tunnel.EventWrapper_PingResponse{
			PingResponse: &tunnel.PingResponse{Ts: tunnel.Now(), EchoedTs: req.Ts},
		},
	}
	return resp
}

func makeSigninResponse(req *tunnel.SigninRequest, success bool) *tunnel.EventWrapper {
	resp := &tunnel.EventWrapper{
		Event: &tunnel.EventWrapper_SigninResponse{
			SigninResponse: &tunnel.SigninResponse{Success: success},
		},
	}
	return resp
}

func (s *tunnelServer) SendToClient(ctx context.Context, req *tunnel.Message) (*tunnel.Message, error) {
	resp, err := sendToClient(req.Target, req.Body)
	if err != nil {
		return nil, err
	}
	return &tunnel.Message{Target: req.Target, Body: resp}, nil
}

func (s *tunnelServer) EventTunnel(stream tunnel.TunnelService_EventTunnelServer) error {
	var clientIdentity string

	inRequest := make(chan *commandMessage)

	ids := make(map[string]chan string)

	go func() {
		ulidContext := ulid.NewContext()

		for {
			request, more := <-inRequest
			if more {
				log.Printf("Got command request: %v", request)
				requestID := ulid.Ulid(ulidContext)
				ids[requestID] = request.out
				resp := &tunnel.EventWrapper{
					Event: &tunnel.EventWrapper_CommandRequest{
						CommandRequest: &tunnel.CommandRequest{Id: requestID, Body: request.message},
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
			return nil
		}
		if err != nil {
			removeClient(clientIdentity)
			log.Printf("Client closed connection: %s", clientIdentity)
			return err
		}

		log.Printf("Received: %s: %v", clientIdentity, in)
		switch x := in.Event.(type) {
		case *tunnel.EventWrapper_PingRequest:
			req := in.GetPingRequest()
			if err := stream.Send(makePingResponse(req)); err != nil {
				return err
			}
		case *tunnel.EventWrapper_SigninRequest:
			req := in.GetSigninRequest()
			if err := stream.Send(makeSigninResponse(req, true)); err != nil {
				return err
			}
			clientIdentity = req.Identity
			addClient(clientIdentity, inRequest)
		case *tunnel.EventWrapper_CommandResponse:
			req := in.GetCommandResponse()
			dest := ids[req.Id]
			if dest != nil {
				dest <- req.Body
				close(dest)
				delete(ids, req.Id)
			}
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T: %v", clientIdentity, x, in)
		}
	}
}

func main() {
	flag.Parse()

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
