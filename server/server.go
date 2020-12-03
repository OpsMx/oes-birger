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
	out chan *tunnel.CommandResponse
	cmd *tunnel.CommandRequest
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

	ids := make(map[string]chan *tunnel.CommandResponse)

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
		case *tunnel.ASEventWrapper_PingRequest:
			req := in.GetPingRequest()
			if err := stream.Send(makePingResponse(req)); err != nil {
				return err
			}
		case *tunnel.ASEventWrapper_SigninRequest:
			req := in.GetSigninRequest()
			if err := stream.Send(makeSigninResponse(req, true)); err != nil {
				return err
			}
			clientIdentity = req.Identity
			addClient(clientIdentity, inRequest)
		case *tunnel.ASEventWrapper_CommandResponse:
			resp := in.GetCommandResponse()
			dest := ids[resp.Id]
			if dest != nil {
				dest <- resp
				close(dest)
				delete(ids, resp.Id)
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
