package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/opsmx/grpc-bidir/pkg/tunnel"
	"github.com/opsmx/grpc-bidir/pkg/webhook"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type tunnelServer struct {
	tunnel.UnimplementedTunnelServiceServer
}

func newServer() *tunnelServer {
	s := &tunnelServer{}
	return s
}

func sendWebhook(state *agentState, namespaces []string) {
	if hook == nil {
		return
	}
	req := &webhook.AgentConnectionNotification{
		Identity:             state.ep.name,
		Protocols:            []string{state.ep.protocol},
		Session:              state.session,
		KubernetesNamespaces: namespaces,
	}
	hook.Send(req)
}

func makePingResponse(req *tunnel.PingRequest) *tunnel.SAEventWrapper {
	resp := &tunnel.SAEventWrapper{
		Event: &tunnel.SAEventWrapper_PingResponse{
			PingResponse: &tunnel.PingResponse{Ts: tunnel.Now(), EchoedTs: req.Ts},
		},
	}
	return resp
}

type sessionList struct {
	sync.RWMutex
	m map[string]chan *tunnel.ASEventWrapper
}

func removeHttpId(httpids *sessionList, id string) {
	httpids.Lock()
	defer httpids.Unlock()
	delete(httpids.m, id)
}

func addHttpId(httpids *sessionList, id string, c chan *tunnel.ASEventWrapper) {
	httpids.Lock()
	defer httpids.Unlock()
	httpids.m[id] = c
}

func handleHttpRequests(session string, httpRequestChan chan *httpMessage, httpids *sessionList, stream tunnel.TunnelService_EventTunnelServer) {
	for request := range httpRequestChan {
		addHttpId(httpids, request.cmd.Id, request.out)
		resp := &tunnel.SAEventWrapper{
			Event: &tunnel.SAEventWrapper_HttpRequest{
				HttpRequest: request.cmd,
			},
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Unable to send to agent %s for HTTP request %s", session, request.cmd.Id)
		}
	}
	log.Printf("Request channel closed for %s", session)
}

func handleHttpAgentResponse(session string, identity string, cancelChan chan *cancelRequest, httpids *sessionList, stream tunnel.TunnelService_EventTunnelServer) {
	for request := range cancelChan {
		removeHttpId(httpids, request.id)
		resp := &tunnel.SAEventWrapper{
			Event: &tunnel.SAEventWrapper_CancelRequest{
				CancelRequest: &tunnel.CancelRequest{Id: request.id, Target: identity},
			},
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Unable to send to agent %s for cancel request %s", session, request.id)
		}
	}
	log.Printf("cancel channel closed for agent %s", session)
}

func closeAllHttp(httpids *sessionList) {
	httpids.Lock()
	defer httpids.Unlock()
	for _, v := range httpids.m {
		close(v)
	}
}

// This runs in its own goroutine, one per GRPC connection from an agent.
func (s *tunnelServer) EventTunnel(stream tunnel.TunnelService_EventTunnelServer) error {
	agentIdentity, err := getAgentNameFromContext(stream.Context())
	if err != nil {
		return err
	}

	sessionIdentity := ulidContext.Ulid()

	inHTTPRequest := make(chan *httpMessage, 1)
	inCancelRequest := make(chan *cancelRequest, 1)
	httpids := &sessionList{m: make(map[string]chan *tunnel.ASEventWrapper)}

	state := &agentState{
		ep:              endpoint{name: agentIdentity, protocol: "UNKNOWN"},
		session:         sessionIdentity,
		inHTTPRequest:   inHTTPRequest,
		inCancelRequest: inCancelRequest,
		connectedAt:     tunnel.Now(),
	}

	log.Printf("Agent %s connected, awaiting hello message", state)

	go handleHttpRequests(sessionIdentity, inHTTPRequest, httpids, stream)

	go handleHttpAgentResponse(sessionIdentity, agentIdentity, inCancelRequest, httpids, stream)

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Closing %s", state)
			closeAllHttp(httpids)
			agents.RemoveAgent(state)
			return nil
		}
		if err != nil {
			log.Printf("Agent closed connection: %s", state)
			closeAllHttp(httpids)
			agents.RemoveAgent(state)
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_PingRequest:
			req := in.GetPingRequest()
			atomic.StoreUint64(&state.lastPing, tunnel.Now())
			if err := stream.Send(makePingResponse(req)); err != nil {
				log.Printf("Unable to respond to %s with ping response: %v", state, err)
				agents.RemoveAgent(state)
				return err
			}
		case *tunnel.ASEventWrapper_AgentHello:
			req := in.GetAgentHello()
			state.ep.protocol = req.Protocols[0] // TODO: handle multiple protocols
			agents.AddAgent(state)
			sendWebhook(state, req.KubernetesNamespaces)
		case *tunnel.ASEventWrapper_HttpResponse:
			resp := in.GetHttpResponse()
			atomic.StoreUint64(&state.lastUse, tunnel.Now())
			httpids.Lock()
			dest := httpids.m[resp.Id]
			if dest != nil {
				dest <- in
				if resp.ContentLength == 0 {
					delete(httpids.m, resp.Id)
				}
			} else {
				log.Printf("Got response to unknown HTTP request id %s from %s", resp.Id, agentIdentity)
			}
			httpids.Unlock()
		case *tunnel.ASEventWrapper_HttpChunkedResponse:
			resp := in.GetHttpChunkedResponse()
			atomic.StoreUint64(&state.lastUse, tunnel.Now())
			httpids.Lock()
			dest := httpids.m[resp.Id]
			if dest != nil {
				dest <- in
				if len(resp.Body) == 0 {
					delete(httpids.m, resp.Id)
				}
			} else {
				log.Printf("Got response to unknown HTTP request id %s from %s", resp.Id, state)
			}
			httpids.Unlock()
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T", state, x)
		}
	}
}

func runGRPCServer(serverCert tls.Certificate) {
	//
	// Set up GRPC server
	//
	log.Printf("Starting GRPC server on port %d...", config.AgentPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.AgentPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	certPool, err := authority.MakeCertPool()
	if err != nil {
		log.Fatalf("While making certpool: %v", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	tunnel.RegisterTunnelServiceServer(grpcServer, newServer())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start GRPC server: %v", err)
	}
}
