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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type agentConnectionNotification struct {
	Identity             string   `json:"identity,omitempty"`
	Protocols            []string `json:"protocols,omitempty"`
	Session              string   `json:"session,omitempty"`
	KubernetesNamespaces []string `json:"namespaces,omitempty"`
	CommandNames         []string `json:"commandNames,omitEmpty"`
}

func sendWebhook(state *agentState, namespaces []string, commandNames []string) {
	if hook == nil {
		return
	}
	req := &agentConnectionNotification{
		Identity:             state.ep.name,
		Protocols:            []string{state.ep.protocol},
		Session:              state.session,
		KubernetesNamespaces: namespaces,
		CommandNames:         commandNames,
	}
	hook.Send(req)
}

func makePingResponse(req *tunnel.PingRequest) *tunnel.ControllerToAgentWrapper {
	resp := &tunnel.ControllerToAgentWrapper{
		Event: &tunnel.ControllerToAgentWrapper_PingResponse{
			PingResponse: &tunnel.PingResponse{Ts: tunnel.Now(), EchoedTs: req.Ts},
		},
	}
	return resp
}

type sessionList struct {
	sync.RWMutex
	m map[string]chan *tunnel.AgentToControllerWrapper
}

func removeHTTPId(httpids *sessionList, id string) {
	httpids.Lock()
	defer httpids.Unlock()
	delete(httpids.m, id)
}

func addHTTPId(httpids *sessionList, id string, c chan *tunnel.AgentToControllerWrapper) {
	httpids.Lock()
	defer httpids.Unlock()
	httpids.m[id] = c
}

func handleHTTPRequests(session string, httpRequestChan chan *httpMessage, httpids *sessionList, stream tunnel.AgentTunnelService_EventTunnelServer) {
	for request := range httpRequestChan {
		addHTTPId(httpids, request.cmd.Id, request.out)
		resp := &tunnel.ControllerToAgentWrapper{
			Event: &tunnel.ControllerToAgentWrapper_HttpRequest{
				HttpRequest: request.cmd,
			},
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Unable to send to agent %s for HTTP request %s", session, request.cmd.Id)
		}
	}
	log.Printf("Request channel closed for %s", session)
}

func handleHTTPCancelRequest(session string, identity string, cancelChan chan *cancelRequest, httpids *sessionList, stream tunnel.AgentTunnelService_EventTunnelServer) {
	for request := range cancelChan {
		removeHTTPId(httpids, request.id)
		resp := &tunnel.ControllerToAgentWrapper{
			Event: &tunnel.ControllerToAgentWrapper_CancelRequest{
				CancelRequest: &tunnel.CancelRequest{Id: request.id, Target: identity},
			},
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Unable to send to agent %s for cancel request %s", session, request.id)
		}
	}
	log.Printf("cancel channel closed for agent %s", session)
}

func closeAllHTTP(httpids *sessionList) {
	httpids.Lock()
	defer httpids.Unlock()
	for _, v := range httpids.m {
		close(v)
	}
}

// This runs in its own goroutine, one per GRPC connection from an agent.
func (s *agentTunnelServer) EventTunnel(stream tunnel.AgentTunnelService_EventTunnelServer) error {
	agentIdentity, err := getAgentNameFromContext(stream.Context())
	if err != nil {
		return err
	}

	sessionIdentity := ulidContext.Ulid()

	inHTTPRequest := make(chan *httpMessage, 1)
	inCancelRequest := make(chan *cancelRequest, 1)
	httpids := &sessionList{m: make(map[string]chan *tunnel.AgentToControllerWrapper)}

	state := &agentState{
		ep:              endpoint{name: agentIdentity, protocol: "UNKNOWN"},
		session:         sessionIdentity,
		inHTTPRequest:   inHTTPRequest,
		inCancelRequest: inCancelRequest,
		connectedAt:     tunnel.Now(),
	}

	log.Printf("Agent %s connected, awaiting hello message", state)

	go handleHTTPRequests(sessionIdentity, inHTTPRequest, httpids, stream)

	go handleHTTPCancelRequest(sessionIdentity, agentIdentity, inCancelRequest, httpids, stream)

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Closing %s", state)
			closeAllHTTP(httpids)
			agents.RemoveAgent(state)
			return nil
		}
		if err != nil {
			log.Printf("Agent closed connection: %s", state)
			closeAllHTTP(httpids)
			agents.RemoveAgent(state)
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.AgentToControllerWrapper_PingRequest:
			req := in.GetPingRequest()
			atomic.StoreUint64(&state.lastPing, tunnel.Now())
			if err := stream.Send(makePingResponse(req)); err != nil {
				log.Printf("Unable to respond to %s with ping response: %v", state, err)
				agents.RemoveAgent(state)
				return err
			}
		case *tunnel.AgentToControllerWrapper_AgentHello:
			req := in.GetAgentHello()
			if req.ProtocolVersion != tunnel.CurrentProtocolVersion {
				return fmt.Errorf("Agent protocol version %d is older than %d", req.ProtocolVersion, tunnel.CurrentProtocolVersion)
			}
			state.ep.protocol = req.Protocols[0] // TODO: handle multiple protocols
			agents.AddAgent(state)
			sendWebhook(state, req.KubernetesNamespaces, req.CommandNames)
		case *tunnel.AgentToControllerWrapper_HttpResponse:
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
		case *tunnel.AgentToControllerWrapper_HttpChunkedResponse:
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

type agentTunnelServer struct {
	tunnel.UnimplementedAgentTunnelServiceServer
}

func newAgentServer() *agentTunnelServer {
	return &agentTunnelServer{}
}

func runAgentGRPCServer(serverCert tls.Certificate) {
	//
	// Set up GRPC server
	//
	log.Printf("Starting Agent GRPC server on port %d...", config.AgentPort)
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
		MinVersion:   tls.VersionTLS13,
	})
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	tunnel.RegisterAgentTunnelServiceServer(grpcServer, newAgentServer())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start Agent GRPC server: %v", err)
	}
}

type cmdToolTunnelServer struct {
	tunnel.UnimplementedCmdToolTunnelServiceServer
}

func newCmdToolServer() *cmdToolTunnelServer {
	return &cmdToolTunnelServer{}
}

func (s *cmdToolTunnelServer) EventTunnel(stream tunnel.CmdToolTunnelService_EventTunnelServer) error {
	return fmt.Errorf("Unimplemented")
}

func runCmdToolGRPCServer(serverCert tls.Certificate) {
	//
	// Set up GRPC server
	//
	log.Printf("Starting Agent GRPC server on port %d...", config.CmdToolPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.CmdToolPort))
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
		MinVersion:   tls.VersionTLS13,
	})
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	tunnel.RegisterCmdToolTunnelServiceServer(grpcServer, newCmdToolServer())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start Agent GRPC server: %v", err)
	}
}
