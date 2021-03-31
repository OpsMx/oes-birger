package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opsmx/oes-birger/pkg/tunnel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type endpointHealth struct {
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	Configured bool   `json:"configured,omitempty"`
}

type agentConnectionNotification struct {
	Identity  string           `json:"identity,omitempty"`
	Session   string           `json:"session,omitempty"`
	Endpoints []endpointHealth `json:"endpoints,omitempty"`
}

func sendWebhook(state *agentState, endpoints []*tunnel.EndpointHealth) {
	if hook == nil {
		return
	}
	eh := make([]endpointHealth, len(endpoints))
	for i, ep := range endpoints {
		eh[i] = endpointHealth{
			Name:       ep.Name,
			Type:       ep.Type,
			Configured: ep.Configured,
		}
	}
	req := &agentConnectionNotification{
		Identity:  state.ep.name,
		Session:   state.session,
		Endpoints: eh,
	}
	hook.Send(req)
}

func makePingResponse(req *tunnel.PingRequest) *tunnel.ControllerToAgentWrapper {
	resp := &tunnel.ControllerToAgentWrapper{
		Event: &tunnel.ControllerToAgentWrapper_PingResponse{
			PingResponse: &tunnel.PingResponse{Ts: uint64(time.Now().UnixNano()), EchoedTs: req.Ts},
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

func handleHTTPRequests(session string, requestChan chan interface{}, httpids *sessionList, stream tunnel.AgentTunnelService_EventTunnelServer) {
	for interfacedRequest := range requestChan {
		switch interfacedRequest.(type) {
		case *httpMessage:
			httpRequest := interfacedRequest.(*httpMessage)
			addHTTPId(httpids, httpRequest.cmd.Id, httpRequest.out)
			resp := &tunnel.ControllerToAgentWrapper{
				Event: &tunnel.ControllerToAgentWrapper_HttpRequest{
					HttpRequest: httpRequest.cmd,
				},
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to agent %s for HTTP request %s", session, httpRequest.cmd.Id)
			}
		case *runCmdMessage:
			cmdRequest := interfacedRequest.(*runCmdMessage)
			log.Printf("cmd %s %s %v %v running", cmdRequest.cmd.Id, cmdRequest.cmd.Name, cmdRequest.cmd.Arguments, cmdRequest.cmd.Environment)
			addHTTPId(httpids, cmdRequest.cmd.Id, cmdRequest.out)
			resp := &tunnel.ControllerToAgentWrapper{
				Event: &tunnel.ControllerToAgentWrapper_CommandRequest{
					CommandRequest: cmdRequest.cmd,
				},
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to agent %s for CMD request %s", session, cmdRequest.cmd.Id)
			}
		default:
			log.Printf("Got unexpected message type: %T", interfacedRequest)
		}
	}
}

func handleHTTPCancelRequest(session string, identity string, cancelChan chan *cancelRequest, httpids *sessionList, stream tunnel.AgentTunnelService_EventTunnelServer) {
	for request := range cancelChan {
		removeHTTPId(httpids, request.id)
		resp := &tunnel.ControllerToAgentWrapper{
			Event: &tunnel.ControllerToAgentWrapper_CancelRequest{
				CancelRequest: &tunnel.CancelRequest{Id: request.id},
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

	inRequest := make(chan interface{}, 1)
	inCancelRequest := make(chan *cancelRequest, 1)
	httpids := &sessionList{m: make(map[string]chan *tunnel.AgentToControllerWrapper)}

	state := &agentState{
		ep:              endpoint{name: agentIdentity, protocols: []string{"UNKNOWN"}},
		session:         sessionIdentity,
		inRequest:       inRequest,
		inCancelRequest: inCancelRequest,
		connectedAt:     tunnel.Now(),
	}

	log.Printf("Agent %s connected, awaiting hello message", state)

	go handleHTTPRequests(sessionIdentity, inRequest, httpids, stream)

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
			// TODO: state.ep.endpoints = req.Endpoints
			agents.AddAgent(state)
			sendWebhook(state, req.Endpoints)
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
		case *tunnel.AgentToControllerWrapper_CommandTermination:
			resp := in.GetCommandTermination()
			atomic.StoreUint64(&state.lastUse, tunnel.Now())
			httpids.Lock()
			dest := httpids.m[resp.Id]
			if dest != nil {
				dest <- in
				close(dest)
				delete(httpids.m, resp.Id)
			} else {
				log.Printf("Got response to unknown CMD request id %s from %s", resp.Id, state)
			}
			httpids.Unlock()
		case *tunnel.AgentToControllerWrapper_CommandData:
			resp := in.GetCommandData()
			atomic.StoreUint64(&state.lastUse, tunnel.Now())
			httpids.Lock()
			dest := httpids.m[resp.Id]
			if dest != nil {
				dest <- in
			} else {
				log.Printf("Got response to unknown CMD request id %s from %s", resp.Id, state)
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

func makeCommandTermination(exitstatus int) *tunnel.ControllerToCmdToolWrapper {
	return &tunnel.ControllerToCmdToolWrapper{
		Event: &tunnel.ControllerToCmdToolWrapper_CommandTermination{
			CommandTermination: &tunnel.CmdToolCommandTermination{
				ExitCode: int32(exitstatus),
			},
		},
	}
}

type runCmdMessage struct {
	out chan *tunnel.AgentToControllerWrapper
	cmd *tunnel.CommandRequest
}

func (s *cmdToolTunnelServer) EventTunnel(stream tunnel.CmdToolTunnelService_EventTunnelServer) error {
	identity, err := getAgentNameFromContext(stream.Context())
	if err != nil {
		return err
	}
	log.Printf("CmdTool %s connected", identity)
	ep := endpoint{protocols: []string{"remote-command"}, name: identity}

	sessionIdentity := ulidContext.Ulid()
	agentResponseChan := make(chan *tunnel.AgentToControllerWrapper)

	go func() {
		for in := range agentResponseChan {
			switch x := in.Event.(type) {
			case *tunnel.AgentToControllerWrapper_CommandTermination:
				resp := in.GetCommandTermination()
				log.Printf("Got command exit code %d", resp.ExitCode)
				if err := stream.Send(makeCommandTermination(int(resp.ExitCode))); err != nil {
					log.Printf("While sending: %v", err)
				}
			case *tunnel.AgentToControllerWrapper_CommandData:
				resp := in.GetCommandData()
				msg := &tunnel.ControllerToCmdToolWrapper{
					Event: &tunnel.ControllerToCmdToolWrapper_CommandData{
						CommandData: &tunnel.CmdToolCommandData{
							Body:    resp.Body,
							Channel: resp.Channel,
							Closed:  resp.Closed,
						},
					},
				}
				if err := stream.Send(msg); err != nil {
					log.Printf("Sending CommandData to tool: %v", err)
				}
			case nil:
				// ignore for now
			default:
				log.Printf("CmdTool %s unknown message from agent: %s: %T", identity, sessionIdentity, x)
			}
		}
	}()

	operationID := ulidContext.Ulid()

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("CmdTool %s closed connection %s", identity, sessionIdentity)
			agents.CancelRequest(ep, &cancelRequest{id: operationID})
			return nil
		}
		if err != nil {
			log.Printf("CmdTool %s closed connection: %s", identity, sessionIdentity)
			agents.CancelRequest(ep, &cancelRequest{id: operationID})
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.CmdToolToControllerWrapper_CommandRequest:
			req := in.GetCommandRequest()
			log.Printf("CmdTool %s request: %v", identity, req)
			cmd := &tunnel.CommandRequest{
				Id:          operationID,
				Name:        req.Name,
				Arguments:   req.Arguments,
				Environment: req.Environment,
			}
			message := &runCmdMessage{out: agentResponseChan, cmd: cmd}
			found := agents.SendToAgent(ep, message)
			if !found {
				close(agentResponseChan)
				return fmt.Errorf("Unknown agent: %s", identity)
			}
		case nil:
			// ignore for now
		default:
			log.Printf("CmdTool %s unknown message: %s: %T", identity, sessionIdentity, x)
		}
	}
}

func runCmdToolGRPCServer(serverCert tls.Certificate) {
	//
	// Set up GRPC server
	//
	log.Printf("Starting CmdTool GRPC server on port %d...", config.CmdToolPort)
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
		log.Fatalf("Failed to start CmdTool GRPC server: %v", err)
	}
}
