package main

/*
 * Copyright 2021 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opsmx/oes-birger/app/controller/agent"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (s *agentTunnelServer) sendWebhook(state agent.Agent, endpoints []*tunnel.EndpointHealth) {
	if hook == nil {
		return
	}
	eh := make([]agent.Endpoint, len(endpoints))
	for i, ep := range endpoints {
		eh[i] = agent.Endpoint{
			Name:       ep.Name,
			Type:       ep.Type,
			Configured: ep.Configured,
			Namespaces: ep.Namespaces,
		}
	}
	req := &agent.BaseStatistics{
		Name:      state.GetName(),
		Session:   state.GetSession(),
		Endpoints: eh,
	}
	hook.Send(req)
}

func (s *agentTunnelServer) makePingResponse(req *tunnel.PingRequest) *tunnel.MessageWrapper {
	resp := &tunnel.MessageWrapper{
		Event: &tunnel.MessageWrapper_PingResponse{
			PingResponse: &tunnel.PingResponse{Ts: uint64(time.Now().UnixNano()), EchoedTs: req.Ts},
		},
	}
	return resp
}

type sessionList struct {
	sync.RWMutex
	m map[string]chan *tunnel.MessageWrapper
}

func (s *agentTunnelServer) removeHTTPId(httpids *sessionList, id string) {
	httpids.Lock()
	defer httpids.Unlock()
	delete(httpids.m, id)
}

func (s *agentTunnelServer) addHTTPId(httpids *sessionList, id string, c chan *tunnel.MessageWrapper) {
	httpids.Lock()
	defer httpids.Unlock()
	httpids.m[id] = c
}

func (s *agentTunnelServer) handleHTTPRequests(session string, requestChan chan interface{}, httpids *sessionList, stream tunnel.AgentTunnelService_EventTunnelServer) {
	for interfacedRequest := range requestChan {
		switch value := interfacedRequest.(type) {
		case *HTTPMessage:
			s.addHTTPId(httpids, value.Cmd.Id, value.Out)
			resp := &tunnel.MessageWrapper{
				Event: tunnel.MakeHTTPTunnelOpenTunnelRequest(value.Cmd),
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to agent %s for HTTP request %s", session, value.Cmd.Id)
			}
		default:
			log.Printf("Got unexpected message type: %T", interfacedRequest)
		}
	}
}

func (s *agentTunnelServer) handleHTTPCancelRequest(session string, cancelChan chan string, httpids *sessionList, stream tunnel.AgentTunnelService_EventTunnelServer) {
	for id := range cancelChan {
		s.removeHTTPId(httpids, id)
		resp := &tunnel.MessageWrapper{
			Event: tunnel.MakeHTTPTunnelCancelRequest(id),
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Unable to send to agent %s for cancel request %s", session, id)
		}
	}
	log.Printf("cancel channel closed for agent %s", session)
}

func (s *agentTunnelServer) closeAllHTTP(httpids *sessionList) {
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
	inCancelRequest := make(chan string, 1)
	httpids := &sessionList{m: make(map[string]chan *tunnel.MessageWrapper)}

	state := &agent.DirectlyConnectedAgent{
		Name:            agentIdentity,
		Session:         sessionIdentity,
		InRequest:       inRequest,
		InCancelRequest: inCancelRequest,
		ConnectedAt:     tunnel.Now(),
	}

	log.Printf("Agent %s connected, awaiting hello message", state)

	go s.handleHTTPRequests(sessionIdentity, inRequest, httpids, stream)

	go s.handleHTTPCancelRequest(sessionIdentity, inCancelRequest, httpids, stream)

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Closing %s", state)
			s.closeAllHTTP(httpids)
			err2 := agents.RemoveAgent(state)
			if err2 != nil {
				log.Printf("while removing agent: %v", err2)
			}
			return nil
		}
		if err != nil {
			log.Printf("Agent closed connection: %s", state)
			s.closeAllHTTP(httpids)
			err2 := agents.RemoveAgent(state)
			if err2 != nil {
				log.Printf("while removing agent: %v", err2)
			}
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.MessageWrapper_PingRequest:
			req := in.GetPingRequest()
			atomic.StoreUint64(&state.LastPing, tunnel.Now())
			if err := stream.Send(s.makePingResponse(req)); err != nil {
				log.Printf("Unable to respond to %s with ping response: %v", state, err)
				err2 := agents.RemoveAgent(state)
				if err2 != nil {
					log.Printf("while removing agent: %v", err2)
				}
				return err
			}
		case *tunnel.MessageWrapper_AgentHello:
			req := in.GetAgentHello()
			endpoints := make([]agent.Endpoint, len(req.Endpoints))
			for i, ep := range req.Endpoints {
				endpoints[i] = agent.Endpoint{
					Name:       ep.Name,
					Type:       ep.Type,
					Configured: ep.Configured,
					Namespaces: ep.Namespaces,
					AccountID:  ep.AccountID,
					AssumeRole: ep.AssumeRole,
				}
			}
			state.Endpoints = endpoints
			state.Version = req.Version
			state.Hostname = req.Hostname
			agents.AddAgent(state)
			s.sendWebhook(state, req.Endpoints)
		case *tunnel.MessageWrapper_HttpTunnelControl:
			handleHTTPControl(x.HttpTunnelControl, state, httpids, in, agentIdentity)
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T", state, x)
		}
	}
}

func handleHTTPControl(httpControl *tunnel.HttpTunnelControl, state *agent.DirectlyConnectedAgent, httpids *sessionList, in *tunnel.MessageWrapper, agentIdentity string) {
	switch controlMessage := httpControl.ControlType.(type) {
	case *tunnel.HttpTunnelControl_HttpTunnelResponse:
		resp := controlMessage.HttpTunnelResponse
		atomic.StoreUint64(&state.LastUse, tunnel.Now())
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
	case *tunnel.HttpTunnelControl_HttpTunnelChunkedResponse:
		resp := controlMessage.HttpTunnelChunkedResponse
		atomic.StoreUint64(&state.LastUse, tunnel.Now())
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
	log.Printf("Starting Agent GRPC server on port %d...", config.AgentListenPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.AgentListenPort))
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
