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
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"

	"github.com/opsmx/oes-birger/internal/serviceconfig"
	"github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/opsmx/oes-birger/internal/tunnelroute"
	"github.com/opsmx/oes-birger/internal/ulid"
	"github.com/opsmx/oes-birger/internal/util"
	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (s *agentTunnelServer) sendWebhook(state tunnelroute.Route, endpoints []*tunnel.EndpointHealth) {
	if hook == nil {
		return
	}
	eh := make([]tunnelroute.Endpoint, len(endpoints))
	for i, ep := range endpoints {
		eh[i] = tunnelroute.Endpoint{
			Name:       ep.Name,
			Type:       ep.Type,
			Configured: ep.Configured,
			Namespaces: ep.Namespaces,
		}
	}
	req := &tunnelroute.BaseStatistics{
		Name:      state.GetName(),
		Session:   state.GetSession(),
		Endpoints: eh,
	}
	hook.Send(req)
}

func handleHTTPRequests(session string, requestChan chan interface{}, httpids *util.SessionList, stream tunnel.GRPCEventStream) {
	for interfacedRequest := range requestChan {
		switch value := interfacedRequest.(type) {
		case *tunnelroute.HTTPMessage:
			httpids.Add(value.Cmd.Id, value.Out)
			resp := &tunnel.MessageWrapper{
				Event: tunnel.MakeHTTPTunnelOpenTunnelRequest(value.Cmd),
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to route %s for HTTP request %s", session, value.Cmd.Id)
			}
		default:
			log.Printf("Got unexpected message type: %T", interfacedRequest)
		}
	}
}

func handleHTTPCancelRequest(session string, cancelChan chan string, httpids *util.SessionList, stream tunnel.GRPCEventStream) {
	for id := range cancelChan {
		httpids.Remove(id)
		resp := &tunnel.MessageWrapper{
			Event: tunnel.MakeHTTPTunnelCancelRequest(id),
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Unable to send to route %s for cancel request %s", session, id)
		}
	}
	log.Printf("cancel channel closed for route %s", session)
}

func dataflowHandler(dataflow chan *tunnel.MessageWrapper, stream tunnel.GRPCEventStream) {
	for ew := range dataflow {
		if err := stream.Send(ew); err != nil {
			log.Fatalf("Unable to respond over GRPC: %v", err)
		}
		util.Debug("GRPC-SEND: %v", ew)
	}
}

// This runs in its own goroutine, one per GRPC connection from an agent.
func (s *agentTunnelServer) EventTunnel(stream tunnel.AgentTunnelService_EventTunnelServer) error {
	var agentIdentity string

	if !s.insecure {
		var err error
		agentIdentity, err = getAgentNameFromContext(stream.Context())
		if err != nil {
			return err
		}
	}

	dataflow := make(chan *tunnel.MessageWrapper, 20)

	go dataflowHandler(dataflow, stream)

	sessionIdentity := ulid.GlobalContext.Ulid()

	inRequest := make(chan interface{}, 1)
	inCancelRequest := make(chan string, 1)
	httpids := util.MakeSessionList()

	state := &tunnelroute.DirectlyConnectedRoute{
		Name:            agentIdentity,
		Session:         sessionIdentity,
		InRequest:       inRequest,
		InCancelRequest: inCancelRequest,
		ConnectedAt:     tunnel.Now(),
	}

	log.Printf("Route %s connected, awaiting hello message", state)

	go handleHTTPRequests(sessionIdentity, inRequest, httpids, stream)

	go handleHTTPCancelRequest(sessionIdentity, inCancelRequest, httpids, stream)

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Closing %s", state)
			httpids.CloseAll()
			routes.Remove(state)
			return nil
		}
		if err != nil {
			log.Printf("Agent closed connection: %s", state)
			httpids.CloseAll()
			routes.Remove(state)
			return err
		}

		util.Debug("GRPC-RECV: %v", in)

		switch x := in.Event.(type) {
		case *tunnel.MessageWrapper_PingRequest:
			req := in.GetPingRequest()
			atomic.StoreUint64(&state.LastPing, tunnel.Now())
			if err := stream.Send(tunnel.MakePingResponse(req)); err != nil {
				log.Printf("Unable to respond to %s with ping response: %v", state, err)
				routes.Remove(state)
				return err
			}
		case *tunnel.MessageWrapper_Hello:
			req := in.GetHello()
			if s.insecure {
				cert, err := x509.ParseCertificate(req.ClientCertificate)
				if err != nil {
					return err
				}
				agentIdentity, err = getAgentNameFromCertificate(cert)
				if err != nil {
					return err
				}
				state.Name = agentIdentity
			}
			endpoints := make([]tunnelroute.Endpoint, len(req.Endpoints))
			for i, ep := range req.Endpoints {
				endpoints[i] = tunnelroute.Endpoint{
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
			routes.Add(state)
			s.sendWebhook(state, req.Endpoints)

			// now, send our response hello
			pbEndpoints := serviceconfig.EndpointsToPB(s.endpoints)
			hello := &tunnel.MessageWrapper{
				Event: &tunnel.MessageWrapper_Hello{
					Hello: &tunnel.Hello{
						Version:   version.String(),
						Endpoints: pbEndpoints,
						Hostname:  "controller",
					},
				},
			}
			if err = stream.Send(hello); err != nil {
				log.Fatalf("Unable to send hello packet: %v", err)
			}

		case *tunnel.MessageWrapper_HttpTunnelControl:
			handleHTTPControl(in, httpids, s.endpoints, dataflow)
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T", state, x)
		}
	}
}

func handleHTTPControl(in *tunnel.MessageWrapper, httpids *util.SessionList, endpoints []serviceconfig.ConfiguredEndpoint, dataflow chan *tunnel.MessageWrapper) {
	tunnelControl := in.GetHttpTunnelControl() // caller ensures this will work
	switch controlMessage := tunnelControl.ControlType.(type) {
	case *tunnel.HttpTunnelControl_CancelRequest:
		tunnel.CallCancelFunction(controlMessage.CancelRequest.Id)
	case *tunnel.HttpTunnelControl_OpenHTTPTunnelRequest:
		req := controlMessage.OpenHTTPTunnelRequest
		found := false
		for _, endpoint := range endpoints {
			if endpoint.Configured && endpoint.Type == req.Type && endpoint.Name == req.Name {
				go endpoint.Instance.ExecuteHTTPRequest(dataflow, req)
				found = true
				break
			}
		}
		if !found {
			log.Printf("Request for unsupported HTTP tunnel type=%s name=%s", req.Type, req.Name)
			dataflow <- tunnel.MakeBadGatewayResponse(req.Id)
		}
	case *tunnel.HttpTunnelControl_HttpTunnelResponse:
		resp := controlMessage.HttpTunnelResponse
		httpids.Lock()
		dest := httpids.FindUnlocked(resp.Id)
		if dest != nil {
			dest <- in
			if resp.ContentLength == 0 {
				httpids.RemoveUnlocked(resp.Id)
			}
		} else {
			log.Printf("Got response to unknown HTTP request id %s", resp.Id)
		}
		httpids.Unlock()
	case *tunnel.HttpTunnelControl_HttpTunnelChunkedResponse:
		resp := controlMessage.HttpTunnelChunkedResponse
		httpids.Lock()
		dest := httpids.FindUnlocked(resp.Id)
		if dest != nil {
			dest <- in
			if len(resp.Body) == 0 {
				httpids.RemoveUnlocked(resp.Id)
			}
		} else {
			log.Printf("Got response to unknown HTTP request id %s", resp.Id)
		}
		httpids.Unlock()
	case nil:
		return
	default:
		log.Printf("Received unknown HttpControl type: %T", controlMessage)
	}
}

type agentTunnelServer struct {
	tunnel.UnimplementedAgentTunnelServiceServer
	endpoints []serviceconfig.ConfiguredEndpoint
	insecure  bool
}

func newAgentServer(insecure bool) *agentTunnelServer {
	return &agentTunnelServer{insecure: insecure}
}

func runAgentGRPCServer(insecureAgents bool, serverCert tls.Certificate) {
	log.Printf("Starting Agent GRPC server on port %d...", config.AgentListenPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.AgentListenPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	if insecureAgents {
		m := cmux.New(lis)
		grpcL := m.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))

		grpcServer := grpc.NewServer()
		server := &agentTunnelServer{insecure: insecureAgents}
		server.endpoints = endpoints
		tunnel.RegisterAgentTunnelServiceServer(grpcServer, server)

		go func() {
			if err := grpcServer.Serve(grpcL); err != nil {
				log.Fatalf("Failed to start Agent GRPC server: %v", err)
			}
		}()

		if err := m.Serve(); err != nil {
			log.Fatalf("Failed to run m.Serve(): %v", err)
		}
	} else {
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
		opts := []grpc.ServerOption{grpc.Creds(creds)}
		grpcServer := grpc.NewServer(opts...)
		server := &agentTunnelServer{insecure: insecureAgents}
		server.endpoints = endpoints
		tunnel.RegisterAgentTunnelServiceServer(grpcServer, server)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to start Agent GRPC server: %v", err)
		}
	}
}
