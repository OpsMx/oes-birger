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
	"net"
	"sync/atomic"

	"github.com/OpsMx/go-app-base/version"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	"github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/opsmx/oes-birger/internal/tunnelroute"
	"github.com/opsmx/oes-birger/internal/ulid"
	"github.com/opsmx/oes-birger/internal/util"
	"github.com/soheilhy/cmux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func (s *agentTunnelServer) sendWebhook(state tunnelroute.Route, endpoints []*tunnel.EndpointHealth) {
	if hook == nil {
		return
	}
	eh := make([]tunnelroute.Endpoint, len(endpoints))
	for i, ep := range endpoints {
		annotations := map[string]string{}
		if ep.Annotations != nil {
			for _, a := range ep.Annotations {
				annotations[a.Name] = a.Value
			}
		}
		eh[i] = tunnelroute.Endpoint{
			Name:        ep.Name,
			Type:        ep.Type,
			Configured:  ep.Configured,
			Namespaces:  ep.Namespaces,
			Annotations: annotations,
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
				zap.S().Warnw("unable to send HTTP request over GRPC", "session", session, "requestId", value.Cmd.Id, "error", err)
			}
		default:
			zap.S().Warnw("unexpected message", "messageType", fmt.Sprintf("%T", interfacedRequest))
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
			zap.S().Warnw("stream.Send() failed", "session", session, "requestId", id, "error", err)
		}
	}
	zap.S().Infow("session closed", "session", session)
}

func dataflowHandler(dataflow chan *tunnel.MessageWrapper, stream tunnel.GRPCEventStream) {
	for ew := range dataflow {
		if err := stream.Send(ew); err != nil {
			zap.S().Errorw("stream.Send() failed", "error", err)
		}
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

	remote := "unknown"
	if p, ok := peer.FromContext(stream.Context()); ok {
		remote = p.Addr.String()
	}
	zap.S().Infow("agent-connect", "route", state.String(), "remote-address", remote)

	go handleHTTPRequests(sessionIdentity, inRequest, httpids, stream)

	go handleHTTPCancelRequest(sessionIdentity, inCancelRequest, httpids, stream)

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			zap.S().Infow("EOF", "route", state.String())
			httpids.CloseAll()
			routes.Remove(state)
			return nil
		}
		if err != nil {
			zap.S().Infow("remote-closed", "route", state.String())
			httpids.CloseAll()
			routes.Remove(state)
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.MessageWrapper_PingRequest:
			req := in.GetPingRequest()
			atomic.StoreUint64(&state.LastPing, tunnel.Now())
			if err := stream.Send(tunnel.MakePingResponse(req)); err != nil {
				zap.S().Warnw("unable to respond to agent ping", "route", state.String(), "error", err)
				routes.Remove(state)
				return err
			}
		case *tunnel.MessageWrapper_Hello:
			req := in.GetHello()
			if s.insecure {
				if agentIdentity, err = getAgentNameFromBytes(req.ClientCertificate); err != nil {
					return err
				}
				state.Name = agentIdentity
			}
			state.Endpoints = reqToEndpoints(req.Endpoints)
			state.Version = req.Version
			state.Hostname = req.Hostname
			state.AgentInfo = req.AgentInfo.FromPB()
			routes.Add(state)
			s.sendWebhook(state, req.Endpoints)

			if err = s.sendHello(stream); err != nil {
				zap.S().Warnw("unable to respond with hello, closing", "route", state.String(), "error", err)
				routes.Remove(state)
				return err
			}
			zap.S().Infow("agent-handshake-complete", "route", state.String())
		case *tunnel.MessageWrapper_HttpTunnelControl:
			handleHTTPControl(state.Name, in, httpids, s.endpoints, dataflow)
		case nil:
			// ignore for now
		default:
			zap.S().Debugw("received unknown message", "route", state.String(), "message", fmt.Sprintf("%#v", x))
		}
	}
}

func getAgentNameFromBytes(data []byte) (name string, err error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return
	}
	name, err = getAgentNameFromCertificate(cert)
	return
}

func reqToEndpoints(health []*tunnel.EndpointHealth) []tunnelroute.Endpoint {
	endpoints := make([]tunnelroute.Endpoint, len(health))
	for i, ep := range health {
		annotations := map[string]string{}
		if ep.Annotations != nil {
			for _, a := range ep.Annotations {
				annotations[a.Name] = a.Value
			}
		}
		endpoints[i] = tunnelroute.Endpoint{
			Name:        ep.Name,
			Type:        ep.Type,
			Configured:  ep.Configured,
			Annotations: annotations,
			Namespaces:  ep.Namespaces,
			AccountID:   ep.AccountID,
			AssumeRole:  ep.AssumeRole,
		}
	}
	return endpoints
}

func (s *agentTunnelServer) sendHello(stream tunnel.AgentTunnelService_EventTunnelServer) error {
	pbEndpoints := serviceconfig.EndpointsToPB(s.endpoints)
	hello := &tunnel.MessageWrapper{
		Event: &tunnel.MessageWrapper_Hello{
			Hello: &tunnel.Hello{
				Version:   version.GitBranch(),
				Endpoints: pbEndpoints,
				Hostname:  "controller",
			},
		},
	}
	return stream.Send(hello)
}

func handleHTTPControl(agentName string, in *tunnel.MessageWrapper, httpids *util.SessionList, endpoints []serviceconfig.ConfiguredEndpoint, dataflow chan *tunnel.MessageWrapper) {
	tunnelControl := in.GetHttpTunnelControl() // caller ensures this will work
	switch controlMessage := tunnelControl.ControlType.(type) {
	case *tunnel.HttpTunnelControl_CancelRequest:
		tunnel.CallCancelFunction(controlMessage.CancelRequest.Id)
	case *tunnel.HttpTunnelControl_OpenHTTPTunnelRequest:
		req := controlMessage.OpenHTTPTunnelRequest
		found := false
		for _, endpoint := range endpoints {
			if endpoint.Configured && endpoint.Type == req.Type && endpoint.Name == req.Name {
				go endpoint.Instance.ExecuteHTTPRequest(agentName, dataflow, req)
				found = true
				break
			}
		}
		if !found {
			zap.S().Warnf("Request for unsupported HTTP tunnel type=%s name=%s", req.Type, req.Name)
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
			zap.S().Warnf("Got response to unknown HTTP request id %s", resp.Id)
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
			zap.S().Debugf("Got response to unknown HTTP request id %s", resp.Id)
		}
		httpids.Unlock()
	case nil:
		return
	default:
		zap.S().Warnf("Received unknown HttpControl type: %T", controlMessage)
	}
}

type agentTunnelServer struct {
	tunnel.UnimplementedAgentTunnelServiceServer
	endpoints []serviceconfig.ConfiguredEndpoint
	insecure  bool
}

func runAgentGRPCServer(insecureAgents bool, serverCert tls.Certificate) {
	zap.S().Infow("starting agent GRPC server", "port", config.AgentListenPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.AgentListenPort))
	if err != nil {
		zap.S().Fatalw("failed to listen on agent port", "error", err)
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
				zap.S().Fatalw("grpcServer.Serve() failed", "error", err)
			}
		}()

		if err := m.Serve(); err != nil {
			zap.S().Fatalw("Failed to run m.Serve()", "error", err)
		}
	} else {
		certPool, err := authority.MakeCertPool()
		if err != nil {
			zap.S().Fatalw("authority.MakeCertPool", "error", err)
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
			zap.S().Fatalw("grpcServer.Serve() failed", "error", err)
		}
	}
}
