package main

import (
	"crypto/tls"
	"io"
	"sync/atomic"
	"time"

	"github.com/OpsMx/go-app-base/version"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	"github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/opsmx/oes-birger/internal/tunnelroute"
	"github.com/opsmx/oes-birger/internal/ulid"
	"github.com/opsmx/oes-birger/internal/util"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type serverContext struct{}

func tickerPinger(stream tunnel.GRPCEventStream) {
	ticker := time.NewTicker(time.Duration(*tickTime) * time.Second)

	for ts := range ticker.C {
		req := &tunnel.MessageWrapper{
			Event: &tunnel.MessageWrapper_PingRequest{
				PingRequest: &tunnel.PingRequest{Ts: uint64(ts.UnixNano())},
			},
		}
		if err := stream.Send(req); err != nil {
			zap.S().Fatalf("Unable to send a PingRequest: %v", err)
		}
	}
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
				zap.S().Warnw("unable to send HTTP request",
					"session", session,
					"id", value.Cmd.Id)
			}
		default:
			zap.S().Debugf("Got unexpected message type: %T", interfacedRequest)
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
			zap.S().Warnw("unable to send cancel", "session", session, "id", id)
		}
	}
}

func dataflowHandler(dataflow chan *tunnel.MessageWrapper, stream tunnel.GRPCEventStream) {
	for ew := range dataflow {
		if err := stream.Send(ew); err != nil {
			zap.S().Fatalw("Unable to respond over GRPC", "error", err)
		}
	}
}

func runTunnel(sa *serverContext, conn *grpc.ClientConn, agentInfo *tunnel.AgentInfo, endpoints []serviceconfig.ConfiguredEndpoint, insecure bool, clcert tls.Certificate) {
	client := tunnel.NewAgentTunnelServiceClient(conn)
	ctx := context.Background()

	stream, err := client.EventTunnel(ctx)
	if err != nil {
		zap.S().Fatalw("EventTunnel(_) = _", "client", client, "error", err)
	}
	pbEndpoints := serviceconfig.EndpointsToPB(endpoints)
	pbAgentInfo := agentInfo.ToPB()
	hello := &tunnel.MessageWrapper{
		Event: &tunnel.MessageWrapper_Hello{
			Hello: &tunnel.Hello{
				Version:           version.GitBranch(),
				Endpoints:         pbEndpoints,
				AgentInfo:         pbAgentInfo,
				Hostname:          hostname,
				ClientCertificate: clcert.Certificate[0],
			},
		},
	}
	if err = stream.Send(hello); err != nil {
		zap.S().Fatalw("unable to send hello message", "error", err)
	}

	dataflow := make(chan *tunnel.MessageWrapper, 20)

	go tickerPinger(stream)
	go dataflowHandler(dataflow, stream)

	sessionIdentity := ulid.GlobalContext.Ulid()

	inRequest := make(chan interface{}, 1)
	inCancelRequest := make(chan string, 1)
	httpids := util.MakeSessionList()

	state := &tunnelroute.DirectlyConnectedRoute{
		Name:            "controller",
		Session:         sessionIdentity,
		InRequest:       inRequest,
		InCancelRequest: inCancelRequest,
		ConnectedAt:     tunnel.Now(),
	}

	go handleHTTPRequests(sessionIdentity, inRequest, httpids, stream)

	go handleHTTPCancelRequest(sessionIdentity, inCancelRequest, httpids, stream)

	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				httpids.CloseAll()
				routes.Remove(state)
				close(waitc)
				return
			}
			if err != nil {
				httpids.CloseAll()
				routes.Remove(state)
				zap.S().Fatalw("failed to receive GRPC", "error", err)
			}

			switch x := in.Event.(type) {
			case *tunnel.MessageWrapper_PingRequest:
				req := in.GetPingRequest()
				atomic.StoreUint64(&state.LastPing, tunnel.Now())
				if err := stream.Send(tunnel.MakePingResponse(req)); err != nil {
					zap.S().Warnw("unable to respond to ping",
						"destination", state,
						"error", err)
					routes.Remove(state)
					close(waitc)
					return
				}
			case *tunnel.MessageWrapper_Hello:
				req := in.GetHello()
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
			case *tunnel.MessageWrapper_PingResponse:
				continue
			case *tunnel.MessageWrapper_HttpTunnelControl:
				handleHTTPControl(in, httpids, endpoints, dataflow)
			case nil:
				continue
			default:
				zap.S().Warnf("Received unknown message: %T", x)
			}
		}
	}()
	<-waitc
	close(dataflow)
	_ = stream.CloseSend()
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
				go endpoint.Instance.ExecuteHTTPRequest("", dataflow, req)
				found = true
				break
			}
		}
		if !found {
			zap.S().Errorf("Request for unsupported HTTP tunnel type=%s name=%s", req.Type, req.Name)
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
			zap.S().Debugf("Got response to unknown HTTP request id %s", resp.Id)
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
		zap.S().Debugf("Received unknown HttpControl type: %T", controlMessage)
	}
}
