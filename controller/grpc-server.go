package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"

	"github.com/opsmx/grpc-bidir/controller/webhook"
	"github.com/opsmx/grpc-bidir/tunnel"
)

type tunnelServer struct {
	tunnel.UnimplementedTunnelServiceServer
}

func newServer() *tunnelServer {
	s := &tunnelServer{}
	return s
}

func sendWebhook(name string, namespaces []string) {
	if hook == nil {
		return
	}
	req := &webhook.WebhookRequest{
		Name:       name,
		Namespaces: namespaces,
	}
	kc, err := authority.MakeKubectlConfig(name, fmt.Sprintf("https://%s:%d", config.ServerNames[0], *apiPort))
	if err != nil {
		log.Printf("Unable to generate a working kubectl: %v", err)
	} else {
		req.Kubeconfig = base64.StdEncoding.EncodeToString([]byte(kc))
	}

	hook.Send(req)
}

//
// endpoints are some way we can send data.  How it is sent and how it gets to where
// it is intended is up to what type of endpoint it may be.
//
type endpoint struct {
	protocol string // "kubernetes" or whatever API we are handling
	name     string // The agent name this transaction is bound to
	session  string // The agent session this transaction is bound to

}

// Transactions are created based on the HTTP request coming in, and stored in a list of currently
// running transactions.  If the destination is lost (an agent disconnects) all transactions
// bound to that destination should be cancelled.
//
// Actual destinations can be a directly connected agent, or it can be another controller
// which has a directly connected agent.
// That is:
//    apiRequest <-> agent
//    apiRequest <-> otherController <-> agent
type transaction struct {
	endpoint
	id string // the per-request id, used for passing info and cancelling if needed
}

//
// Flow:
//  * API request comes in
//  * We look in our local list of possible endpoints.  Error if not found.
//  * One of the endpoint paths (directly connected preferred, but if none use another controller)
//  * The message is sent to the endpoint.
//  * If the "other side" cancells the request, we expect to get notified.
//  * If we cancel the request, we notify the endpoint.
//  * Multiple data packets can flow in either direction:  { header, data... }
//  * If the endpoint vanishes, we will cancel all outstanding transactions.

// Impl:
//
// An agent uses a tunnel, which will allow messages to flow back and forth. If the connection
// is closed, we can detect this.  Each agent has only one ID and one protocol it can handle.
//
// A peer controller also uses a tunnel, where it sends a list of ( protocol, agentID, agentSession )
// to allow proxying through this controller.  If it closes, all endpoints handled by this
// tunnel are closed.
//
// Endpoints always receive the full list of

func (s *tunnelServer) EventTunnel(stream tunnel.TunnelService_EventTunnelServer) error {
	agentIdentity, err := getAgentNameFromContext(stream.Context())
	if err != nil {
		return err
	}

	sessionIdentity := ulidContext.Ulid()
	log.Printf("Registered agent: %s, session id %s", agentIdentity, sessionIdentity)

	inHTTPRequest := make(chan *httpMessage, 1)
	inCancelRequest := make(chan *cancelRequest, 1)
	httpids := struct {
		sync.RWMutex
		m map[string]chan *tunnel.ASEventWrapper
	}{m: make(map[string]chan *tunnel.ASEventWrapper)}

	state := &agentState{
		identity:        agentIdentity,
		sessionIdentity: sessionIdentity,
		inHTTPRequest:   inHTTPRequest,
		inCancelRequest: inCancelRequest,
		connectedAt:     tunnel.Now(),
	}

	log.Printf("Agent %s connected, session id %s, awaiting hello message", state.identity, state.sessionIdentity)

	go func() {
		for {
			request, more := <-inHTTPRequest
			if !more {
				log.Printf("Request channel closed for %s", agentIdentity)
				return
			}
			httpids.Lock()
			httpids.m[request.cmd.Id] = request.out
			httpids.Unlock()
			resp := &tunnel.SAEventWrapper{
				Event: &tunnel.SAEventWrapper_HttpRequest{
					HttpRequest: request.cmd,
				},
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to agent %s for HTTP request %s", agentIdentity, request.cmd.Id)
			}
		}
	}()

	go func() {
		for {
			request, more := <-inCancelRequest
			if !more {
				log.Printf("cancel channel closed for agent %s", agentIdentity)
				return
			}
			httpids.Lock()
			delete(httpids.m, request.id)
			httpids.Unlock()
			resp := &tunnel.SAEventWrapper{
				Event: &tunnel.SAEventWrapper_HttpRequestCancel{
					HttpRequestCancel: &tunnel.HttpRequestCancel{Id: request.id, Target: agentIdentity},
				},
			}
			if err := stream.Send(resp); err != nil {
				log.Printf("Unable to send to agent %s for cancel request %s", agentIdentity, request.id)
			}
		}
	}()

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Printf("Closing %s", agentIdentity)
			httpids.Lock()
			for _, v := range httpids.m {
				close(v)
			}
			httpids.Unlock()
			agents.RemoveAgent(state)
			return nil
		}
		if err != nil {
			log.Printf("Agent closed connection: %s", agentIdentity)
			httpids.Lock()
			for _, v := range httpids.m {
				close(v)
			}
			httpids.Unlock()
			agents.RemoveAgent(state)
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_PingRequest:
			req := in.GetPingRequest()
			atomic.StoreUint64(&state.lastPing, tunnel.Now())
			if err := stream.Send(makePingResponse(req)); err != nil {
				log.Printf("Unable to respond to %s with ping response: %v", agentIdentity, err)
				agents.RemoveAgent(state)
				return err
			}
		case *tunnel.ASEventWrapper_AgentHello:
			req := in.GetAgentHello()
			agents.AddAgent(state)
			sendWebhook(state.identity, req.Namespaces)
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
				log.Printf("Got response to unknown HTTP request id %s from %s", resp.Id, agentIdentity)
			}
			httpids.Unlock()
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %s: %T", agentIdentity, x)
		}
	}
}
