package main

import (
	"io/ioutil"
	"log"
	"net/http"

	"github.com/opsmx/oes-birger/app/controller/agent"
	"github.com/opsmx/oes-birger/pkg/ca"
	"github.com/opsmx/oes-birger/pkg/tunnel"
)

func certificateAuthAPIHandler(serviceType string, w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		log.Printf("client did not present a certificate, returning Forbidden")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	names, err := ca.GetCertificateNameFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		log.Printf("%v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if names.Purpose != ca.CertificatePurposeService {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	endpointType := names.Type
	endpointName := names.Name
	agentIdentity := names.Agent

	if endpointType != serviceType {
		log.Printf("client cert type is %s, expected %s", endpointType, serviceType)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ep := agent.AgentSearch{
		Identity:     agentIdentity,
		EndpointType: endpointType,
		EndpointName: endpointName,
	}
	runAPIHandler(ep, w, r)
}

func runAPIHandler(ep agent.AgentSearch, w http.ResponseWriter, r *http.Request) {
	apiRequestCounter.WithLabelValues(ep.Identity).Inc()

	transactionID := ulidContext.Ulid()

	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Id:      transactionID,
		Type:    ep.EndpointType,
		Name:    ep.EndpointName,
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: makeHeaders(r.Header),
		Body:    body,
	}
	message := &HTTPMessage{Out: make(chan *tunnel.AgentToControllerWrapper), Cmd: req}
	sessionID, found := agents.Send(ep, message)
	if !found {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	ep.Session = sessionID

	cleanClose := false
	notify := r.Context().Done()
	go func() {
		<-notify
		if !cleanClose {
			agents.Cancel(ep, transactionID)
		}
	}()

	seenHeader := false
	isChunked := false
	flusher := w.(http.Flusher)
	for {
		in, more := <-message.Out
		if !more {
			if !seenHeader {
				log.Printf("Request timed out sending to agent")
				w.WriteHeader(http.StatusBadGateway)
			}
			cleanClose = true
			return
		}

		switch x := in.Event.(type) {
		case *tunnel.AgentToControllerWrapper_HttpResponse:
			resp := in.GetHttpResponse()
			seenHeader = true
			isChunked = resp.ContentLength < 0
			for name := range w.Header() {
				r.Header.Del(name)
			}
			for _, header := range resp.Headers {
				for _, value := range header.Values {
					w.Header().Add(header.Name, value)
				}
			}
			w.WriteHeader(int(resp.Status))
			if resp.ContentLength == 0 {
				cleanClose = true
				return
			}
		case *tunnel.AgentToControllerWrapper_HttpChunkedResponse:
			resp := in.GetHttpChunkedResponse()
			if !seenHeader {
				log.Printf("Error: got ChunkedResponse before HttpResponse")
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if len(resp.Body) == 0 {
				cleanClose = true
				return
			}
			w.Write(resp.Body)
			if isChunked {
				flusher.Flush()
			}
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %T", x)
		}
	}
}
