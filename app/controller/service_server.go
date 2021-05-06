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
	"io/ioutil"
	"log"
	"net/http"

	"github.com/opsmx/oes-birger/app/controller/agent"
	"github.com/opsmx/oes-birger/pkg/ca"
	"github.com/opsmx/oes-birger/pkg/jwtutil"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"github.com/opsmx/oes-birger/pkg/util"
)

func runHTTPSServer(serverCert tls.Certificate) {
	log.Printf("Running service HTTPS listener on port %d", config.ServiceListenPort)

	certPool, err := authority.MakeCertPool()
	if err != nil {
		log.Fatalf("While making certpool: %v", err)
	}

	tlsConfig := &tls.Config{
		ClientCAs:    certPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", serviceAPIHandler)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.ServiceListenPort),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	log.Fatal(server.ListenAndServeTLS("", ""))
}

func extractEndpointFromCert(r *http.Request) (agentIdentity string, endpointType string, endpointName string, validated bool) {
	if len(r.TLS.PeerCertificates) == 0 {
		return "", "", "", false
	}

	names, err := ca.GetCertificateNameFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		log.Printf("%v", err)
		return "", "", "", false
	}

	if names.Purpose != ca.CertificatePurposeService {
		return "", "", "", false
	}

	return names.Agent, names.Type, names.Name, true
}

func extractEndpointFromJWT(r *http.Request) (agentIdentity string, endpointType string, endpointName string, validated bool) {
	authPassword := r.Header.Get("X-Opsmx-Token")
	r.Header.Del("X-Opsmx-Token")

	if authPassword == "" {
		var ok bool
		if _, authPassword, ok = r.BasicAuth(); !ok {
			return "", "", "", false
		}
	}

	endpointType, endpointName, agentIdentity, err := jwtutil.ValidateJWT(jwtKeyset, authPassword)
	if err != nil {
		log.Printf("%v", err)
		return "", "", "", false
	}

	return agentIdentity, endpointType, endpointName, true
}

func extractEndpoint(r *http.Request) (agentIdentity string, endpointType string, endpointName string, err error) {
	agentIdentity, endpointType, endpointName, found := extractEndpointFromCert(r)
	if found {
		return agentIdentity, endpointType, endpointName, nil
	}

	agentIdentity, endpointType, endpointName, found = extractEndpointFromJWT(r)
	if found {
		return agentIdentity, endpointType, endpointName, nil
	}

	return "", "", "", fmt.Errorf("no valid credentials or JWT found")
}

func serviceAPIHandler(w http.ResponseWriter, r *http.Request) {
	agentIdentity, endpointType, endpointName, err := extractEndpoint(r)
	if err != nil {
		util.FailRequest(w, err, http.StatusBadRequest)
		return
	}
	ep := agent.AgentSearch{
		Name:         agentIdentity,
		EndpointType: endpointType,
		EndpointName: endpointName,
	}
	runAPIHandler(ep, w, r)
}

func runAPIHandler(ep agent.AgentSearch, w http.ResponseWriter, r *http.Request) {
	apiRequestCounter.WithLabelValues(ep.Name).Inc()

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
			err := agents.Cancel(ep, transactionID)
			if err != nil {
				log.Printf("while cancelling http request: %v", err)
			}
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
			n, err := w.Write(resp.Body)
			if err != nil {
				log.Printf("Error: cannot write: %v", err)
				if !seenHeader {
					w.WriteHeader(http.StatusBadGateway)
				}
				return
			}
			if n != len(resp.Body) {
				log.Printf("Error: did not write full message: %d of %d written", n, len(resp.Body))
				if !seenHeader {
					w.WriteHeader(http.StatusBadGateway)
				}
				return
			}
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
