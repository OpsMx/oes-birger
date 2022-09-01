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

package serviceconfig

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/OpsMx/go-app-base/httputil"
	"github.com/opsmx/oes-birger/internal/ca"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/opsmx/oes-birger/internal/tunnelroute"
	"github.com/opsmx/oes-birger/internal/ulid"
	"github.com/opsmx/oes-birger/internal/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tevino/abool"
	"go.uber.org/zap"
)

var (
	// metrics
	apiRequestCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "api_requests_total",
		Help: "The total number of API requests",
	}, []string{"route", "service"})
)

// RunHTTPSServer will listen for incoming service requests on a provided port, and
// currently will use certificates or JWT to identify the destination.
func RunHTTPSServer(routes *tunnelroute.ConnectedRoutes, ca *ca.CA, serverCert tls.Certificate, service IncomingServiceConfig) {
	zap.S().Infof("Running service HTTPS listener on port %d", service.Port)

	certPool, err := ca.MakeCertPool()
	if err != nil {
		zap.S().Fatalf("While making certpool: %v", err)
	}

	tlsConfig := &tls.Config{
		ClientCAs:    certPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", secureAPIHandlerMaker(routes, service))

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", service.Port),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	zap.S().Fatal(server.ListenAndServeTLS("", ""))
}

// RunHTTPServer will listen on an unencrypted HTTP only port, and will always forward
// incoming requests to the hard-coded configured destination.
func RunHTTPServer(routes *tunnelroute.ConnectedRoutes, service IncomingServiceConfig) {
	zap.S().Infof("Running service HTTP listener on port %d", service.Port)

	mux := http.NewServeMux()

	mux.HandleFunc("/", fixedIdentityAPIHandlerMaker(routes, service))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", service.Port),
		Handler: mux,
	}

	zap.S().Fatal(server.ListenAndServe())
}

func fixedIdentityAPIHandlerMaker(routes *tunnelroute.ConnectedRoutes, service IncomingServiceConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ep := tunnelroute.Search{
			Name:         service.Destination,
			EndpointType: service.ServiceType,
			EndpointName: service.DestinationService,
		}
		runAPIHandler(routes, ep, w, r)
	}
}

func extractEndpointFromCert(r *http.Request) (agentIdentity string, endpointType string, endpointName string, validated bool) {
	if len(r.TLS.PeerCertificates) == 0 {
		return "", "", "", false
	}

	names, err := ca.GetCertificateNameFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		zap.S().Errorf("%v", err)
		return "", "", "", false
	}

	if names.Purpose != ca.CertificatePurposeService {
		return "", "", "", false
	}

	return names.Agent, names.Type, names.Name, true
}

func extractEndpointFromJWT(r *http.Request) (agentIdentity string, endpointType string, endpointName string, validated bool) {
	// First check for our specific header.
	authPassword := r.Header.Get("X-Opsmx-Token")
	r.Header.Del("X-Opsmx-Token")

	// First, check Bearer authentication type.
	if authPassword == "" {
		authHeader := r.Header.Get("Authorization")
		items := strings.SplitN(authHeader, " ", 2)
		if len(items) == 2 {
			if items[0] == "Bearer" {
				authPassword = items[1]
			}
		}
	}

	// If that fails, check HTTP Basic (ignoring the username)
	if authPassword == "" {
		var ok bool
		if _, authPassword, ok = r.BasicAuth(); !ok {
			return "", "", "", false
		}
	}

	endpointType, endpointName, agentIdentity, err := jwtutil.ValidateJWT(authPassword, nil)
	if err != nil {
		zap.S().Errorf("%v", err)
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

func secureAPIHandlerMaker(routes *tunnelroute.ConnectedRoutes, service IncomingServiceConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		agentIdentity, endpointType, endpointName, err := extractEndpoint(r)
		if err != nil {
			util.FailRequest(w, err, http.StatusBadRequest)
			return
		}
		ep := tunnelroute.Search{
			Name:         agentIdentity,
			EndpointType: endpointType,
			EndpointName: endpointName,
		}
		runAPIHandler(routes, ep, w, r)
	}
}

func copyHeaders(resp *tunnel.HttpTunnelResponse, w http.ResponseWriter) {
	for name := range w.Header() {
		w.Header().Del(name)
	}
	for _, header := range resp.Headers {
		for _, value := range header.Values {
			w.Header().Add(header.Name, value)
		}
	}
}

func handleDone(n <-chan struct{}, routes *tunnelroute.ConnectedRoutes, state *apiHandlerState, target tunnelroute.Search, id string) {
	<-n
	if state.cleanClose.IsNotSet() {
		err := routes.Cancel(target, id)
		if err != nil {
			zap.S().Errorf("while cancelling http request: %v", err)
		}
	}
}

type apiHandlerState struct {
	seenHeader bool
	isChunked  bool
	flusher    http.Flusher
	cleanClose abool.AtomicBool
}

func runAPIHandler(routes *tunnelroute.ConnectedRoutes, ep tunnelroute.Search, w http.ResponseWriter, r *http.Request) {
	apiRequestCounter.WithLabelValues(ep.Name, ep.EndpointName).Inc()
	transactionID := ulid.GlobalContext.Ulid()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		zap.S().Errorf("unable to read entire message body")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	headers, err := tunnel.MakeHeaders(r.Header)
	if err != nil {
		zap.S().Errorf("unable to convert headers")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	req := &tunnel.OpenHTTPTunnelRequest{
		Id:      transactionID,
		Type:    ep.EndpointType,
		Name:    ep.EndpointName,
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: headers,
		Body:    body,
	}
	message := &tunnelroute.HTTPMessage{Out: make(chan *tunnel.MessageWrapper), Cmd: req}
	sessionID, err := routes.Send(ep, message)
	if err != nil {
		zap.S().Warnw("cannot-send", "error", err, "destination", ep.Name, "service", ep.EndpointName, "serviceType", ep.EndpointType)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	ep.Session = sessionID

	var handlerState = &apiHandlerState{}
	notify := r.Context().Done()
	go handleDone(notify, routes, handlerState, ep, transactionID)

	handlerState.flusher = w.(http.Flusher)
	for {
		in, more := <-message.Out
		if !more {
			if !handlerState.seenHeader {
				zap.S().Warnw("timeout sending", "destination", ep.Name, "service", ep.EndpointName, "serviceType", ep.EndpointType, "session", ep.Session)
				w.WriteHeader(http.StatusBadGateway)
			}
			handlerState.cleanClose.Set()
			return
		}

		switch x := in.Event.(type) {
		case *tunnel.MessageWrapper_HttpTunnelControl:
			if handleTunnelControl(ep, handlerState, x.HttpTunnelControl, w, r) {
				return
			}
		case nil:
			// ignore for now
		default:
			zap.S().Debugf("Received unknown message: %T", x)
		}
	}
}

func handleTunnelControl(ep tunnelroute.Search, state *apiHandlerState, tunnelControl *tunnel.HttpTunnelControl, w http.ResponseWriter, r *http.Request) bool {
	switch controlMessage := tunnelControl.ControlType.(type) {
	case *tunnel.HttpTunnelControl_HttpTunnelResponse:
		resp := controlMessage.HttpTunnelResponse
		state.seenHeader = true
		state.isChunked = resp.ContentLength < 0
		copyHeaders(resp, w)
		w.WriteHeader(int(resp.Status))
		if !httputil.StatusCodeOK(int(resp.Status)) {
			zap.S().Infow("Non-2xx response", "code", resp.Status, "destination", ep.Name, "service", ep.EndpointName, "serviceType", ep.EndpointType, "session", ep.Session)
		}
		if resp.ContentLength == 0 {
			state.cleanClose.Set()
			return true
		}
	case *tunnel.HttpTunnelControl_HttpTunnelChunkedResponse:
		resp := controlMessage.HttpTunnelChunkedResponse
		if !state.seenHeader {
			zap.S().Warnf("got ChunkedResponse before HttpResponse")
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		if len(resp.Body) == 0 {
			state.cleanClose.Set()
			return true
		}
		n, err := w.Write(resp.Body)
		if err != nil {
			zap.S().Errorf("cannot write: %v", err)
			if !state.seenHeader {
				w.WriteHeader(http.StatusBadGateway)
			}
			return true
		}
		if n != len(resp.Body) {
			zap.S().Errorf("did not write full message: %d of %d written", n, len(resp.Body))
			if !state.seenHeader {
				w.WriteHeader(http.StatusBadGateway)
			}
			return true
		}
		if state.isChunked {
			state.flusher.Flush()
		}
	case nil:
		// ignore for now
	default:
		zap.S().Debugf("Received unknown HTTP control message: %T", controlMessage)
	}
	return false
}
