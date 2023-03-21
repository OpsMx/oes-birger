/*
 * Copyright 2021-2023 OpsMx, Inc.
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

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/opsmx/oes-birger/internal/ca"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/opsmx/oes-birger/internal/ulid"
)

// RunHTTPSServer will listen for incoming service requests on a provided port, and
// currently will use certificates or JWT to identify the destination.
func RunHTTPSServer(ctx context.Context, routes *AgentSessions, ca *ca.CA, serverCert tls.Certificate, service serviceconfig.IncomingServiceConfig) {
	_, logger := loggerFromContext(ctx)
	logger.Infof("Running service HTTPS listener on port %d", service.Port)

	certPool, err := ca.MakeCertPool()
	if err != nil {
		logger.Fatalf("While making certpool: %v", err)
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
	addDefaults(ctx, server)
	logger.Fatal(server.ListenAndServeTLS("", ""))
}

// RunHTTPServer will listen on an unencrypted HTTP only port, and will always forward
// incoming requests to the hard-coded configured destination.
func RunHTTPServer(ctx context.Context, routes *AgentSessions, service serviceconfig.IncomingServiceConfig) {
	_, logger := loggerFromContext(ctx)
	logger.Infof("Running service HTTP listener on port %d", service.Port)

	mux := http.NewServeMux()

	mux.HandleFunc("/", fixedIdentityAPIHandlerMaker(routes, service))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", service.Port),
		Handler: mux,
	}
	addDefaults(ctx, server)
	logger.Fatal(server.ListenAndServe())
}

func addDefaults(ctx context.Context, server *http.Server) {
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	server.IdleTimeout = 4 * time.Second
	server.ReadHeaderTimeout = 4 * time.Second
}

func fixedIdentityAPIHandlerMaker(routes *AgentSessions, service serviceconfig.IncomingServiceConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ep := SessionSearch{
			AgentID:     service.Destination,
			ServiceType: service.ServiceType,
			ServiceName: service.DestinationService,
		}
		runAPIHandler(routes, ep, w, r)
	}
}

func extractEndpointFromCert(r *http.Request) (agentIdentity string, endpointType string, endpointName string, validated bool) {
	_, logger := loggerFromContext(r.Context())

	if len(r.TLS.PeerCertificates) == 0 {
		return "", "", "", false
	}

	names, err := ca.GetCertificateNameFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		logger.Errorf("%v", err)
		return "", "", "", false
	}

	if names.Purpose != ca.CertificatePurposeService {
		return "", "", "", false
	}

	return names.Agent, names.Type, names.Name, true
}

func extractEndpointFromJWT(r *http.Request) (agentIdentity string, endpointType string, endpointName string, validated bool) {
	_, logger := loggerFromContext(r.Context())

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

	endpointType, endpointName, agentIdentity, err := jwtutil.ValidateServiceJWT(authPassword, nil)
	if err != nil {
		logger.Errorf("%v", err)
		return "", "", "", false
	}

	return agentIdentity, endpointType, endpointName, true
}

func extractEndpoint(r *http.Request) (agentIdentity string, endpointType string, endpointName string, err error) {
	_, logger := loggerFromContext(r.Context())
	agentIdentity, endpointType, endpointName, found := extractEndpointFromCert(r)
	if found {
		return agentIdentity, endpointType, endpointName, nil
	}

	agentIdentity, endpointType, endpointName, found = extractEndpointFromJWT(r)
	if found {
		return agentIdentity, endpointType, endpointName, nil
	}

	logger.Warnw("invalid-credentials", "remote", r.RemoteAddr, "url", r.URL)

	return "", "", "", fmt.Errorf("no valid credentials or JWT found")
}

func secureAPIHandlerMaker(routes *AgentSessions, service serviceconfig.IncomingServiceConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		agentIdentity, endpointType, endpointName, err := extractEndpoint(r)
		if err != nil {
			r.Body.Close()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ep := SessionSearch{
			AgentID:     agentIdentity,
			ServiceType: endpointType,
			ServiceName: endpointName,
		}
		runAPIHandler(routes, ep, w, r)
	}
}

func runAPIHandler(routes *AgentSessions, ep SessionSearch, w http.ResponseWriter, r *http.Request) {
	ctx, logger := loggerFromContext(r.Context())

	session := routes.find(ctx, ep)
	if session == nil {
		logger.Warnw("no such agent for service request", "agentID", ep.AgentID, "serviceName", ep.ServiceName, "serviceType", ep.ServiceType)
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// TODO: read should be limited in size...
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("unable to read entire message body")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	r.Body.Close()

	headers, err := serviceconfig.HTTPHeadersToPB(r.Header)
	if err != nil {
		logger.Errorf("unable to convert headers")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	streamID := ulid.GlobalContext.Ulid()
	echo := MakeIncomingEchoer(ctx, streamID)

	session.requestChan <- serviceRequest{
		req: &pb.TunnelRequest{
			StreamId: streamID,
			Name:     ep.ServiceName,
			Type:     ep.ServiceType,
			Method:   r.Method,
			URI:      r.RequestURI,
			Body:     body,
			Headers:  headers,
		},
		echo: echo,
	}

	defer echo.Shutdown(ctx)
	runEcho(ctx, echo, w, r)
}

func runEcho(ctx context.Context, echo *ServerEcho, w http.ResponseWriter, r *http.Request) {
	_, logger := loggerFromContext(ctx)
	headersSent := false
	flusher := w.(http.Flusher)
	interMessageTime := 10 * time.Second
	t := time.NewTimer(10 * interMessageTime)

	for {
		select {
		case <-t.C:
			logger.Infof("stream timed out")
			return
		case <-r.Context().Done():
			logger.Debugf("client closed, stopping data flow")
			// TODO: send cancel event over gRPC
			return
		case <-echo.doneChan:
			return
		case code := <-echo.failChan:
			if !headersSent {
				w.WriteHeader(code)
			}
			return
		case data := <-echo.dataChan:
			t.Reset(interMessageTime)
			n, err := w.Write(data)
			if err != nil {
				// TODO: send cancel over gRPC
				logger.Warnf("send to client: %v", err)
				return
			}
			if n != len(data) {
				// TODO: send cancel over gRPC
				logger.Warnf("short send to client: wrote %d, wanted to write %d bytes", n, len(data))
				return
			}
			flusher.Flush()
		case headers := <-echo.headersChan:
			t.Reset(interMessageTime)
			headersSent = true
			for name := range w.Header() {
				w.Header().Del(name)
			}
			for _, header := range headers.Headers {
				for _, value := range header.Values {
					w.Header().Add(header.Name, value)
				}
			}
			w.WriteHeader(int(headers.StatusCode))
		}
	}
}
