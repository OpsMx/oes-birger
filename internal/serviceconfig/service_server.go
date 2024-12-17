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

package serviceconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
	"os"

	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/opsmx/oes-birger/internal/logging"
	"github.com/opsmx/oes-birger/internal/ulid"
)

type Endpoint struct {
	Name        string            `json:"name,omitempty"`
	Type        string            `json:"type,omitempty"`
	Configured  bool              `json:"configured,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type Destination interface {
}

type Destinations interface {
	Search(ctx context.Context, spec SearchSpec) Destination
}

type SearchSpec struct {
	Destination string
	ServiceName string
	ServiceType string
}

// RunHTTPSServer will listen for incoming service requests on a provided port, and
// currently will use certificates or JWT to identify the destination.
func RunHTTPSServer(ctx context.Context, em EchoManager, routes Destinations, tlsPath string, service IncomingServiceConfig) {
	logger := logging.WithContext(ctx).Sugar()

	logger.Infow("Entered RunHTTPSServer")
	mux := http.NewServeMux()
	mux.HandleFunc("/", secureAPIHandlerMaker(em, routes, service))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", service.Port),
		Handler: mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	defer func() {
		logger.Infow("RunHTTPSServer Server stopped! with service",service.Name)
		// logger.Infow("Restarting it!")
		// RunHTTPSServer(ctx, em, routes, tlsPath, service)
	}()
	addDefaults(ctx, server)

	if tlsPath != "" {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
		logger.Infof("Running service HTTPS listener on port %d", service.Port)
		// logger.Fatal(server.ListenAndServeTLS(path.Join(tlsPath, "tls.crt"), path.Join(tlsPath, "tls.key")))
		if err := server.ListenAndServeTLS(path.Join(tlsPath, "tls.crt"), path.Join(tlsPath, "tls.key")); err != nil && err != http.ErrServerClosed { 
			logger.Errorf("Error received on server: %v", err)
			gracefulShutdown(server, ctx)
		}
	} else {
		logger.Infof("Running service HTTP listener on port %d", service.Port)
		// logger.Fatal(server.ListenAndServe())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("Error received on server: %v", err)
			gracefulShutdown(server, ctx)
		}
	}
}

func gracefulShutdown(server *http.Server, ctx context.Context){
	logger := logging.WithContext(ctx).Sugar()
	logger.Infof("Received signal: %v. Initiating graceful shutdown...\n")

	// Create a context with timeout for the shutdown process
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown the server gracefully
	if err := server.Shutdown(ctx); err != nil {
		logger.Infof("Server shutdown failed: %v\n", err)
	} else {
		logger.Infof("Server shutdown completed successfully.")
	}

	// sigchan <- syscall.SIGTERM
	os.Exit(0)
}

// RunHTTPServer will listen on an unencrypted HTTP only port, and will always forward
// incoming requests to the hard-coded configured destination.
func RunHTTPServer(ctx context.Context, em EchoManager, routes Destinations, service IncomingServiceConfig) {
	logger := logging.WithContext(ctx).Sugar()
	logger.Infof("Running service HTTP listener on port %d", service.Port)

	mux := http.NewServeMux()

	mux.HandleFunc("/", fixedIdentityAPIHandlerMaker(em, routes, service))
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", service.Port),
		Handler: mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	addDefaults(ctx, server)
	// logger.Fatal(server.ListenAndServe())
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Errorf("Error received on server: %v", err)
		gracefulShutdown(server, ctx)
	}
	defer func() {
		logger.Infow("RunHTTPSServer Server stopped! with service",service.Name)
		// logger.Infow("Restarting it!")
		// RunHTTPSServer(ctx, em, routes, tlsPath, service)
	}()
}

func addDefaults(ctx context.Context, server *http.Server) {
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	server.IdleTimeout = 4 * time.Second
	server.ReadHeaderTimeout = 4 * time.Second
}

func fixedIdentityAPIHandlerMaker(em EchoManager, routes Destinations, service IncomingServiceConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logging.WithContext(r.Context()).Sugar()
		logger.Infow("Entered fixedIdentityAPIHandlerMaker with request uri", r.URL.String())
		ep := SearchSpec{
			Destination: service.Destination,
			ServiceType: service.ServiceType,
			ServiceName: service.DestinationService,
		}
		defer func() {
            if err := recover(); err != nil {
                logger.Errorf("Recovered from panic: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            }
        }()
		runAPIHandler(em, routes, ep, w, r)
	}
}

func extractEndpointFromJWT(r *http.Request) (agentIdentity string, endpointType string, endpointName string, validated bool) {
	logger := logging.WithContext(r.Context()).Sugar()

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
	logger := logging.WithContext(r.Context()).Sugar()
	agentIdentity, endpointType, endpointName, found := extractEndpointFromJWT(r)
	if found {
		return agentIdentity, endpointType, endpointName, nil
	}
	logger.Warnw("invalid-credentials", "remote", r.RemoteAddr, "url", r.URL)
	return "", "", "", fmt.Errorf("no valid JWT found")
}

func secureAPIHandlerMaker(em EchoManager, routes Destinations, service IncomingServiceConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logging.WithContext(r.Context()).Sugar()
		logger.Infow("Entered secureAPIHandlerMaker with request uri", r.URL.String())
		agentIdentity, endpointType, endpointName, err := extractEndpoint(r)
		if err != nil {
			r.Body.Close()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ep := SearchSpec{
			Destination: agentIdentity,
			ServiceType: endpointType,
			ServiceName: endpointName,
		}
		runAPIHandler(em, routes, ep, w, r)
		defer func() {
            if err := recover(); err != nil {
                logger.Errorf("Recovered from panic: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            }
        }()
	}
}

func runAPIHandler(em EchoManager, routes Destinations, ep SearchSpec, w http.ResponseWriter, r *http.Request) {
	// ctx := logging.NewContext(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	logger := logging.WithContext(ctx).Sugar()
	logger.Infow("Entered runAPIHandler with request uri", r.URL.String())
	session := routes.Search(ctx, ep)
	if session == nil {
		logger.Warnw("no such destination for service request", "destination", ep.Destination, "serviceName", ep.ServiceName, "serviceType", ep.ServiceType)
		w.WriteHeader(http.StatusBadGateway)
		cancel()
		return
	}

	// TODO: read should be limited in size...
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("unable to read entire message body")
		w.WriteHeader(http.StatusServiceUnavailable)
		cancel()
		return
	}
	r.Body.Close()

	streamID := ulid.GlobalContext.Ulid()
	echo := em.MakeRequester(ctx, ep, streamID)

	defer func() {
		cancel()
		echo.Shutdown(ctx)
		}()
	echo.RunRequest(ctx, session, body, w, r)
}
