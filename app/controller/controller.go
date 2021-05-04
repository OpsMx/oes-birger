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
	"context"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/opsmx/oes-birger/app/controller/agent"
	"github.com/opsmx/oes-birger/pkg/ca"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"github.com/opsmx/oes-birger/pkg/ulid"
	"github.com/opsmx/oes-birger/pkg/util"
	"github.com/opsmx/oes-birger/pkg/webhook"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	serviceAuthPath = "/app/secrets/serviceAuth"
)

var (
	versionBuild = -1
	version      = util.Versions{Major: 2, Minor: 2, Patch: 0, Build: versionBuild}

	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	jwtKeyset     = jwk.NewSet()
	jwtCurrentKey string

	config *ControllerConfig

	authority *ca.CA

	ulidContext = ulid.NewContext()

	hook *webhook.Runner

	agents = agent.MakeAgents()

	// metrics
	apiRequestCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controller_api_requests_total",
		Help: "The total numbe of API requests",
	}, []string{"agent"})
)

func getAgentNameFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer found")
	}
	tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
	}
	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "could not verify peer certificate")
	}
	names, err := ca.GetCertificateNameFromCert(tlsAuth.State.VerifiedChains[0][0])
	if err != nil {
		return "", err
	}
	if names.Purpose != ca.CertificatePurposeAgent {
		return "", fmt.Errorf("not an agent certificate")
	}
	return names.Agent, nil
}

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		if name != "Authorization" {
			ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
		}
	}
	return ret
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
// is closed, we can detect this.  Each agent is known by a name ("Target")
// and one protocol it can handle.
//
// A peer controller also uses a tunnel, where it sends a list of ( protocol, agentID, agentSession )
// to allow proxying through this controller.  If it closes, all endpoints handled by this
// tunnel are closed.
//

type HTTPMessage struct {
	Out chan *tunnel.AgentToControllerWrapper
	Cmd *tunnel.HttpRequest
}

func healthcheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	w.Write([]byte("{}"))
	w.WriteHeader(200)
}

func runPrometheusHTTPServer(port uint16) {
	log.Printf("Running HTTP listener for Prometheus on port %d", port)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/", healthcheck)
	mux.HandleFunc("/health", healthcheck)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	server.ListenAndServe()

	prometheus.MustRegister(apiRequestCounter)
	agent.PrometheusRegister()
}

func loadKeyset() {
	if config.ServiceAuth.CurrentKeyName == "" {
		log.Fatalf("No primary serviceAuth key name provided")
	}
	jwtCurrentKey = config.ServiceAuth.CurrentKeyName

	err := filepath.WalkDir(serviceAuthPath, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !info.Type().IsRegular() {
			return nil
		}
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		key, err := jwk.New(content)
		if err != nil {
			return err
		}
		key.Set(jwk.KeyIDKey, info.Name())
		jwtKeyset.Add(key)
		log.Printf("Loaded service key name %s, length %d", info.Name(), len(content))
		return nil
	})
	if err != nil {
		log.Fatalf("cannot load key serviceAuth keys: %v", err)
	}

	log.Printf("Loaded %d serviceKeys", jwtKeyset.Len())
}

func parseConfig(filename string) (*ControllerConfig, error) {
	f, err := os.Open(*configFile)
	if err != nil {
		return nil, fmt.Errorf("while opening configfile: %w", err)
	}

	c, err := LoadConfig(f)
	if err != nil {
		return nil, fmt.Errorf("while loading config: %w", err)
	}

	return c, nil
}

func main() {
	log.Printf("Controller version %s starting", version.String())

	flag.Parse()

	var err error

	config, err = parseConfig(*configFile)
	if err != nil {
		log.Fatalf("%v", err)
	}
	config.Dump()

	loadKeyset()

	if len(config.Webhook) > 0 {
		hook = webhook.NewRunner(config.Webhook)
		go hook.Run()
	}

	//
	// Make a new CA, for our use to generate server and other certificates.
	//
	caLocal, err := ca.LoadCAFromFile(config.CAConfig)
	if err != nil {
		log.Fatalf("Cannot create authority: %v", err)
	}
	authority = caLocal

	//
	// Make a server certificate.
	//
	log.Println("Generating a server certificate...")
	serverCert, err := authority.MakeServerCert(config.ServerNames)
	if err != nil {
		log.Fatalf("Cannot make server certificate: %v", err)
	}

	go runHTTPSServer(*serverCert)

	cncserver := &CNCServer{}
	go cncserver.runCommandHTTPServer(config.ControlListenPort, *serverCert)

	go runCmdToolGRPCServer(*serverCert)

	go runAgentGRPCServer(*serverCert)

	runPrometheusHTTPServer(config.PrometheusListenPort)
}
