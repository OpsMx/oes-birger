package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/opsmx/oes-birger/app/controller/agent"
	"github.com/opsmx/oes-birger/pkg/ca"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"github.com/opsmx/oes-birger/pkg/ulid"
	"github.com/opsmx/oes-birger/pkg/webhook"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	jwtKeyset jwk.Set

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

func getNamesFromContext(ctx context.Context) ([]string, error) {
	p, ok := peer.FromContext(ctx)
	empty := make([]string, 0)
	if !ok {
		return empty, status.Error(codes.Unauthenticated, "no peer found")
	}
	tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return empty, status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
	}
	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return empty, status.Error(codes.Unauthenticated, "could not verify peer certificate")
	}
	return strings.Split(tlsAuth.State.VerifiedChains[0][0].Subject.CommonName, "."), nil
}

func getAgentNameFromContext(ctx context.Context) (string, error) {
	names, err := getNamesFromContext(ctx)
	if err != nil {
		return "", err
	}
	return names[0], nil
}

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		if name != "Accept-Encoding" {
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

func getServiceTypeFromName(httpRequest *http.Request) string {
	items := strings.Split(httpRequest.Host, ":")
	items2 := strings.Split(items[0], ".")
	return items2[0]
}

func serviceAPIHandler(w http.ResponseWriter, r *http.Request) {
	serviceType := getServiceTypeFromName(r)
	if serviceType == "kubernetes" {
		certificateAuthAPIHandler(serviceType, w, r)
	} else {
		basicAuthAPIHandler(serviceType, w, r)
	}
}

func runHTTPSServer(serverCert tls.Certificate) {
	log.Printf("Running generic API HTTPS listener on port %d", config.ServicePort)

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
		Addr:      fmt.Sprintf(":%d", config.ServicePort),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	server.ListenAndServeTLS("", "")
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

func main() {
	flag.Parse()

	c, err := LoadConfig(*configFile)
	if err != nil {
		log.Printf("Server names for generated certificate: %v", config.ServerNames)
	}
	config = c
	c.Dump()

	if len(config.Webhook) > 0 {
		hook = webhook.NewRunner(config.Webhook)
		go hook.Run()
	}

	//
	// Make a new CA, for our use to generate server and other certificates.
	//
	caLocal, err := ca.MakeCA(config.CAConfig)
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
	go runCommandHTTPServer(*serverCert)
	go runCmdToolGRPCServer(*serverCert)
	go runAgentGRPCServer(*serverCert)
	runPrometheusHTTPServer(config.PrometheusPort)
}
