package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/opsmx/grpc-bidir/ca"
	"github.com/opsmx/grpc-bidir/controller/webhook"
	"github.com/opsmx/grpc-bidir/tunnel"
	"github.com/opsmx/grpc-bidir/ulid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	agents *Agents = MakeAgents()

	config *ControllerConfig

	authority *ca.CA

	ulidContext = ulid.NewContext()

	hook *webhook.Runner

	rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

	// metrics
	apiRequestCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controller_api_requests_total",
		Help: "The total numbe of API requests",
	}, []string{"agent", "protocol"})
	connectedAgentsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agents_connected",
		Help: "The currently connected agents",
	}, []string{"agent", "protocol"})
)

func makePingResponse(req *tunnel.PingRequest) *tunnel.SAEventWrapper {
	resp := &tunnel.SAEventWrapper{
		Event: &tunnel.SAEventWrapper_PingResponse{
			PingResponse: &tunnel.PingResponse{Ts: tunnel.Now(), EchoedTs: req.Ts},
		},
	}
	return resp
}

func firstLabel(name string) string {
	return strings.Split(name, ".")[0]
}

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
	shortName := strings.Split(tlsAuth.State.VerifiedChains[0][0].Subject.CommonName, ".")
	return shortName[0], nil
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

func kubernetesAPIHandler(w http.ResponseWriter, r *http.Request) {
	agentname := firstLabel(r.TLS.PeerCertificates[0].Subject.CommonName)
	ep := endpoint{protocol: "kubernetes", name: agentname}
	apiRequestCounter.WithLabelValues(agentname, "kubernetes").Inc()

	agents.RLock()
	agent := agents.AgentFor(ep)
	if agent == nil {
		agents.RUnlock()
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Id:       ulidContext.Ulid(),
		Target:   agentname,
		Protocol: "kubernetes",
		Method:   r.Method,
		URI:      r.RequestURI,
		Headers:  makeHeaders(r.Header),
		Body:     body,
	}
	message := &httpMessage{out: make(chan *tunnel.ASEventWrapper), cmd: req}
	agent.inHTTPRequest <- message
	agents.RUnlock()

	cleanClose := false

	notify := r.Context().Done()
	go func() {
		<-notify
		if !cleanClose {
			agent.inCancelRequest <- &cancelRequest{id: req.Id}
		}
	}()

	seenHeader := false
	isChunked := false
	flusher := w.(http.Flusher)
	for {
		in, more := <-message.out
		if !more {
			if !seenHeader {
				log.Printf("Request timed out sending to agent %s", req.Target)
				w.WriteHeader(http.StatusBadGateway)
			}
			cleanClose = true
			return
		}

		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_HttpResponse:
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
		case *tunnel.ASEventWrapper_HttpChunkedResponse:
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
			log.Printf("Received unknown message: %s: %T", agentname, x)
		}
	}
}

func (s *tunnelServer) GetStatistics(ctx context.Context, in *empty.Empty) (*tunnel.ControllerStatistics, error) {
	agents.RLock()
	defer agents.RUnlock()
	as := make([]*tunnel.ControllerAgentStatistics, 0)
	for _, list := range agents.m {
		for _, agent := range list {
			a := &tunnel.ControllerAgentStatistics{
				Identity:    agent.ep.name,
				Protocol:    agent.ep.protocol,
				Session:     agent.session,
				ConnectedAt: agent.connectedAt,
				LastPing:    agent.lastPing,
				LastUse:     agent.lastUse,
			}
			as = append(as, a)
		}
	}
	ret := &tunnel.ControllerStatistics{
		AgentStatistics: as,
	}

	return ret, nil
}

func runAgentHTTPServer(serverCert tls.Certificate) {
	log.Printf("Running HTTPS listener on port %d", config.APIPort)

	certPool, err := authority.MakeCertPool()
	if err != nil {
		log.Fatalf("While making certpool: %v", err)
	}

	tlsConfig := &tls.Config{
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

	mux := http.NewServeMux()

	mux.HandleFunc("/", kubernetesAPIHandler)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.APIPort),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	server.ListenAndServeTLS("", "")
}

func runPrometheusHTTPServer(port int) {
	log.Printf("Running HTTP listener for Prometheus on port %d", port)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	server.ListenAndServe()

	prometheus.MustRegister(apiRequestCounter)
	prometheus.MustRegister(connectedAgentsGauge)
}

func runGRPCServer(serverCert tls.Certificate) {
	//
	// Set up GRPC server
	//
	log.Printf("Starting GRPC server on port %d...", config.GRPCPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.GRPCPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	certPool, err := authority.MakeCertPool()
	if err != nil {
		log.Fatalf("While making certpool: %v", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	tunnel.RegisterTunnelServiceServer(grpcServer, newServer())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start GRPC server: %v", err)
	}
}

func main() {
	flag.Parse()

	c, err := LoadConfig(*configFile)
	if err != nil {
		log.Printf("Server names for generated certificate: %v", config.ServerNames)
	}
	config = c

	if len(config.Webhook) > 0 {
		hook = webhook.NewRunner(config.Webhook)
		hook.Run()
	}

	//
	// Make a new CA, for our use to generate server and other certificates.
	//
	caLocal, err := ca.MakeCA(&config.CAConfig)
	if err != nil {
		log.Fatalf("Cannot create authority: %v", err)
	}
	authority = caLocal

	//
	// Run Prometheus HTTP server
	//
	go runPrometheusHTTPServer(config.PrometheusPort)

	serverCert, err := authority.MakeServerCert(config.ServerNames)
	if err != nil {
		log.Fatalf("Cannot make server certificate: %v", err)
	}

	//
	// Set up HTTP server
	//
	go runAgentHTTPServer(*serverCert)

	// never returns
	runGRPCServer(*serverCert)
}
