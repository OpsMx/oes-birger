package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v2"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skandragon/grpc-bidir/controller/webhook"
	"github.com/skandragon/grpc-bidir/kubeconfig"
	"github.com/skandragon/grpc-bidir/tunnel"
	"github.com/skandragon/grpc-bidir/ulid"
)

var (
	port           = flag.Int("port", tunnel.DefaultPort, "The GRPC port to listen on")
	apiPort        = flag.Int("apiPort", 9002, "The HTTPS port to listen for Kubernetes API requests on")
	prometheusPort = flag.Int("prometheusPort", 9102, "The HTTP port to serve /metrics for Prometheus")
	caCertFile     = flag.String("caCertFile", "/app/config/ca.pem", "The file containing the CA certificate")
	caKeyFile      = flag.String("caKeyFile", "/app/config/cakey.pem", "The CA key file")
	configFile     = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	agents = struct {
		sync.RWMutex
		m map[string][]*agentState
	}{m: make(map[string][]*agentState)}

	config *controllerConfig

	ulidContext = ulid.NewContext()

	hook *webhook.WebhookRunner

	rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

	// metrics
	apiRequestCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controller_api_requests_total",
		Help: "The total numbe of API requests",
	}, []string{"agent_identity"})
	connectedAgentsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agents_connected",
		Help: "The currently connected agents",
	}, []string{"agent_identity"})

	caCert tls.Certificate
)

func makeServerCert(ca tls.Certificate) tls.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"OpsMX API Forwarder"},
			Country:      []string{"US"},
			Province:     []string{},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     config.ServerNames,
	}
	certPrivKey, err := rsa.GenerateKey(crand.Reader, 4096)
	if err != nil {
		log.Fatalf("Unable to generate server key: %v", err)
	}

	// we now have a certificate and private key.  Now, sign the cert with the CA.

	caCert, err := x509.ParseCertificate(ca.Certificate[0])

	certBytes, err := x509.CreateCertificate(crand.Reader, cert, caCert, &certPrivKey.PublicKey, ca.PrivateKey)
	if err != nil {
		log.Fatalf("Unable to generate server certificate: %v", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		log.Fatalf("Unable to convert to TLS server certificate: %v", err)
	}
	return serverCert
}

func makeKubectlConfig(name string, ca tls.Certificate) string {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   name + ".client",
			Organization: []string{"OpsMX API Forwarder Client"},
			Country:      []string{"US"},
			Province:     []string{},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     config.ServerNames,
	}
	certPrivKey, err := rsa.GenerateKey(crand.Reader, 4096)
	if err != nil {
		log.Fatalf("Unable to generate server key: %v", err)
	}

	// we now have a certificate and private key.  Now, sign the cert with the CA.

	caCert, err := x509.ParseCertificate(ca.Certificate[0])

	certBytes, err := x509.CreateCertificate(crand.Reader, cert, caCert, &certPrivKey.PublicKey, ca.PrivateKey)
	if err != nil {
		log.Fatalf("Unable to generate server certificate: %v", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	cert64 := base64.StdEncoding.EncodeToString(certPEM.Bytes())

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	certPrivKey64 := base64.StdEncoding.EncodeToString(certPrivKeyPEM.Bytes())

	caPEM, err := ioutil.ReadFile(*caCertFile)
	ca64 := base64.StdEncoding.EncodeToString(caPEM)
	joinName := "forwarder"

	k := kubeconfig.KubeConfig{
		APIVersion: "v1",
		Kind:       "config",
		Contexts: []kubeconfig.Context{
			{
				Name: joinName,
				Context: kubeconfig.ContextDetails{
					User: joinName,
				},
			},
		},
		Users: []kubeconfig.User{
			{
				Name: joinName,
				User: kubeconfig.UserDetails{
					ClientCertificateData: cert64,
					ClientKeyData:         certPrivKey64,
				},
			},
		},
		Clusters: []kubeconfig.Cluster{
			{
				Name: joinName,
				Cluster: kubeconfig.ClusterDetails{
					Server:                   fmt.Sprintf("https://%s:%d", config.ServerNames[0], *apiPort),
					CertificateAuthorityData: ca64,
				},
			},
		},
		CurrentContext: joinName,
	}

	js, _ := json.Marshal(k)
	return string(js)
}

type controllerConfig struct {
	Agents      map[string]*agentConfig `yaml:"agents"`
	Webhook     string                  `yaml:"webhook"`
	ServerNames []string                `yaml:"serverNames"`
}

type agentConfig struct {
	Identity string `yaml:"identity"`
}

func loadConfig() *controllerConfig {
	buf, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Unable to load config file: %v", err)
	}

	config := &controllerConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		log.Fatalf("Unable to read config file: %v", err)
	}
	return config
}

type httpMessage struct {
	out chan *tunnel.ASEventWrapper
	cmd *tunnel.HttpRequest
}

type cancelRequest struct {
	id string
}

func sliceIndex(limit int, predicate func(i int) bool) int {
	for i := 0; i < limit; i++ {
		if predicate(i) {
			return i
		}
	}
	return -1
}

type agentState struct {
	identity        string
	sessionIdentity string
	inHTTPRequest   chan *httpMessage
	inCancelRequest chan *cancelRequest
	connectedAt     uint64
	lastPing        uint64
	lastUse         uint64
}

func sendWebhook(name string, namespaces []string) {
	if hook == nil {
		return
	}
	kc := makeKubectlConfig(name, caCert)
	req := &webhook.WebhookRequest{
		Name:       name,
		Namespaces: namespaces,
		Kubeconfig: base64.StdEncoding.EncodeToString([]byte(kc)),
	}
	hook.Send(req)
}

func addAgent(state *agentState) {
	agents.Lock()
	defer agents.Unlock()
	agentList, ok := agents.m[state.identity]
	if !ok {
		log.Printf("No previous agent for id %s found, creating a new list", state.identity)
		agentList = make([]*agentState, 0)
	}
	agentList = append(agentList, state)
	agents.m[state.identity] = agentList
	log.Printf("Session %s added for agent %s, now at %d endpoints", state.sessionIdentity, state.identity, len(agentList))
	connectedAgentsGauge.WithLabelValues(state.identity).Inc()
}

func removeAgent(state *agentState) {
	agents.Lock()
	defer agents.Unlock()
	agentList, ok := agents.m[state.identity]
	if !ok {
		log.Printf("ERROR: removing unknown agent: (%s, %s)", state.identity, state.sessionIdentity)
		return
	}

	close(state.inHTTPRequest)
	close(state.inCancelRequest)

	// TODO: We should always find our entry...
	i := sliceIndex(len(agentList), func(i int) bool { return agentList[i] == state })
	if i != -1 {
		agentList[i] = agentList[len(agentList)-1]
		agentList[len(agentList)-1] = nil
		agentList = agentList[:len(agentList)-1]
		agents.m[state.identity] = agentList
		connectedAgentsGauge.WithLabelValues(state.identity).Dec()
	} else {
		log.Printf("Agent session %s not found in list of agents for %s", state.sessionIdentity, state.identity)
	}
	log.Printf("Session %s removed for agent %s, now at %d endpoints", state.sessionIdentity, state.identity, len(agentList))
}

type tunnelServer struct {
	tunnel.UnimplementedTunnelServiceServer
}

func newServer() *tunnelServer {
	s := &tunnelServer{}
	return s
}

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
		lastPing:        0,
		lastUse:         0,
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
			removeAgent(state)
			return nil
		}
		if err != nil {
			log.Printf("Agent closed connection: %s", agentIdentity)
			httpids.Lock()
			for _, v := range httpids.m {
				close(v)
			}
			httpids.Unlock()
			removeAgent(state)
			return err
		}

		switch x := in.Event.(type) {
		case *tunnel.ASEventWrapper_PingRequest:
			req := in.GetPingRequest()
			atomic.StoreUint64(&state.lastPing, tunnel.Now())
			if err := stream.Send(makePingResponse(req)); err != nil {
				log.Printf("Unable to respond to %s with ping response: %v", agentIdentity, err)
				removeAgent(state)
				return err
			}
		case *tunnel.ASEventWrapper_AgentHello:
			req := in.GetAgentHello()
			addAgent(state)
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
// Look up the target name we are given in our config.  If it doesn't exist,
// use the name provided as the target.
//
func mapTarget(name string) string {
	target, ok := config.Agents[name]
	if !ok {
		return name
	}
	return target.Identity
}

func handler(w http.ResponseWriter, r *http.Request) {
	agentname := firstLabel(r.TLS.PeerCertificates[0].Subject.CommonName)
	target := mapTarget(agentname)

	apiRequestCounter.WithLabelValues(target).Inc()

	agents.RLock()
	agentList, ok := agents.m[target]
	if !ok || len(agentList) == 0 {
		agents.RUnlock()
		log.Printf("No agents connected for: %s", target)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	agent := agentList[rnd.Intn(len(agentList))]
	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Id:      ulidContext.Ulid(),
		Target:  target,
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: makeHeaders(r.Header),
		Body:    body,
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
				Identity:        agent.identity,
				SessionIdentity: agent.sessionIdentity,
				ConnectedAt:     agent.connectedAt,
				LastPing:        agent.lastPing,
				LastUse:         agent.lastUse,
			}
			as = append(as, a)
		}
	}
	ret := &tunnel.ControllerStatistics{
		AgentStatistics: as,
	}

	return ret, nil
}

func runAgentHTTPServer(caCert tls.Certificate, serverCert tls.Certificate) {
	log.Printf("Running HTTPS listener on port %d", *apiPort)

	caCertPool := x509.NewCertPool()
	//for _, cert := range caCert.Certificate {
	//	caCertPool.AppendCertsFromPEM(cert)
	//}
	ca, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("could not read ca certificate: %s", err)
	}
	if ok := caCertPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append agent certs")
	}

	tlsConfig := &tls.Config{
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

	mux := http.NewServeMux()

	mux.HandleFunc("/", handler)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", *apiPort),
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

func runGRPCServer(caCert tls.Certificate, serverCert tls.Certificate) {
	//
	// Set up GRPC server
	//
	log.Printf("Starting GRPC server on port %d...", *port)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	if err != nil {
		log.Fatalf("could not load server key pair: %s", err)
	}
	caCertPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("could not read ca certificate: %s", err)
	}
	if ok := caCertPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append agent certs")
	}
	creds := credentials.NewTLS(&tls.Config{
		ClientCAs:    caCertPool,
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

	config = loadConfig()
	log.Printf("Server names for generated certificate: %v", config.ServerNames)

	if len(config.Webhook) > 0 {
		hook = webhook.NewRunner(config.Webhook)
		hook.Run()
	}

	//
	// Run Prometheus HTTP server
	//
	if prometheusPort != nil {
		go runPrometheusHTTPServer(*prometheusPort)
	}

	caCertLocal, err := tls.LoadX509KeyPair(*caCertFile, *caKeyFile)
	if err != nil {
		log.Fatalf("Unable to load CA cetificate or key: %v", err)
	}
	caCert = caCertLocal
	serverCert := makeServerCert(caCert)

	//
	// Set up HTTP server
	//
	go runAgentHTTPServer(caCert, serverCert)

	// never returns
	runGRPCServer(caCert, serverCert)
}
