/*
 * Copyright 2023 OpsMx, Inc.
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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	pprofhttp "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/OpsMx/go-app-base/httputil"
	"github.com/OpsMx/go-app-base/tracer"
	"github.com/OpsMx/go-app-base/util"
	"github.com/OpsMx/go-app-base/version"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/opsmx/oes-birger/internal/ca"
	"github.com/opsmx/oes-birger/internal/logging"
	"github.com/opsmx/oes-birger/internal/secrets"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"gopkg.in/yaml.v3"
)

const (
	appName = "agent-client"
)

var (
	tickTime   = flag.Int("tickTime", 10, "Time between sending Ping messages")
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	// eg, http://localhost:14268/api/traces
	jaegerEndpoint = flag.String("jaeger-endpoint", "", "Jaeger collector endpoint")
	traceToStdout  = flag.Bool("traceToStdout", false, "log traces to stdout")
	traceRatio     = flag.Float64("traceRatio", 0.01, "ratio of traces to create, if incoming request is not traced")
	showversion    = flag.Bool("version", false, "show the version and exit")
	profile        = flag.Bool("profile", false, "enable memory and CPU profiling")

	hostname = getHostname()

	config         *agentConfig
	tracerProvider *tracer.TracerProvider
	secretsLoader  secrets.SecretLoader
	endpoints      []serviceconfig.ConfiguredEndpoint
)

func check(ctx context.Context, err error) {
	_, logger := loggerFromContext(ctx)
	if err != nil {
		logger.Fatal(err)
	}
}

type AgentSession struct {
	agentID       string
	sessionID     string
	authorization string
	rpcTimeout    time.Duration
	done          chan struct{}
}

var session = AgentSession{
	rpcTimeout: 20 * time.Second,
	done:       make(chan struct{}),
}

func sendHello(ctx context.Context, c pb.TunnelServiceClient, info *pb.AgentInfo, endpoints []serviceconfig.ConfiguredEndpoint, hostname string, version string) (*pb.HelloResponse, error) {
	ctx, cancel := getHeaderContext(ctx, session.rpcTimeout)
	defer cancel()

	req := &pb.HelloRequest{
		Hostname:  hostname,
		Version:   version,
		Endpoints: serviceconfig.EndpointsToPB(endpoints),
		AgentInfo: info,
	}
	return c.Hello(ctx, req)
}

func getHeaderContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	headers := metadata.New(map[string]string{
		"authorization": session.authorization,
	})
	if session.sessionID != "" {
		headers.Set("x-session-id", session.sessionID)
	}
	ctx = metadata.NewOutgoingContext(ctx, headers)
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func waitForRequest(ctx context.Context, c pb.TunnelServiceClient) error {
	ctx, logger := loggerFromContext(ctx)
	ctx, cancel := getHeaderContext(ctx, 0)
	defer cancel()
	stream, err := c.WaitForRequest(ctx, &pb.WaitForRequestArgs{})
	if err != nil {
		return err
	}
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		logger.Debugw("waitForRequest response",
			"streamID", req.StreamId,
			"method", req.Method,
			"serviceName", req.Name,
			"serviceType", req.Type,
			"uri", req.URI,
			"bodyLength", len(req.Body))

		// TODO: implement endpoint search and dispatch request
		doneChan := make(chan bool)
		echo := MakeEcho(ctx, c, req.StreamId, doneChan)
		ep, found := findEndpoint(ctx, req.Name, req.Type)
		if !found {
			if err := echo.Fail(ctx, http.StatusBadGateway, fmt.Errorf("no such service on agent")); err != nil {
				logger.Warn(err)
			}
			echo.Shutdown(ctx)
			continue
		}

		labels := pprof.Labels("req.URI", req.URI)
		go pprof.Do(ctx, labels, func(ctx context.Context) {
			defer echo.Shutdown(ctx)
			if err := ep.Instance.ExecuteHTTPRequest(ctx, session.agentID, echo, req); err != nil {
				logger.Warn(err)
			}
		})
	}
}

func findEndpoint(ctx context.Context, serviceName string, serviceType string) (*serviceconfig.ConfiguredEndpoint, bool) {
	for _, ep := range endpoints {
		if ep.Name == serviceName && ep.Type == serviceType {
			return &ep, true
		}
	}
	return nil, false
}

func pinger(ctx context.Context, c pb.TunnelServiceClient, tickTime int) error {
	ctx, logger := loggerFromContext(ctx)
	for {
		time.Sleep(time.Duration(tickTime) * time.Second)
		ctx, cancel := getHeaderContext(ctx, session.rpcTimeout)
		defer cancel()
		r, err := c.Ping(ctx, &pb.PingRequest{
			Ts: uint64(time.Now().UnixNano()),
		})
		if err != nil {
			return err
		}
		logger.Infof("Got ping repsonse: servertime=%d, mytime=%d", r.Ts, r.EchoedTs)
	}
}

func connect(ctx context.Context, address string, ta credentials.TransportCredentials) *grpc.ClientConn {
	kparams := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}
	gopts := []grpc.DialOption{
		grpc.WithTransportCredentials(ta),
		grpc.WithKeepaliveParams(kparams),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
		grpc.WithUnaryInterceptor(grpc_prometheus.UnaryClientInterceptor),
		grpc.WithStreamInterceptor(grpc_prometheus.StreamClientInterceptor),
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address, gopts...)
	check(ctx, err)

	return conn
}

func loggerFromContext(ctx context.Context) (context.Context, *zap.SugaredLogger) {
	fields := []zap.Field{}
	if session.agentID != "" {
		fields = append(fields, zap.String("agentID", session.agentID))
	}
	if session.sessionID != "" {
		fields = append(fields, zap.String("sessionID", session.sessionID))
	}
	ctx = logging.NewContext(ctx, fields...)
	return ctx, logging.WithContext(ctx).Sugar()
}

func loadCACertPEM(ctx context.Context) []byte {
	_, logger := loggerFromContext(ctx)
	cert, err := os.ReadFile(config.CACertFile)
	if err == nil {
		return cert
	}
	if config.CACert64 == "" {
		logger.Fatal("Unable to load CA certificate from file or from config")
	}
	cert, err = base64.StdEncoding.DecodeString(config.CACert64)
	if err != nil {
		logger.Fatal("Unable to decode CA cert base64 from config")
	}
	return cert
}

func loadCACert(ctx context.Context) []byte {
	_, logger := loggerFromContext(ctx)
	certPEM := loadCACertPEM(ctx)

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		logger.Fatal("failed to parse certificate PEM")
	}

	err := ca.ValidateCACert(block.Bytes)
	if err != nil {
		logger.Fatalf("Bad CA cert: %v", err)
	}

	return certPEM
}

func getHostname() string {
	hn, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hn
}

func getAuthToken(filename string) (string, error) {
	if token, ok := os.LookupEnv("AUTH_TOKEN"); ok {
		return token, nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	token, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	ret := strings.TrimSpace(string(token))
	ret = strings.ReplaceAll(ret, "\n\r", "")
	return ret, nil
}

func loadAgentInfo(filename string) (*pb.AgentInfo, error) {
	type AgentInfoType struct {
		Annotations map[string]string `yaml:"annotations,omitempty"`
	}

	type AgentInfoContainer struct {
		AgentInfo AgentInfoType `yaml:"agentInfo,omitempty"`
	}

	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	info := AgentInfoContainer{}
	err = yaml.Unmarshal(buf, &info)
	if err != nil {
		return nil, err
	}

	annotations := []*pb.Annotation{}
	for k, v := range info.AgentInfo.Annotations {
		annotations = append(annotations, &pb.Annotation{Name: k, Value: v})
	}

	pbinfo := &pb.AgentInfo{
		Annotations: annotations,
	}

	return pbinfo, nil
}

func healthcheck(w http.ResponseWriter, r *http.Request) {
}

func runPrometheusHTTPServer(ctx context.Context, port uint16, profile bool) {
	_, logger := loggerFromContext(ctx)
	logger.Infof("Running HTTP listener for Prometheus on port %d", port)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/", healthcheck)
	mux.HandleFunc("/health", healthcheck)
	if profile {
		logger.Infof("Prometheus handler includes /debug/pprof endpoints")
		mux.HandleFunc("/debug/pprof/", pprofhttp.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprofhttp.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprofhttp.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprofhttp.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprofhttp.Trace)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	logger.Fatal(server.ListenAndServe())
}

func makeSecretsLoader(ctx context.Context) secrets.SecretLoader {
	logger := logging.WithContext(ctx).Sugar()
	namespace, ok := os.LookupEnv("POD_NAMESPACE")
	if !ok {
		logger.Info("POD_NAMESPACE not set.  Disabling Kubernetes secret handling.")
		return nil
	}
	loader, err := secrets.MakeKubernetesSecretLoader(namespace)
	if err != nil {
		logger.Fatalf("loading Kubernetes secrets: %v", err)
		return nil
	}
	return loader
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, logger := loggerFromContext(ctx)

	logger.Infof("%s", version.VersionString())
	flag.Parse()
	if *showversion {
		os.Exit(0)
	}

	logger.Infow("agent starting",
		"version", version.VersionString(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"cores", runtime.NumCPU(),
	)

	var err error
	tracerProvider, err = tracer.NewTracerProvider(*jaegerEndpoint, *traceToStdout, version.GitHash(), appName, *traceRatio)
	util.Check(err)
	defer tracerProvider.Shutdown(ctx)

	if c, err := loadConfig(*configFile); err != nil {
		logger.Fatalf("loading config: %v", err)
	} else {
		config = c
	}
	logger.Infow("config", "controllerHostname", config.ControllerHostname)

	agentServiceConfig, err := serviceconfig.LoadServiceConfig(config.ServicesConfigFile)
	if err != nil {
		logger.Fatalf("loading services config: %v", err)
	}

	secretsLoader = makeSecretsLoader(ctx)
	endpoints = serviceconfig.ConfigureEndpoints(ctx, secretsLoader, agentServiceConfig)

	clientConfig := httputil.ClientConfig{
		DialTimeout:           4,
		ResponseHeaderTimeout: 4,
		MaxIdleConnections:    10,
		ClientTimeout:         4,
	}
	httputil.SetClientConfig(clientConfig)
	http.DefaultClient = httputil.NewHTTPClient(nil)

	authToken, err := getAuthToken(config.AuthTokenFile)
	if err != nil {
		logger.Fatal(err)
	}
	session.authorization = authToken

	agentInfo, err := loadAgentInfo(config.ServicesConfigFile)
	if err != nil {
		logger.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	cacert := loadCACert(ctx)
	if ok := caCertPool.AppendCertsFromPEM(cacert); !ok {
		logger.Fatalf("append certificate to pool: %v", err)
	}

	ta := credentials.NewTLS(&tls.Config{
		RootCAs: caCertPool,
	})

	conn := connect(ctx, "localhost:8003", ta)
	defer conn.Close()
	c := pb.NewTunnelServiceClient(conn)

	hello, err := sendHello(ctx, c, agentInfo, endpoints, hostname, version.VersionString())
	check(ctx, err)
	session.sessionID = hello.InstanceId
	session.agentID = hello.AgentId
	logger.Infow("controller services", "endpoints", hello.Endpoints)

	go func() {
		err := waitForRequest(ctx, c)
		log.Printf("waitForRequest failed: %v", err)
		session.done <- struct{}{}
	}()

	go func() {
		err := pinger(ctx, c, *tickTime)
		log.Printf("pinger failed: %v", err)
		session.done <- struct{}{}
	}()

	go runPrometheusHTTPServer(ctx, config.PrometheusListenPort, *profile)

	<-session.done
}
