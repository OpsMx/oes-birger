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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/OpsMx/go-app-base/tracer"
	"github.com/OpsMx/go-app-base/version"
	"github.com/opsmx/oes-birger/internal/ca"
	"github.com/opsmx/oes-birger/internal/secrets"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	"github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/opsmx/oes-birger/internal/tunnelroute"

	"go.uber.org/zap"
)

var (
	tickTime   = flag.Int("tickTime", 30, "Time between sending Ping messages")
	caCertFile = flag.String("caCertFile", "/app/config/ca.pem", "The file containing the CA certificate we will use to verify the controller's cert")
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	// eg, http://localhost:14268/api/traces
	jaegerEndpoint = flag.String("jaeger-endpoint", "", "Jaeger collector endpoint")
	traceToStdout  = flag.Bool("traceToStdout", false, "log traces to stdout")
	traceRatio     = flag.Float64("traceRatio", 0.01, "ratio of traces to create, if incoming request is not traced")
	showversion    = flag.Bool("version", false, "show the version and exit")

	config         *agentConfig
	tracerProvider *tracer.TracerProvider

	hostname = getHostname()

	secretsLoader secrets.SecretLoader

	endpoints []serviceconfig.ConfiguredEndpoint

	routes = tunnelroute.MakeRoutes()
	logger *zap.Logger
	sl     *zap.SugaredLogger

	agentInfo *tunnel.AgentInfo
)

func loadCACertPEM() []byte {
	cert, err := ioutil.ReadFile(*caCertFile)
	if err == nil {
		return cert
	}
	if config.CACert64 == nil {
		zap.S().Fatal("Unable to load CA certificate from file or from config")
	}
	cert, err = base64.StdEncoding.DecodeString(*config.CACert64)
	if err != nil {
		zap.S().Fatal("Unable to decode CA cert base64 from config")
	}
	return cert
}

func loadCACert() []byte {
	certPEM := loadCACertPEM()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		zap.S().Fatal("failed to parse certificate PEM")
	}

	err := ca.ValidateCACert(block.Bytes)
	if err != nil {
		zap.S().Fatalf("Bad CA cert: %v", err)
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

func main() {
	log.Printf("%s", version.VersionString())
	flag.Parse()
	if *showversion {
		os.Exit(0)
	}

	var err error

	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("setting up logger: %v", err)
	}
	defer func() {
		_ = logger.Sync()
	}()
	_ = zap.ReplaceGlobals(logger)
	sl = logger.Sugar()

	grpc.EnableTracing = true

	sl.Infow("agent starting",
		"version", version.VersionString(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"cores", runtime.NumCPU(),
	)

	namespace, ok := os.LookupEnv("POD_NAMESPACE")
	if ok {
		secretsLoader, err = secrets.MakeKubernetesSecretLoader(namespace)
		if err != nil {
			sl.Fatalf("loading Kubernetes secrets: %v", err)
		}
	} else {
		logger.Info("POD_NAMESPACE not set.  Disabling Kubernetes secret handling.")
	}

	c, err := loadConfig(*configFile)
	if err != nil {
		sl.Fatalf("loading config: %v", err)
	}
	config = c
	sl.Infow("config", "controllerHostname", config.ControllerHostname)

	agentServiceConfig, err := serviceconfig.LoadServiceConfig(config.ServicesConfigPath)
	if err != nil {
		sl.Fatalf("loading services config: %v", err)
	}

	endpoints = serviceconfig.ConfigureEndpoints(secretsLoader, agentServiceConfig)

	// If the user supplied an agentInfo block in the service config file, load that as well.
	agentInfo, err = loadAgentInfo(config.ServicesConfigPath)
	if err != nil {
		sl.Fatalf("loading agentInfo from services config: %v", err)
	}

	// load client cert/key, cacert
	clcert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		sl.Fatalf("loading agent certificate or key: %v", err)
	}
	caCertPool := x509.NewCertPool()
	cacert := loadCACert()
	if ok := caCertPool.AppendCertsFromPEM(cacert); !ok {
		sl.Fatalf("append certificate to pool: %v", err)
	}

	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clcert},
		RootCAs:      caCertPool,
	})

	sa := &serverContext{}

	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	}

	if config.InsecureControllerAllowed {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(ta))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, config.ControllerHostname, opts...)
	if err != nil {
		sl.Fatalw("Could not establish GRPC connection to",
			"target", config.ControllerHostname,
			"error", err)
	}
	defer conn.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go runTunnel(&wg, sa, conn, agentInfo, endpoints, config.InsecureControllerAllowed, clcert)

	for _, service := range agentServiceConfig.IncomingServices {
		go serviceconfig.RunHTTPServer(routes, service)
	}

	wg.Wait()
}
