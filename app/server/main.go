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
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	pprofhttp "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/OpsMx/go-app-base/tracer"
	"github.com/OpsMx/go-app-base/util"
	"github.com/OpsMx/go-app-base/version"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opsmx/oes-birger/app/server/cncserver"
	"github.com/opsmx/oes-birger/internal/ca"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/keepalive"
)

const (
	appName = "agent-server"
)

var (
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	// eg, http://localhost:14268/api/traces
	jaegerEndpoint = flag.String("jaeger-endpoint", "", "Jaeger collector endpoint")
	traceToStdout  = flag.Bool("traceToStdout", false, "log traces to stdout")
	traceRatio     = flag.Float64("traceRatio", 0.01, "ratio of traces to create, if incoming request is not traced")
	showversion    = flag.Bool("version", false, "show the version and exit")
	profile        = flag.Bool("profile", false, "enable memory and CPU profiling")

	tracerProvider *tracer.TracerProvider

	serviceKeyset     = jwk.NewSet()
	agentKeyset       = jwk.NewSet()
	currentServiceKey string
	currentAgentKey   string
	config            *ControllerConfig
	//secretsLoader     secrets.SecretLoader
	authority *ca.CA
	//endpoints         []serviceconfig.ConfiguredEndpoint
	agents = makeAgentSessions()
)

var kaep = keepalive.EnforcementPolicy{
	MinTime:             5 * time.Second,
	PermitWithoutStream: true,
}

var kasp = keepalive.ServerParameters{
	MaxConnectionIdle: 20 * time.Minute,
	Time:              10 * time.Second,
	Timeout:           10 * time.Second,
}

func healthcheck(w http.ResponseWriter, r *http.Request) {
	_, logger := loggerFromContext(r.Context())
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(200)
	n, err := w.Write([]byte("{}"))
	if err != nil {
		logger.Warnf("Error writing healthcheck response: %v", err)
		return
	}
	if n != 2 {
		logger.Warnf("Failed to write 2 bytes: %d written", n)
	}
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

func loadServiceAuthKeyset(ctx context.Context) {
	_, logger := loggerFromContext(ctx)

	if config.ServiceAuth.CurrentKeyName == "" {
		logger.Fatalf("No primary serviceAuth key name provided")
	}

	err := filepath.WalkDir(config.ServiceAuth.SecretsPath, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// skip not regular files
		if !info.Type().IsRegular() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		key, err := jwk.FromRaw(content)
		if err != nil {
			return err
		}
		if err := key.Set(jwk.KeyIDKey, info.Name()); err != nil {
			return err
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.HS256); err != nil {
			return err
		}
		if err := serviceKeyset.AddKey(key); err != nil {
			return err
		}
		logger.Infof("Loaded service key name %s, length %d", info.Name(), len(content))
		return nil
	})
	if err != nil {
		logger.Fatalf("cannot load key serviceAuth keys: %v", err)
	}

	currentServiceKey = config.ServiceAuth.CurrentKeyName
	if len(currentServiceKey) == 0 {
		logger.Fatal("serviceAuth.currentKeyName is not set")
	}
	if _, found := serviceKeyset.LookupKeyID(currentServiceKey); !found {
		logger.Fatal("serviceAuth.currentKeyName is not in the loaded list of keys")
	}

	if len(config.ServiceAuth.HeaderMutationKeyName) == 0 {
		logger.Fatal("serviceAuth.headerMutationKeyName is not set")
	}

	logger.Infof("Loaded %d serviceAuth keys", serviceKeyset.Len())
}

func loadAgentAuthKeyset(ctx context.Context) {
	_, logger := loggerFromContext(ctx)
	if config.AgentAuth.CurrentKeyName == "" {
		logger.Fatalf("No primary agentAuth key name provided")
	}

	err := filepath.WalkDir(config.AgentAuth.SecretsPath, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// skip not regular files
		if !info.Type().IsRegular() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		key, err := jwk.FromRaw(content)
		if err != nil {
			return err
		}
		if err := key.Set(jwk.KeyIDKey, info.Name()); err != nil {
			return err
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.HS256); err != nil {
			return err
		}
		if err := agentKeyset.AddKey(key); err != nil {
			return err
		}
		logger.Infof("Loaded agent key name %s, length %d", info.Name(), len(content))
		return nil
	})
	if err != nil {
		logger.Fatalf("cannot load key agentAuth keys: %v", err)
	}

	currentAgentKey = config.AgentAuth.CurrentKeyName
	if len(currentAgentKey) == 0 {
		logger.Fatal("agentAuth.currentKeyName is not set")
	}
	if _, found := agentKeyset.LookupKeyID(currentAgentKey); !found {
		logger.Fatal("agentAuth.currentKeyName is not in the loaded list of keys")
	}

	logger.Infof("Loaded %d agentAuth keys", agentKeyset.Len())
}

//func getSecretsLoader(ctx context.Context) *secrets.KubernetesSecretLoader {
//	_, logger := loggerFromContext(ctx)
//	namespace, ok := os.LookupEnv("POD_NAMESPACE")
//	if !ok {
//		logger.Infof("POD_NAMESPACE not set.  Disabling Kubeernetes secret handling.")
//		return nil
//	}
//	if secretsLoader, err := secrets.MakeKubernetesSecretLoader(namespace); err == nil {
//		return secretsLoader
//	} else {
//		logger.Fatal(err)
//	}
//	return nil
//}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, logger := loggerFromContext(ctx)

	logger.Infof("%s", version.VersionString())
	flag.Parse()
	if *showversion {
		os.Exit(0)
	}

	logger.Infow("controller starting",
		"version", version.VersionString(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"cores", runtime.NumCPU(),
	)

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGTERM, syscall.SIGINT)

	if *jaegerEndpoint != "" {
		*jaegerEndpoint = util.GetEnvar("JAEGER_TRACE_URL", "")
	}

	var err error
	tracerProvider, err = tracer.NewTracerProvider(*jaegerEndpoint, *traceToStdout, version.GitHash(), appName, *traceRatio)
	util.Check(err)
	defer tracerProvider.Shutdown(ctx)

	config, err = parseConfig(*configFile)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	config.Dump()

	//secretsLoader = getSecretsLoader(ctx)
	loadServiceAuthKeyset(ctx)
	loadAgentAuthKeyset(ctx)

	// Create registry entries to sign and validate JWTs for service authentication,
	// and protect x-spinnaker-user header.
	if err = jwtutil.RegisterServiceKeyset(serviceKeyset, config.ServiceAuth.CurrentKeyName); err != nil {
		logger.Fatal(err)
	}
	if err = jwtutil.RegisterMutationKeyset(serviceKeyset, config.ServiceAuth.HeaderMutationKeyName); err != nil {
		logger.Fatal(err)
	}
	if err = jwtutil.RegisterAgentKeyset(agentKeyset, config.AgentAuth.CurrentKeyName); err != nil {
		logger.Fatal(err)
	}

	//
	// Make a new CA, for our use to generate server and other certificates.
	//
	caLocal, err := ca.LoadCAFromFile(config.CAConfig)
	if err != nil {
		logger.Fatalf("Cannot create authority: %v", err)
	}
	authority = caLocal

	//
	// Make a server certificate.
	//
	logger.Infof("Generating a server certificate...")
	serverCert, err := authority.MakeServerCert(config.ServerNames)
	if err != nil {
		logger.Fatalf("Cannot make server certificate: %v", err)
	}

	cnc := cncserver.MakeCNCServer(config, authority, agents, version.GitBranch(), nil)
	go cnc.RunServer(*serverCert)

	go runAgentGRPCServer(ctx, config.AgentUseTLS, serverCert)

	echoManager := &ServerEchoManager{}

	// Always listen on our well-known port, and always use HTTPS for this one.
	go serviceconfig.RunHTTPSServer(ctx, echoManager, agents, authority, *serverCert, serviceconfig.IncomingServiceConfig{
		Name: "_services",
		Port: config.ServiceListenPort,
	})

	//endpoints = serviceconfig.ConfigureEndpoints(ctx, secretsLoader, &config.ServiceConfig)

	// Now, add all the others defined by our config.
	for _, service := range config.ServiceConfig.IncomingServices {
		if service.UseHTTP {
			go serviceconfig.RunHTTPServer(ctx, echoManager, agents, service)
		} else {
			go serviceconfig.RunHTTPSServer(ctx, echoManager, agents, authority, *serverCert, service)
		}
	}

	go runPrometheusHTTPServer(ctx, config.PrometheusListenPort, *profile)

	agentJWT, err := jwtutil.MakeAgentJWT("smith", nil)
	if err != nil {
		logger.Fatalf("cannot make sample agent JWT")
	}
	logger.Infow("sample agent JWT", "jwt", agentJWT, "name", "smith")

	<-sigchan
	logger.Infof("Exiting Cleanly")
}
