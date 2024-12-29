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
	"log"
	"net/http"
	pprofhttp "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/OpsMx/go-app-base/tracer"
	"github.com/OpsMx/go-app-base/util"
	"github.com/OpsMx/go-app-base/version"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opsmx/oes-birger/app/server/cncserver"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/opsmx/oes-birger/internal/logging"
	"github.com/opsmx/oes-birger/internal/secrets"
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
	otlpEndpoint          = flag.String("otlp-endpoint", "", "OTLP collector endpoint")
	traceToStdout         = flag.Bool("traceToStdout", false, "log traces to stdout")
	traceRatio            = flag.Float64("traceRatio", 0.01, "ratio of traces to create, if incoming request is not traced")
	showversion           = flag.Bool("version", false, "show the version and exit")
	profile               = flag.Bool("profile", true, "enable memory and CPU profiling")
	generateControlTokens = flag.String("generate-control-tokens", "", "generate control tokens.  Example: ground,mission")
	generateAgentTokens   = flag.String("generate-agent-tokens", "", "generate agent tokens.  Example: agentsmith,agentbob,alice")

	tracerProvider *tracer.TracerProvider

	serviceKeyset     = jwk.NewSet()
	agentKeyset       = jwk.NewSet()
	currentServiceKey string
	currentAgentKey   string
	config            *ControllerConfig
	secretsLoader     secrets.SecretLoader
	endpoints         []serviceconfig.ConfiguredEndpoint
	agents            = makeAgentSessions()
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
	logger.Infof("Running HTTP listener for Prometheus on port %d", 9102)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/", healthcheck)
	mux.HandleFunc("/health", healthcheck)
	// if profile {
	logger.Infof("Prometheus handler includes /debug/pprof endpoints")
	mux.HandleFunc("/debug/pprof/", pprofhttp.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprofhttp.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprofhttp.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprofhttp.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprofhttp.Trace)
	// }

	server := &http.Server{
		// Addr:    fmt.Sprintf(":%d", 9102),
		Addr:    ":9102",
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

	if *otlpEndpoint != "" {
		*otlpEndpoint = util.GetEnvar("OTLP_URL", "")
	}

	var err error
	tracerProvider, err = tracer.NewTracerProvider(ctx, *otlpEndpoint, *traceToStdout, version.GitHash(), appName, *traceRatio)
	util.Check(err)
	defer tracerProvider.Shutdown(ctx)

	config, err = parseConfig(*configFile)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	config.Dump(logger)

	//secretsLoader = getSecretsLoader(ctx)
	loadServiceAuthKeyset(ctx)
	loadAgentAuthKeyset(ctx)

	// Create registry entries to sign and validate JWTs for service authentication,
	// and protect x-spinnaker-user header.
	if err = jwtutil.RegisterServiceKeyset(serviceKeyset, config.ServiceAuth.CurrentKeyName); err != nil {
		logger.Fatal(err)
	}
	// TODO: use a different keyset?
	if err = jwtutil.RegisterControlKeyset(serviceKeyset, config.ServiceAuth.CurrentKeyName); err != nil {
		logger.Fatal(err)
	}
	if err = jwtutil.RegisterMutationKeyset(serviceKeyset, config.ServiceAuth.HeaderMutationKeyName); err != nil {
		logger.Fatal(err)
	}
	if err = jwtutil.RegisterAgentKeyset(agentKeyset, config.AgentAuth.CurrentKeyName); err != nil {
		logger.Fatal(err)
	}

	if *generateAgentTokens != "" {
		generateSomeAgentTokens(config, *generateAgentTokens)
		os.Exit(0)
	}

	if *generateControlTokens != "" {
		generateSomeControlTokens(config, *generateControlTokens)
		os.Exit(0)
	}

	cnc := cncserver.MakeCNCServer(config, agents, version.GitBranch(), config.ControlTLSPath, nil)
	go cnc.RunServer(ctx)

	go runAgentGRPCServer(ctx, config.AgentTLSPath)

	secretsLoader = makeSecretsLoader(ctx)
	endpoints = serviceconfig.ConfigureEndpoints(ctx, secretsLoader, &config.ServiceConfig)

	echoManager := &ServerEchoManager{}

	// Always listen on our well-known port, and always use HTTPS for this one.
	go serviceconfig.RunHTTPSServer(ctx, echoManager, agents, config.ServiceTLSPath, serviceconfig.IncomingServiceConfig{
		Name: "_services",
		Port: config.ServiceListenPort,
	})

	// Now, add all the others defined by our config.
	for _, service := range config.ServiceConfig.IncomingServices {
		logger.Infow("Service name for which starting HTTP(S) server is", service.Name, " Type is", service.ServiceType)
		if service.UseHTTP {
			go serviceconfig.RunHTTPServer(ctx, echoManager, agents, service)
		} else {
			go serviceconfig.RunHTTPSServer(ctx, echoManager, agents, config.ServiceTLSPath, service)
		}
	}

	go healthCheckRunRequestFlow()

	go runPrometheusHTTPServer(ctx, config.PrometheusListenPort, *profile)

	<-sigchan
	logger.Infof("Exiting Cleanly")
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

func generateSomeAgentTokens(c *ControllerConfig, names string) {
	n := strings.Split(names, ",")
	for _, name := range n {
		name = strings.TrimSpace(name)
		token, err := jwtutil.MakeAgentJWT(name, nil)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%s\n", token)
	}
}

func generateSomeControlTokens(c *ControllerConfig, names string) {
	n := strings.Split(names, ",")
	for _, name := range n {
		name = strings.TrimSpace(name)
		token, err := jwtutil.MakeControlJWT(name, nil)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%s\n", token)
	}
}

// The below code acts as a workaround for carina controller issue, it will restart the contoller in case http server on port 9002 is unresponsive.
// TODO: the below solution is only temporary, to be removed once we get the real solution.
// func healthCheckRunRequestFlow() {
// 		// Define the timeout for API response and interval for execution
// 		timeout := 10 * time.Second
// 		interval := 60 * time.Second
// 		ctx2, _ := context.WithCancel(context.Background())
// 		logger := logging.WithContext(ctx2).Sugar()
// 		logger.Infof("Started local healthcheck goroutine.")
// 		// Start a goroutine to periodically check the API response
// 	ticker := time.NewTicker(interval)
// 		defer ticker.Stop()

// 		for {
// 			select {
// 			case <-ticker.C:
// 				// Create a context with timeout
// 				ctx, cancel := context.WithTimeout(context.Background(), timeout)
// 				defer cancel()

// 				// Make the HTTP request with a timeout
// 				req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:9002/api/v1/applications", nil)
// 				if err != nil {
// 					// fmt.Println("Error creating request:", err)
// 					os.Exit(0)
// 				}

// 				client := &http.Client{
// 					Timeout: timeout,
// 				}

// 				resp, err := client.Do(req)
// 				if err != nil {
// 					// fmt.Println("Error making request or timeout occurred:", err)
// 					os.Exit(0)
// 				}
// 				defer resp.Body.Close()

// 			}
// 		}
// }
