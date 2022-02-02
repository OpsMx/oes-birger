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

	"github.com/opsmx/oes-birger/pkg/secrets"
	"github.com/opsmx/oes-birger/pkg/serviceconfig"
	"github.com/opsmx/oes-birger/pkg/tunnelroute"
	"github.com/opsmx/oes-birger/pkg/updater"
	"github.com/opsmx/oes-birger/pkg/util"
)

var (
	versionBuild = -1
	version      = util.Versions{Major: 3, Minor: 1, Patch: 0, Build: versionBuild}

	tickTime   = flag.Int("tickTime", 30, "Time between sending Ping messages")
	caCertFile = flag.String("caCertFile", "/app/config/ca.pem", "The file containing the CA certificate we will use to verify the controller's cert")
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")
	debug      = flag.Bool("debug", false, "enable debugging")

	config *agentConfig

	hostname = getHostname()

	secretsLoader secrets.SecretLoader

	endpoints []serviceconfig.ConfiguredEndpoint

	routes = tunnelroute.MakeRoutes()
)

func loadCert() []byte {
	cert, err := ioutil.ReadFile(*caCertFile)
	if err == nil {
		return cert
	}
	if config.CACert64 == nil {
		log.Fatal("Unable to load CA certificate from file or from config")
	}
	cert, err = base64.StdEncoding.DecodeString(*config.CACert64)
	if err != nil {
		log.Fatal("Unable to decode CA cert base64 from config")
	}
	return cert
}

func getHostname() string {
	hn, err := os.Hostname()
	if err != nil {
		log.Printf("Unable to get hostname: %v, using 'unknown'", err)
		return "unknown"
	}
	return hn
}

func main() {
	flag.Parse()

	grpc.EnableTracing = true
	util.Debugging = *debug

	log.Printf("Agent version %s starting", version.String())

	var err error

	arg0hash, err := updater.HashSelf()
	if err != nil {
		log.Printf("Could not hash self: %v", err)
		arg0hash = "unknown"
	}
	log.Printf("Binary hash: %s\n", arg0hash)

	log.Printf("OS type: %s, CPU: %s, cores: %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	namespace, ok := os.LookupEnv("POD_NAMESPACE")
	if ok {
		secretsLoader, err = secrets.MakeKubernetesSecretLoader(namespace)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("POD_NAMESPACE not set.  Disabling Kubernetes secret handling.")
	}

	c, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	config = c
	log.Printf("controller hostname: %s", config.ControllerHostname)

	agentServiceConfig, err := serviceconfig.LoadServiceConfig(config.ServicesConfigPath)
	if err != nil {
		log.Fatalf("Error loading services config: %v", err)
	}

	endpoints = serviceconfig.ConfigureEndpoints(secretsLoader, agentServiceConfig)

	// load client cert/key, cacert
	clcert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Fatalf("Unable to load agent certificate or key: %v", err)
	}
	caCertPool := x509.NewCertPool()
	srvcert := loadCert()
	if ok := caCertPool.AppendCertsFromPEM(srvcert); !ok {
		log.Fatalf("Unable to append certificate to pool: %v", err)
	}

	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clcert},
		RootCAs:      caCertPool,
	})

	sa := &serverContext{}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(ta),
		grpc.WithBlock(),
	}

	if config.InsecureControllerAllowed {
		opts = append(opts, grpc.WithInsecure())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, config.ControllerHostname, opts...)
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}
	defer conn.Close()

	var wg sync.WaitGroup

	log.Printf("Starting GRPC tunnel.")
	wg.Add(1)
	go runTunnel(&wg, sa, conn, endpoints, config.InsecureControllerAllowed, clcert)

	log.Printf("Starting any local HTTP service listeners.")
	for _, service := range agentServiceConfig.IncomingServices {
		go serviceconfig.RunHTTPServer(routes, service)
	}

	wg.Wait()
	log.Printf("Done.")
}
