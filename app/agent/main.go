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
	"io"
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
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"github.com/opsmx/oes-birger/pkg/updater"
	"github.com/opsmx/oes-birger/pkg/util"
)

var (
	versionBuild = -1
	version      = util.Versions{Major: 2, Minor: 1, Patch: 5, Build: versionBuild}

	tickTime   = flag.Int("tickTime", 30, "Time between sending Ping messages")
	caCertFile = flag.String("caCertFile", "/app/config/ca.pem", "The file containing the CA certificate we will use to verify the controller's cert")
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	config *agentConfig

	hostname = getHostname()

	secretsLoader secrets.SecretLoader

	endpoints []serviceconfig.ConfiguredEndpoint
)

type serverContext struct{}

func tickerPinger(stream tunnel.AgentTunnelService_EventTunnelClient) {
	ticker := time.NewTicker(time.Duration(*tickTime) * time.Second)

	for ts := range ticker.C {
		req := &tunnel.MessageWrapper{
			Event: &tunnel.MessageWrapper_PingRequest{
				PingRequest: &tunnel.PingRequest{Ts: uint64(ts.UnixNano())},
			},
		}
		if err := stream.Send(req); err != nil {
			log.Fatalf("Unable to send a PingRequest: %v", err)
		}
	}
}

func dataflowHandler(dataflow chan *tunnel.MessageWrapper, stream tunnel.AgentTunnelService_EventTunnelClient) {
	for ew := range dataflow {
		if err := stream.Send(ew); err != nil {
			log.Fatalf("Unable to respond over GRPC: %v", err)
		}
	}

}

func runTunnel(wg *sync.WaitGroup, sa *serverContext, conn *grpc.ClientConn, endpoints []serviceconfig.ConfiguredEndpoint) {
	defer wg.Done()

	client := tunnel.NewAgentTunnelServiceClient(conn)
	ctx := context.Background()

	stream, err := client.EventTunnel(ctx)
	if err != nil {
		log.Fatalf("%v.EventTunnel(_) = _, %v", client, err)
	}
	pbEndpoints := serviceconfig.EndpointsToPB(endpoints)
	helloMsg := &tunnel.AgentHello{
		Version:   version.String(),
		Endpoints: pbEndpoints,
		Hostname:  hostname,
	}
	hello := &tunnel.MessageWrapper{
		Event: &tunnel.MessageWrapper_AgentHello{
			AgentHello: helloMsg,
		},
	}
	if err = stream.Send(hello); err != nil {
		log.Fatalf("Unable to send hello packet: %v", err)
	}

	dataflow := make(chan *tunnel.MessageWrapper, 20)

	go tickerPinger(stream)
	go dataflowHandler(dataflow, stream)

	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				// Server has closed the connection.
				close(waitc)
				return
			}
			if err != nil {
				log.Fatalf("Failed to receive a message: %T: %v", err, err)
			}
			switch x := in.Event.(type) {
			case *tunnel.MessageWrapper_PingResponse:
				continue
			case *tunnel.MessageWrapper_HttpTunnelControl:
				handleTunnelCommand(x.HttpTunnelControl, endpoints, dataflow)
			case nil:
				continue
			default:
				log.Printf("Received unknown message: %T", x)
			}
		}
	}()
	<-waitc
	close(dataflow)
	_ = stream.CloseSend()
}

func handleTunnelCommand(tunnelControl *tunnel.HttpTunnelControl, endpoints []serviceconfig.ConfiguredEndpoint, dataflow chan *tunnel.MessageWrapper) {
	switch controlMessage := tunnelControl.ControlType.(type) {
	case *tunnel.HttpTunnelControl_CancelRequest:
		tunnel.CallCancelFunction(controlMessage.CancelRequest.Id)
	case *tunnel.HttpTunnelControl_OpenHTTPTunnelRequest:
		req := controlMessage.OpenHTTPTunnelRequest
		found := false
		for _, endpoint := range endpoints {
			if endpoint.Configured && endpoint.Type == req.Type && endpoint.Name == req.Name {
				go endpoint.Instance.ExecuteHTTPRequest(dataflow, req)
				found = true
				break
			}
		}
		if !found {
			log.Printf("Request for unsupported HTTP tunnel type=%s name=%s", req.Type, req.Name)
			dataflow <- tunnel.MakeBadGatewayResponse(req.Id)
		}
	case nil:
		return
	default:
		log.Printf("Received unknown HttpControl type: %T", controlMessage)
	}
}

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
	log.Printf("Agent version %s starting", version.String())

	var err error

	arg0hash, err := updater.HashSelf()
	if err != nil {
		log.Printf("Could not hash self: %v", err)
		arg0hash = "unknown"
	}
	log.Printf("Binary hash: %s\n", arg0hash)

	flag.Parse()

	log.Printf("OS type: %s, CPU: %s, cores: %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	namespace, ok := os.LookupEnv("POD_NAMESPACE")
	if !ok {
		log.Fatalf("envar POD_NAMESPACE not set to the pod's namespace")
	}
	secretsLoader, err = secrets.MakeKubernetesSecretLoader(namespace)
	if err != nil {
		log.Fatal(err)
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
	go runTunnel(&wg, sa, conn, endpoints)

	wg.Wait()
	log.Printf("Done.")
}
