package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/opsmx/oes-birger/app/agent/cfg"
	"github.com/opsmx/oes-birger/pkg/tunnel"
)

var (
	tickTime   = flag.Int("tickTime", 30, "Time between sending Ping messages")
	caCertFile = flag.String("caCertFile", "/app/config/ca.pem", "The file containing the CA certificate we will use to verify the controller's cert")
	configFile = flag.String("configFile", "/app/config/config.yaml", "The file with the controller config")

	emptyBytes = []byte("")

	config    *cfg.AgentConfig
	endpoints = []Endpoint{}
)

type serverContext struct {
}

// TODO: this is currently copied from the controller.  Should be shared.
type Endpoint struct {
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	Configured bool   `json:"configured,omitempty"`

	instance HTTPRequestProcessor
}

type HTTPRequestProcessor interface {
	executeHTTPRequest(chan *tunnel.AgentToControllerWrapper, *tunnel.HttpRequest)
}

// TODO: this is currently copied from the controller.  Should be shared.
func (e *Endpoint) String() string {
	return fmt.Sprintf("(%s, %s, %v)", e.Type, e.Name, e.Configured)
}

func runTunnel(wg *sync.WaitGroup, sa *serverContext, conn *grpc.ClientConn, endpoints []Endpoint) {
	defer wg.Done()

	ticker := time.NewTicker(time.Duration(*tickTime) * time.Second)

	client := tunnel.NewAgentTunnelServiceClient(conn)
	ctx := context.Background()

	stream, err := client.EventTunnel(ctx)
	if err != nil {
		log.Fatalf("%v.EventTunnel(_) = _, %v", client, err)
	}
	pbEndpoints := make([]*tunnel.EndpointHealth, len(endpoints))
	for i, ep := range endpoints {
		pbEndpoints[i] = &tunnel.EndpointHealth{
			Name:       ep.Name,
			Type:       ep.Type,
			Configured: ep.Configured,
		}
	}
	helloMsg := &tunnel.AgentHello{
		Endpoints: pbEndpoints,
	}
	hello := &tunnel.AgentToControllerWrapper{
		Event: &tunnel.AgentToControllerWrapper_AgentHello{
			AgentHello: helloMsg,
		},
	}
	if err = stream.Send(hello); err != nil {
		log.Fatalf("Unable to send hello packet: %v", err)
	}

	dataflow := make(chan *tunnel.AgentToControllerWrapper, 20)

	// Handle periodic pings from the ticker.
	go func() {
		for ts := range ticker.C {
			req := &tunnel.AgentToControllerWrapper{
				Event: &tunnel.AgentToControllerWrapper_PingRequest{
					PingRequest: &tunnel.PingRequest{Ts: uint64(ts.UnixNano())},
				},
			}
			if err = stream.Send(req); err != nil {
				log.Fatalf("Unable to send a PingRequest: %v", err)
			}
		}
	}()

	// Handle data flowing back to the controller
	go func() {
		for ew := range dataflow {
			if err = stream.Send(ew); err != nil {
				log.Printf("Unable to respond over GRPC: %v", err)
			}
		}
	}()

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
			case *tunnel.ControllerToAgentWrapper_PingResponse:
				continue
			case *tunnel.ControllerToAgentWrapper_CancelRequest:
				req := in.GetCancelRequest()
				callCancelFunction(req.Id)
			case *tunnel.ControllerToAgentWrapper_HttpRequest:
				req := in.GetHttpRequest()
				found := false
				for _, endpoint := range endpoints {
					if endpoint.Configured && endpoint.Type == req.Type && endpoint.Name == req.Name {
						go endpoint.instance.executeHTTPRequest(dataflow, req)
						found = true
						break
					}
				}
				if !found {
					log.Printf("Request for unsupported HTTP tunnel type=%s name=%s", req.Type, req.Name)
					dataflow <- makeBadGatewayResponse(req.Id)
				}
			case *tunnel.ControllerToAgentWrapper_CommandRequest:
				req := in.GetCommandRequest()
				log.Printf("Got cmd request: %s %v %v", req.Name, req.Arguments, req.Environment)
				switch req.Name {
				case "sh":
					log.Printf("Running 'sh'")
					go runCommand(dataflow, req)
				default:
					log.Printf("Unknown command %s", req.Name)
					dataflow <- makeCommandFailed(req, nil, "Agent: Unknown command")
				}
			case nil:
				continue
			default:
				log.Printf("Received unknown message: %T", x)
			}
		}
	}()
	<-waitc
	close(dataflow)
	stream.CloseSend()
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

func configureEndpoints() {
	log.Printf("%#v", config)
	for _, c := range config.Services {
		endpoints = append(endpoints, Endpoint{
			Type:       c.Type,
			Name:       c.Name,
			Configured: c.Enabled,
		})
	}
}

func main() {
	flag.Parse()

	log.Printf("OS type: %s, CPU: %s, cores: %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	c, err := cfg.Load(*configFile)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	config = c
	log.Printf("controller hostname: %s", config.ControllerHostname)

	configureEndpoints()

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

	if config.Kubernetes.Enabled {
		k := MakeKubernetesEndpoint()

		endpoints = append(endpoints, Endpoint{
			Type:       "kubernetes",
			Name:       "kubernetes1",
			Configured: true,
			instance:   k,
		})
	}

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
