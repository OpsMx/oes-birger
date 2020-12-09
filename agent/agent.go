package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/skandragon/grpc-bidir/kubeconfig"
	"github.com/skandragon/grpc-bidir/tunnel"
)

var (
	tickTime           = flag.Int("tickTime", 30, "Time between sending Ping messages")
	host               = flag.String("host", tunnel.DefaultHostAndPort, "The address:port of the controller to connect to")
	agentCertFile      = flag.String("certFile", "/app/config/cert.pem", "The file containing the certificate used to connect to the controller")
	agentKeyFile       = flag.String("keyFile", "/app/config/key.pem", "The file containing the certificate used to connect to the controller")
	caCertFile         = flag.String("caCertFile", "/app/config/ca.pem", "The file containing the CA certificate we will use to verify the controller's cert")
	kubeConfigFilename = flag.String("kubeconfig", "/app/config/kubeconfig.yaml", "The location of a kubeconfig file to define endpoints and kube API auth")
)

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
	}
	return ret
}

type cancelState struct {
	id     string
	cancel context.CancelFunc
}

var cancelRegistry = struct {
	sync.Mutex
	m map[string]context.CancelFunc
}{m: make(map[string]context.CancelFunc)}

func registerCancelFunction(id string, cancel context.CancelFunc) {
	cancelRegistry.Lock()
	cancelRegistry.m[id] = cancel
	cancelRegistry.Unlock()
}

func unregisterCancelFunction(id string) {
	cancelRegistry.Lock()
	delete(cancelRegistry.m, id)
	cancelRegistry.Unlock()
}

func callCancelFunction(id string) {
	cancelRegistry.Lock()
	cancel, ok := cancelRegistry.m[id]
	if ok {
		cancel()
		log.Printf("Cancelling request %s", id)
	}
	cancelRegistry.Unlock()
}

func executeRequest(dataflow chan *tunnel.ASEventWrapper, c *serverContext, req *tunnel.HttpRequest) {
	// TODO: A ServerCA is technically optional, but we might want to fail if it's not present...
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.insecure,
	}
	if c.clientCert != nil {
		caCertPool := x509.NewCertPool()
		caCertPool.AddCert(c.serverCA)
		tlsConfig.Certificates = []tls.Certificate{*c.clientCert}
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	}
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
	}
	client := &http.Client{
		Transport: tr,
	}

	ctx, cancel := context.WithCancel(context.Background())

	registerCancelFunction(req.Id, cancel)
	defer func() {
		unregisterCancelFunction(req.Id)
	}()

	httpRequest, err := http.NewRequestWithContext(ctx, req.Method, c.serverURL+req.URI, bytes.NewBuffer(req.Body))
	if err != nil {
		log.Printf("Failed to build request for %s to %s: %v", req.Method, c.serverURL+req.URI, err)
		resp := &tunnel.ASEventWrapper{
			Event: &tunnel.ASEventWrapper_HttpResponse{
				HttpResponse: &tunnel.HttpResponse{
					Id:            req.Id,
					Target:        req.Target,
					Status:        http.StatusBadGateway,
					ContentLength: 0,
				},
			},
		}
		dataflow <- resp
		return
	}
	for _, header := range req.Headers {
		for _, value := range header.Values {
			httpRequest.Header.Add(header.Name, value)
		}
	}
	//log.Printf("Sending HTTP request: %v", httpRequest)
	get, err := client.Do(httpRequest)
	if err != nil {
		log.Printf("Failed to execute request for %s to %s: %v", req.Method, c.serverURL+req.URI, err)
		resp := &tunnel.ASEventWrapper{
			Event: &tunnel.ASEventWrapper_HttpResponse{
				HttpResponse: &tunnel.HttpResponse{
					Id:            req.Id,
					Target:        req.Target,
					Status:        http.StatusBadGateway,
					ContentLength: 0,
				},
			},
		}
		dataflow <- resp
		return
	}

	// First, send the headers.
	resp := &tunnel.ASEventWrapper{
		Event: &tunnel.ASEventWrapper_HttpResponse{
			HttpResponse: &tunnel.HttpResponse{
				Id:            req.Id,
				Target:        req.Target,
				Status:        int32(get.StatusCode),
				ContentLength: get.ContentLength,
				Headers:       makeHeaders(get.Header),
			},
		},
	}
	dataflow <- resp

	// Now, send one or more data packet.
	for {
		buf := make([]byte, 10240)
		n, err := get.Body.Read(buf)
		if n > 0 {
			resp := &tunnel.ASEventWrapper{
				Event: &tunnel.ASEventWrapper_HttpChunkedResponse{
					HttpChunkedResponse: &tunnel.HttpChunkedResponse{
						Id:     req.Id,
						Target: req.Target,
						Body:   buf[:n],
					},
				},
			}
			dataflow <- resp
		}
		if err == io.EOF {
			resp := &tunnel.ASEventWrapper{
				Event: &tunnel.ASEventWrapper_HttpChunkedResponse{
					HttpChunkedResponse: &tunnel.HttpChunkedResponse{
						Id:     req.Id,
						Target: req.Target,
						Body:   []byte(""),
					},
				},
			}
			dataflow <- resp
			return
		}
		if err == context.Canceled {
			log.Printf("Context cancelled, request ID %s", req.Id)
			return
		}
		if err != nil {
			log.Printf("Got error on HTTP read: %v", err)
			// todo: send an error message somehow.  For now, just send EOF
			resp := &tunnel.ASEventWrapper{
				Event: &tunnel.ASEventWrapper_HttpChunkedResponse{
					HttpChunkedResponse: &tunnel.HttpChunkedResponse{
						Id:     req.Id,
						Target: req.Target,
						Body:   []byte(""),
					},
				},
			}
			dataflow <- resp
			return
		}
	}
}

func runTunnel(config *serverConfig, client tunnel.TunnelServiceClient, ticker chan uint64, identity string) {
	ctx := context.Background()
	stream, err := client.EventTunnel(ctx)
	if err != nil {
		log.Fatalf("%v.EventTunnel(_) = _, %v", client, err)
	}

	dataflow := make(chan *tunnel.ASEventWrapper, 20)

	// Handle periodic pings from the ticker.
	go func() {
		for {
			ts, more := <-ticker
			if !more {
				return
			}
			req := &tunnel.ASEventWrapper{
				Event: &tunnel.ASEventWrapper_PingRequest{
					PingRequest: &tunnel.PingRequest{Ts: ts},
				},
			}
			if err = stream.Send(req); err != nil {
				log.Fatalf("Unable to send a PingRequest: %v", err)
			}
		}
	}()

	// Handle HTTP fetch responses
	go func() {
		for {
			ew, more := <-dataflow
			if !more {
				return
			}
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
			case *tunnel.SAEventWrapper_PingResponse:
				continue
			case *tunnel.SAEventWrapper_HttpRequestCancel:
				req := in.GetHttpRequestCancel()
				callCancelFunction(req.Id)
			case *tunnel.SAEventWrapper_HttpRequest:
				req := in.GetHttpRequest()
				c := config.contexts[config.defaultContext]
				go executeRequest(dataflow, c, req)
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

func runTicker(tickTime int, ticker chan uint64) {
	log.Printf("Starting ticker to send pings every %d seconds.", tickTime)
	go func() {
		for {
			time.Sleep(time.Duration(tickTime) * time.Second)
			ticker <- tunnel.Now()
		}
	}()

}

type serverContext struct {
	username   string
	serverURL  string
	serverCA   *x509.Certificate
	clientCert *tls.Certificate
	insecure   bool
}

type serverConfig struct {
	defaultContext string
	contexts       map[string]*serverContext
}

func makeServerConfig(kconfig *kubeconfig.KubeConfig) *serverConfig {

	contexts := make(map[string]*serverContext)

	names := kconfig.GetContextNames()
	for _, name := range names {
		user, cluster, err := kconfig.FindContext(name)
		if err != nil {
			log.Fatalf("Unable to retrieve cluster and user info for context %s: %v", name, err)
		}

		certData, err := b64.StdEncoding.DecodeString(user.User.ClientCertificateData)
		if err != nil {
			log.Fatalf("Error decoding user cert from base64 (%s): %v", user.Name, err)
		}
		keyData, err := b64.StdEncoding.DecodeString(user.User.ClientKeyData)
		if err != nil {
			log.Fatalf("Error decoding user key from base64 (%s): %v", user.Name, err)
		}

		clientKeypair, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			log.Fatalf("Error loading client cert/key: %v", err)
		}

		sa := &serverContext{
			username:   user.Name,
			clientCert: &clientKeypair,
			serverURL:  cluster.Cluster.Server,
			insecure:   cluster.Cluster.InsecureSkipTLSVerify,
		}

		if len(cluster.Cluster.CertificateAuthorityData) > 0 {
			serverCA, err := b64.StdEncoding.DecodeString(cluster.Cluster.CertificateAuthorityData)
			if err != nil {
				log.Fatalf("Error decoding server CA cert from base64 (%s): %v", cluster.Name, err)
			}
			pemBlock, _ := pem.Decode(serverCA)
			serverCert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				log.Fatalf("Error parsing server certificate: %v", err)
			}
			sa.serverCA = serverCert
		}

		contexts[name] = sa
	}

	config := &serverConfig{
		defaultContext: kconfig.CurrentContext,
		contexts:       contexts,
	}
	return config
}

func main() {
	flag.Parse()

	// load client cert/key, cacert
	clcert, err := tls.LoadX509KeyPair(*agentCertFile, *agentKeyFile)
	if err != nil {
		log.Fatalf("Unable to load agent certificate or key: %v", err)
	}
	srvcert, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("Unable to load CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(srvcert); !ok {
		log.Fatalf("Unable to append certificat to pool: %v", err)
	}

	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clcert},
		RootCAs:      caCertPool,
	})

	kconfig, err := kubeconfig.ReadKubeConfig(*kubeConfigFilename)
	if err != nil {
		log.Fatalf("Unable to read kubeconfig: %v", err)
	}
	config := makeServerConfig(kconfig)
	log.Printf("Kubernetes context: %s", config.defaultContext)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(ta),
		grpc.WithBlock(),
		grpc.WithTimeout(10 * time.Second),
	}

	conn, err := grpc.Dial(*host, opts...)
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}
	defer conn.Close()

	client := tunnel.NewTunnelServiceClient(conn)

	ticker := make(chan uint64)
	runTicker(*tickTime, ticker)

	log.Printf("Starting tunnel.")
	runTunnel(config, client, ticker, "skan")
	log.Printf("Done.")
}
