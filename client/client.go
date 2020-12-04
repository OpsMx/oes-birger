package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"

	"google.golang.org/grpc"

	"github.com/skandragon/grpc-bidir/tunnel"
)

var (
	host     = flag.String("host", tunnel.DefaultHostAndPort, "Server and port to connect to")
	rpcHost  = flag.String("rpcHost", "kubernetes.docker.internal:6443", "Host and port to connect to Kubernetes API")
	tickTime = flag.Int("tickTime", 30, "Time between sending Ping messages")
	identity = flag.String("identity", "", "The client ID to send to the server")
)

type kubeConfig struct {
	APIVersion string
	Clusters   []struct {
		Name    string
		Cluster struct {
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string
		}
	}
	Contexts []struct {
		Name    string
		Context struct {
			Cluster string
			User    string
		}
	}
	Users []struct {
		Name string
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		}
	}
}

func readKubeConfig() (*kubeConfig, error) {
	filename := os.Getenv("HOME") + "/.kube/config"

	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &kubeConfig{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %v", filename, err)
	}

	return c, nil
}

func runCommand(args []string, stdin string) (stdout string, stderr string, exitCode int32, err error) {
	var outb, errb bytes.Buffer
	cmd := exec.Command("kubectl", args...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "REMOTE=true")
	if err := cmd.Run(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			stdoutb, _ := ioutil.ReadAll(&outb)
			stderrb, _ := ioutil.ReadAll(&errb)
			return string(stdoutb), string(stderrb), int32(exiterr.ExitCode()), nil
		}
	}
	stdoutb, _ := ioutil.ReadAll(&outb)
	stderrb, _ := ioutil.ReadAll(&errb)
	return string(stdoutb), string(stderrb), 0, nil
}

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
	}
	return ret
}

func runTunnel(client tunnel.TunnelServiceClient, ticker chan uint64, identity string) {
	ctx := context.Background()
	stream, err := client.EventTunnel(ctx)
	if err != nil {
		log.Fatalf("%v.EventTunnel(_) = _, %v", client, err)
	}

	// Sign in
	req := &tunnel.ASEventWrapper{
		Event: &tunnel.ASEventWrapper_SigninRequest{
			SigninRequest: &tunnel.SigninRequest{Identity: identity, StartTime: tunnel.Now()},
		},
	}
	log.Printf("Sending: %v", req)
	if err = stream.Send(req); err != nil {
		log.Fatalf("Unable to send a SigninRequest: %v", err)
	}

	// Handle periodic pings from the ticker.
	go func() {
		for {
			ts := <-ticker
			req := &tunnel.ASEventWrapper{
				Event: &tunnel.ASEventWrapper_PingRequest{
					PingRequest: &tunnel.PingRequest{Ts: ts},
				},
			}
			log.Printf("Sending %v", req)
			if err = stream.Send(req); err != nil {
				log.Fatalf("Unable to send a PingRequest: %v", err)
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
				req := in.GetPingResponse()
				log.Printf("Received: PingResponse: %v", req)
			case *tunnel.SAEventWrapper_SigninResponse:
				req := in.GetSigninResponse()
				log.Printf("Succesfully signed in: %v", req)
			case *tunnel.SAEventWrapper_CommandRequest:
				req := in.GetCommandRequest()
				stdout, stderr, exitCode, err := runCommand(req.CmdlineArgs, req.Stdin)
				if err != nil {
					log.Printf("Command err: %v", err)
					continue
				}
				resp := &tunnel.ASEventWrapper{
					Event: &tunnel.ASEventWrapper_CommandResponse{
						CommandResponse: &tunnel.CommandResponse{Id: req.Id, Target: req.Target, Stdout: stdout, Stderr: stderr, ExitCode: exitCode},
					},
				}
				log.Printf("Sending %v", resp)
				if err = stream.Send(resp); err != nil {
					log.Fatalf("Unable to send: %v", err)
				}
			case *tunnel.SAEventWrapper_HttpRequest:
				req := in.GetHttpRequest()
				log.Printf("Got request: %v", req)
				tr := &http.Transport{
					MaxIdleConns:       10,
					IdleConnTimeout:    30 * time.Second,
					DisableCompression: true,
					TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
				}
				client := &http.Client{Transport: tr}
				httpRequest, _ := http.NewRequest(req.Method, "https://"+*rpcHost+req.URI, nil)
				httpRequest.Proto = req.Protocol
				for _, header := range req.Headers {
					for _, value := range header.Values {
						httpRequest.Header.Add(header.Name, value)
					}
				}
				log.Printf("Sending HTTP request: %v", httpRequest)
				get, err := client.Do(httpRequest)
				if err != nil {
					log.Printf("Failed to %s to %s: %v", req.Method, req.URI, err)
					continue
				}
				body, _ := ioutil.ReadAll(get.Body)
				resp := &tunnel.ASEventWrapper{
					Event: &tunnel.ASEventWrapper_HttpResponse{
						HttpResponse: &tunnel.HttpResponse{
							Id:      req.Id,
							Target:  req.Target,
							Status:  int32(get.StatusCode),
							Body:    string(body),
							Headers: makeHeaders(get.Header),
						},
					},
				}
				log.Printf("Sending %v", resp)
				if err = stream.Send(resp); err != nil {
					log.Fatalf("Unable to send: %v", err)
				}
			case nil:
				// ignore for now
			default:
				log.Printf("Received unknown message: %T: %v", x, in)
			}
		}
	}()
	<-waitc
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

func main() {
	flag.Parse()
	if *identity == "" {
		log.Fatal("Must specify an -identity")
	}

	kconfig, err := readKubeConfig()
	if err != nil {
		log.Fatalf("Unable to read kubeconfig: %v", err)
	}
	log.Printf("Kube config: %v", *kconfig)

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())

	conn, err := grpc.Dial(*host, opts...)
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}
	defer conn.Close()

	client := tunnel.NewTunnelServiceClient(conn)

	ticker := make(chan uint64)
	runTicker(*tickTime, ticker)

	log.Printf("Starting tunnel.")
	runTunnel(client, ticker, *identity)
	log.Printf("Done.")
}
