package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-resty/resty/v2"
)

var (
	certFile      = flag.String("certFile", "tls.crt", "The file containing the certificate used to connect to the controller")
	keyFile       = flag.String("keyFile", "tls.key", "The file containing the certificate used to connect to the controller")
	caCertFile    = flag.String("caCertFile", "ca.pem", "The file containing the CA certificate we will use to verify the controller's cert")
	host          = flag.String("host", "forwarder-controller:9003", "The hostname of the controller")
	endpointName  = flag.String("name", "", "Item name")
	agentIdentity = flag.String("agent", "", "agent name (required)")
	endpointType  = flag.String("type", "", "endpoint type")
)

func usage(message string) {
	if len(message) > 0 {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", message)
	}
	flag.Usage()
	os.Exit(-1)
}

func makeClient() *resty.Client {
	client := resty.New()
	client.SetRootCertificate(*caCertFile)
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("%v", err)
	}
	client.SetCertificates(cert)
	return client
}

func getKubeconfigCreds() {
	client := makeClient()
	resp, err := client.R().
		EnableTrace().
		Post("...")
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	fmt.Printf("%#v\n", resp)
}

func main() {
	flag.Parse()

	if len(*agentIdentity) == 0 {
		usage("'agent' must be specified")
	}
}
