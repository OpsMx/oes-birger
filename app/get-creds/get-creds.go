package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-resty/resty/v2"
	"github.com/opsmx/oes-birger/pkg/fwdapi"
)

var (
	certFile      = flag.String("certFile", "tls.crt", "The file containing the certificate used to connect to the controller")
	keyFile       = flag.String("keyFile", "tls.key", "The file containing the certificate used to connect to the controller")
	caCertFile    = flag.String("caCertFile", "ca.pem", "The file containing the CA certificate we will use to verify the controller's cert")
	host          = flag.String("host", "forwarder-controller:9003", "The hostname of the controller")
	endpointName  = flag.String("name", "", "Item name")
	agentIdentity = flag.String("agent", "", "agent name")
	endpointType  = flag.String("type", "", "endpoint type")
	action        = flag.String("action", "", "action, one of: agent, kubectl, agent-manifest, remote-command, control")
)

func usage(message string) {
	if len(message) > 0 {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", message)
	}
	flag.Usage()
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  'kubectl' requires: agent, endpointName.\n")
	fmt.Fprintf(os.Stderr, "  'service' requires: agent, endpointType, endpointName.\n")
	fmt.Fprintf(os.Stderr, "  'remote-command' requires: agent, endpointName.\n")
	fmt.Fprintf(os.Stderr, "  'agent-manifest' requires: agent.\n")
	fmt.Fprintf(os.Stderr, "  'control' requires no other options.\n")
	os.Exit(-1)
}

func makeClient() *resty.Client {
	client := resty.New()
	client.SetRootCertificate(*caCertFile)
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Panicf("%v", err)
	}
	client.SetCertificates(cert)
	return client
}

func getKubeconfigCreds() {
	request := fwdapi.KubeConfigRequest{
		AgentName: *agentIdentity,
		Name:      *endpointName,
	}
	client := makeClient()
	resp, err := client.R().
		EnableTrace().
		SetBody(request).
		Post(fmt.Sprintf("https://%s%s", *host, fwdapi.KUBECONFIG_ENDPOINT))
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	if resp.StatusCode() != 200 {
		log.Fatalf("Request failed: %s", resp.Status())
	}
	fmt.Printf("%s\n", string(resp.Body()))
}

func getAgentManifest() {
	request := fwdapi.ManifestRequest{
		AgentName: *agentIdentity,
	}
	client := makeClient()
	resp, err := client.R().
		EnableTrace().
		SetBody(request).
		Post(fmt.Sprintf("https://%s%s", *host, fwdapi.MANIFEST_ENDPOINT))
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	if resp.StatusCode() != 200 {
		log.Fatalf("Request failed: %s", resp.Status())
	}
	fmt.Printf("%s\n", string(resp.Body()))
}

func getStatistics() {
	client := makeClient()
	resp, err := client.R().
		EnableTrace().
		Get(fmt.Sprintf("https://%s%s", *host, fwdapi.STATISTICS_ENDPOINT))
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	if resp.StatusCode() != 200 {
		log.Fatalf("Request failed: %s", resp.Status())
	}
	fmt.Printf("%s\n", string(resp.Body()))
}

func insist(s *string, name string, expected bool) {
	if expected && (s == nil || *s == "") {
		usage(fmt.Sprintf("%s: required", name))
	}
	if !expected && (s != nil && *s != "") {
		log.Panicf("%s: not allowed for this action", name)
	}
}

func main() {
	flag.Parse()

	switch *action {
	case "kubectl":
		insist(agentIdentity, "agent", true)
		insist(endpointName, "name", true)
		insist(endpointType, "type", false)
		getKubeconfigCreds()
	case "agent-manifest":
		insist(agentIdentity, "agent", true)
		insist(endpointName, "name", false)
		insist(endpointType, "type", false)
		getAgentManifest()
	case "remote-command":
		insist(agentIdentity, "agent", true)
		insist(endpointName, "name", true)
		insist(endpointType, "type", false)
	case "service":
		insist(agentIdentity, "agent", true)
		insist(endpointName, "name", true)
		insist(endpointType, "type", true)
	case "control":
		insist(agentIdentity, "agent", false)
		insist(endpointName, "name", false)
		insist(endpointType, "type", false)
	case "statistics":
		//insist(agentIdentity, "agent", false)
		insist(endpointName, "name", false)
		insist(endpointType, "type", false)
		getStatistics()
	default:
		log.Panicf("Unknown action: %s", *action)
	}
}
