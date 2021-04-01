package main

import (
	"bytes"
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/opsmx/oes-birger/pkg/tunnel"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
)

type JenkinsConfig struct {
	SecretPath string `yaml:"secretPath,omitempty"`
	URL        string `yaml:"url,omitempty"`
}

type JenkinsEndpoint struct {
	config JenkinsConfig
}

func MakeJenkinsEndpoint(name string, configBytes []byte) (*JenkinsEndpoint, bool, error) {
	ep := &JenkinsEndpoint{}

	var config JenkinsConfig
	err := yaml.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, false, err
	}
	ep.config = config

	if ep.config.SecretPath == "" {
		log.Printf("secretPath not set for jenkins/%s", name)
		return nil, false, nil
	}

	if ep.config.URL == "" {
		log.Printf("url not set for jenkins/%s", name)
		return nil, false, nil
	}

	return ep, true, nil
}

func (ke *JenkinsEndpoint) executeHTTPRequest(dataflow chan *tunnel.AgentToControllerWrapper, req *tunnel.HttpRequest) {
	log.Printf("Running request %v", req)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
	defer unregisterCancelFunction(req.Id)

	httpRequest, err := http.NewRequestWithContext(ctx, req.Method, ke.config.URL+req.URI, bytes.NewBuffer(req.Body))
	if err != nil {
		log.Printf("Failed to build request for %s to %s: %v", req.Method, ke.config.URL+req.URI, err)
		dataflow <- makeBadGatewayResponse(req.Id)
		return
	}

	copyHeaders(req, httpRequest)

	runHTTPRequest(client, req, httpRequest, dataflow, ke.config.URL)
}
