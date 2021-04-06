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

type JenkinsCredentials struct {
	Type     string `yaml:"type,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Token    string `yaml:"token,omitempty"`
}

type JenkinsConfig struct {
	URL         string `yaml:"url,omitempty"`
	Insecure    bool   `yaml:"insecure,omitempty"`
	Credentials JenkinsCredentials
}

type JenkinsEndpoint struct {
	endpointType string
	endpointName string
	config       JenkinsConfig
}

func (ke JenkinsEndpoint) cleanupCreds() bool {
	creds := ke.config.Credentials
	switch creds.Type {
	case "":
		creds.Type = "none"
		return true
	case "none":
		return true
	case "bearer":
		if creds.Token == "" {
			log.Printf("Credentials for %s/%s type bearer requires 'token'", ke.endpointType, ke.endpointName)
			return false
		}
		ke.config.Credentials = creds
		return true
	case "basic":
		if creds.Username == "" {
			log.Printf("Credentials for %s/%s type basic requires 'username'", ke.endpointType, ke.endpointName)
			return false
		}
		if creds.Password == "" && creds.Token == "" {
			log.Printf("Credentials for %s/%s type basic requires 'password' or 'token'", ke.endpointType, ke.endpointName)
			return false
		}
		if creds.Password != "" && creds.Token != "" {
			log.Printf("Credentials for %s/%s type basic requires only one of 'password' or 'token'", ke.endpointType, ke.endpointName)
			return false
		}
		ke.config.Credentials = creds
		return true
	}
	log.Printf("Unknown authentication type for %s/%s: %s", ke.endpointType, ke.endpointName, creds.Type)
	return false
}

func MakeJenkinsEndpoint(endpointType string, endpointName string, configBytes []byte) (*JenkinsEndpoint, bool, error) {
	ep := &JenkinsEndpoint{
		endpointType: endpointType,
		endpointName: endpointName,
	}

	var config JenkinsConfig
	err := yaml.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, false, err
	}
	ep.config = config
	if !ep.cleanupCreds() {
		return nil, false, nil
	}

	if ep.config.URL == "" {
		log.Printf("url not set for %s/%s", endpointType, endpointName)
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
	if ke.config.Insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true
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

	creds := ke.config.Credentials
	switch creds.Type {
	case "basic":
		if creds.Password == "" {
			httpRequest.SetBasicAuth(creds.Username, creds.Token)
		} else {
			httpRequest.SetBasicAuth(creds.Username, creds.Password)
		}
	case "bearer":
		httpRequest.Header.Set("Authorization", "Bearer "+creds.Token)
	}

	runHTTPRequest(client, req, httpRequest, dataflow, ke.config.URL)
}
