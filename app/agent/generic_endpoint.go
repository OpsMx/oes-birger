package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/opsmx/oes-birger/pkg/secrets"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
)

type GenericEndpointCredentials struct {
	Type       string `yaml:"type,omitempty"`
	Username   string `yaml:"username,omitempty"`
	Password   string `yaml:"password,omitempty"`
	Token      string `yaml:"token,omitempty"`
	SecretName string `yaml:"secretName,omitempty"`

	rawUsername string `yaml:"-"`
	rawPassword string `yaml:"-"`
	rawToken    string `yaml:"-"`
}

type GenericEndpointConfig struct {
	URL         string                     `yaml:"url,omitempty"`
	Insecure    bool                       `yaml:"insecure,omitempty"`
	Credentials GenericEndpointCredentials `yaml:"credentials,omitempty"`
}

type GenericEndpoint struct {
	endpointType string
	endpointName string
	config       GenericEndpointConfig
}

func (ep *GenericEndpoint) loadSecrets(secretsLoader secrets.SecretLoader) error {
	if ep.config.Credentials.SecretName == "" {
		return ep.loadBase64Secrets()
	}
	return ep.loadKubernetesSecrets(secretsLoader)
}

func (ep *GenericEndpoint) loadBase64Secrets() error {
	token := ep.config.Credentials.Token
	username := ep.config.Credentials.Username
	password := ep.config.Credentials.Password

	switch ep.config.Credentials.Type {
	case "none", "":
		if token != "" || username != "" || password != "" {
			return fmt.Errorf("username, password, or token set for credential type none")
		}
		ep.config.Credentials.Type = "none"
		return nil
	case "basic":
		if token != "" {
			return fmt.Errorf("token set, but credential type set to basic")
		}
		if username == "" || password == "" {
			return fmt.Errorf("username or password missing for credential type basic")
		}
		rawUsername, err := base64.StdEncoding.DecodeString(username)
		if err != nil {
			return err
		}
		rawPassword, err := base64.StdEncoding.DecodeString(password)
		if err != nil {
			return err
		}
		ep.config.Credentials.rawUsername = string(rawUsername)
		ep.config.Credentials.rawPassword = string(rawPassword)
		return nil
	case "bearer":
		if token == "" {
			return fmt.Errorf("token missing for credential type bearer")
		}
		if username != "" || password != "" {
			return fmt.Errorf("username or password set for credential type bearer")
		}
		rawToken, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			return err
		}
		ep.config.Credentials.rawToken = string(rawToken)
		return nil
	default:
		return fmt.Errorf("unknown credential type %s", ep.config.Credentials.Type)
	}
}

func (ep *GenericEndpoint) loadKubernetesSecrets(secretsLoader secrets.SecretLoader) error {
	if ep.config.Credentials.Type == "none" || ep.config.Credentials.Type == "" {
		return fmt.Errorf("none: secretName should not be set")
	}

	secret, err := secretsLoader.GetSecret(ep.config.Credentials.SecretName)
	if err != nil {
		return err
	}

	token, hasToken := (*secret)["token"]
	hasToken = hasToken && len(token) > 0
	username, hasUsername := (*secret)["username"]
	hasUsername = hasUsername && len(username) > 0
	password, hasPassword := (*secret)["password"]
	hasPassword = hasPassword && len(password) > 0

	switch ep.config.Credentials.Type {
	case "basic":
		if !hasUsername {
			return fmt.Errorf("basic: username missing in secret")
		}
		if !hasPassword {
			return fmt.Errorf("basic: password missing in secret")
		}
		if hasToken {
			return fmt.Errorf("basic: token should not be set in secret")
		}
		ep.config.Credentials.rawUsername = string(username)
		ep.config.Credentials.rawPassword = string(password)
		return nil
	case "bearer":
		if hasUsername {
			return fmt.Errorf("bearer: username should not be set in secret")
		}
		if hasPassword {
			return fmt.Errorf("bearer: password should not be set in secret")
		}
		if !hasToken {
			return fmt.Errorf("bearer: token missing in secret")
		}
		ep.config.Credentials.rawToken = string(token)
		return nil
	default:
		return fmt.Errorf("unknown credential type %s", ep.config.Credentials.Type)
	}
}

func MakeGenericEndpoint(endpointType string, endpointName string, configBytes []byte, secretsLoader secrets.SecretLoader) (*GenericEndpoint, bool, error) {
	ep := &GenericEndpoint{
		endpointType: endpointType,
		endpointName: endpointName,
	}

	var config GenericEndpointConfig
	err := yaml.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, false, err
	}
	ep.config = config

	err = ep.loadSecrets(secretsLoader)
	if err != nil {
		log.Printf("Unable to load secret: %v", err)
		return nil, false, nil
	}

	if ep.config.URL == "" {
		log.Printf("url not set for %s/%s", endpointType, endpointName)
		return nil, false, nil
	}

	return ep, true, nil
}

func (ep *GenericEndpoint) executeHTTPRequest(dataflow chan *tunnel.AgentToControllerWrapper, req *tunnel.HttpRequest) {
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
	if ep.config.Insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	client := &http.Client{
		Transport: tr,
	}

	ctx, cancel := context.WithCancel(context.Background())
	registerCancelFunction(req.Id, cancel)
	defer unregisterCancelFunction(req.Id)

	httpRequest, err := http.NewRequestWithContext(ctx, req.Method, ep.config.URL+req.URI, bytes.NewBuffer(req.Body))
	if err != nil {
		log.Printf("Failed to build request for %s to %s: %v", req.Method, ep.config.URL+req.URI, err)
		dataflow <- makeBadGatewayResponse(req.Id)
		return
	}

	copyHeaders(req, httpRequest)

	creds := ep.config.Credentials
	switch creds.Type {
	case "basic":
		httpRequest.SetBasicAuth(creds.rawUsername, creds.rawPassword)
	case "bearer":
		httpRequest.Header.Set("Authorization", "Bearer "+creds.rawToken)
	}

	runHTTPRequest(client, req, httpRequest, dataflow, ep.config.URL)
}
