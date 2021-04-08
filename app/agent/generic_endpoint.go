package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/opsmx/oes-birger/pkg/kube"
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

	rawUsername []byte `yamp:"-"`
	rawPassword []byte `yamp:"-"`
	rawToken    []byte `yamp:"-"`
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

func (ep *GenericEndpoint) loadSecrets(secretsLoader *kube.SecretsLoader) error {
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
	case "none":
		if token != "" || username != "" || password != "" {
			return fmt.Errorf("username, password, or token set for credential type none")
		}
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
		ep.config.Credentials.rawUsername = rawUsername
		ep.config.Credentials.rawPassword = rawPassword
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
		ep.config.Credentials.rawToken = rawToken
		return nil
	default:
		return fmt.Errorf("unknown credential type %s", ep.config.Credentials.Type)
	}
}

func (ep *GenericEndpoint) loadKubernetesSecrets(secretsLoader *kube.SecretsLoader) error {
	secret, err := secretsLoader.GetSecret(ep.config.Credentials.SecretName)
	if err != nil {
		return err
	}

	token, hasToken := (*secret)["token"]
	username, hasUsername := (*secret)["username"]
	password, hasPassword := (*secret)["password"]

	switch ep.config.Credentials.Type {
	case "none":
		return fmt.Errorf("secretName set, but credential type set to none")
	case "basic":
		if !hasUsername {
			return fmt.Errorf("username not set for credential type basic")
		}
		if !hasPassword {
			return fmt.Errorf("password not set for credential type basic")
		}
		if hasToken {
			return fmt.Errorf("token set in secret, but credential type set to basic")
		}
		ep.config.Credentials.rawUsername = username
		ep.config.Credentials.rawPassword = password
		return nil
	case "bearer":
		if hasUsername {
			return fmt.Errorf("username set, but credential type is bearer")
		}
		if hasPassword {
			return fmt.Errorf("password set, but credential type is bearer")
		}
		if !hasToken {
			return fmt.Errorf("token not set in secret for credential type bearer")
		}
		ep.config.Credentials.rawToken = token
		return nil
	default:
		return fmt.Errorf("unknown credential type %s", ep.config.Credentials.Type)
	}
}

func MakeGenericEndpoint(endpointType string, endpointName string, configBytes []byte, secretsLoader *kube.SecretsLoader) (*GenericEndpoint, bool, error) {
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
		if creds.Password == "" {
			httpRequest.SetBasicAuth(creds.Username, creds.Token)
		} else {
			httpRequest.SetBasicAuth(creds.Username, creds.Password)
		}
	case "bearer":
		httpRequest.Header.Set("Authorization", "Bearer "+creds.Token)
	}

	runHTTPRequest(client, req, httpRequest, dataflow, ep.config.URL)
}
