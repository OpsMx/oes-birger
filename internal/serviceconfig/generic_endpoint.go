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

package serviceconfig

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/opsmx/oes-birger/internal/secrets"
	"github.com/opsmx/oes-birger/internal/tunnel"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
)

type genericEndpointCredentials struct {
	Type       string `yaml:"type,omitempty"`
	Username   string `yaml:"username,omitempty"`
	Password   string `yaml:"password,omitempty"`
	Token      string `yaml:"token,omitempty"`
	SecretName string `yaml:"secretName,omitempty"`

	rawUsername string `yaml:"-"`
	rawPassword string `yaml:"-"`
	rawToken    string `yaml:"-"`
}

type genericEndpointConfig struct {
	URL         string                     `yaml:"url,omitempty"`
	Insecure    bool                       `yaml:"insecure,omitempty"`
	Credentials genericEndpointCredentials `yaml:"credentials,omitempty"`
}

// GenericEndpoint defines the state (config and credentials) for a generic HTTP
// endpoint.
type GenericEndpoint struct {
	endpointType string
	endpointName string
	config       genericEndpointConfig
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
		ep.config.Credentials.Type = "none"
		return nil
	case "basic":
		if username == "" || password == "" {
			return fmt.Errorf("username or password missing for credential type 'basic'")
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
	case "bearer", "token":
		if token == "" {
			return fmt.Errorf("token missing for credential type '%s'", ep.config.Credentials.Type)
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

func getItem(m *map[string][]byte, key string) ([]byte, bool) {
	s, found := (*m)[key]
	return s, found && len(s) > 0
}

func (ep *GenericEndpoint) loadKubernetesSecrets(secretsLoader secrets.SecretLoader) error {
	if secretsLoader == nil {
		return fmt.Errorf("cannot load Kubernetes secrets from outside the cluster")
	}

	if ep.config.Credentials.Type == "none" || ep.config.Credentials.Type == "" {
		return fmt.Errorf("none: secretName should not be set")
	}

	secret, err := secretsLoader.GetSecret(ep.config.Credentials.SecretName)
	if err != nil {
		return err
	}

	token, hasToken := getItem(secret, "token")
	username, hasUsername := getItem(secret, "username")
	password, hasPassword := getItem(secret, "password")

	switch ep.config.Credentials.Type {
	case "basic":
		if !hasUsername {
			return fmt.Errorf("basic: username missing in secret")
		}
		if !hasPassword {
			return fmt.Errorf("basic: password missing in secret")
		}
		ep.config.Credentials.rawUsername = string(username)
		ep.config.Credentials.rawPassword = string(password)
		return nil
	case "bearer", "token":
		at := ep.config.Credentials.Type
		if !hasToken {
			return fmt.Errorf("%s: token missing in secret", at)
		}
		ep.config.Credentials.rawToken = string(token)
		return nil
	default:
		return fmt.Errorf("unknown or unsupported credential type %s", ep.config.Credentials.Type)
	}
}

// MakeGenericEndpoint returns a generic HTTP endpoint which allows calling a HTTP service.
func MakeGenericEndpoint(endpointType string, endpointName string, configBytes []byte, secretsLoader secrets.SecretLoader) (*GenericEndpoint, bool, error) {
	ep := &GenericEndpoint{
		endpointType: endpointType,
		endpointName: endpointName,
	}

	var config genericEndpointConfig
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

func (ep *GenericEndpoint) unmutateURI(typ string, method string, uri string, clock jwt.Clock) (unmutatedURI string, err error) {
	if typ != "fiat" {
		return uri, nil
	}
	if method != http.MethodGet {
		return uri, nil
	}
	if !jwtutil.MutationIsRegistered() {
		return uri, nil
	}
	parts := strings.Split(uri, "/")
	if len(parts) >= 3 && parts[1] == "authorize" {
		if parts[2], err = jwtutil.UnmutateHeader([]byte(parts[2]), clock); err != nil {
			return "", err
		}
		return strings.Join(parts, "/"), nil
	}
	return uri, nil
}

// ExecuteHTTPRequest does the actual call to connect to HTTP, and will send the data back over the
// tunnel.
func (ep *GenericEndpoint) ExecuteHTTPRequest(dataflow chan *tunnel.MessageWrapper, req *tunnel.OpenHTTPTunnelRequest) {
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

	uri, err := ep.unmutateURI(req.Type, req.Method, req.URI, nil)
	if err != nil {
		log.Printf("Failed to unmutate URI %s to %s: %v", req.Method, ep.config.URL+req.URI, err)
		dataflow <- tunnel.MakeBadGatewayResponse(req.Id)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	tunnel.RegisterCancelFunction(req.Id, cancel)
	defer tunnel.UnregisterCancelFunction(req.Id)

	httpRequest, err := http.NewRequestWithContext(ctx, req.Method, ep.config.URL+uri, bytes.NewBuffer(req.Body))
	if err != nil {
		log.Printf("Failed to build request for %s to %s: %v", req.Method, ep.config.URL+uri, err)
		dataflow <- tunnel.MakeBadGatewayResponse(req.Id)
		return
	}

	err = tunnel.CopyHeaders(req.Headers, &httpRequest.Header)
	if err != nil {
		log.Printf("failed to copy headers: %v", err)
		dataflow <- tunnel.MakeBadGatewayResponse(req.Id)
		return
	}

	creds := ep.config.Credentials
	switch creds.Type {
	case "basic":
		httpRequest.SetBasicAuth(creds.rawUsername, creds.rawPassword)
	case "bearer":
		httpRequest.Header.Set("Authorization", "Bearer "+creds.rawToken)
	case "token":
		httpRequest.Header.Set("Authorization", "Token "+creds.rawToken)
	}

	tunnel.RunHTTPRequest(client, req, httpRequest, dataflow, ep.config.URL)
}
