package main

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

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/opsmx/oes-birger/pkg/secrets"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
)

type AwsConfig struct {
	Credentials AwsCredentials `yaml:"credentials,omitempty"`
}

type AwsCredentials struct {
	SecretName string `yaml:"secretName,omitempty"`
}

type AwsEndpoint struct {
	sync.RWMutex
	creds  *credentials.Credentials
	signer *v4.Signer
}

const awsTimeFormat = "20060102T150405Z"

var stripHeaders = map[string]bool{
	"Authorization":                true,
	"Connection":                   true,
	"X-Amz-Content-Sha256":         true,
	"X-Opsmx-Original-Host":        true,
	"X-Opsmx-Original-Port":        true,
	"X-Opsmx-Signing-Region":       true,
	"X-Opsmx-Service-Signing-Name": true,
}

func MakeAwsEndpoint(name string, configBytes []byte, secretsLoader secrets.SecretLoader) (*AwsEndpoint, bool, error) {
	k := &AwsEndpoint{}

	var config AwsConfig
	err := yaml.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, false, err
	}

	if config.Credentials.SecretName == "" {
		return k, false, fmt.Errorf("aws: secretName is not set")
	}

	secret, err := secretsLoader.GetSecret(config.Credentials.SecretName)
	if err != nil {
		return k, false, err
	}

	awsAccessKey, hasAwsAccessKey := getItem(secret, "awsAccessKey")
	awsSecretAccessKey, hasAwsSecretAccessKey := getItem(secret, "awsSecretAccessKey")

	if !hasAwsAccessKey {
		return k, false, fmt.Errorf("aws: secret does not have 'awsAccessKey")
	}
	if !hasAwsSecretAccessKey {
		return k, false, fmt.Errorf("aws: secret does not have 'awsSecretAccessKey")
	}

	k.creds = credentials.NewStaticCredentials(string(awsAccessKey), string(awsSecretAccessKey), "")
	k.signer = v4.NewSigner(k.creds)

	return k, true, nil
}

func (a *AwsEndpoint) executeHTTPRequest(dataflow chan *tunnel.AgentToControllerWrapper, req *tunnel.HttpRequest) {
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

	host := req.GetHeaderValue("x-opsmx-original-host")
	port := req.GetHeaderValue("x-opsmx-original-port")
	signerService := req.GetHeaderValue("x-opsmx-service-signing-name")
	signingRegion := req.GetHeaderValue("x-opsmx-signing-region")
	timestamp := req.GetHeaderValue("x-amz-date")

	ts, err := time.Parse(awsTimeFormat, timestamp)
	if err != nil {
		ts = time.Now()
	}

	if len(host) == 0 || len(port) == 0 || len(signerService) == 0 || len(signingRegion) == 0 || len(timestamp) == 0 {
		log.Printf("aws: required headers missing from request")
		dataflow <- makeBadGatewayResponse(req.Id)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	registerCancelFunction(req.Id, cancel)
	defer unregisterCancelFunction(req.Id)

	baseURL := fmt.Sprintf("https://%s:%s", host, port)
	actualurl := fmt.Sprintf("https://%s:%s%s", host, port, req.URI)

	httpRequest, err := http.NewRequestWithContext(ctx, req.Method, actualurl, bytes.NewBuffer(req.Body))
	if err != nil {
		log.Printf("Failed to build request for %s to %s: %v", req.Method, actualurl, err)
		dataflow <- makeBadGatewayResponse(req.Id)
		return
	}

	for _, header := range req.Headers {
		targetName := strings.ToLower(header.Name)
		if skip, found := stripHeaders[targetName]; found && skip {
			continue
		}
		for _, value := range header.Values {
			httpRequest.Header.Add(header.Name, value)
		}
	}

	bodyBuffer := bytes.NewReader(req.Body)
	a.signer.Sign(httpRequest, bodyBuffer, signerService, signingRegion, ts)

	runHTTPRequest(client, req, httpRequest, dataflow, baseURL)
}
