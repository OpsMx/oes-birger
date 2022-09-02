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

// Package fwdapi handles all the types and some minimal validation of
// the control API endpoints.
package fwdapi

// Endpoint paths
const (
	KubeconfigEndpoint = "/api/v1/generateKubectlComponents"
	ManifestEndpoint   = "/api/v1/generateAgentManifestComponents"
	ServiceEndpoint    = "/api/v1/generateServiceCredentials"
	StatisticsEndpoint = "/api/v1/getAgentStatistics"
	ControlEndpoint    = "/api/v1/generateControlCredentials"
)

// KubeConfigRequest defines the request for the KubeconfigEndpoint
type KubeConfigRequest struct {
	AgentName string `json:"agentName,omitempty"`
	Name      string `json:"name,omitempty"`
}

// KubeConfigResponse defines the response for the KubeconfigEndpoint
type KubeConfigResponse struct {
	AgentName       string `json:"agentName,omitempty"`
	Name            string `json:"name,omitempty"`
	ServerURL       string `json:"serverUrl,omitempty"`
	UserCertificate string `json:"userCertificate,omitempty"`
	UserKey         string `json:"userKey,omitempty"`
	CACert          string `json:"caCert,omitempty"`
}

// ManifestRequest defines the request for the ManifestEndpoint
type ManifestRequest struct {
	AgentName string `json:"agentName,omitempty"`
}

// ManifestResponse defines the response for the ManifestEndpoint
type ManifestResponse struct {
	AgentName        string `json:"agentName,omitempty"`
	ServerHostname   string `json:"serverHostname,omitempty"`
	ServerPort       uint16 `json:"serverPort,omitempty"`
	AgentCertificate string `json:"agentCertificate,omitempty"`
	AgentVersion     string `json:"agentVersion,omitempty"`
	AgentKey         string `json:"agentKey,omitempty"`
	CACert           string `json:"caCert,omitempty"`
}

// StatisticsResponse defines the response for the StatisticsEndpoint
type StatisticsResponse struct {
	ServerTime      uint64      `json:"serverTime,omitempty"`
	Version         string      `json:"version,omitempty"`
	ConnectedAgents interface{} `json:"connectedAgents,omitempty"`
}

// ServiceCredentialRequest defines the request for the ServiceEndpoint
type ServiceCredentialRequest struct {
	AgentName string `json:"agentName,omitempty"`
	Type      string `json:"type,omitempty"`
	Name      string `json:"name,omitempty"`
	OldType   string `json:"Type,omitempty"` // depricated
	OldName   string `json:"Name,omitempty"` // depricated
}

// ServiceCredentialResponse defines the response for the ServiceEndpoint
type ServiceCredentialResponse struct {
	AgentName      string      `json:"agentName,omitempty"`
	Name           string      `json:"name,omitempty"`
	Type           string      `json:"type,omitempty"`
	Username       string      `json:"username,omitempty"`
	Password       string      `json:"password,omitempty"`
	CredentialType string      `json:"credentialType,omitempty"`
	Credential     interface{} `json:"credential,omitempty"`
	URL            string      `json:"url,omitempty"`
	CACert         string      `json:"caCert,omitempty"`
}

// BasicCredentialResponse is the "http basic auth" configuration.
type BasicCredentialResponse struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// AwsCredentialResponse is the "aws access key and secret" configuration.
type AwsCredentialResponse struct {
	AwsAccessKey       string `json:"awsAccessKey,omitempty"`
	AwsSecretAccessKey string `json:"awsSecretAccessKey,omitempty"`
}

// ControlCredentialsRequest defines the request for the ControlEndpoint
type ControlCredentialsRequest struct {
	Name string `json:"name,omitempty"`
}

// ControlCredentialsResponse defines the response for the ControlEndpoint
type ControlCredentialsResponse struct {
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"`
	Certificate string `json:"userCertificate,omitempty"`
	Key         string `json:"userKey,omitempty"`
	CACert      string `json:"caCert,omitempty"`
}
