package fwdapi

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

const (
	KUBECONFIG_ENDPOINT = "/api/v1/generateKubectlComponents"
	MANIFEST_ENDPOINT   = "/api/v1/generateAgentManifestComponents"
	SERVICE_ENDPOINT    = "/api/v1/generateServiceCredentials"
	STATISTICS_ENDPOINT = "/api/v1/getAgentStatistics"
	CONTROL_ENDPOINT    = "/api/v1/generateControlCredentials"
)

///
/// KUBECONFIG_ENDPOINT
///
type KubeConfigRequest struct {
	AgentName string `json:"agentName"`
	Name      string `json:"name"`
}

type KubeConfigResponse struct {
	AgentName       string `json:"agentName"`
	Name            string `json:"name"`
	ServerURL       string `json:"serverUrl"`
	UserCertificate string `json:"userCertificate"`
	UserKey         string `json:"userKey"`
	CACert          string `json:"caCert"`
}

///
/// MANIFEST_ENDPOINT
///
type ManifestRequest struct {
	AgentName string `json:"agentName"`
}

type ManifestResponse struct {
	AgentName        string `json:"agentName"`
	ServerHostname   string `json:"serverHostname"`
	ServerPort       uint16 `json:"serverPort"`
	AgentCertificate string `json:"agentCertificate"`
	AgentKey         string `json:"agentKey"`
	CACert           string `json:"caCert"`
}

///
/// STATISTICS_ENDPOINT
///
type StatisticsResponse struct {
	ServerTime      uint64      `json:"serverTime,omitempty"`
	Version         string      `json:"version,omitempty"`
	ConnectedAgents interface{} `json:"connectedAgents,omitempty"`
}

///
/// SERVICE_ENDPOINT
///
type ServiceCredentialRequest struct {
	AgentName string `json:"agentName,omitempty"`
	Type      string `json:"Type,omitempty"`
	Name      string `json:"Name,omitempty"`
}

type ServiceCredentialResponse struct {
	AgentName string `json:"agentName,omitempty"`
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	URL       string `json:"url,omitempty"`
	CACert    string `json:"caCert"`
}

///
/// CONTROL_ENDPOINT
///
type ControlCredentialsRequest struct {
	Name string `json:"name,omitempty"`
}

type ControlCredentialsResponse struct {
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"`
	Certificate string `json:"userCertificate,omitempty"`
	Key         string `json:"userKey,omitempty"`
	CACert      string `json:"caCert,omitempty"`
}
