package fwdapi

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
	ServerTime      uint64      `json:"serverTime"`
	ConnectedAgents interface{} `json:"connectedAgents"`
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
