package fwdapi

type KubeConfigRequest struct {
	Identity string `json:"identity"`
	Name     string `json:"name"`
}

type KubeConfigResponse struct {
	Identity        string `json:"identity"`
	Name            string `json:"name"`
	ServerURL       string `json:"serverUrl"`
	UserCertificate string `json:"userCertificate"`
	UserKey         string `json:"userKey"`
	CACert          string `json:"caCert"`
}

type ManifestRequest struct {
	Identity string `json:"identity"`
}

type ManifestResponse struct {
	Identity         string `json:"identity"`
	ServerHostname   string `json:"serverHostname"`
	ServerPort       uint16 `json:"serverPort"`
	AgentCertificate string `json:"agentCertificate"`
	AgentKey         string `json:"agentKey"`
	CACert           string `json:"caCert"`
}

type StatisticsResponse struct {
	ServerTime      uint64      `json:"serverTime"`
	ConnectedAgents interface{} `json:"connectedAgents"`
}

type ServiceCredentialRequest struct {
	Identity string `json:"identity,omitempty"`
	Type     string `json:"Type,omitempty"`
	Name     string `json:"Name,omitempty"`
}

type ServiceCredentialResponse struct {
	Identity string `json:"identity,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	URL      string `json:"url,omitempty"`
	CACert   string `json:"caCert"`
}
