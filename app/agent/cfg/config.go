package cfg

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_CERT_PATH = "/app/secrets/agent/tls.crt"
	DEFAULT_KEY_PATH  = "/app/secrets/agent/tls.key"
)

// CommandConfig defines a remote host we can run commands on.
// Each host has a `Name`, which can be targeted from Spinnaker.
// There are no environment overrides for these.
type CommandConfig struct {
	Enabled               bool   `yaml:"enabled"`
	Name                  string `yaml:"name"`
	Host                  string `yaml:"host"`
	Username              string `yaml:"username"`
	KnownHosts            string `yaml:"knownHostsPath"`
	InsecureIgnoreHostKey bool   `yaml:"insecureIgnoreHostKey"`
	UserKeyPath           string `yaml:"userKeyPath"`
	PasswordPath          string `yaml:"passwordPath"`
}

//
// KubernetesConfig holds the config for Kubernetes endpoints.
//
type KubernetesConfig struct {
	Enabled bool `yaml:"enabled"`
}

//
// ServiceCredentials holds what we use to authenticate the agent to the
// service, in a somewhat generic way.
//
type ServiceCredentials struct {
	Type     string  `yaml:"type,omitempty"`
	Username *string `yaml:"username,omitempty"`
	Password *string `yaml:"password,omitempty"`
	Token    *string `yaml:"token,omitempty"`
}

//
// ServiceConfig holds configuration for a service, like a Jenkins endpoint.
//
type ServiceConfig struct {
	Enabled     bool               `yaml:"enabled"`
	Name        string             `yaml:"name"`
	Type        string             `yaml:"type"`
	URL         string             `yaml:"url"`
	Credentials ServiceCredentials `yaml:"credentials"`
}

// AgentConfig holds all the configuration for the agent.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type AgentConfig struct {
	ControllerHostname string            `yaml:"controllerHostname,omitempty"`
	CACert64           *string           `yaml:"caCert64,omitempty"`
	Commands           []CommandConfig   `yaml:"commands,omitempty"`
	Kubernetes         *KubernetesConfig `yaml:"kubernetes,omitempty"`
	Services           *ServiceConfig    `yaml:"services,omitempty"`
	CertFile           string            `yaml:"certFile,omitempty"`
	KeyFile            string            `yaml:"keyFile,omitempty"`
}

func (c *AgentConfig) applyDefaults() {
	if len(c.ControllerHostname) == 0 {
		c.ControllerHostname = "forwarder-controller:9001"
	}

	if len(c.CertFile) == 0 {
		c.CertFile = DEFAULT_CERT_PATH
	}

	if len(c.KeyFile) == 0 {
		c.KeyFile = DEFAULT_KEY_PATH
	}

	if c.Kubernetes == nil {
		c.Kubernetes = &KubernetesConfig{
			Enabled: false,
		}
	}
}

// Load will load YAML configuration from the provided filename, and then apply
// environment variables to override some subset of available options.
func Load(filename string) (*AgentConfig, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	config := &AgentConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}

	config.applyDefaults()

	return config, nil
}
