package main

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v3"
)

// CommandConfig defines a remote host we can run commands on.
// Each host has a `Name`, which can be targeted from Spinnaker.
// There are no environment overrides for these.
type CommandConfig struct {

	// Name is the name known by Spinnaker.
	Name string `yaml:"name"`

	// Host is the hostname we will ssh into.  It can be an IP address or a hostname,
	// which will be resolved.  Port 22 is assumed.  If needed, a port may be specified
	// by adding `:1234` to the hostname.
	Host string `yaml:"host"`

	// Username is the username we will log in as.
	Username string `yaml:"username"`

	// A path to a known_hosts format file.
	// default:  /app/agent/ssh/$name/known_hosts, if not found /app/agent/ssh/common/known_hosts.
	// If a host is not in this file, we will reject it and return an for the request.
	// One of the paths must exist unless `InsecureIgnoreHostKey` is true.
	KnownHosts string `yaml:"knownHostsPath"`

	// InsecureIgnoreHostKey will disable host key checking.  76Not recommended.
	InsecureIgnoreHostKey bool `yaml:"insecureIgnoreHostKey"`

	// UserKeyPath is where the Kubernetes secret of type `ssh-key-secret` is mounted.
	// The secret must not have a passphrase.
	// default: /app/agent/ssh/$name/userkey/{ssh-publickey,ssh-privatekey}
	UserKeyPath string `yaml:"userKeyPath"`

	// PasswordPath is where the Kubernetes secret of type `opaque` is mounted.
	// It should contain the user's password.  If this is provided, the SSH key is
	// ignored.
	// default: /app/agent/ssh/$name/password (and if not present, UserKeyPath will be used.)
	PasswordPath string `yaml:"passwordPath"`
}

// AgentConfig holds all the configuration for the agent.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type AgentConfig struct {

	// Namespaces are the Kubernetes namespaces we are configured to use.
	Namespaces []string `yaml:"namespaces,omitempty"`

	// This is the controller hostname we will connect to, including the port.  "host:port"
	ControllerHostname string `yaml:"controllerHostname,omitempty"`

	// This is the CA cert in base64 format.
	CACert64 *string `yaml:"caCert64,omitempty"`

	// This is the list of remote commands (SSH targets) we are configured to allow.
	Commands []CommandConfig `yaml:"commands,omitempty"`
}

// LoadConfig will load YAML configuration from the provided filename, and then apply
// environment variables to override some subset of available options.
func LoadConfig(filename string) (*AgentConfig, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	config := &AgentConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}

	if len(config.ControllerHostname) == 0 {
		config.ControllerHostname = "forwarder-controller:9001"
	}

	return config, nil
}

// DumpConfig will display all the configuration items, including the empty ones.
func (c *AgentConfig) DumpConfig() {
	log.Printf("config: Namespaces: %v", c.Namespaces)
	log.Printf("controller hostname: %s", c.ControllerHostname)
}
