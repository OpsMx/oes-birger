package main

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

// AgentConfig holds all the configuration for the agent.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type AgentConfig struct {
	Namespaces         []string `yaml:"namespaces,omitempty"`
	ControllerHostname string   `yaml:"controllerHostname,omitempty"`
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
