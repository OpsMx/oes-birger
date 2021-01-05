package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/opsmx/grpc-bidir/ca"
)

// ControllerConfig holds all the configuration for the controller.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type ControllerConfig struct {
	Agents      map[string]*agentConfig `yaml:"agents,omitempty"`
	Webhook     string                  `yaml:"webhook,omitempty"`
	ServerNames []string                `yaml:"serverNames,omitempty"`
	CAConfig    ca.Config               `yaml:"caConfig,omitempty"`
}

type agentConfig struct {
	Identity string `yaml:"identity,omitempty"`
}

// LoadConfig will load YAML configuration from the provided filename,
// and then apply environment variables to override some subset of
// available options.
func LoadConfig(filename string) (*ControllerConfig, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	config := &ControllerConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
