package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v3"

	"github.com/opsmx/oes-birger/pkg/ca"
)

// ControllerConfig holds all the configuration for the controller.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type ControllerConfig struct {
	Agents                map[string]*agentConfig `yaml:"agents,omitempty"`
	ServiceAuth           serviceAuthConfig       `yaml:"serviceAuth,omitempty"`
	Webhook               string                  `yaml:"webhook,omitempty"`
	ServerNames           []string                `yaml:"serverNames,omitempty"`
	CAConfig              ca.Config               `yaml:"caConfig,omitempty"`
	PrometheusPort        uint16                  `yaml:"prometheusPort"`
	ServiceHostname       *string                 `yaml:"serviceHostname"`
	ServicePort           uint16                  `yaml:"servicePort"`
	ControlHostname       *string                 `yaml:"controlHostname"`
	ControlPort           uint16                  `yaml:"controlPort"`
	AgentHostname         *string                 `yaml:"agentHostname"`
	AgentPort             uint16                  `yaml:"agentPort"`
	RemoteCommandHostname *string                 `yaml:"remoteCommandHostname"`
	RemoteCommandPort     uint16                  `yaml:"remoteCommandPort"`
}

type agentConfig struct {
	Identity string `yaml:"identity,omitempty"`
}

type serviceAuthConfig struct {
	CurrentKeyName string `yaml:"currentKeyName,omitempty"`
}

// LoadConfig will load YAML configuration from the provided filename,
// and then apply environment variables to override some subset of
// available options.
func LoadConfig(f io.Reader) (*ControllerConfig, error) {
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	config := &ControllerConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}

	if config.AgentPort == 0 {
		config.AgentPort = 9001
	}
	if config.AgentHostname == nil {
		return nil, fmt.Errorf("agentHostname not set")
	}

	if config.ServicePort == 0 {
		config.ServicePort = 9002
	}
	if config.ServiceHostname == nil {
		return nil, fmt.Errorf("serviceHostname not set")
	}

	if config.ControlPort == 0 {
		config.ControlPort = 9003
	}
	if config.ControlHostname == nil {
		return nil, fmt.Errorf("controlHostname not set")
	}

	if config.RemoteCommandPort == 0 {
		config.RemoteCommandPort = 9004
	}
	if config.RemoteCommandHostname == nil {
		return nil, fmt.Errorf("remoteCommandHostname not set")
	}

	if config.PrometheusPort == 0 {
		config.PrometheusPort = 9102
	}

	config.addAllHostnames()

	return config, nil
}

func (c *ControllerConfig) hasServerName(target string) bool {
	for _, a := range c.ServerNames {
		if a == target {
			return true
		}
	}
	return false
}

func (c *ControllerConfig) addIfMissing(target *string, reason string) {
	if target != nil && !c.hasServerName(*target) {
		c.ServerNames = append(c.ServerNames, *target)
		log.Printf("Adding %s to ServerNames (for %s configuration setting)", *target, reason)
	}
}

func (c *ControllerConfig) addAllHostnames() {
	c.addIfMissing(c.AgentHostname, "agentHostname")
	c.addIfMissing(c.ControlHostname, "commandHostname")
	c.addIfMissing(c.ServiceHostname, "ServiceBaseHostname")
	c.addIfMissing(c.RemoteCommandHostname, "cmdToolHostname")
}

func (c *ControllerConfig) getServiceURL() string {
	return fmt.Sprintf("https://%s:%d", *c.ServiceHostname, c.ServicePort)
}

func (c *ControllerConfig) getControlURL() string {
	return fmt.Sprintf("https://%s:%d", *c.ControlHostname, c.ControlPort)
}

//
// Dump will display MOST of the controller's configuration.
//
func (c *ControllerConfig) Dump() {
	log.Println("ControllerConfig:")
	log.Printf("ServerNames:")
	for _, n := range config.ServerNames {
		log.Printf("  %s", n)
	}
	log.Printf("Service hostname: %s, port: %d", *c.ServiceHostname, c.ServicePort)
	log.Printf("URL returned for kubectl components: %s", c.getServiceURL())
	log.Printf("Agent hostname: %s, port %d", *c.AgentHostname, c.AgentPort)
	log.Printf("Control hostname: %s, port %d", *c.ControlHostname, c.ControlPort)
	log.Printf("RemoteCommand hostname: %s, port %d", *c.RemoteCommandHostname, c.RemoteCommandPort)
}
