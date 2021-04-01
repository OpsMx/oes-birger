package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v3"

	"github.com/opsmx/oes-birger/pkg/ca"
)

// ControllerConfig holds all the configuration for the controller.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type ControllerConfig struct {
	Agents              map[string]*agentConfig `yaml:"agents,omitempty"`
	Webhook             string                  `yaml:"webhook,omitempty"`
	ServerNames         []string                `yaml:"serverNames,omitempty"`
	CAConfig            ca.Config               `yaml:"caConfig,omitempty"`
	PrometheusPort      uint16                  `yaml:"prometheusPort"`
	ServiceBaseHostname *string                 `yaml:"serviceBaseHostname"`
	ServicePort         uint16                  `yaml:"servicePort"`
	CommandHostname     *string                 `yaml:"commandHostname"`
	CommandPort         uint16                  `yaml:"commandPort"`
	AgentHostname       *string                 `yaml:"agentHostname"`
	AgentPort           uint16                  `yaml:"agentPort"`
	CmdToolHostname     *string                 `yaml:"cmdToolHostname"`
	CmdToolPort         uint16                  `yaml:"cmdToolPort"`
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

	if config.ServiceBaseHostname == nil {
		log.Fatalf("serviceBaseHostname is not set.")
	}

	if config.AgentPort == 0 {
		config.AgentPort = 9001
	}

	if config.ServicePort == 0 {
		config.ServicePort = 9002
	}

	if config.CommandPort == 0 {
		config.CommandPort = 9003
	}

	if config.CmdToolPort == 0 {
		config.CmdToolPort = 9004
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
	c.addIfMissing(c.CommandHostname, "commandHostname")
	c.addIfMissing(c.ServiceBaseHostname, "ServiceBaseHostname")
	baseWildcard := "*." + *c.ServiceBaseHostname
	c.addIfMissing(&baseWildcard, "Service wildcard")
	c.addIfMissing(c.CmdToolHostname, "cmdToolHostname")
}

func (c *ControllerConfig) getAgentHostname() string {
	if c.AgentHostname != nil {
		return *c.AgentHostname
	}
	return c.ServerNames[0]
}

func (c *ControllerConfig) getAgentPort() uint16 {
	return c.AgentPort
}

func (c *ControllerConfig) getKubernetesURL() string {
	return fmt.Sprintf("https://kubernetes.%s:%d", *c.ServiceBaseHostname, c.ServicePort)
}

func (c *ControllerConfig) getCommandHostname() string {
	if c.CommandHostname != nil {
		return *c.CommandHostname
	}
	return c.ServerNames[0]
}

func (c *ControllerConfig) getCmdToolHostname() string {
	if c.CmdToolHostname != nil {
		return *c.CmdToolHostname
	}
	return c.ServerNames[0]
}

//
// Dump will display MOST of the controller's configuration.
//
func (c *ControllerConfig) Dump() {
	log.Println("ControllerConfig:")
	log.Printf("ServerNames: %v", config.ServerNames)
	log.Printf("Kubernetes API URL returned for kubectl components: %s", c.getKubernetesURL())
	log.Printf("Agent hostname: %s, port %d", c.getAgentHostname(), c.getAgentPort())
	log.Printf("Command Hostname: %s, port %d", c.getCommandHostname(), c.CommandPort)
	log.Printf("CmdTool Hostname: %s, port %d", c.getCmdToolHostname(), c.CmdToolPort)
}
