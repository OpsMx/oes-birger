package main

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

import (
	"fmt"
	"io"
	"os"
	"path"

	"github.com/opsmx/oes-birger/internal/serviceconfig"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ControllerConfig holds all the configuration for the controller.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type ControllerConfig struct {
	Agents               map[string]*agentConfig     `yaml:"agents,omitempty" json:"agents,omitempty"`
	ServiceAuth          serviceAuthConfig           `yaml:"serviceAuth,omitempty" json:"serviceAuth,omitempty"`
	AgentAuth            agentAuthConfig             `yaml:"agentAuth,omitempty" json:"agentAuth,omitempty"`
	Webhook              string                      `yaml:"webhook,omitempty" json:"webhook,omitempty"`
	PrometheusListenPort uint16                      `yaml:"prometheusListenPort,omitempty" json:"prometheusListenPort,omitempty"`
	ServiceHostname      *string                     `yaml:"serviceHostname,omitempty" json:"serviceHostname,omitempty"`
	ServiceListenPort    uint16                      `yaml:"serviceListenPort,omitempty" json:"serviceListenPort,omitempty"`
	ServiceTLSPath       string                      `json:"serviceTLSPath,omitempty" yaml:"serviceTLSPath,omitempty"`
	ControlHostname      *string                     `yaml:"controlHostname,omitempty" json:"controlHostname,omitempty"`
	ControlListenPort    uint16                      `yaml:"controlListenPort,omitempty" json:"controlListenPort,omitempty"`
	ControlTLSPath       string                      `json:"controlTLSPath,omitempty" yaml:"controlTLSPath,omitempty"`
	AgentHostname        *string                     `yaml:"agentHostname,omitempty" json:"agentHostname,omitempty"`
	AgentListenPort      uint16                      `yaml:"agentListenPort,omitempty" json:"agentListenPort,omitempty"`
	AgentTLSPath         string                      `json:"agentTLSPath,omitempty" yaml:"agentTLSPath,omitempty"`
	AgentAdvertisePort   uint16                      `yaml:"agentAdvertisePort,omitempty" json:"agentAdvertisePort,omitempty"`
	AgentUseTLS          bool                        `yaml:"agentUseTLS,omitempty" json:"agentUseTLS,omitempty"`
	ServiceConfig        serviceconfig.ServiceConfig `yaml:"services,omitempty" json:"serviceConfig,omitempty"`
}

type agentConfig struct {
	Name string `yaml:"name,omitempty"`
}

type serviceAuthConfig struct {
	CurrentKeyName        string `yaml:"currentKeyName,omitempty"`
	HeaderMutationKeyName string `yaml:"headerMutationKeyName,omitempty"`
	SecretsPath           string `yaml:"secretsPath,omitempty"`
}

type agentAuthConfig struct {
	CurrentKeyName string `yaml:"currentKeyName,omitempty"`
	SecretsPath    string `yaml:"secretsPath,omitempty"`
}

// Simplistic check to ensure the two files we need exist.  We should likely also
// check that they are readable, but we will just fail later if needed.  These
// could be links, so don't assume regular files.
func checkTLSPath(p string) bool {
	if _, err := os.Stat(path.Join(p, "tls.crt")); err != nil {
		return false
	}
	if _, err := os.Stat(path.Join(p, "tls.key")); err != nil {
		return false
	}
	return true
}

// LoadConfig will load YAML configuration from the provided filename,
// and then apply environment variables to override some subset of
// available options.
func LoadConfig(f io.Reader) (*ControllerConfig, error) {
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	config := &ControllerConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}

	if config.AgentListenPort == 0 {
		config.AgentListenPort = 9001
	}
	if config.AgentAdvertisePort == 0 {
		config.AgentAdvertisePort = config.AgentListenPort
	}
	if config.AgentHostname == nil {
		return nil, fmt.Errorf("agentHostname not set")
	}

	if config.ServiceListenPort == 0 {
		config.ServiceListenPort = 9002
	}
	if config.ServiceHostname == nil {
		return nil, fmt.Errorf("serviceHostname not set")
	}

	if config.ControlListenPort == 0 {
		config.ControlListenPort = 9003
	}
	if config.ControlHostname == nil {
		return nil, fmt.Errorf("controlHostname not set")
	}

	if config.PrometheusListenPort == 0 {
		config.PrometheusListenPort = 9102
	}

	if len(config.ServiceAuth.SecretsPath) == 0 {
		config.ServiceAuth.SecretsPath = "/app/secrets/serviceAuth"
	}

	if len(config.AgentAuth.SecretsPath) == 0 {
		config.AgentAuth.SecretsPath = "/app/secrets/agentAuth"
	}

	// TLS setup
	if config.AgentTLSPath != "" {
		if found := checkTLSPath(config.AgentTLSPath); !found {
			return nil, fmt.Errorf("agentTLSPath doesn't seem to be a directory that contains tls.crt and tls.key")
		}
	}
	if config.ControlTLSPath != "" {
		if found := checkTLSPath(config.ControlTLSPath); !found {
			return nil, fmt.Errorf("controlTLSPath doesn't seem to be a directory that contains tls.crt and tls.key")
		}
	}
	if config.ServiceTLSPath != "" {
		if found := checkTLSPath(config.ServiceTLSPath); !found {
			return nil, fmt.Errorf("serviceTLSPath doesn't seem to be a directory that contains tls.crt and tls.key")
		}
	}

	return config, nil
}

// GetServiceURL returns a fullly formatted URL string with hostname and port.
func (c *ControllerConfig) GetServiceURL() string {
	scheme := "https"
	if c.ServiceTLSPath == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, *c.ServiceHostname, c.ServiceListenPort)
}

// GetControlURL returns a fullly formatted URL string with hostname and port.
func (c *ControllerConfig) GetControlURL() string {
	scheme := "https"
	if c.ControlTLSPath == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, *c.ControlHostname, c.ControlListenPort)
}

// GetAgentAdvertisePort returns the port the CNC server will use to advertise agent
// connections in manifests.
func (c *ControllerConfig) GetAgentAdvertisePort() uint16 {
	return c.AgentAdvertisePort
}

// GetAgentHostname is the hostname used in CNC manifests for agents.
func (c *ControllerConfig) GetAgentHostname() string {
	return *c.AgentHostname
}

// GetControlListenPort returns the port the CNC server should listen on.
func (c *ControllerConfig) GetControlListenPort() uint16 {
	return c.ControlListenPort
}

// Dump will display MOST of the controller's configuration.
func (c *ControllerConfig) Dump(logger *zap.SugaredLogger) {
	logger.Infow("Service config", "hostname", *c.ServiceHostname, "port", c.ServiceListenPort)
	logger.Infow("URL returned for kubectl components", "url", c.GetServiceURL())
	logger.Infow("Agent config", "hostname", *c.AgentHostname, "port", c.AgentListenPort, "advertisedPort", c.AgentAdvertisePort)
	logger.Infow("Control config", "hostname", *c.ControlHostname, "port", c.ControlListenPort)
}

func parseConfig(filename string) (*ControllerConfig, error) {
	f, err := os.Open(*configFile)
	if err != nil {
		return nil, fmt.Errorf("while opening configfile: %w", err)
	}

	c, err := LoadConfig(f)
	if err != nil {
		return nil, fmt.Errorf("while loading config: %w", err)
	}

	return c, nil
}
