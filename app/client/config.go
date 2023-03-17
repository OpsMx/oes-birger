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

package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

const (
	defaultCACertPath     = "/app/config/ca.pem"
	defaultUserconfigPath = "/app/config/services.yaml"
	defaultAuthTokenPath  = "/app/secrets/authtoken"
	defaultDialMaxRetries = 10
	defaultDialRetryTime  = 10
)

// agentConfig holds all the configuration for the agent.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type agentConfig struct {
	ControllerHostname   string `json:"controllerHostname,omitempty" yaml:"controllerHostname,omitempty"`
	CACertFile           string `json:"caCertFile,omitempty" yaml:"caCertFile,omitempty"`
	CACert64             string `json:"caCert64,omitempty" yaml:"caCert64,omitempty"`
	AuthTokenFile        string `json:"authTokenFile,omitempty" yaml:"authTokenFile,omitempty"`
	ServicesConfigFile   string `json:"servicesConfigFile,omitempty" yaml:"servicesConfigFile,omitempty"`
	DialMaxRetries       int    `json:"dialMaxRetries,omitempty" yaml:"dialMaxRetries,omitempty"`
	DialRetryTime        int    `json:"dialRetryTime,omitempty" yaml:"dialRetryTime,omitempty"`
	PrometheusListenPort uint16 `json:"prometheusListenPort,omitempty" yaml:"prometheusListenPort,omitempty"`
}

func (c *agentConfig) applyDefaults() {
	if len(c.ControllerHostname) == 0 {
		c.ControllerHostname = "agent-controller:9001"
	}

	if len(c.CACertFile) == 0 {
		c.CACertFile = defaultCACertPath
	}

	if len(c.AuthTokenFile) == 0 {
		c.AuthTokenFile = defaultAuthTokenPath
	}

	if len(c.ServicesConfigFile) == 0 {
		c.ServicesConfigFile = defaultUserconfigPath
	}

	if c.DialMaxRetries == 0 {
		c.DialMaxRetries = defaultDialMaxRetries
	}

	if c.DialRetryTime == 0 {
		c.DialRetryTime = defaultDialRetryTime
	}

	if c.PrometheusListenPort == 0 {
		c.PrometheusListenPort = 9102
	}
}

// loadConfig will load YAML configuration from the provided filename, and then apply
// environment variables to override some subset of available options.
func loadConfig(filename string) (*agentConfig, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	config := &agentConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}

	config.applyDefaults()

	return config, nil
}
