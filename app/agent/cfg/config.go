package cfg

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
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_CERT_PATH       = "/app/secrets/agent/tls.crt"
	DEFAULT_KEY_PATH        = "/app/secrets/agent/tls.key"
	DEFAULT_USERCONFIG_PATH = "/app/config/services.yaml"
)

// AgentConfig holds all the configuration for the agent.  The
// configuration file is loaded from disk first, and then any
// environment variables are applied.
type AgentConfig struct {
	ControllerHostname string  `yaml:"controllerHostname,omitempty"`
	CACert64           *string `yaml:"caCert64,omitempty"`
	CertFile           string  `yaml:"certFile,omitempty"`
	KeyFile            string  `yaml:"keyFile,omitempty"`
	ServicesConfigPath string  `yaml:"servicesConfigPath,omitempty"`
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

	if len(c.ServicesConfigPath) == 0 {
		c.ServicesConfigPath = DEFAULT_USERCONFIG_PATH
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
