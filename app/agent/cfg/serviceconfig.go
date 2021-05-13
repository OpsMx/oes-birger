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

//
// Package cfg handles the top level agent configuration YAML handling.
//
// The service-level "Config" element is handled by the Make() methods on
// each service endpoint type.
//
package cfg

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
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
// ServiceConfig holds configuration for a service, like a Jenkins endpoint.
//
type ServiceConfig struct {
	Enabled    bool                        `yaml:"enabled"`
	Name       string                      `yaml:"name"`
	Type       string                      `yaml:"type"`
	Config     map[interface{}]interface{} `yaml:"config,omitempty"`
	Namespaces []serviceNamespace          `yaml:"namespaces,omitempty"`
}

type serviceNamespace struct {
	Name       string   `yaml:"name"`
	Namespaces []string `yaml:"namespaces"`
}

// AgentServiceConfig defines a service level configuration top-level list.
type AgentServiceConfig struct {
	Commands []CommandConfig `yaml:"commands,omitempty"`
	Services []ServiceConfig `yaml:"services,omitempty"`
}

// LoadServiceConfig loads a service configuration YAML file.
func LoadServiceConfig(filename string) (*AgentServiceConfig, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	config := &AgentServiceConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
