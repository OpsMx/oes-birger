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

// Package serviceconfig handles the top level agent configuration YAML handling.
//
// The service-level "Config" element is handled by the Make() methods on
// each service endpoint type.
package serviceconfig

import (
	"os"

	"gopkg.in/yaml.v3"
)

// IncomingServiceConfig defines an incoming service port, where we may specify
// "http" or "auto" for the service type, and lock the destination down to a
// specific outgoing service on a specific agent.  If not specified, the
// type, destination, service will be detected based on credentials provided.
type IncomingServiceConfig struct {
	Name               string `yaml:"name,omitempty"`
	Port               uint16 `yaml:"port,omitempty"`
	UseHTTP            bool   `yaml:"useHTTP,omitempty"`
	ServiceType        string `yaml:"serviceType,omitempty"`
	Destination        string `yaml:"destination,omitempty"`
	DestinationService string `yaml:"destinationService,omitempty"`
}

// OutgoingServiceConfig defines a way to reach out to another service, such as Jenkins.
type OutgoingServiceConfig struct {
	Enabled     bool                        `yaml:"enabled"`
	Name        string                      `yaml:"name"`
	Type        string                      `yaml:"type"`
	Config      map[interface{}]interface{} `yaml:"config,omitempty"`
	Annotations map[string]string           `yaml:"annotations,omitempty"`
	Namespaces  []serviceNamespace          `yaml:"namespaces,omitempty"`
	AccountID   string                      `yaml:"accountId,omitempty"`
	AssumeRole  string                      `yaml:"assumeRole,omitempty"`
}

type serviceNamespace struct {
	Name       string   `yaml:"name"`
	Namespaces []string `yaml:"namespaces"`
}

// ServiceConfig defines a service level configuration top-level list.
type ServiceConfig struct {
	OutgoingServices []OutgoingServiceConfig `yaml:"outgoingServices,omitempty"`
	IncomingServices []IncomingServiceConfig `yaml:"incomingServices,omitempty"`
}

// LoadServiceConfig loads a service configuration YAML file.
func LoadServiceConfig(filename string) (*ServiceConfig, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	config := &ServiceConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
