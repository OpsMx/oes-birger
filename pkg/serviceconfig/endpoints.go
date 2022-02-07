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

package serviceconfig

import (
	"fmt"
	"log"

	"github.com/opsmx/oes-birger/pkg/secrets"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"gopkg.in/yaml.v2"
)

// ConfiguredEndpoint defines an endpoint we have loaded, and have a request processor attached.
type ConfiguredEndpoint struct {
	Name       string   `json:"name,omitempty"`
	Type       string   `json:"type,omitempty"`
	Configured bool     `json:"configured,omitempty"`
	Namespace  []string `json:"namespace,omitempty"`
	AccountID  string   `json:"accountId,omitempty"`
	AssumeRole string   `json:"assumeRole,omitempty"`

	Instance httpRequestProcessor
}

type httpRequestProcessor interface {
	ExecuteHTTPRequest(chan *tunnel.MessageWrapper, *tunnel.OpenHTTPTunnelRequest)
}

func (e *ConfiguredEndpoint) String() string {
	return fmt.Sprintf("(type=%s, name=%s, configured=%v)", e.Type, e.Name, e.Configured)
}

// EndpointsToPB builds the protobuf component of the "hello" message to advertise the
// endpoints we have defined.
func EndpointsToPB(endpoints []ConfiguredEndpoint) []*tunnel.EndpointHealth {
	pbEndpoints := make([]*tunnel.EndpointHealth, len(endpoints))
	for i, ep := range endpoints {
		endp := &tunnel.EndpointHealth{
			Name:       ep.Name,
			Type:       ep.Type,
			Configured: ep.Configured,
			Namespaces: ep.Namespace,
			AccountID:  ep.AccountID,
			AssumeRole: ep.AssumeRole,
		}
		pbEndpoints[i] = endp
	}
	return pbEndpoints
}

// ConfigureEndpoints will load services from the config, attach a processor, and return the configured
// list.
func ConfigureEndpoints(secretsLoader secrets.SecretLoader, serviceConfig *ServiceConfig) []ConfiguredEndpoint {
	// For each service, if it is enabled, find and create an instance.
	endpoints := []ConfiguredEndpoint{}
	for _, service := range serviceConfig.OutgoingServices {
		var instance httpRequestProcessor
		var configured bool

		if service.Enabled {
			config, err := yaml.Marshal(service.Config)
			if err != nil {
				log.Fatal(err)
			}
			switch service.Type {
			case "kubernetes":
				if secretsLoader == nil {
					log.Fatalf("kuberenetes is disabled, but a kubernetes service is configured.")
				}
				instance, configured, err = MakeKubernetesEndpoint(service.Name, config)
			case "aws":
				instance, configured, err = MakeAwsEndpoint(service.Name, config, secretsLoader)
			default:
				instance, configured, err = MakeGenericEndpoint(service.Type, service.Name, config, secretsLoader)
			}

			// If the instance-specific make method returns an error, catch it here.
			if err != nil {
				log.Fatal(err)
			}

			if len(service.Namespaces) == 0 {
				// If it did not return an error, a nil instance means it is not fully configured.
				log.Printf("Adding endpoint type %s, name %s, configured %v", service.Type, service.Name, configured)
				endpoints = append(endpoints, ConfiguredEndpoint{
					Type:       service.Type,
					Name:       service.Name,
					Configured: configured,
					Instance:   instance,
					AccountID:  service.AccountID,
					AssumeRole: service.AssumeRole,
				})
			} else {
				for _, ns := range service.Namespaces {
					log.Printf("Adding endpoint type %s, name %s, configured %v, namespaces %v", service.Type, ns.Name, configured, ns.Namespaces)
					newep := ConfiguredEndpoint{
						Type:       service.Type,
						Name:       ns.Name,
						Configured: configured,
						Instance:   instance,
						Namespace:  ns.Namespaces,
					}
					endpoints = append(endpoints, newep)
				}
			}
		}
	}
	return endpoints
}
