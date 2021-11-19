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
// Package agent implements a directly-connected agent.  This is where the GRPC
// connection is terminated inside this controller.
//
package agent

import "fmt"

// DirectlyConnectedAgent holds all the magic needed to implement a directly connected agent.
type DirectlyConnectedAgent struct {
	Name            string
	Session         string
	Endpoints       []Endpoint
	Version         string
	Hostname        string
	InRequest       chan interface{}
	InCancelRequest chan string
	ConnectedAt     uint64
	LastPing        uint64
	LastUse         uint64
}

// GetSession returns the randomly assigned session ID.  This is assigned each time
// an agent connects, and allows routing of cancellation and other messages to the
// correct instance of an agent.
func (s *DirectlyConnectedAgent) GetSession() string {
	return s.Session
}

// GetName returns the agent name.
func (s *DirectlyConnectedAgent) GetName() string {
	return s.Name
}

// GetEndpoints returns the list of endpoints.
func (s *DirectlyConnectedAgent) GetEndpoints() []Endpoint {
	return s.Endpoints
}

func (s DirectlyConnectedAgent) String() string {
	return fmt.Sprintf("(name=%s, session=%s)", s.Name, s.Session)
}

// Close will shut down an agent's requests channels.
func (s *DirectlyConnectedAgent) Close() {
	close(s.InRequest)
	close(s.InCancelRequest)
}

//
// Send sends a message to a specific Agent
//
func (s *DirectlyConnectedAgent) Send(message interface{}) string {
	s.InRequest <- message
	return s.Session
}

//
// Cancel cancels a specific stream
//
func (s *DirectlyConnectedAgent) Cancel(id string) {
	s.InCancelRequest <- id
}

//
// HasEndpoint returns true if the endpoint is presend and configured.
//
func (s *DirectlyConnectedAgent) HasEndpoint(endpointType string, endpointName string) bool {
	for _, ep := range s.Endpoints {
		if ep.Type == endpointType && ep.Name == endpointName {
			return ep.Configured
		}
	}
	return false
}

//
// DirectlyConnectedAgentStatistics describes statistics for a directly connected agent.
//
type DirectlyConnectedAgentStatistics struct {
	BaseStatistics
	ConnectedAt uint64 `json:"connectedAt"`
	LastPing    uint64 `json:"lastPing"`
	LastUse     uint64 `json:"lastUse"`
}

//
// GetStatistics returns a set of stats for connected agents.
//
func (s *DirectlyConnectedAgent) GetStatistics() interface{} {
	ret := &DirectlyConnectedAgentStatistics{
		ConnectedAt: s.ConnectedAt,
		LastPing:    s.LastPing,
		LastUse:     s.LastUse,
	}
	ret.Name = s.Name
	ret.Session = s.Session
	ret.ConnectionType = "direct"
	ret.Endpoints = s.Endpoints
	ret.Version = s.Version
	ret.Hostname = s.Hostname
	return ret
}
