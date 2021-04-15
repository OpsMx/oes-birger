package agent

import "fmt"

type AgentState struct {
	Identity        string
	Session         string
	Endpoints       []Endpoint
	InRequest       chan interface{}
	InCancelRequest chan string
	ConnectedAt     uint64
	LastPing        uint64
	LastUse         uint64
}

func (s *AgentState) GetSession() string {
	return s.Session
}

func (s *AgentState) GetIdentity() string {
	return s.Identity
}

func (s *AgentState) GetEndpoints() []Endpoint {
	return s.Endpoints
}

func (s AgentState) String() string {
	return fmt.Sprintf("(identity=%s, session=%s)", s.Identity, s.Session)
}

func (s *AgentState) Close() {
	close(s.InRequest)
	close(s.InCancelRequest)
}

//
// Send sends a message to a specific Agent
//
func (s *AgentState) Send(message interface{}) string {
	s.InRequest <- message
	return s.Session
}

//
// Cancel cancels a specific stream
//
func (s *AgentState) Cancel(id string) {
	s.InCancelRequest <- id
}

//
// HasEndpoint returns true if the endpoint is presend and configured.
//
func (s *AgentState) HasEndpoint(endpointType string, endpointName string) bool {
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
	AgentStatistics
	ConnectedAt uint64 `json:"connectedAt"`
	LastPing    uint64 `json:"lastPing"`
	LastUse     uint64 `json:"lastUse"`
}

//
// Get statistics for this agent
//
func (s *AgentState) GetStatistics() interface{} {
	ret := &DirectlyConnectedAgentStatistics{
		ConnectedAt: s.ConnectedAt,
		LastPing:    s.LastPing,
		LastUse:     s.LastUse,
	}
	ret.Identity = s.Identity
	ret.Session = s.Session
	ret.ConnectionType = "direct"
	ret.Endpoints = s.Endpoints
	return ret
}
