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

func (s *AgentState) String() string {
	return fmt.Sprintf("(%s, %s)", s.Identity, s.Session)
}

//
// Send sends a message to a specific Agent
//
func (s *AgentState) Send(message interface{}) string {
	s.InRequest <- message
	return s.Session
}

//
// SendCancel canceles a specific stream
//
func (s *AgentState) Cancel(id string) {
	s.InCancelRequest <- id
}

//
// Get statistics for this agent
//
func (s *AgentState) GetStatistics() interface{} {
	return &DirectlyConnectedAgentStatistics{
		Identity:       s.Identity,
		Session:        s.Session,
		ConnectedAt:    s.ConnectedAt,
		LastPing:       s.LastPing,
		LastUse:        s.LastUse,
		ConnectionType: "direct",
	}
}
