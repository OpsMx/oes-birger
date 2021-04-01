package agent

import (
	"log"
	rnd "math/rand"
	"sync"

	"github.com/opsmx/oes-birger/pkg/tunnel"
)

var (
	agents *ConnectedAgents = MakeAgents()
)

//
// Agent is a thing that looks like a connected agent, either directly connected or
// through another controller.
//
type Agent interface {
	Send(interface{}) string
	Cancel(string)

	GetStatistics() interface{}
}

type Endpoint struct {
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	Configured bool   `json:"configured,omitempty"`
}

//
// ConnectedAgents holds a list of all currently connected or known agents
//
type ConnectedAgents struct {
	sync.RWMutex
	m map[string][]Agent
}

type HTTPMessage struct {
	Out chan *tunnel.AgentToControllerWrapper
	Cmd *tunnel.HttpRequest
}

//
// DirectlyConnectedAgentStatistics describes statistics for a directly connected agent.
//
type DirectlyConnectedAgentStatistics struct {
	Identity       string `json:"identity"`
	Session        string `json:"session"`
	ConnectedAt    uint64 `json:"connectedAt"`
	LastPing       uint64 `json:"lastPing"`
	LastUse        uint64 `json:"lastUse"`
	ConnectionType string `json:"connectionType"`
}

//
// GetStatistics returns statistics for all agents currently connected.
// The statistics returned is an opaque object, intended to be rendered to JSON or some
// other output format using a system that uses introspection.
//
func (s *ConnectedAgents) GetStatistics() interface{} {
	ret := make([]interface{}, 0)
	s.RLock()
	defer s.RUnlock()
	for _, agentList := range s.m {
		for _, agent := range agentList {
			ret = append(ret, agent.GetStatistics())
		}
	}
	return ret
}

func GetStatistics() interface{} {
	return agents.GetStatistics()
}

//
// MakeAgents returns a new agent object which will manage (safely) agents
// connected directly or indirectly.
//
func MakeAgents() *ConnectedAgents {
	return &ConnectedAgents{
		m: make(map[string][]Agent),
	}
}

func sliceIndex(limit int, predicate func(i int) bool) int {
	for i := 0; i < limit; i++ {
		if predicate(i) {
			return i
		}
	}
	return -1
}

//
// AddAgent will add a bew agent to our list.
//
func (s *ConnectedAgents) AddAgent(state *AgentState) {
	s.Lock()
	defer s.Unlock()
	agentList, ok := s.m[state.Identity]
	if !ok {
		agentList = make([]Agent, 0)
	}
	agentList = append(agentList, state)
	s.m[state.Identity] = agentList
	log.Printf("Agent %s added, now at %d endpoints", state, len(agentList))
	connectedAgentsGauge.WithLabelValues(state.Identity).Inc()
}

//
// RemoveAgent will remove an agent and signal to it that closing down is started.
//
func (s *ConnectedAgents) RemoveAgent(state *AgentState) {
	s.Lock()
	defer s.Unlock()

	close(state.InRequest)
	close(state.InCancelRequest)

	agentList, ok := s.m[state.Identity]
	if !ok {
		// This should not be possible.
		log.Printf("RemoveAgent: No agents known by the name of %s", state)
		return
	}

	// TODO: We should always find our entry...
	i := sliceIndex(len(agentList), func(i int) bool { return agentList[i] == state })
	if i == -1 {
		log.Printf("Attempt to remove unknown agent %s", state)
		return
	}
	agentList[i] = agentList[len(agentList)-1]
	agentList[len(agentList)-1] = nil
	agentList = agentList[:len(agentList)-1]
	s.m[state.Identity] = agentList
	connectedAgentsGauge.WithLabelValues(state.Identity).Dec()
	log.Printf("Agent %s removed, now at %d endpoints", state, len(agentList))
}

//
// SendToAgent will send a new httpMessage to an agent, and return true if an agent
// was found.
//
func (s *ConnectedAgents) Send(ep AgentSearch, message interface{}) (string, bool) {
	s.RLock()
	defer s.RUnlock()
	agentList, ok := s.m[ep.Identity]
	if !ok || len(agentList) == 0 {
		log.Printf("No agents connected for: %s", ep)
		return "", false
	}
	a := agentList[rnd.Intn(len(agentList))]
	session := a.Send(message)
	return session, true
}

//
// Cancel will cancel an ongoing request.
// XXXMLG this is broken...  it needs to send the cancel to the specific agent
// which owns this ID...  not one at random.
//
func (s *ConnectedAgents) Cancel(ep AgentSearch, id string) bool {
	s.RLock()
	defer s.RUnlock()
	agentList, ok := s.m[ep.Identity]
	if !ok || len(agentList) == 0 {
		log.Printf("No agents connected for: %s", ep)
		return false
	}
	agent := agentList[rnd.Intn(len(agentList))]
	agent.Cancel(id)
	return true
}
