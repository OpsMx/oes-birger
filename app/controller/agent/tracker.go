package agent

import (
	"log"
	"math/rand"
	"sync"
	"time"
)

var (
	rnd = rand.New(rand.NewSource(time.Now().UnixNano())) // not used for crypto
)

//
// Agent is a thing that looks like a connected agent, either directly connected or
// through another controller.
//
type Agent interface {
	Send(interface{}) string
	Cancel(string)
	HasEndpoint(string, string) bool
	GetSession() string

	GetStatistics() interface{}
}

//
// ConnectedAgents holds a list of all currently connected or known agents
//
type ConnectedAgents struct {
	sync.RWMutex
	m map[string][]Agent
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
	log.Printf("Agent %s added, now at %d paths, %d endpoints", state, len(agentList), len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		log.Printf("  agent %s, endpoint: %s", state, &endpoint)
	}
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
	log.Printf("Agent %s removed, now at %d paths", state, len(agentList))
}

//
// Send will search for the specific agent and endpoint. send a message to an agent, and return true if an agent
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
	possibleAgents := []int{}
	for i, a := range agentList {
		if a.HasEndpoint(ep.EndpointType, ep.EndpointName) {
			possibleAgents = append(possibleAgents, i)
		}
	}
	if len(possibleAgents) == 0 {
		log.Printf("Request for %s, no such path exists or all are unconfigured.", ep)
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
	// The session must be set, if not this is an error.
	if len(ep.Session) == 0 {
		log.Printf("ERROR: session is not set.  Coding error.")
		return false
	}

	s.RLock()
	defer s.RUnlock()
	agentList, ok := s.m[ep.Identity]
	if !ok || len(agentList) == 0 {
		log.Printf("ERROR: No agents connected for: %s.  Likely coding error.", ep)
		return false
	}

	for _, a := range agentList {
		if a.GetSession() == ep.Session {
			a.Cancel(id)
			return true
		}
	}

	log.Printf("ERROR: No agents with specific session exist for %s.  Likely coding error.", ep)
	return false
}
