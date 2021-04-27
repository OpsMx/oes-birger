package agent

import (
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

var (
	rnd = rand.New(rand.NewSource(time.Now().UnixNano())) // not used for crypto
)

type AgentStatistics struct {
	Name           string     `json:"name,omitempty"`
	Session        string     `json:"session,omitempty"`
	ConnectionType string     `json:"connectionType,omitempty"`
	Endpoints      []Endpoint `json:"endpoints,omitempty"`
	Version        string     `json:"version,omitempty"`
	Hostname       string     `json:"hostname,omitempty"`
}

//
// Agent is a thing that looks like a connected agent, either directly connected or
// through another controller.
//
type Agent interface {
	Close()
	Send(interface{}) string
	Cancel(string)
	HasEndpoint(string, string) bool
	GetSession() string
	GetName() string
	GetEndpoints() []Endpoint

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
// AddAgent will add a new agent to our list.
//
func (s *ConnectedAgents) AddAgent(state Agent) {
	s.Lock()
	defer s.Unlock()
	agentList, ok := s.m[state.GetName()]
	if !ok {
		agentList = make([]Agent, 0)
	}
	agentList = append(agentList, state)
	s.m[state.GetName()] = agentList
	log.Printf("Agent %s added, now at %d paths, %d endpoints", state, len(agentList), len(state.GetEndpoints()))
	for _, endpoint := range state.GetEndpoints() {
		log.Printf("  agent %s, endpoint: %s", state, &endpoint)
	}
	connectedAgentsGauge.WithLabelValues(state.GetName()).Inc()
}

//
// RemoveAgent will remove an agent and signal to it that closing down is started.
//
func (s *ConnectedAgents) RemoveAgent(state Agent) error {
	s.Lock()
	defer s.Unlock()

	state.Close()

	agentList, ok := s.m[state.GetName()]
	if !ok {
		// This should not be possible.
		err := fmt.Errorf("no agents known by the name of %s", state)
		log.Printf("%v", err)
		return err
	}

	// TODO: We should always find our entry...
	i := sliceIndex(len(agentList), func(i int) bool { return agentList[i] == state })
	if i == -1 {
		err := fmt.Errorf("attempt to remove unknown agent %s", state)
		log.Printf("%v", err)
		return err
	}
	agentList[i] = agentList[len(agentList)-1]
	agentList[len(agentList)-1] = nil
	agentList = agentList[:len(agentList)-1]
	s.m[state.GetName()] = agentList
	connectedAgentsGauge.WithLabelValues(state.GetName()).Dec()
	log.Printf("agent %s removed, now at %d paths", state, len(agentList))
	return nil
}

func (s *ConnectedAgents) findService(ep AgentSearch) (Agent, error) {
	agentList, ok := s.m[ep.Name]
	if !ok || len(agentList) == 0 {
		return nil, fmt.Errorf("no agents connected for %s", ep)
	}
	possibleAgents := []int{}
	for i, a := range agentList {
		if a.HasEndpoint(ep.EndpointType, ep.EndpointName) {
			possibleAgents = append(possibleAgents, i)
		}
	}
	if len(possibleAgents) == 0 {
		return nil, fmt.Errorf("request for %s, no such path exists or all are unconfigured", ep)
	}
	selected := possibleAgents[rnd.Intn(len(possibleAgents))]
	return agentList[selected], nil
}

//
// Send will search for the specific agent and endpoint. send a message to an agent, and return true if an agent
// was found.
//
func (s *ConnectedAgents) Send(ep AgentSearch, message interface{}) (string, bool) {
	s.RLock()
	defer s.RUnlock()
	agent, err := s.findService(ep)
	if err != nil {
		log.Printf("%v", err)
		return "", false
	}
	session := agent.Send(message)
	return session, true
}

//
// Cancel will cancel an ongoing request.
//
func (s *ConnectedAgents) Cancel(ep AgentSearch, id string) error {
	// The session must be set, if not this is an error.
	if len(ep.Session) == 0 {
		return fmt.Errorf("session is not set (coding error)")
	}

	s.RLock()
	defer s.RUnlock()
	agentList, ok := s.m[ep.Name]
	if !ok || len(agentList) == 0 {
		return fmt.Errorf("no agents connected for: %s (likely coding error)", ep)
	}

	for _, a := range agentList {
		if ep.MatchesAgent(a) {
			a.Cancel(id)
			return nil
		}
	}

	return fmt.Errorf("no agents with specific session exist for %s (likely coding error)", ep)
}
