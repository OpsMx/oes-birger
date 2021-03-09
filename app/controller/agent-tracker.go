package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/opsmx/oes-birger/pkg/tunnel"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	connectedAgentsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agents_connected",
		Help: "The currently connected agents",
	}, []string{"agent"})
)

//
// Agent is a thing that looks like a connected agent, either directly connected or
// through another controller.
//
type Agent interface {
	Send(interface{})
	CancelRequest(*cancelRequest)

	Endpoint() endpoint
	Session() string
	ConnectedAt() uint64
	LastPing() uint64
	LastUse() uint64
	GetStatistics() interface{}
}

//
// AgentNameList holds a list of all currently known agents
//
type AgentNameList struct {
	sync.RWMutex
	m map[string][]Agent
}

type httpMessage struct {
	out chan *tunnel.AgentToControllerWrapper
	cmd *tunnel.HttpRequest
}

type cancelRequest struct {
	id string
}

type agentState struct {
	ep              endpoint
	session         string
	inRequest       chan interface{}
	inCancelRequest chan *cancelRequest
	connectedAt     uint64
	lastPing        uint64
	lastUse         uint64
}

//
// DirectlyConnectedAgentStatistics describes statistics for a directly connected agent.
//
type DirectlyConnectedAgentStatistics struct {
	Identity       string   `json:"identity"`
	Protocols      []string `json:"protocols"`
	Session        string   `json:"session"`
	ConnectedAt    uint64   `json:"connectedAt"`
	LastPing       uint64   `json:"lastPing"`
	LastUse        uint64   `json:"lastUse"`
	ConnectionType string   `json:"connectionType"`
}

//
// GetStatistics returns statistics for all agents currently connected.
// The statistics returned is an opaque object, intended to be rendered to JSON or some
// other output format using a system that uses introspection.
//
func (s *AgentNameList) GetStatistics() interface{} {
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

func (s *agentState) Endpoint() endpoint {
	return s.ep
}

func (s *agentState) Session() string {
	return s.session
}

func (s *agentState) ConnectedAt() uint64 {
	return s.connectedAt
}

func (s *agentState) LastPing() uint64 {
	return s.lastPing
}

func (s *agentState) LastUse() uint64 {
	return s.lastUse
}

func (s *agentState) String() string {
	return fmt.Sprintf("(%s, [%v], %s)", s.ep.name, s.ep.protocols, s.session)
}

type endpoint struct {
	name      string   // The agent name
	protocols []string // "kubernetes", "remote-command", etc.
}

//
// MakeAgents returns a new agent object which will manage (safely) agents
// connected directly or indirectly.
//
func MakeAgents() *AgentNameList {
	return &AgentNameList{
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
func (s *AgentNameList) AddAgent(state *agentState) {
	s.Lock()
	defer s.Unlock()
	agentList, ok := s.m[state.ep.name]
	if !ok {
		agentList = make([]Agent, 0)
	}
	agentList = append(agentList, state)
	s.m[state.ep.name] = agentList
	log.Printf("Agent %s added, now at %d endpoints", state, len(agentList))
	connectedAgentsGauge.WithLabelValues(state.ep.name).Inc()
}

//
// RemoveAgent will remove an agent and signal to it that closing down is started.
//
func (s *AgentNameList) RemoveAgent(state *agentState) {
	s.Lock()
	defer s.Unlock()
	agentList, ok := s.m[state.ep.name]
	if !ok {
		log.Printf("RemoveAgent: No agents known by the name of %s", state)
		return
	}

	close(state.inRequest)
	close(state.inCancelRequest)

	// TODO: We should always find our entry...
	i := sliceIndex(len(agentList), func(i int) bool { return agentList[i] == state })
	if i != -1 {
		agentList[i] = agentList[len(agentList)-1]
		agentList[len(agentList)-1] = nil
		agentList = agentList[:len(agentList)-1]
		s.m[state.ep.name] = agentList
		connectedAgentsGauge.WithLabelValues(state.ep.name).Dec()
	} else {
		log.Printf("Attempt to remove unknown agent %s", state)
	}
	log.Printf("Agent %s removed, now at %d endpoints", state, len(agentList))
}

//
// SendToAgent will send a new httpMessage to an agent, and return true if an agent
// was found.
//
func (s *AgentNameList) SendToAgent(ep endpoint, message interface{}) bool {
	s.RLock()
	defer s.RUnlock()
	agentList, ok := s.m[ep.name]
	if !ok || len(agentList) == 0 {
		log.Printf("No agents connected for: %s", ep)
		return false
	}
	agent := agentList[rnd.Intn(len(agentList))]
	agent.Send(message)
	return true
}

//
// CancelRequest will cancel an ongoing request.
//
func (s *AgentNameList) CancelRequest(ep endpoint, message *cancelRequest) bool {
	s.RLock()
	defer s.RUnlock()
	agentList, ok := s.m[ep.name]
	if !ok || len(agentList) == 0 {
		log.Printf("No agents connected for: %s", ep)
		return false
	}
	agent := agentList[rnd.Intn(len(agentList))]
	agent.CancelRequest(message)
	return true
}

//
// Send sends a message to a specific Agent
//
func (s *agentState) Send(message interface{}) {
	s.inRequest <- message
}

//
// CancelRequest canceles a specific stream
//
func (s *agentState) CancelRequest(message *cancelRequest) {
	s.inCancelRequest <- message
}

//
// Get statistics for this agent
//
func (s *agentState) GetStatistics() interface{} {
	return &DirectlyConnectedAgentStatistics{
		Identity:       s.ep.name,
		Protocols:      s.ep.protocols,
		Session:        s.session,
		ConnectedAt:    s.connectedAt,
		LastPing:       s.lastPing,
		LastUse:        s.lastUse,
		ConnectionType: "direct",
	}
}
