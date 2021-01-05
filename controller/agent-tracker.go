package main

import (
	"log"
	"sync"

	"github.com/opsmx/grpc-bidir/tunnel"
)

type Agents struct {
	sync.RWMutex
	m map[string][]*agentState
}

type httpMessage struct {
	out chan *tunnel.ASEventWrapper
	cmd *tunnel.HttpRequest
}

type cancelRequest struct {
	id string
}

type agentState struct {
	identity        string
	sessionIdentity string
	inHTTPRequest   chan *httpMessage
	inCancelRequest chan *cancelRequest
	connectedAt     uint64
	lastPing        uint64
	lastUse         uint64
}

func MakeAgents() *Agents {
	return &Agents{
		m: make(map[string][]*agentState),
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

func (a *Agents) AddAgent(state *agentState) {
	agents.Lock()
	defer agents.Unlock()
	agentList, ok := agents.m[state.identity]
	if !ok {
		log.Printf("No previous agent for id %s found, creating a new list", state.identity)
		agentList = make([]*agentState, 0)
	}
	agentList = append(agentList, state)
	agents.m[state.identity] = agentList
	log.Printf("Session %s added for agent %s, now at %d endpoints", state.sessionIdentity, state.identity, len(agentList))
	connectedAgentsGauge.WithLabelValues(state.identity).Inc()
}

func (a *Agents) RemoveAgent(state *agentState) {
	agents.Lock()
	defer agents.Unlock()
	agentList, ok := agents.m[state.identity]
	if !ok {
		log.Printf("ERROR: removing unknown agent: (%s, %s)", state.identity, state.sessionIdentity)
		return
	}

	close(state.inHTTPRequest)
	close(state.inCancelRequest)

	// TODO: We should always find our entry...
	i := sliceIndex(len(agentList), func(i int) bool { return agentList[i] == state })
	if i != -1 {
		agentList[i] = agentList[len(agentList)-1]
		agentList[len(agentList)-1] = nil
		agentList = agentList[:len(agentList)-1]
		agents.m[state.identity] = agentList
		connectedAgentsGauge.WithLabelValues(state.identity).Dec()
	} else {
		log.Printf("Agent session %s not found in list of agents for %s", state.sessionIdentity, state.identity)
	}
	log.Printf("Session %s removed for agent %s, now at %d endpoints", state.sessionIdentity, state.identity, len(agentList))
}
