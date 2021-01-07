package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/opsmx/grpc-bidir/tunnel"
)

type Agents struct {
	sync.RWMutex
	m map[endpoint][]*agentState
}

type httpMessage struct {
	out chan *tunnel.ASEventWrapper
	cmd *tunnel.HttpRequest
}

type cancelRequest struct {
	id string
}

type agentState struct {
	ep              endpoint
	session         string
	inHTTPRequest   chan *httpMessage
	inCancelRequest chan *cancelRequest
	connectedAt     uint64
	lastPing        uint64
	lastUse         uint64
}

func (s *agentState) String() string {
	return fmt.Sprintf("(%s, %s, %s)", s.ep.name, s.ep.protocol, s.session)
}

type endpoint struct {
	name     string // The agent name
	protocol string // "kubernetes" or whatever API we are handling
}

func MakeAgents() *Agents {
	return &Agents{
		m: make(map[endpoint][]*agentState),
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
	agentList, ok := agents.m[state.ep]
	if !ok {
		agentList = make([]*agentState, 0)
	}
	agentList = append(agentList, state)
	agents.m[state.ep] = agentList
	log.Printf("Agent %s added, now at %d endpoints", state, len(agentList))
	connectedAgentsGauge.WithLabelValues(state.ep.name, state.ep.protocol).Inc()
}

func (a *Agents) RemoveAgent(state *agentState) {
	agents.Lock()
	defer agents.Unlock()
	agentList, ok := agents.m[state.ep]
	if !ok {
		log.Printf("Attempt to remove unknown agent %s", state)
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
		agents.m[state.ep] = agentList
		connectedAgentsGauge.WithLabelValues(state.ep.name, state.ep.protocol).Dec()
	} else {
		log.Printf("Attempt to remove unknown agent %s", state)
	}
	log.Printf("Agent %s removed, now at %d endpoints", state, len(agentList))
}

func (a *Agents) SendToAgent(ep endpoint, message *httpMessage) *agentState {
	agents.RLock()
	defer agents.RUnlock()
	agentList, ok := agents.m[ep]
	if !ok || len(agentList) == 0 {
		log.Printf("No agents connected for: %s", ep)
		return nil
	}
	agent := agentList[rnd.Intn(len(agentList))]
	agent.inHTTPRequest <- message
	return agent
}
