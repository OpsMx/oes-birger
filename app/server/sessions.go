/*
 * Copyright 2023 OpsMx, Inc.
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

package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opsmx/oes-birger/internal/logging"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
	"go.uber.org/zap"
)

type AgentContext struct {
	AgentKey
	ConfiguredEndpoints []serviceconfig.Endpoint `json:"endpoints,omitempty"`
	AgentInfo           *pb.AgentInfo            `json:"agentInfo,omitempty"`
	Version             string                   `json:"version,omitempty"`
	Hostname            string                   `json:"hostname,omitempty"`
	ConnectedAt         int64                    `json:"connectedAt,omitempty"`
	LastPing            int64                    `json:"lastPing,omitempty"`
	LastUse             int64                    `json:"lastUse,omitempty"`

	requestChan chan serviceRequest
}

type AgentKey struct {
	AgentID   string `json:"agentId,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

type AgentSessions struct {
	sync.RWMutex
	agents map[AgentKey]*AgentContext
}

func makeAgentSessions() *AgentSessions {
	return &AgentSessions{
		agents: map[AgentKey]*AgentContext{},
	}
}

func newSessionContext(agentID string, sessionID string, hostname string, version string, agentInfo *pb.AgentInfo, endpoints []*pb.EndpointHealth) (*AgentContext, AgentKey) {
	key := AgentKey{AgentID: agentID, SessionID: sessionID}
	now := time.Now().UnixNano()
	eps := []serviceconfig.Endpoint{}
	for _, ep := range endpoints {
		annotations := map[string]string{}
		for _, a := range ep.Annotations {
			annotations[a.Name] = a.Value
		}
		eps = append(eps, serviceconfig.Endpoint{
			Name:        ep.Name,
			Type:        ep.Type,
			Configured:  ep.Configured,
			Annotations: annotations,
		})
	}
	session := &AgentContext{
		AgentKey:            key,
		requestChan:         make(chan serviceRequest),
		LastUse:             now,
		ConnectedAt:         now,
		Hostname:            hostname,
		Version:             version,
		AgentInfo:           agentInfo,
		ConfiguredEndpoints: eps,
	}
	return session, key
}

func (a *AgentSessions) Search(ctx context.Context, spec serviceconfig.SearchSpec) serviceconfig.Destination {
	a.RLock()
	defer a.RUnlock()
	for _, agent := range a.agents {
		if agent.AgentID == spec.Destination {
			for _, ep := range agent.ConfiguredEndpoints {
				if ep.Configured && ep.Name == spec.ServiceName && ep.Type == spec.ServiceType {
					return agent
				}
			}
		}
	}
	return nil
}

func (a *AgentSessions) findSession(ctx context.Context) (*AgentContext, error) {
	a.RLock()
	defer a.RUnlock()
	agentID, sessionID := IdentityFromContext(ctx)
	key := AgentKey{AgentID: agentID, SessionID: sessionID}
	if session, found := a.agents[key]; found {
		return session, nil
	}
	return nil, fmt.Errorf("no such agent session connected: %s/%s", agentID, sessionID)
}

func loggerFromContext(ctx context.Context, fields ...zap.Field) (context.Context, *zap.SugaredLogger) {
	agentID, sessionID := IdentityFromContext(ctx)
	if agentID != "" {
		fields = append(fields, zap.String("agentID", agentID))
	}
	if sessionID != "" {
		fields = append(fields, zap.String("sessionID", sessionID))
	}
	ctx = logging.NewContext(ctx, fields...)
	return ctx, logging.WithContext(ctx).Sugar()
}

func (a *AgentSessions) registerSession(agentID string, sessionID string, hostname string, version string, agentInfo *pb.AgentInfo, endpoints []*pb.EndpointHealth) *AgentContext {
	a.Lock()
	defer a.Unlock()
	session, key := newSessionContext(agentID, sessionID, hostname, version, agentInfo, endpoints)
	a.agents[key] = session
	return session
}

func (a *AgentSessions) removeSession(session *AgentContext) {
	a.Lock()
	defer a.Unlock()
	a.removeSessionUnlocked(session)
}

func (a *AgentSessions) removeSessionUnlocked(session *AgentContext) {
	key := AgentKey{AgentID: session.AgentID, SessionID: session.SessionID}
	delete(a.agents, key)
}

func (a *AgentSessions) touchSession(session *AgentContext, t int64) {
	a.Lock()
	defer a.Unlock()
	a.agents[session.AgentKey].LastUse = t
}

func (a *AgentSessions) checkSessionTimeouts(ctx context.Context, idleTimeout int64) {
	t := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now().UnixNano()
			a.expireOldSessions(ctx, now, idleTimeout)
		}
	}
}

func (a *AgentSessions) expireOldSessions(ctx context.Context, now int64, idleTimeout int64) {
	a.Lock()
	defer a.Unlock()
	_, logging := loggerFromContext(ctx)

	for key, session := range a.agents {
		if session.LastUse+idleTimeout < now {
			logging.Infow("disconnecting idle agent", "lastUsed", session.LastUse, "now", now, "agentID", key.AgentID, "sessionID", key.SessionID)
			a.removeSessionUnlocked(session)
		}
	}
}

func (a *AgentSessions) GetStatistics() interface{} {
	a.RLock()
	defer a.RUnlock()
	ret := []interface{}{}
	for _, ac := range a.agents {
		ret = append(ret, ac.GetStatistics())
	}
	return ret
}

type AgentContextStatistics struct {
	AgentID        string                   `json:"agentId,omitempty"`
	SessionID      string                   `json:"session,omitempty"`
	Name           string                   `json:"name,omitempty"`      // depricated
	Session        string                   `json:"sessionId,omitempty"` // depricated
	ConnectionType string                   `json:"connectionType,omitempty"`
	Endpoints      []serviceconfig.Endpoint `json:"endpoints,omitempty"`
	Version        string                   `json:"version,omitempty"`
	Hostname       string                   `json:"hostname,omitempty"`
	ConnectedAt    uint64                   `json:"connectedAt,omitempty"`
	LastPing       uint64                   `json:"lastPing,omitempty"`
	LastUse        uint64                   `json:"lastUse,omitempty"`
	AgentInfo      *pb.AgentInfo            `json:"agentInfo,omitempty"`
}

func (ac *AgentContext) GetStatistics() interface{} {
	ret := &AgentContextStatistics{
		ConnectedAt: uint64(ac.ConnectedAt),
		LastPing:    uint64(ac.LastPing),
		LastUse:     uint64(ac.LastUse),
		AgentInfo:   ac.AgentInfo,
	}
	ret.AgentID = ac.AgentID
	ret.SessionID = ac.SessionID
	ret.Name = ac.AgentID      // depricated
	ret.Session = ac.SessionID // depricated
	ret.ConnectionType = "direct"
	ret.Endpoints = ac.ConfiguredEndpoints
	ret.Version = ac.Version
	ret.Hostname = ac.Hostname
	return ret
}
