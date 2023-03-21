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
	"sync"

	"github.com/opsmx/oes-birger/internal/serviceconfig"
)

type StreamManager struct {
	sync.RWMutex
	streams map[string]*Stream
}

type Stream struct {
	agentID   string
	sessionID string
	echo      serviceconfig.Echo
	closechan chan bool
}

func NewStreamManager() *StreamManager {
	return &StreamManager{
		streams: map[string]*Stream{},
	}
}

func (sm *StreamManager) Register(ctx context.Context, session *AgentContext, streamID string, closechan chan bool, echo serviceconfig.Echo) {
	sm.Lock()
	defer sm.Unlock()
	sm.streams[streamID] = &Stream{
		agentID:   session.AgentID,
		sessionID: session.SessionID,
		echo:      echo,
		closechan: closechan,
	}
}

func (sm *StreamManager) Unregister(ctx context.Context, streamID string) {
	sm.Lock()
	defer sm.Unlock()
	delete(sm.streams, streamID)
}

func (sm *StreamManager) Find(ctx context.Context, streamID string) (*Stream, bool) {
	sm.RLock()
	defer sm.RUnlock()
	stream, found := sm.streams[streamID]
	return stream, found
}

func (sm *StreamManager) FlushAgent(ctx context.Context, session *AgentContext) {
	sm.Lock()
	defer sm.Unlock()
	sm.flushUnlocked(ctx, session)
}

func (sm *StreamManager) flushUnlocked(ctx context.Context, session *AgentContext) {
	_, logger := loggerFromContext(ctx)
	logger.Infof("flushing agent %s session %s", session.AgentID, session.SessionID)
	targets := []string{}
	for k, v := range sm.streams {
		logger.Infof("Checking stream %s, agent %s", k, v.agentID)
		if v.sessionID == session.SessionID {
			targets = append(targets, k)
		}
	}
	for _, target := range targets {
		stream := sm.streams[target]
		stream.echo.Cancel(ctx)
		delete(sm.streams, target)
		logger.Infof("flushed agent %s session %s stream %s", session.AgentID, session.SessionID, target)
	}
}
