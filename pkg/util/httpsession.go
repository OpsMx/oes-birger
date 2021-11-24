/*
 * Copyright 2021 OpsMx, Inc.
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

package util

import (
	"sync"

	"github.com/opsmx/oes-birger/pkg/tunnel"
)

// SessionList holds a list of IDs that have been used on a specific route,
// so if that route goes away we can close them all forcefully, as well
// as track those in progress.
type SessionList struct {
	sync.RWMutex
	m map[string]chan *tunnel.MessageWrapper
}

// MakeSessionList will return a new SessionList.
func MakeSessionList() *SessionList {
	return &SessionList{m: make(map[string]chan *tunnel.MessageWrapper)}
}

// Add adds a specific ID and its channel to our list.
func (s *SessionList) Add(id string, c chan *tunnel.MessageWrapper) {
	s.Lock()
	defer s.Unlock()
	s.m[id] = c
}

// FindUnlocked will return the channel for a specific ID, if present, without locking.
func (s *SessionList) FindUnlocked(id string) chan *tunnel.MessageWrapper {
	return s.m[id]
}

// Find will return the channel for a specific ID, if present.
func (s *SessionList) Find(id string) chan *tunnel.MessageWrapper {
	s.Lock()
	defer s.Unlock()
	return s.m[id]
}

// RemoveUnlocked will remoev a specific id from the list.  The channel is not closed.
func (s *SessionList) RemoveUnlocked(id string) {
	delete(s.m, id)
}

// Remove will remoev a specific id from the list.  The channel is not closed.
func (s *SessionList) Remove(id string) {
	s.Lock()
	defer s.Unlock()
	delete(s.m, id)
}

// CloseAll empties the list of all IDs, and closes all channels.
func (s *SessionList) CloseAll() {
	s.Lock()
	defer s.Unlock()
	for _, v := range s.m {
		close(v)
	}
	for k := range s.m {
		delete(s.m, k)
	}
}
