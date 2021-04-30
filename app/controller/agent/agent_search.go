package agent

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

import (
	"fmt"
	"strings"
)

type AgentSearch struct {
	Name         string // The agent name
	EndpointType string // the endpoint type, eg "jenkins", "kubernetes", "remote-command"
	EndpointName string // the endpoint name, eg "jenkins1" or "kubernetes1"
	Session      string // the session ID for a specific agent, used to cancel.
}

func (a AgentSearch) String() string {
	l := []string{
		fmt.Sprintf("name=%s", a.Name),
	}
	if len(a.Session) > 0 {
		l = append(l, fmt.Sprintf("session=%s", a.Session))
	}
	if len(a.EndpointType) > 0 {
		l = append(l, fmt.Sprintf("endpointType=%s", a.EndpointType))
	}
	if len(a.EndpointName) > 0 {
		l = append(l, fmt.Sprintf("endpointName=%s", a.EndpointName))
	}
	return fmt.Sprintf("(%s)", strings.Join(l, ", "))
}

func (a *AgentSearch) MatchesAgent(t Agent) bool {
	return a.Name == t.GetName() && (len(a.Session) == 0 || a.Session == t.GetSession())
}
