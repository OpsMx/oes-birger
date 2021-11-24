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

package tunnelroute

import (
	"encoding/json"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type MySuite struct{}

var _ = Suite(&MySuite{})

var (
	agent1Session1 = &FakeAgent{
		name:      "agent1",
		session:   "agent1.session1",
		endpoints: []Endpoint{},
	}

	agent1Session2 = &FakeAgent{
		name:    "agent1",
		session: "agent1.session2",
		endpoints: []Endpoint{
			{Name: "ep1", Type: "type1", Configured: true},
			{Name: "ep2", Type: "type1", Configured: true},
			{Name: "ep3", Type: "type2", Configured: true},
			{Name: "ep4", Type: "type2", Configured: false},
		},
	}

	bogusagent = &FakeAgent{
		name:      "agent99",
		session:   "agent99.session1",
		endpoints: []Endpoint{},
	}
)

type FakeAgent struct {
	name      string
	session   string
	endpoints []Endpoint

	lastCancelled string
	lastMessage   int
}

func (a *FakeAgent) Close() {}

func (a *FakeAgent) Send(m interface{}) string {
	a.lastMessage = m.(int)
	return a.session
}

func (a *FakeAgent) Cancel(id string) {
	a.lastCancelled = id
}

func (a *FakeAgent) HasEndpoint(endpointType string, endpointName string) bool {
	for _, ep := range a.endpoints {
		if ep.Type == endpointType && ep.Name == endpointName {
			return ep.Configured
		}
	}
	return false
}

func (a *FakeAgent) GetName() string {
	return a.name
}
func (a *FakeAgent) GetSession() string {
	return a.session
}

type FakeStats BaseStatistics

func (a *FakeAgent) GetStatistics() interface{} {
	return FakeStats{Name: a.name, Session: a.session, ConnectionType: "fake"}
}

func (a *FakeAgent) GetEndpoints() []Endpoint {
	return a.endpoints
}

func (s *MySuite) TestConnectedAgents(c *C) {
	agents := MakeRoutes()

	///
	/// AddAgent()
	///

	agents.Add(agent1Session1)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 1)

	agents.Add(agent1Session2)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 2)

	///
	/// RemoveAgent()
	///

	err := agents.Remove(agent1Session1)
	c.Assert(err, IsNil)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 1)

	// bogus agent, never was added
	err = agents.Remove(bogusagent)
	c.Assert(err, ErrorMatches, ".*no routes known by the name.*agent99.*")

	// agent name exists, session does not
	err = agents.Remove(agent1Session1)
	c.Assert(err, ErrorMatches, ".*attempt to remove unknown route.*agent1.session1.*")

	///
	/// findService()
	///

	// now that only agent1State2 exists in the list, find some endpoints.
	agent, err := agents.findService(Search{Name: "agent1", EndpointType: "type1", EndpointName: "ep1"})
	c.Assert(err, IsNil)
	c.Assert(agent.GetName(), Equals, "agent1")
	c.Assert(agent.GetSession(), Equals, "agent1.session2")

	// Try to find an agent that does not exist
	_, err = agents.findService(Search{Name: "agent99", EndpointType: "type1", EndpointName: "ep1"})
	c.Assert(err, ErrorMatches, "no routes connected for.*")

	// Try to find a service on an agent, where the agent exists but the service does not.
	_, err = agents.findService(Search{Name: "agent1", EndpointType: "type99", EndpointName: "ep1"})
	c.Assert(err, ErrorMatches, ".*no such route exists.*")

	///
	/// Send()
	///

	// send to non-existent agent
	session, found := agents.Send(Search{Name: "agent19", EndpointType: "type1", EndpointName: "ep1"}, 5)
	c.Assert(found, Equals, false)
	c.Assert(session, Equals, "")

	// working
	session, found = agents.Send(Search{Name: "agent1", EndpointType: "type1", EndpointName: "ep1"}, 5)
	c.Assert(found, Equals, true)
	c.Assert(session, Equals, "agent1.session2")
	c.Assert(agent1Session2.lastMessage, Equals, 5)

	///
	/// Cancel()
	///

	// Broken cancel request
	err = agents.Cancel(Search{Name: "agent1", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, ErrorMatches, ".*session is not set.*")

	// No agent
	err = agents.Cancel(Search{Session: "nosession", Name: "agent99", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, ErrorMatches, ".*no routes connected for.*")

	// Agent exists, session does not
	err = agents.Cancel(Search{Session: "nosession", Name: "agent1", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, ErrorMatches, ".*with specific session.*")

	// Attempt to cancel an id
	err = agents.Cancel(Search{Session: "agent1.session2", Name: "agent1", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, IsNil)
	c.Assert(agent1Session2.lastCancelled, Equals, "abc123")

	///
	/// GetStatistics
	///

	stats := agents.GetStatistics()
	j, err := json.Marshal(stats)
	c.Assert(err, IsNil) // json should not fail...
	c.Assert(string(j), Equals, `[{"name":"agent1","session":"agent1.session2","connectionType":"fake"}]`)
}

func (s *MySuite) TestConnectedAgents_sliceIndex(c *C) {
	ints := []int{5, 8, 42, 45}

	c.Assert(sliceIndex(len(ints), func(i int) bool { return ints[i] == 8 }), Equals, 1)
	c.Assert(sliceIndex(len(ints), func(i int) bool { return ints[i] == -99 }), Equals, -1)
}
