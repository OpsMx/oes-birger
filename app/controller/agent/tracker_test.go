package agent

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
		identity:  "agent1",
		session:   "agent1.session1",
		endpoints: []Endpoint{},
	}

	agent1Session2 = &FakeAgent{
		identity: "agent1",
		session:  "agent1.session2",
		endpoints: []Endpoint{
			{Name: "ep1", Type: "type1", Configured: true},
			{Name: "ep2", Type: "type1", Configured: true},
			{Name: "ep3", Type: "type2", Configured: true},
			{Name: "ep4", Type: "type2", Configured: false},
		},
	}

	bogusagent = &FakeAgent{
		identity:  "agent99",
		session:   "agent99.session1",
		endpoints: []Endpoint{},
	}
)

type FakeAgent struct {
	identity  string
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

func (a *FakeAgent) GetIdentity() string {
	return a.identity
}
func (a *FakeAgent) GetSession() string {
	return a.session
}

type FakeStats AgentStatistics

func (a *FakeAgent) GetStatistics() interface{} {
	return FakeStats{Identity: a.identity, Session: a.session, ConnectionType: "fake"}
}

func (a *FakeAgent) GetEndpoints() []Endpoint {
	return a.endpoints
}

func (s *MySuite) TestConnectedAgents(c *C) {
	agents := MakeAgents()

	///
	/// AddAgent()
	///

	agents.AddAgent(agent1Session1)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 1)

	agents.AddAgent(agent1Session2)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 2)

	///
	/// RemoveAgent()
	///

	err := agents.RemoveAgent(agent1Session1)
	c.Assert(err, IsNil)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 1)

	// bogus agent, never was added
	err = agents.RemoveAgent(bogusagent)
	c.Assert(err, ErrorMatches, ".*no agents known by the name.*agent99.*")

	// agent name exists, session does not
	err = agents.RemoveAgent(agent1Session1)
	c.Assert(err, ErrorMatches, ".*attempt to remove unknown agent.*agent1.session1.*")

	///
	/// findService()
	///

	// now that only agent1State2 exists in the list, find some endpoints.
	agent, err := agents.findService(AgentSearch{Identity: "agent1", EndpointType: "type1", EndpointName: "ep1"})
	c.Assert(err, IsNil)
	c.Assert(agent.GetIdentity(), Equals, "agent1")
	c.Assert(agent.GetSession(), Equals, "agent1.session2")

	// Try to find an agent that does not exist
	_, err = agents.findService(AgentSearch{Identity: "agent99", EndpointType: "type1", EndpointName: "ep1"})
	c.Assert(err, ErrorMatches, "no agents connected for.*")

	// Try to find a service on an agent, where the agent exists but the service does not.
	_, err = agents.findService(AgentSearch{Identity: "agent1", EndpointType: "type99", EndpointName: "ep1"})
	c.Assert(err, ErrorMatches, ".*no such path exists.*")

	///
	/// Send()
	///

	// send to non-existant agent
	session, found := agents.Send(AgentSearch{Identity: "agent19", EndpointType: "type1", EndpointName: "ep1"}, 5)
	c.Assert(found, Equals, false)
	c.Assert(session, Equals, "")

	// working
	session, found = agents.Send(AgentSearch{Identity: "agent1", EndpointType: "type1", EndpointName: "ep1"}, 5)
	c.Assert(found, Equals, true)
	c.Assert(session, Equals, "agent1.session2")
	c.Assert(agent1Session2.lastMessage, Equals, 5)

	///
	/// Cancel()
	///

	// Broken cancel request
	err = agents.Cancel(AgentSearch{Identity: "agent1", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, ErrorMatches, ".*session is not set.*")

	// No agent
	err = agents.Cancel(AgentSearch{Session: "nosession", Identity: "agent99", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, ErrorMatches, ".*no agents connected for.*")

	// Agent exists, session does not
	err = agents.Cancel(AgentSearch{Session: "nosession", Identity: "agent1", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, ErrorMatches, ".*with specific session.*")

	// Attempt to cancel an id
	err = agents.Cancel(AgentSearch{Session: "agent1.session2", Identity: "agent1", EndpointType: "type1", EndpointName: "ep1"}, "abc123")
	c.Assert(err, IsNil)
	c.Assert(agent1Session2.lastCancelled, Equals, "abc123")

	///
	/// GetStatistics
	///

	stats := agents.GetStatistics()
	j, err := json.Marshal(stats)
	c.Assert(err, IsNil) // json should not fail...
	c.Assert(string(j), Equals, `[{"identity":"agent1","session":"agent1.session2","connectionType":"fake"}]`)
}

func (s *MySuite) TestConnectedAgents_sliceIndex(c *C) {
	ints := []int{5, 8, 42, 45}

	c.Assert(sliceIndex(len(ints), func(i int) bool { return ints[i] == 8 }), Equals, 1)
	c.Assert(sliceIndex(len(ints), func(i int) bool { return ints[i] == -99 }), Equals, -1)
}
