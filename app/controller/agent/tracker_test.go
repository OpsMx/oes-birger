package agent

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type MySuite struct{}

var _ = Suite(&MySuite{})

var (
	agent1State1 = &AgentState{
		Identity:        "agent1",
		Session:         "agent1.session1",
		Endpoints:       []Endpoint{},
		InRequest:       make(chan interface{}),
		InCancelRequest: make(chan string),
	}

	agent1State2 = &AgentState{
		Identity:        "agent1",
		Session:         "agent1.session2",
		Endpoints:       []Endpoint{},
		InRequest:       make(chan interface{}),
		InCancelRequest: make(chan string),
	}
)

func (s *MySuite) TestConnectedAgents(c *C) {
	agents := MakeAgents()

	agents.AddAgent(agent1State1)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 1)

	agents.AddAgent(agent1State2)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 2)

	agents.RemoveAgent(agent1State1)
	c.Assert(agents.m, HasLen, 1)
	c.Assert(agents.m["agent1"], HasLen, 1)
}
