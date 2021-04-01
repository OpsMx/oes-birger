package agent

import "fmt"

type AgentSearch struct {
	Identity     string // The agent identity
	EndpointType string // the endpoint type, eg "jenkins", "kubernetes", "remote-command"
	EndpointName string // the endpoint name, eg "jenkins1" or "kubernetes1"
	Session      string // the session ID for a specific agent, used to cancel.
}

func (a *AgentSearch) String() string {
	return fmt.Sprintf("(%s, %s, %s)", a.Identity, a.EndpointType, a.EndpointName)
}
