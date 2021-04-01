package agent

func Send(ep AgentSearch, message interface{}) (session string, found bool) {
	return agents.Send(ep, message)
}

func Cancel(ep AgentSearch, id string) bool {
	return agents.Cancel(ep, id)
}

func RemoveAgent(as *AgentState) {
	agents.RemoveAgent(as)
}

func AddAgent(as *AgentState) {
	agents.AddAgent(as)
}
