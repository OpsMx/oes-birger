package cncserver

type fakeStats struct{}

func FakeStats() cncAgentStatsReporter {
	return &fakeStats{}
}

func (*fakeStats) GetStatistics() interface{} {
	return struct{}{}
}
