package agent

import "testing"

func TestAgentSearch_MatchesAgent(t *testing.T) {
	type fields struct {
		Identity     string
		EndpointType string
		EndpointName string
		Session      string
	}
	type args struct {
		t Agent
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			"matching name and session",
			fields{Identity: "a1", Session: "abc"},
			args{t: &AgentState{Name: "a1", Session: "abc"}},
			true,
		},
		{
			"matching name",
			fields{Identity: "a1"},
			args{t: &AgentState{Name: "a1", Session: "abc"}},
			true,
		},
		{
			"non-matching name",
			fields{Identity: "a2"},
			args{t: &AgentState{Name: "a1", Session: "abc"}},
			false,
		},
		{
			"matching name, non-matching session",
			fields{Identity: "a1", Session: "cda"},
			args{t: &AgentState{Name: "a1", Session: "abc"}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AgentSearch{
				Name:         tt.fields.Identity,
				EndpointType: tt.fields.EndpointType,
				EndpointName: tt.fields.EndpointName,
				Session:      tt.fields.Session,
			}
			if got := a.MatchesAgent(tt.args.t); got != tt.want {
				t.Errorf("AgentSearch.MatchesAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}
