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
			args{t: &DirectlyConnectedAgent{Name: "a1", Session: "abc"}},
			true,
		},
		{
			"matching name",
			fields{Identity: "a1"},
			args{t: &DirectlyConnectedAgent{Name: "a1", Session: "abc"}},
			true,
		},
		{
			"non-matching name",
			fields{Identity: "a2"},
			args{t: &DirectlyConnectedAgent{Name: "a1", Session: "abc"}},
			false,
		},
		{
			"matching name, non-matching session",
			fields{Identity: "a1", Session: "cda"},
			args{t: &DirectlyConnectedAgent{Name: "a1", Session: "abc"}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Search{
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
