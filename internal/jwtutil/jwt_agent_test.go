/*
 * Copyright 2021-2023 OpsMx, Inc.
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

package jwtutil

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/skandragon/jwtregistry/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeAgentJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterAgentKeyset(keyset, "key1")
	require.NoError(t, err)
	tests := []struct {
		name    string
		agent   string
		clock   jwt.Clock
		want    string
		wantErr bool
	}{
		{
			"key1",
			"agent1",
			&jwtregistry.TimeClock{NowTime: 1111},
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWFnZW50LWF1dGgiLCJvcHNteC5hZ2VudC5uYW1lIjoiYWdlbnQxIn0.fRE1PyLaHngNlPrQ5D3jN-LlgS_mWvxO_yWFgFNx2wE",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeAgentJWT(tt.agent, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeAgentJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMakeAgentJWT_BrokenSigner(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterAgentKeyset(keyset, "not-there")
	require.NoError(t, err)
	tests := []struct {
		name    string
		agent   string
		clock   jwt.Clock
		want    string
		wantErr bool
	}{
		{
			"key1",
			"agent1",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeAgentJWT(tt.agent, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeAgentJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func makeToken(registry string, claims map[string]string, clock jwt.Clock) string {
	signed, err := sign(registry, claims, clock)
	if err != nil {
		panic(err)
	}
	return string(signed)
}

func TestValidateAgentJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterAgentKeyset(keyset, "key2")
	require.NoError(t, err)

	if err := jwtregistry.Register("not-agent-registry", "not-opsmx", jwtregistry.WithKeyset(keyset), jwtregistry.WithSigningKeyName("key2")); err != nil {
		panic(err)
	}

	clock := &jwtregistry.TimeClock{NowTime: 1111}

	tests := []struct {
		name          string
		token         string
		clock         jwt.Clock
		wantAgent     string
		wantErrString string
	}{
		{
			"valid",
			makeToken(agentRegistryName, map[string]string{
				claimOpsmxAgentName: "agent1",
			}, clock),
			clock,
			"agent1",
			"",
		},
		{
			"wrong-issuer",
			makeToken("not-agent-registry", map[string]string{}, clock),
			clock,
			"",
			`"iss" not satisfied: values do not match`,
		},
		{
			"missing-sub",
			makeToken(agentRegistryName, map[string]string{}, clock),
			clock,
			"",
			fmt.Sprintf(`no '%s' key in JWT claims`, claimOpsmxAgentName),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAgent, err := ValidateAgentJWT(tt.token, tt.clock)
			if tt.wantErrString != "" {
				require.EqualError(t, err, tt.wantErrString)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAgent, gotAgent)
		})
	}
}
