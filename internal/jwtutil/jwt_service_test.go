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
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/skandragon/jwtregistry/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeServiceJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterServiceKeyset(keyset, "key1")
	require.NoError(t, err)
	tests := []struct {
		name    string
		epType  string
		epName  string
		agent   string
		clock   jwt.Clock
		want    string
		wantErr bool
	}{
		{
			"key1",
			"artifactory",
			"bob",
			"agent1",
			&jwtregistry.TimeClock{NowTime: 1111},
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaWF0IjoxMTExLCJpc3MiOiJvcHNteCIsIm4iOiJib2IiLCJ0IjoiYXJ0aWZhY3RvcnkifQ.DW4Dj8C94KzKUaZ8tIrMrDnaXc-ipHaEL50N2IcHAoA",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeServiceJWT(tt.epType, tt.epName, tt.agent, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeServiceJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMakeServiceJWT_BrokenSigner(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterServiceKeyset(keyset, "not-there")
	require.NoError(t, err)
	tests := []struct {
		name    string
		epType  string
		epName  string
		agent   string
		clock   jwt.Clock
		want    string
		wantErr bool
	}{
		{
			"key1",
			"artifactory",
			"bob",
			"agent1",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeServiceJWT(tt.epType, tt.epName, tt.agent, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeServiceJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateServiceJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterServiceKeyset(keyset, "key1")
	require.NoError(t, err)
	tests := []struct {
		name          string
		token         string
		clock         jwt.Clock
		wantType      string
		wantName      string
		wantAgent     string
		wantErrString string
	}{
		{
			"valid",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaWF0IjoxMTExLCJpc3MiOiJvcHNteCIsIm4iOiJib2IiLCJ0IjoiYXJ0aWZhY3RvcnkifQ.DW4Dj8C94KzKUaZ8tIrMrDnaXc-ipHaEL50N2IcHAoA",
			&jwtregistry.TimeClock{NowTime: 1111},
			"artifactory",
			"bob",
			"agent1",
			"",
		},
		{
			"wrong-issuer",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaWF0IjoxMTExLCJpc3MiOiJub3QtdmFsaWQiLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.bplIcfd1SlifxrzOKTuXTj5J1VkSkmmRw2PsRWzFymc",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			"",
			"",
			`"iss" not satisfied: values do not match`,
		},
		{
			"missing-a",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJheCI6ImFnZW50MSIsImlhdCI6MTExMSwiaXNzIjoib3BzbXgiLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.9wy-WWMMDTDiDNZ1XF0a7cCgNfvTTlxbyxkag9PKoq4",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			"",
			"",
			`no 'a' key in JWT claims`,
		},
		{
			"missing-n",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaWF0IjoxMTExLCJpc3MiOiJvcHNteCIsIm54IjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.LSH68qx5PEkB-lfN5nztFVYFlSZChCU33zJf2NWVxBE",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			"",
			"",
			`no 'n' key in JWT claims`,
		},
		{
			"missing-t",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaWF0IjoxMTExLCJpc3MiOiJvcHNteCIsIm4iOiJib2IiLCJ0eCI6ImFydGlmYWN0b3J5In0.noL3WZ4ScRylMOSP1ZKjJ0vPLudMSQc5CGB77W6WyFE",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			"",
			"",
			`no 't' key in JWT claims`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotName, gotAgent, err := ValidateServiceJWT(tt.token, tt.clock)
			if tt.wantErrString != "" {
				require.EqualError(t, err, tt.wantErrString)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAgent, gotAgent)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantType, gotType)
		})
	}
}
