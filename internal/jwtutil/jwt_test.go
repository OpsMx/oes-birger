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

package jwtutil

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/skandragon/jwtregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterServiceauthKeyset(keyset, "key1")
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
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaWF0IjoxMTExLCJpc3MiOiJvcHNteC1oZWFkZXItbXV0YXRpb24iLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.SWFm9OopZa8sZ1UZnV8u70gefHps3tAVlslcczofU_0",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeJWT(tt.epType, tt.epName, tt.agent, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterServiceauthKeyset(keyset, "key1")
	require.NoError(t, err)
	tests := []struct {
		name      string
		token     string
		clock     jwt.Clock
		wantType  string
		wantName  string
		wantAgent string
		wantErr   bool
	}{
		{
			"valid",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaWF0IjoxMTExLCJpc3MiOiJvcHNteC1oZWFkZXItbXV0YXRpb24iLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.SWFm9OopZa8sZ1UZnV8u70gefHps3tAVlslcczofU_0",
			&jwtregistry.TimeClock{NowTime: 1111},
			"artifactory",
			"bob",
			"agent1",
			false,
		},
		{
			"invalid1",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaXNzIjoib3BzbXgiLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			"",
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotName, gotAgent, err := ValidateJWT(tt.token, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotType != tt.wantType {
				t.Errorf("ValidateJWT() gotType = %v, want %v", gotType, tt.wantType)
			}
			if gotName != tt.wantName {
				t.Errorf("ValidateJWT() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotAgent != tt.wantAgent {
				t.Errorf("ValidateJWT() gotAgent = %v, want %v", gotAgent, tt.wantAgent)
			}
		})
	}
}
