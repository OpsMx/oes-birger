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

func TestMakeControlJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterControlKeyset(keyset, "key1")
	require.NoError(t, err)

	tests := []struct {
		name    string
		epName  string
		clock   jwt.Clock
		want    string
		wantErr bool
	}{
		{
			"key1",
			"bob",
			&jwtregistry.TimeClock{NowTime: 1111},
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214Lm5hbWUiOiJib2IiLCJvcHNteC5wdXJwb3NlIjoiY29udHJvbCJ9.rE-Jlbd3Qkh1vW0xU62mGUqVMBgj_2_jH_yEkhdRgNE",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeControlJWT(tt.epName, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeControlJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMakeControlJWT_BrokenSigner(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterControlKeyset(keyset, "not-there")
	require.NoError(t, err)
	tests := []struct {
		name    string
		epName  string
		clock   jwt.Clock
		want    string
		wantErr bool
	}{
		{
			"key1",
			"bob",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeControlJWT(tt.epName, tt.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeControlJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateControlJWT(t *testing.T) {
	keyset := LoadTestKeys(t)
	err := RegisterControlKeyset(keyset, "key1")
	require.NoError(t, err)
	tests := []struct {
		name          string
		token         string
		clock         jwt.Clock
		wantName      string
		wantErrString string
	}{
		{
			"valid",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214Lm5hbWUiOiJib2IiLCJvcHNteC5wdXJwb3NlIjoiY29udHJvbCJ9.rE-Jlbd3Qkh1vW0xU62mGUqVMBgj_2_jH_yEkhdRgNE",
			&jwtregistry.TimeClock{NowTime: 1111},
			"bob",
			"",
		},
		{
			"wrong-issuer",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Indyb25nIiwib3BzbXgubmFtZSI6ImJvYiIsIm9wc214LnB1cnBvc2UiOiJjb250cm9sIn0.P7rljWqgFuej2AcP9UGuBAAOxKy_zQoxgAPauWGonwk",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			`"iss" not satisfied: values do not match`,
		},
		{
			"wrong-purpose",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214Lm5hbWUiOiJib2IiLCJvcHNteC5wdXJwb3NlIjoid3JvbmcifQ.0v6aVtbDk62gP-1URP7JHMk0riYABXD3ePu2LTPMRbQ",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			`expected a control JWT, got a 'wrong'`,
		},
		{
			"missing-purpose",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214Lm5hbWUiOiJib2IifQ.YEKwSTFl9Rg4Ayu8o9z1tPeoXXnzSXvgRmWJy7pALdQ",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			`no 'opsmx.purpose' key in JWT claims`,
		},
		{
			"missing-name",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214LnB1cnBvc2UiOiJjb250cm9sIn0.x3fVYkRhC8Ytyt4WcQVFWqP8haP_HnxQFYDivpXPey0",
			&jwtregistry.TimeClock{NowTime: 1111},
			"",
			`no 'opsmx.name' key in JWT claims`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, err := ValidateControlJWT(tt.token, tt.clock)
			if tt.wantErrString != "" {
				require.EqualError(t, err, tt.wantErrString)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, gotName)
		})
	}
}
