/*
 * Copyright 2022 OpsMx, Inc.
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
	"log"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/skandragon/jwtregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MutateHeader(t *testing.T) {
	err := RegisterMutationKeyset(LoadTestKeys(t), "key1")
	require.NoError(t, err)
	type args struct {
		data  string
		clock jwt.Clock
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"simpleTest",
			args{
				"alice",
				&jwtregistry.TimeClock{NowTime: 1111},
			},
			[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjIwMTEsImlhdCI6MTExMSwiaXNzIjoib3BzbXgtaGVhZGVyLW11dGF0aW9uIiwidSI6ImFsaWNlIn0.5ufaewbtmA85c0wDHYA72XIxHJQgTRrtfWvZlj1os6Q"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MutateHeader(tt.args.data, tt.args.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("mutateHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			log.Printf("%s", got)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUnmutateHeader(t *testing.T) {
	err := jwtregistry.Register(mutateRegistryName, "opsmx-clouddriver-proxy",
		jwtregistry.WithKeyset(LoadTestKeys(t)),
		jwtregistry.WithSigningKeyName("key1"),
	)
	require.NoError(t, err)
	type args struct {
		tokenString []byte
		clock       jwt.Clock
	}
	tests := []struct {
		name         string
		args         args
		wantUsername string
		wantErr      bool
	}{
		{
			"valid",
			args{
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNsb3VkZHJpdmVyLXByb3h5IiwidSI6ImFsaWNlIn0.Vl1-Dtwj5O2lzOSkZFmBjSwatTHxko0RmS16d3oqfz4"),
				&jwtregistry.TimeClock{NowTime: 5555},
			},
			"alice",
			false,
		},
		{
			"before created time",
			args{
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjk5OTk5LCJpYXQiOjEyMzQsImlzcyI6Im9wc214IiwidSI6ImFsaWNlIn0.Sz9tP7CKNGSrrovn3zEv5bO3eMivTAPXnp_AYLtUtvE"),
				&jwtregistry.TimeClock{NowTime: 111},
			},
			"",
			true,
		},
		{
			"after expiry time",
			args{
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjk5OTk5LCJpYXQiOjEyMzQsImlzcyI6Im9wc214IiwidSI6ImFsaWNlIn0.Sz9tP7CKNGSrrovn3zEv5bO3eMivTAPXnp_AYLtUtvE"),
				&jwtregistry.TimeClock{NowTime: 99999},
			},
			"",
			true,
		},
		{
			"no such key",
			args{
				[]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJpc3MiOiJvcHNteCIsInUiOiJhbGljZSIsImlhdCI6MTIzNCwiZXhwIjo5OTk5fQ.Ayh-HqzKAcpZqHFi7dtdGdNCPX0Ipp7Vi7BD5bQx9Q0"),
				&jwtregistry.TimeClock{NowTime: 5555},
			},
			"",
			true,
		},
		{
			"missing 'u'",
			args{
				[]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJpc3MiOiJvcHNteCIsImlhdCI6MTIzNCwiZXhwIjo5OTk5fQ.Ke_f3wGC4DiaXzoLW7Ymz_HRMRPxH-A4BJCqzGd0TpM"),
				&jwtregistry.TimeClock{NowTime: 5555},
			},
			"",
			true,
		},
		{
			"missing 'iss'",
			args{
				[]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJpYXQiOjEyMzQsInUiOiJhbGljZSIsImV4cCI6OTk5OX0.RfuheRuXlrRUcIjEzyLX_Imy2POFfYIoJZ9Uj89dFUQ"),
				&jwtregistry.TimeClock{NowTime: 5555},
			},
			"",
			true,
		},
		{
			"bad 'iss'",
			args{
				[]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJpc3MiOiJmb28iLCJpYXQiOjEyMzQsInUiOiJhbGljZSIsImV4cCI6OTk5OX0.xGCEiPf1wiAUQ32bCClW7NIFqq3Cc1fBqKDWDlWr7tk"),
				&jwtregistry.TimeClock{NowTime: 5555},
			},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUsername, err := UnmutateHeader(tt.args.tokenString, tt.args.clock)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmutateHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUsername != tt.wantUsername {
				t.Errorf("UnmutateHeader() = %v, want %v", gotUsername, tt.wantUsername)
			}
		})
	}
}

func TestUnregisterMutationKeyset(t *testing.T) {
	err := jwtregistry.Register(mutateRegistryName, "opsmx-clouddriver-proxy",
		jwtregistry.WithKeyset(LoadTestKeys(t)),
		jwtregistry.WithSigningKeyName("key1"),
	)
	require.NoError(t, err)
	t.Run("register/unregister sequence", func(t *testing.T) {
		assert.True(t, MutationIsRegistered())
		UnregisterMutationKeyset()
		assert.False(t, MutationIsRegistered())
	})
}
