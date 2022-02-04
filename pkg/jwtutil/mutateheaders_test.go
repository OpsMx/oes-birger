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
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func Test_MutateHeader(t *testing.T) {
	keyset := loadkeys(t)
	type args struct {
		keyid     string
		inception time.Time
		expiry    time.Time
		data      string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"simpleTest",
			args{"key1",
				time.Unix(1234, 0),
				time.Unix(99999, 0),
				"alice",
			},
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjk5OTk5LCJpYXQiOjEyMzQsImlzcyI6Im9wc214IiwidSI6ImFsaWNlIn0.Sz9tP7CKNGSrrovn3zEv5bO3eMivTAPXnp_AYLtUtvE",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key jwk.Key
			var ok bool
			if key, ok = keyset.LookupKeyID(tt.args.keyid); !ok {
				t.Errorf("key not found: %s", tt.args.keyid)
				t.FailNow()
			}
			got, err := MutateHeader(key, tt.args.inception, tt.args.expiry, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("mutateHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("mutateHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testclock struct {
	now int64
}

func (tc testclock) Now() time.Time {
	return time.Unix(tc.now, 0)
}

func newTestClock(now int64) jwt.Clock {
	return testclock{now}
}

func TestUnmutateHeader(t *testing.T) {
	keyset := loadkeys(t)
	type args struct {
		tokenString string
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
				"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjk5OTk5LCJpYXQiOjEyMzQsImlzcyI6Im9wc214IiwidSI6ImFsaWNlIn0.Sz9tP7CKNGSrrovn3zEv5bO3eMivTAPXnp_AYLtUtvE",
				newTestClock(5555),
			},
			"alice",
			false,
		},
		{
			"before created time",
			args{
				"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjk5OTk5LCJpYXQiOjEyMzQsImlzcyI6Im9wc214IiwidSI6ImFsaWNlIn0.Sz9tP7CKNGSrrovn3zEv5bO3eMivTAPXnp_AYLtUtvE",
				newTestClock(111),
			},
			"",
			true,
		},
		{
			"after expiry time",
			args{
				"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjk5OTk5LCJpYXQiOjEyMzQsImlzcyI6Im9wc214IiwidSI6ImFsaWNlIn0.Sz9tP7CKNGSrrovn3zEv5bO3eMivTAPXnp_AYLtUtvE",
				newTestClock(99999),
			},
			"",
			true,
		},
		{
			"no such key",
			args{
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJpc3MiOiJvcHNteCIsInUiOiJhbGljZSIsImlhdCI6MTIzNCwiZXhwIjo5OTk5fQ.Ayh-HqzKAcpZqHFi7dtdGdNCPX0Ipp7Vi7BD5bQx9Q0",
				newTestClock(5555),
			},
			"",
			true,
		},
		{
			"missing 'u'",
			args{
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJpc3MiOiJvcHNteCIsImlhdCI6MTIzNCwiZXhwIjo5OTk5fQ.Ke_f3wGC4DiaXzoLW7Ymz_HRMRPxH-A4BJCqzGd0TpM",
				newTestClock(5555),
			},
			"",
			true,
		},
		{
			"missing 'iss'",
			args{
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJpYXQiOjEyMzQsInUiOiJhbGljZSIsImV4cCI6OTk5OX0.RfuheRuXlrRUcIjEzyLX_Imy2POFfYIoJZ9Uj89dFUQ",
				newTestClock(5555),
			},
			"",
			true,
		},
		{
			"bad 'iss'",
			args{
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJpc3MiOiJmb28iLCJpYXQiOjEyMzQsInUiOiJhbGljZSIsImV4cCI6OTk5OX0.xGCEiPf1wiAUQ32bCClW7NIFqq3Cc1fBqKDWDlWr7tk",
				newTestClock(5555),
			},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUsername, err := UnmutateHeader(keyset, tt.args.tokenString, tt.args.clock)
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
