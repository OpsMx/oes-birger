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

package serviceconfig

import (
	"fmt"
	"log"
	"strings"
	"testing"
)

func makeMap(username *string, password *string, token *string) *map[string][]byte {
	ret := map[string][]byte{}
	if username != nil {
		ret["username"] = []byte(*username)
	}
	if password != nil {
		ret["password"] = []byte(*password)
	}
	if token != nil {
		ret["token"] = []byte(*token)
	}
	return &ret
}

func sp(s string) *string {
	return &s
}

var (
	fooString = "Zm9v"
	barString = "YmFy"
	bazString = "YmF6"

	keyset = map[string]*map[string][]byte{
		"u__": makeMap(sp("foo"), nil, nil),
		"_p_": makeMap(nil, sp("bar"), nil),
		"__t": makeMap(nil, nil, sp("baz")),
		"up_": makeMap(sp("foo"), sp("bar"), nil),
		"upt": makeMap(sp("foo"), sp("bar"), sp("baz")),
		"u_t": makeMap(sp("foo"), nil, sp("baz")),
		"_pt": makeMap(nil, sp("bar"), sp("baz")),
		"Xp_": makeMap(sp(""), sp("bar"), nil),
		"uX_": makeMap(sp("foo"), sp(""), nil),
		"__X": makeMap(nil, nil, sp("")),
		"___": makeMap(nil, nil, nil),
	}
)

type FakeSecretLoader struct {
}

func (f *FakeSecretLoader) GetSecret(name string) (*map[string][]byte, error) {
	if m, found := keyset[name]; found {
		return m, nil
	}

	return nil, fmt.Errorf("secret key not found")
}

func TestGenericEndpoint_loadBase64Secrets(t *testing.T) {
	tests := []struct {
		name            string
		creds           genericEndpointCredentials
		wantRawUsername string
		wantRawPassword string
		wantRawToken    string
		wantErr         bool
	}{
		// Bogus credential type
		{
			"credential type bogus",
			genericEndpointCredentials{Type: "X"},
			"", "", "",
			true,
		},

		// No type set
		{
			"no credential fields set",
			genericEndpointCredentials{},
			"", "", "",
			false,
		},

		// Type 'none'
		{
			"credential type none, no other fields set",
			genericEndpointCredentials{},
			"", "", "",
			false,
		},

		// Type 'basic'
		{
			"credential type basic, nothing set",
			genericEndpointCredentials{Type: "basic"},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, passowrd not set",
			genericEndpointCredentials{Type: "basic", Username: fooString},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, passowrd not set",
			genericEndpointCredentials{Type: "basic", Password: barString},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, password set",
			genericEndpointCredentials{Type: "basic", Username: fooString, Password: barString},
			"foo", "bar", "",
			false,
		},
		{
			"credential type basic, username junk, password set",
			genericEndpointCredentials{Type: "basic", Username: "X", Password: barString},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, password junk",
			genericEndpointCredentials{Type: "basic", Username: fooString, Password: "X"},
			"", "", "",
			true,
		},

		// Type 'bearer'
		{
			"credential type bearer, nothing set",
			genericEndpointCredentials{Type: "bearer"},
			"", "", "",
			true,
		},
		{
			"credential type bearer, token set",
			genericEndpointCredentials{Type: "bearer", Token: bazString},
			"", "", "baz",
			false,
		},
		{
			"credential type bearer, token bogus",
			genericEndpointCredentials{Type: "bearer", Token: "X"},
			"", "", "",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &GenericEndpoint{
				endpointType: "jenkins",
				endpointName: "epname",
				config: genericEndpointConfig{
					URL:         "http://example.com",
					Credentials: tt.creds,
				},
			}
			if err := ep.loadBase64Secrets(); (err != nil) != tt.wantErr {
				t.Errorf("GenericEndpoint.loadBase64Secrets() error = %v, wantErr %v", err, tt.wantErr)
			}

			compareBytes(t, tt.wantRawUsername, ep.config.Credentials.rawUsername, "rawUsername")
			compareBytes(t, tt.wantRawPassword, ep.config.Credentials.rawPassword, "rawPassword")
			compareBytes(t, tt.wantRawToken, ep.config.Credentials.rawToken, "rawToken")
		})
	}
}

func compareBytes(t *testing.T, expected string, found string, name string) {
	if expected != found {
		t.Errorf("%s: expected %s != found %s", name, expected, found)
	}
}

func TestGenericEndpoint_loadKubernetesSecrets(t *testing.T) {
	loader := &FakeSecretLoader{}

	tests := []struct {
		loader          *FakeSecretLoader
		name            string
		creds           genericEndpointCredentials
		wantRawUsername string
		wantRawPassword string
		wantRawToken    string
		wantErr         string
	}{
		{
			loader,
			"credential type bogus",
			genericEndpointCredentials{Type: "X", SecretName: "__t"},
			"", "", "",
			"unknown or unsupported credential type",
		},

		// Type 'none'
		{
			loader,
			"credential type none, secretName set",
			genericEndpointCredentials{Type: "none", SecretName: "u__"},
			"", "", "",
			"none: secretName should not be set",
		},

		// Type 'basic
		{
			loader,
			"credential type basic, secretName missing",
			genericEndpointCredentials{Type: "basic", SecretName: "missing"},
			"", "", "",
			"secret key not found",
		},
		{
			loader,
			"credential type basic, secretName has username",
			genericEndpointCredentials{Type: "basic", SecretName: "u__"},
			"", "", "",
			"basic: password missing",
		},
		{
			loader,
			"credential type basic, secretName has password",
			genericEndpointCredentials{Type: "basic", SecretName: "_p_"},
			"", "", "",
			"basic: username missing",
		},
		{
			loader,
			"credential type basic, secretName has username password",
			genericEndpointCredentials{Type: "basic", SecretName: "up_"},
			"foo", "bar", "",
			"",
		},

		// Type 'bearer'
		{
			loader,
			"credential type bearer, secretName has token",
			genericEndpointCredentials{Type: "bearer", SecretName: "__t"},
			"", "", "baz",
			"",
		},
		{
			loader,
			"credential type bearer, secretName has no token",
			genericEndpointCredentials{Type: "bearer", SecretName: "___"},
			"", "", "",
			"bearer: token missing in secret",
		},

		// nil loader
		{
			nil,
			"nil loader",
			genericEndpointCredentials{Type: "basic", SecretName: "up_"},
			"", "", "",
			"cannot load Kubernetes secrets from outside the cluster",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &GenericEndpoint{
				endpointType: "jenkins",
				endpointName: "j1",
				config: genericEndpointConfig{
					URL:         "http://example.com",
					Credentials: tt.creds,
				},
			}
			log.Printf("loader: %v", loader)

			// Without this dance, it seems Go will create an empty struct for us...
			var err error
			if tt.loader == nil {
				err = ep.loadKubernetesSecrets(nil)
			} else {
				err = ep.loadKubernetesSecrets(tt.loader)
			}

			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("GenericEndpoint.loadKubernetesSecrets() error = %v, wantErr %v", err, tt.wantErr)
				} else {
					if !strings.Contains(err.Error(), tt.wantErr) {
						t.Errorf("Error %v should contain %s", err, tt.wantErr)
					}
				}
			} else if err != nil {
				t.Errorf("GenericEndpoint.loadKubernetesSecrets() error = %v, wantErr %v", err, tt.wantErr)
			}

			compareBytes(t, tt.wantRawUsername, ep.config.Credentials.rawUsername, "rawUsername")
			compareBytes(t, tt.wantRawPassword, ep.config.Credentials.rawPassword, "rawPassword")
			compareBytes(t, tt.wantRawToken, ep.config.Credentials.rawToken, "rawToken")
		})
	}
}
