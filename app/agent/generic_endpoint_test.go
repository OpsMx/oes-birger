package main

import (
	"fmt"
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
		creds           GenericEndpointCredentials
		wantRawUsername string
		wantRawPassword string
		wantRawToken    string
		wantErr         bool
	}{
		// Bogus credential type
		{
			"credential type bogus",
			GenericEndpointCredentials{Type: "X"},
			"", "", "",
			true,
		},

		// No type set
		{
			"no credential fields set",
			GenericEndpointCredentials{},
			"", "", "",
			false,
		},

		// Type 'none'
		{
			"credential type none, no other fields set",
			GenericEndpointCredentials{},
			"", "", "",
			false,
		},
		{
			"credential type none, username set",
			GenericEndpointCredentials{Type: "none", Username: fooString},
			"", "", "",
			true,
		},
		{
			"credential type none, password set",
			GenericEndpointCredentials{Type: "none", Password: fooString},
			"", "", "",
			true,
		},
		{
			"credential type none, token set",
			GenericEndpointCredentials{Type: "none", Token: fooString},
			"", "", "",
			true,
		},

		// Type 'basic'
		{
			"credential type basic, nothing set",
			GenericEndpointCredentials{Type: "basic"},
			"", "", "",
			true,
		},
		{
			"credential type basic, token set",
			GenericEndpointCredentials{Type: "basic", Token: bazString},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, passowrd not set",
			GenericEndpointCredentials{Type: "basic", Username: fooString},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, passowrd not set",
			GenericEndpointCredentials{Type: "basic", Password: barString},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, password set",
			GenericEndpointCredentials{Type: "basic", Username: fooString, Password: barString},
			"foo", "bar", "",
			false,
		},
		{
			"credential type basic, username junk, password set",
			GenericEndpointCredentials{Type: "basic", Username: "X", Password: barString},
			"", "", "",
			true,
		},
		{
			"credential type basic, username set, password junk",
			GenericEndpointCredentials{Type: "basic", Username: fooString, Password: "X"},
			"", "", "",
			true,
		},

		// Type 'bearer'
		{
			"credential type bearer, nothing set",
			GenericEndpointCredentials{Type: "bearer"},
			"", "", "",
			true,
		},
		{
			"credential type bearer, token set",
			GenericEndpointCredentials{Type: "bearer", Token: bazString},
			"", "", "baz",
			false,
		},
		{
			"credential type bearer, token bogus",
			GenericEndpointCredentials{Type: "bearer", Token: "X"},
			"", "", "",
			true,
		},
		{
			"credential type bearer, username set",
			GenericEndpointCredentials{Type: "bearer", Token: bazString, Username: fooString},
			"", "", "",
			true,
		},
		{
			"credential type bearer, password set",
			GenericEndpointCredentials{Type: "bearer", Token: bazString, Password: barString},
			"", "", "",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &GenericEndpoint{
				endpointType: "jenkins",
				endpointName: "epname",
				config: GenericEndpointConfig{
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
		name            string
		creds           GenericEndpointCredentials
		wantRawUsername string
		wantRawPassword string
		wantRawToken    string
		wantErr         string
	}{
		{
			"credential type bogus",
			GenericEndpointCredentials{Type: "X", SecretName: "__t"},
			"", "", "",
			"unknown or unsupported credential type",
		},

		// Type 'none'
		{
			"credential type none, secretName set",
			GenericEndpointCredentials{Type: "none", SecretName: "u__"},
			"", "", "",
			"none: secretName should not be set",
		},

		// Type 'basic
		{
			"credential type basic, secretName missing",
			GenericEndpointCredentials{Type: "basic", SecretName: "missing"},
			"", "", "",
			"secret key not found",
		},
		{
			"credential type basic, secretName has username",
			GenericEndpointCredentials{Type: "basic", SecretName: "u__"},
			"", "", "",
			"basic: password missing",
		},
		{
			"credential type basic, secretName has password",
			GenericEndpointCredentials{Type: "basic", SecretName: "_p_"},
			"", "", "",
			"basic: username missing",
		},
		{
			"credential type basic, secretName has username password",
			GenericEndpointCredentials{Type: "basic", SecretName: "up_"},
			"foo", "bar", "",
			"",
		},
		{
			"credential type basic, secretName has token",
			GenericEndpointCredentials{Type: "basic", SecretName: "upt"},
			"", "", "",
			"basic: token should not be set",
		},

		// Type 'bearer'
		{
			"credential type bearer, secretName has token",
			GenericEndpointCredentials{Type: "bearer", SecretName: "__t"},
			"", "", "baz",
			"",
		},
		{
			"credential type bearer, secretName has username and token",
			GenericEndpointCredentials{Type: "bearer", SecretName: "u_t"},
			"", "", "",
			"bearer: username should not be set",
		},
		{
			"credential type bearer, secretName has no token",
			GenericEndpointCredentials{Type: "bearer", SecretName: "___"},
			"", "", "",
			"bearer: token missing in secret",
		},
		{
			"credential type bearer, secretName has password and token",
			GenericEndpointCredentials{Type: "bearer", SecretName: "_pt"},
			"", "", "",
			"bearer: password should not be set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &GenericEndpoint{
				endpointType: "jenkins",
				endpointName: "j1",
				config: GenericEndpointConfig{
					URL:         "http://example.com",
					Credentials: tt.creds,
				},
			}
			err := ep.loadKubernetesSecrets(loader)
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
