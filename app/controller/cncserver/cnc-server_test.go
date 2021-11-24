package cncserver

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

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/opsmx/oes-birger/pkg/ca"
	"github.com/opsmx/oes-birger/pkg/fwdapi"
)

type handlerTracker struct {
	called bool
}

func (h *handlerTracker) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		h.called = true
	}
}

type mockConfig struct{}

func (*mockConfig) GetAgentAdvertisePort() uint16 { return 1234 }

func (*mockConfig) GetControlListenPort() uint16 { return 4321 }

func (*mockConfig) GetControlURL() string { return "https://control.local" }

func (*mockConfig) GetServiceURL() string { return "https://service.local" }

func (*mockConfig) GetAgentHostname() string { return "agent.local" }

type mockAuthority struct{}

func (*mockAuthority) GenerateCertificate(name ca.CertificateName) (string, string, string, error) {
	return "a", "b", "c", nil
}

func (*mockAuthority) GetCACert() (string, error) {
	return "base64-cacert", nil
}

func (*mockAuthority) MakeCertPool() (*x509.CertPool, error) {
	return nil, nil
}

type mockAgents struct{}

func (*mockAgents) GetStatistics() interface{} {
	return struct {
		Foo string `json:"foo"`
	}{Foo: "foostring"}
}

type verifierFunc func(*testing.T, []byte)

func requireError(matchstring string) verifierFunc {
	type errorMessage struct {
		Error struct {
			Message string `json:"message,omitempty"`
		} `json:"error,omitempty"`
	}

	return func(t *testing.T, body []byte) {
		var msg errorMessage
		err := json.Unmarshal(body, &msg)
		if err != nil {
			panic(err)
		}
		if msg.Error.Message == "" {
			t.Errorf("Expected non-empty error, got %v", msg)
		}
		if matchstring == "" {
			return
		}
		if !strings.Contains(msg.Error.Message, matchstring) {
			t.Errorf("Expected '%s' to contain '%s'", msg.Error.Message, matchstring)
		}
	}
}

func stringEquals(t *testing.T, msg string, got string, want string) {
	if want != got {
		t.Errorf("Expected %s to be '%s', not '%s'", msg, want, got)
	}
}

var (
	goodCert = x509.Certificate{
		Subject: pkix.Name{
			OrganizationalUnit: []string{`{"purpose":"control"}`},
		},
	}

	wrongTypeCert = x509.Certificate{
		Subject: pkix.Name{
			OrganizationalUnit: []string{`{"purpose":"xxx"}`},
		},
	}

	invalidCert = x509.Certificate{}
)

func TestCNCServer_authenticate(t *testing.T) {
	tests := []struct {
		name   string
		method string
		cert   *x509.Certificate
		want   bool
	}{
		{"GET", "GET", &invalidCert, false},   // missing special OU JSON
		{"GET", "GET", &wrongTypeCert, false}, // wrong purpose
		{"GET", "POST", &goodCert, false},     // method missmatch
		{"GET", "GET", &goodCert, true},       // good!
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MakeCNCServer(nil, nil, nil, nil, "", "")
			h := handlerTracker{}
			r := httptest.NewRequest("GET", "https://localhost/statistics", nil)
			r.TLS.PeerCertificates = []*x509.Certificate{tt.cert}
			w := httptest.NewRecorder()
			c.authenticate(tt.method, h.handler())(w, r)
			if h.called != tt.want {
				t.Errorf("CNCServer.authenticate = %v, want %v, error %v", h.called, tt.want, w.Body)
			}
		})
	}
}

func TestCNCServer_generateKubectlComponents(t *testing.T) {
	checkFunc := func(t *testing.T, body []byte) {
		var response fwdapi.KubeConfigResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		stringEquals(t, "AgentName", response.AgentName, "agent smith")
		stringEquals(t, "Name", response.Name, "alice smith")
		stringEquals(t, "ServerURL", response.ServerURL, "https://service.local")
		stringEquals(t, "UserCertificate", response.UserCertificate, "b")
		stringEquals(t, "UserKey", response.UserKey, "c")
		stringEquals(t, "CACert", response.CACert, "a")
	}

	tests := []struct {
		name         string
		request      interface{}
		validateBody verifierFunc
		wantStatus   int
	}{
		{
			"badJSON",
			"badjson",
			requireError("json: cannot unmarshal"),
			http.StatusBadRequest,
		},
		{
			"missingName",
			fwdapi.KubeConfigRequest{},
			requireError(" is invalid"),
			http.StatusBadRequest,
		},
		{
			"working",
			fwdapi.KubeConfigRequest{
				AgentName: "agent smith",
				Name:      "alice smith",
			},
			checkFunc,
			http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MakeCNCServer(&mockConfig{}, &mockAuthority{}, nil, nil, "", "")

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			w := httptest.NewRecorder()
			h := c.generateKubectlComponents()
			h.ServeHTTP(w, r)

			if w.Result().StatusCode != tt.wantStatus {
				t.Errorf("Expected status code %d, got %d", tt.wantStatus, w.Code)
			}

			ct := w.Result().Header.Get("content-type")
			if ct != "application/json" {
				t.Errorf("Expected content-type to be application/json, not %s", ct)
			}

			resultBody, err := ioutil.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func TestCNCServer_generateAgentManifestComponents(t *testing.T) {
	checkFunc := func(t *testing.T, body []byte) {
		var response fwdapi.ManifestResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		stringEquals(t, "AgentName", response.AgentName, "agent smith")
		stringEquals(t, "ServerHostname", response.ServerHostname, "agent.local")
		stringEquals(t, "ServerPort", fmt.Sprintf("%d", response.ServerPort), "1234")
		stringEquals(t, "AgentCertificate", response.AgentCertificate, "b")
		stringEquals(t, "AgentKey", response.AgentKey, "c")
		stringEquals(t, "CACert", response.CACert, "a")
	}

	tests := []struct {
		name         string
		request      interface{}
		validateBody verifierFunc
		wantStatus   int
	}{
		{
			"badJSON",
			"badjson",
			requireError("json: cannot unmarshal"),
			http.StatusBadRequest,
		},
		{
			"missingName",
			fwdapi.ManifestRequest{},
			requireError("'agentName' is invalid"),
			http.StatusBadRequest,
		},
		{
			"working",
			fwdapi.ManifestRequest{AgentName: "agent smith"},
			checkFunc,
			http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MakeCNCServer(&mockConfig{}, &mockAuthority{}, nil, nil, "", "")

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			w := httptest.NewRecorder()
			h := c.generateAgentManifestComponents()
			h.ServeHTTP(w, r)

			if w.Result().StatusCode != tt.wantStatus {
				t.Errorf("Expected status code %d, got %d", tt.wantStatus, w.Code)
			}

			ct := w.Result().Header.Get("content-type")
			if ct != "application/json" {
				t.Errorf("Expected content-type to be application/json, not %s", ct)
			}

			resultBody, err := ioutil.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func MakeServiceCheckFunc() func(*testing.T, []byte) {
	return func(t *testing.T, body []byte) {
		var response fwdapi.ServiceCredentialResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		stringEquals(t, "AgentName", response.AgentName, "agent smith")
		stringEquals(t, "Name", response.Name, "service smith")
		stringEquals(t, "Type", response.Type, "jenkins")
		stringEquals(t, "URL", response.URL, "https://service.local")
		stringEquals(t, "CACert", response.CACert, "base64-cacert")
		stringEquals(t, "CredentialType", response.CredentialType, "basic")
		creds := response.Credential.(map[string]interface{})
		if len(creds) != 2 {
			t.Errorf("Unexpected keys: %#v", creds)
		}
		if _, found := creds["username"]; !found {
			t.Errorf("Credential does not have key 'username': %#v", creds)
		}
		if _, found := creds["password"]; !found {
			t.Errorf("Credential does not have key 'password': %#v", creds)
		}
	}
}

func MakeAWSCheckFunc() func(*testing.T, []byte) {
	return func(t *testing.T, body []byte) {
		var response fwdapi.ServiceCredentialResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		stringEquals(t, "AgentName", response.AgentName, "agent smith")
		stringEquals(t, "Name", response.Name, "service smith")
		stringEquals(t, "Type", response.Type, "aws")
		stringEquals(t, "URL", response.URL, "https://service.local")
		stringEquals(t, "CACert", response.CACert, "base64-cacert")
		stringEquals(t, "CredentialType", response.CredentialType, "aws")
		creds := response.Credential.(map[string]interface{})
		if len(creds) != 2 {
			t.Errorf("Unexpected keys: %#v", creds)
		}
		if _, found := creds["awsAccessKey"]; !found {
			t.Errorf("Credential does not have key 'awsAccessKey': %#v", creds)
		}
		if _, found := creds["awsSecretAccessKey"]; !found {
			t.Errorf("Credential does not have key 'awsSecretAccessKey': %#v", creds)
		}
	}
}

func TestCNCServer_generateServiceCredentials(t *testing.T) {
	serviceCheckFunc := MakeServiceCheckFunc()
	awsCheckFunc := MakeAWSCheckFunc()

	tests := []struct {
		name         string
		request      interface{}
		jwkKey       string
		validateBody verifierFunc
		wantStatus   int
	}{
		{
			"badJSON",
			"badjson",
			"key1",
			requireError("json: cannot unmarshal"),
			http.StatusBadRequest,
		},
		{
			"missingName",
			fwdapi.ServiceCredentialRequest{},
			"key1",
			requireError("is invalid"),
			http.StatusBadRequest,
		},
		{
			"working",
			fwdapi.ServiceCredentialRequest{
				AgentName: "agent smith",
				Type:      "jenkins",
				Name:      "service smith",
			},
			"key1",
			serviceCheckFunc,
			http.StatusOK,
		},
		{
			"bad-jwt-key",
			fwdapi.ServiceCredentialRequest{
				AgentName: "agent smith",
				Type:      "jenkins",
				Name:      "service smith",
			},
			"missingKey",
			requireError("unable to find service key"),
			http.StatusBadRequest,
		},
		{
			"aws",
			fwdapi.ServiceCredentialRequest{
				AgentName: "agent smith",
				Type:      "aws",
				Name:      "service smith",
			},
			"key1",
			awsCheckFunc,
			http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1, err := jwk.New([]byte("key 1"))
			if err != nil {
				panic(err)
			}
			err = key1.Set(jwk.KeyIDKey, "key1")
			if err != nil {
				panic(err)
			}
			err = key1.Set(jwk.AlgorithmKey, jwa.HS256)
			if err != nil {
				panic(err)
			}
			keys := jwk.NewSet()
			keys.Add(key1)
			c := MakeCNCServer(&mockConfig{}, &mockAuthority{}, nil, keys, tt.jwkKey, "")

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			w := httptest.NewRecorder()
			h := c.generateServiceCredentials()
			h.ServeHTTP(w, r)

			if w.Result().StatusCode != tt.wantStatus {
				t.Errorf("Expected status code %d, got %d", tt.wantStatus, w.Code)
			}

			ct := w.Result().Header.Get("content-type")
			if ct != "application/json" {
				t.Errorf("Expected content-type to be application/json, not %s", ct)
			}

			resultBody, err := ioutil.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func TestCNCServer_generateControlCredentials(t *testing.T) {
	checkFunc := func(t *testing.T, body []byte) {
		var response fwdapi.ControlCredentialsResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		stringEquals(t, "Name", response.Name, "contra smith")
		stringEquals(t, "URL", response.URL, "https://control.local")
		stringEquals(t, "Certificate", response.Certificate, "b")
		stringEquals(t, "Key", response.Key, "c")
		stringEquals(t, "CACert", response.CACert, "a")
	}

	tests := []struct {
		name         string
		request      interface{}
		validateBody verifierFunc
		wantStatus   int
	}{
		{
			"badJSON",
			"badjson",
			requireError("json: cannot unmarshal"),
			http.StatusBadRequest,
		},
		{
			"missingName",
			fwdapi.ControlCredentialsRequest{},
			requireError("'name' is invalid"),
			http.StatusBadRequest,
		},
		{
			"working",
			fwdapi.ControlCredentialsRequest{Name: "contra smith"},
			checkFunc,
			http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MakeCNCServer(&mockConfig{}, &mockAuthority{}, nil, nil, "", "")

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			w := httptest.NewRecorder()
			h := c.generateControlCredentials()
			h.ServeHTTP(w, r)

			if w.Result().StatusCode != tt.wantStatus {
				t.Errorf("Expected status code %d, got %d", tt.wantStatus, w.Code)
			}

			ct := w.Result().Header.Get("content-type")
			if ct != "application/json" {
				t.Errorf("Expected content-type to be application/json, not %s", ct)
			}

			resultBody, err := ioutil.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func TestCNCServer_getStatistics(t *testing.T) {
	t.Run("getCredentials", func(t *testing.T) {
		c := MakeCNCServer(nil, nil, &mockAgents{}, nil, "", "")

		r := httptest.NewRequest("GET", "https://localhost/foo", nil)
		w := httptest.NewRecorder()
		h := c.getStatistics()
		h.ServeHTTP(w, r)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
		}

		ct := w.Result().Header.Get("content-type")
		if ct != "application/json" {
			t.Errorf("Expected content-type to be application/json, not %s", ct)
		}

		resultBody, err := ioutil.ReadAll(w.Result().Body)
		if err != nil {
			panic(err)
		}
		if !strings.Contains(string(resultBody), `"connectedAgents":{"foo":"foostring"}`) {
			t.Errorf("body invalid: %s", string(resultBody))
		}
	})
}
