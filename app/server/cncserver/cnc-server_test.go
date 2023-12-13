package cncserver

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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opsmx/oes-birger/internal/fwdapi"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/skandragon/jwtregistry/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

const (
	goodJWT      = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214Lm5hbWUiOiJib2IiLCJvcHNteC5wdXJwb3NlIjoiY29udHJvbCJ9.rE-Jlbd3Qkh1vW0xU62mGUqVMBgj_2_jH_yEkhdRgNE"
	wrongTypeJWT = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214Lm5hbWUiOiJib2IiLCJvcHNteC5wdXJwb3NlIjoid3JvbmcifQ.0v6aVtbDk62gP-1URP7JHMk0riYABXD3ePu2LTPMRbQ"
)

var (
	testclock = &jwtregistry.TimeClock{NowTime: 1234}
)

func TestCNCServer_authenticate(t *testing.T) {
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterControlKeyset(keyset, "key1")
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		token  string
		want   bool
	}{
		{"GET", "GET", wrongTypeJWT, false}, // wrong purpose
		{"GET", "POST", goodJWT, false},     // method missmatch
		{"GET", "GET", goodJWT, true},       // good!
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MakeCNCServer(nil, nil, "", testclock)
			h := handlerTracker{}
			r := httptest.NewRequest("GET", "https://localhost/statistics", nil)
			r.Header.Set("authorization", "Bearer "+tt.token)
			w := httptest.NewRecorder()
			c.authenticate(tt.method, h.handler())(w, r)
			if h.called != tt.want {
				t.Errorf("CNCServer.authenticate = %v, want %v, error %v", h.called, tt.want, w.Body)
			}
		})
	}
}

func TestCNCServer_generateKubectlComponents(t *testing.T) {
	{
		keyset := jwtutil.LoadTestKeys(t)
		err := jwtutil.RegisterControlKeyset(keyset, "key1")
		require.NoError(t, err)
	}
	{
		keyset := jwtutil.LoadTestKeys(t)
		err := jwtutil.RegisterServiceKeyset(keyset, "key1")
		require.NoError(t, err)
	}

	checkFunc := func(t *testing.T, body []byte) {

		var response fwdapi.KubeConfigResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			log.Printf("body: %s", string(body))
			panic(err)
		}
		assert.Equal(t, "agent smith", response.AgentName)
		assert.Equal(t, "alice smith", response.Name)
		assert.Equal(t, "https://service.local", response.ServerURL)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQgc21pdGgiLCJpYXQiOjEyMzQsImlzcyI6Im9wc214IiwibiI6ImFsaWNlIHNtaXRoIiwib3BzbXgucHVycG9zZSI6InNlcnZpY2UiLCJ0Ijoia3ViZXJuZXRlcyJ9.qAYKWyP9Rocpay5VNkZYNs4ShL3ktG7oxJQkUlYHCTg", response.Token)
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
			c := MakeCNCServer(&mockConfig{}, nil, "", testclock)

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			r.Header.Set("authorization", "Bearer "+goodJWT)
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

			resultBody, err := io.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func TestCNCServer_generateAgentManifestComponents(t *testing.T) {
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterControlKeyset(keyset, "key1")
	require.NoError(t, err)

	checkFunc := func(t *testing.T, body []byte) {
		var response fwdapi.ManifestResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		assert.Equal(t, "agent smith", response.AgentName)
		assert.Equal(t, "agent.local", response.ServerHostname)
		assert.Equal(t, "1234", fmt.Sprintf("%d", response.ServerPort))
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsImtpZCI6ImFnZW50a2V5MSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjEyMzQsImlzcyI6Im9wc214LWFnZW50LWF1dGgiLCJvcHNteC5hZ2VudC5uYW1lIjoiYWdlbnQgc21pdGgiLCJvcHNteC5wdXJwb3NlIjoiYWdlbnQifQ.f3kMIDFpxrt9Xm_Qk8F69w3LiitfBphfvvEXeBNm0_c", response.AgentToken)
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
			keyset := makeTestKeyset("agentkey1")
			if err := jwtutil.RegisterAgentKeyset(keyset, "agentkey1"); err != nil {
				panic(err)
			}
			c := MakeCNCServer(&mockConfig{}, nil, "", testclock)

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			r.Header.Set("authorization", "Bearer "+goodJWT)
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

			resultBody, err := io.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func MakeServiceCheckFunc() func(*testing.T, []byte) {
	return func(t *testing.T, body []byte) {
		keyset := jwtutil.LoadTestKeys(t)
		err := jwtutil.RegisterControlKeyset(keyset, "key1")
		require.NoError(t, err)

		var response fwdapi.ServiceCredentialResponse
		err = json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		assert.Equal(t, "agent smith", response.AgentName)
		assert.Equal(t, "service smith", response.Name)
		assert.Equal(t, "jenkins", response.Type)
		assert.Equal(t, "https://service.local", response.URL)
		assert.Equal(t, "basic", response.CredentialType)
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
		keyset := jwtutil.LoadTestKeys(t)
		err := jwtutil.RegisterControlKeyset(keyset, "key1")
		require.NoError(t, err)

		var response fwdapi.ServiceCredentialResponse
		err = json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		assert.Equal(t, "agent smith", response.AgentName)
		assert.Equal(t, "service smith", response.Name)
		assert.Equal(t, "aws", response.Type)
		assert.Equal(t, "https://service.local", response.URL)
		assert.Equal(t, "aws", response.CredentialType)
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
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterControlKeyset(keyset, "key1")
	require.NoError(t, err)

	serviceCheckFunc := MakeServiceCheckFunc()
	awsCheckFunc := MakeAWSCheckFunc()

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
			fwdapi.ServiceCredentialRequest{},
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
			serviceCheckFunc,
			http.StatusOK,
		},
		{
			"aws",
			fwdapi.ServiceCredentialRequest{
				AgentName: "agent smith",
				Type:      "aws",
				Name:      "service smith",
			},
			awsCheckFunc,
			http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyset := makeTestKeyset("key1")
			if err := jwtutil.RegisterServiceKeyset(keyset, "key1"); err != nil {
				panic(err)
			}
			c := MakeCNCServer(&mockConfig{}, nil, "", testclock)

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			r.Header.Set("authorization", "Bearer "+goodJWT)
			w := httptest.NewRecorder()
			h := c.generateServiceCredentials()
			h.ServeHTTP(w, r)

			assert.Equal(t, tt.wantStatus, w.Result().StatusCode)
			assert.Equal(t, "application/json", w.Result().Header.Get("content-type"), "incorrect returned content type")

			resultBody, err := io.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func makeTestKeyset(keyid string) jwk.Set {
	key, err := jwk.FromRaw([]byte("keydata+" + keyid))
	if err != nil {
		panic(err)
	}
	if err := key.Set(jwk.KeyIDKey, keyid); err != nil {
		panic(err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.HS256); err != nil {
		panic(err)
	}
	keyset := jwk.NewSet()
	if err := keyset.AddKey(key); err != nil {
		panic(err)
	}
	return keyset
}

func TestCNCServer_generateControlCredentials(t *testing.T) {
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterControlKeyset(keyset, "key1")
	require.NoError(t, err)

	checkFunc := func(t *testing.T, body []byte) {
		var response fwdapi.ControlCredentialsResponse
		err := json.Unmarshal(body, &response)
		if err != nil {
			panic(err)
		}
		assert.Equal(t, "contra smith", response.Name)
		assert.Equal(t, "https://control.local", response.URL)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjEyMzQsImlzcyI6Im9wc214LWNvbnRyb2wtYXV0aCIsIm9wc214Lm5hbWUiOiJjb250cmEgc21pdGgiLCJvcHNteC5wdXJwb3NlIjoiY29udHJvbCJ9.so_DhMqNtPFlorGgDn2_88z4DKhqt26fI9bw_XrTgLY",
			response.Token)
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
			c := MakeCNCServer(&mockConfig{}, nil, "", testclock)

			body, err := json.Marshal(tt.request)
			if err != nil {
				panic(err)
			}

			r := httptest.NewRequest("POST", "https://localhost/foo", bytes.NewReader(body))
			r.Header.Set("authorization", "Bearer "+goodJWT)
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

			resultBody, err := io.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}

func TestCNCServer_getStatistics(t *testing.T) {
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterControlKeyset(keyset, "key1")
	require.NoError(t, err)

	t.Run("getCredentials", func(t *testing.T) {
		c := MakeCNCServer(nil, &mockAgents{}, "", testclock)

		r := httptest.NewRequest("GET", "https://localhost/foo", nil)
		r.Header.Set("authorization", "Bearer "+goodJWT)
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

		resultBody, err := io.ReadAll(w.Result().Body)
		if err != nil {
			panic(err)
		}
		if !strings.Contains(string(resultBody), `"connectedAgents":{"foo":"foostring"}`) {
			t.Errorf("body invalid: %s", string(resultBody))
		}
	})
}
