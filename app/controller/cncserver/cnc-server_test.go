package cncserver

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

var (
	goodCert = x509.Certificate{
		Subject: pkix.Name{
			Names: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, ca.OPSMX_OID_VALUE},
					Value: `{"purpose":"control"}`,
				},
			},
		},
	}

	wrongTypeCert = x509.Certificate{
		Subject: pkix.Name{
			Names: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, ca.OPSMX_OID_VALUE},
					Value: `{"purpose":"xxx"}`,
				},
			},
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
		{"GET", "GET", &invalidCert, false},   // missing special OID
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

func (*mockAuthority) GetCACert() string {
	return ""
}

func (*mockAuthority) MakeCertPool() (*x509.CertPool, error) {
	return nil, nil
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

func TestCNCServer_generateKubectlComponents(t *testing.T) {
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
			mc := &mockConfig{}
			auth := &mockAuthority{}
			c := MakeCNCServer(mc, auth, nil, nil, "", "")

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

			resultBody, err := ioutil.ReadAll(w.Result().Body)
			if err != nil {
				panic(err)
			}

			tt.validateBody(t, resultBody)
		})
	}
}
