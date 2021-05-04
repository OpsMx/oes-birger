package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opsmx/oes-birger/pkg/ca"
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
			c := &CNCServer{}
			h := handlerTracker{}
			r := httptest.NewRequest("GET", "https://localhost/statistics", nil)
			r.TLS.PeerCertificates = []*x509.Certificate{tt.cert}
			w := httptest.NewRecorder()
			mux := http.NewServeMux()
			c.routes(mux)
			c.authenticate(tt.method, h.handler())(w, r)
			if h.called != tt.want {
				t.Errorf("CNCServer.authenticate = %v, want %v, error %v", h.called, tt.want, w.Body)
			}
		})
	}
}
