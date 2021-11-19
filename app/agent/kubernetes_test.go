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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

var (
	goodX509      = x509.Certificate{Raw: []byte("cert1")}
	wrongTypeX509 = x509.Certificate{Raw: []byte("cert2")}
	goodTLS       = tls.Certificate{Certificate: [][]byte{goodX509.Raw}}
	wrongTypeTLS  = tls.Certificate{Certificate: [][]byte{wrongTypeX509.Raw}}
)

func TestKubernetesTLSCertCompare(t *testing.T) {
	tests := []struct {
		name string
		c1   *tls.Certificate
		c2   *tls.Certificate
		want bool
	}{
		{"both-nil", nil, nil, true},
		{"c1-nil", nil, &goodTLS, false},
		{"c2-nil", &goodTLS, nil, false},
		{"different", &goodTLS, &wrongTypeTLS, false},
		{"same", &goodTLS, &goodTLS, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tlsCertEqual(tt.c1, tt.c2) != tt.want {
				t.Errorf("%s failed: got %v, wanted %v", tt.name, tt.want, !tt.want)
			}
		})
	}
}

func TestKubernetesx509CertCompare(t *testing.T) {
	tests := []struct {
		name string
		c1   *x509.Certificate
		c2   *x509.Certificate
		want bool
	}{
		{"both-nil", nil, nil, true},
		{"c1-nil", nil, &goodX509, false},
		{"c2-nil", &goodX509, nil, false},
		{"different", &goodX509, &wrongTypeX509, false},
		{"same", &goodX509, &goodX509, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if x509CertEqual(tt.c1, tt.c2) != tt.want {
				t.Errorf("%s failed: got %v, wanted %v", tt.name, tt.want, !tt.want)
			}
		})
	}
}
