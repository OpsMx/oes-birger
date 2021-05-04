package main

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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/oklog/ulid/v2"
	"github.com/opsmx/oes-birger/pkg/ca"
	"github.com/opsmx/oes-birger/pkg/fwdapi"
)

type cncCertificateAuthority interface {
	ca.CertificateIssuer
	ca.CertPoolGenerator
}

type cncConfig interface {
	GetAgentHostname() string
	GetAgentAdvertisePort() uint16
	GetServiceURL() string
	GetControlURL() string
	GetControlListenPort() uint16
}

type cncServer struct {
	cfg cncConfig
	ca  cncCertificateAuthority
}

func MakeCNCServer(config cncConfig, authority cncCertificateAuthority) *cncServer {
	return &cncServer{
		cfg: config,
		ca:  authority,
	}
}

func (c *cncServer) authenticate(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			err := fmt.Errorf("only '%s' is accepted (not '%s')", method, r.Method)
			failrequest(w, err, http.StatusMethodNotAllowed)
			return
		}

		names, err := ca.GetCertificateNameFromCert(r.TLS.PeerCertificates[0])
		if err != nil {
			failrequest(w, err, http.StatusForbidden)
			return
		}
		if names.Purpose != ca.CertificatePurposeControl {
			err := fmt.Errorf("certificate is not authorized for 'control': %s", names.Purpose)
			failrequest(w, err, http.StatusForbidden)
			return
		}

		h(w, r)
	}
}

func (s *cncServer) decodeKubectlRequest(j io.Reader) (*fwdapi.KubeConfigRequest, error) {
	var req fwdapi.KubeConfigRequest
	err := json.NewDecoder(j).Decode(&req)
	if err != nil {
		return nil, err
	}

	err = req.Validate()
	if err != nil {
		return nil, err
	}

	return &req, nil
}

func (s *cncServer) generateKubectlComponents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		req, err := s.decodeKubectlRequest(r.Body)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		name := ca.CertificateName{
			Name:    req.Name,
			Type:    "kubernetes",
			Agent:   req.AgentName,
			Purpose: ca.CertificatePurposeService,
		}
		ca64, user64, key64, err := s.ca.GenerateCertificate(name)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		ret := fwdapi.KubeConfigResponse{
			AgentName:       req.AgentName,
			Name:            req.Name,
			ServerURL:       s.cfg.GetServiceURL(),
			UserCertificate: user64,
			UserKey:         key64,
			CACert:          ca64,
		}
		json, err := json.Marshal(ret)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		w.Write(json)
	}
}

func (s *cncServer) generateAgentManifestComponents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		var req fwdapi.ManifestRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		err = req.Validate()
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		name := ca.CertificateName{
			Agent:   req.AgentName,
			Purpose: ca.CertificatePurposeAgent,
		}
		ca64, user64, key64, err := s.ca.GenerateCertificate(name)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		ret := fwdapi.ManifestResponse{
			AgentName:        req.AgentName,
			ServerHostname:   s.cfg.GetAgentHostname(),
			ServerPort:       s.cfg.GetAgentAdvertisePort(),
			AgentCertificate: user64,
			AgentKey:         key64,
			CACert:           ca64,
		}
		json, err := json.Marshal(ret)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		w.Write(json)
	}
}

func (s *cncServer) getStatistics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		ret := fwdapi.StatisticsResponse{
			ServerTime:      ulid.Now(),
			Version:         version.String(),
			ConnectedAgents: agents.GetStatistics(),
		}
		json, err := json.Marshal(ret)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		w.Write(json)
	}
}

func (s *cncServer) generateServiceCredentials() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		var req fwdapi.ServiceCredentialRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		err = req.Validate()
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		var key jwk.Key
		var ok bool
		if key, ok = jwtKeyset.LookupKeyID(jwtCurrentKey); !ok {
			err := fmt.Errorf("unable to find service key '%s'", jwtCurrentKey)
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		token, err := MakeJWT(key, req.Type, req.Name, req.AgentName)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		ret := fwdapi.ServiceCredentialResponse{
			AgentName: req.AgentName,
			Name:      req.Name,
			Type:      req.Type,
			URL:       s.cfg.GetServiceURL(),
			CACert:    s.ca.GetCACert(),
		}

		username := fmt.Sprintf("%s.%s", req.Name, req.AgentName)

		switch req.Type {
		case "aws":
			ret.CredentialType = "aws"
			ret.Credential = fwdapi.AwsCredentialResponse{
				AwsAccessKey:       username,
				AwsSecretAccessKey: token,
			}
		default:
			ret.Username = username // deprecated
			ret.Password = token    // deprecated
			ret.CredentialType = "basic"
			ret.Credential = fwdapi.BasicCredentialResponse{
				Username: username,
				Password: token,
			}
		}
		json, err := json.Marshal(ret)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		w.Write(json)
	}
}

func (s *cncServer) generateControlCredentials() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		var req fwdapi.ControlCredentialsRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}

		name := ca.CertificateName{
			Name:    req.Name,
			Purpose: ca.CertificatePurposeAgent,
		}
		ca64, user64, key64, err := s.ca.GenerateCertificate(name)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		ret := fwdapi.ControlCredentialsResponse{
			Name:        req.Name,
			URL:         s.cfg.GetControlURL(),
			Certificate: user64,
			Key:         key64,
			CACert:      ca64,
		}
		json, err := json.Marshal(ret)
		if err != nil {
			failrequest(w, err, http.StatusBadRequest)
			return
		}
		w.Write(json)
	}
}

func (s *cncServer) routes(mux *http.ServeMux) {
	mux.HandleFunc(fwdapi.KUBECONFIG_ENDPOINT,
		s.authenticate("POST", s.generateKubectlComponents()))

	mux.HandleFunc(fwdapi.MANIFEST_ENDPOINT,
		s.authenticate("POST", s.generateAgentManifestComponents()))

	mux.HandleFunc(fwdapi.SERVICE_ENDPOINT,
		s.authenticate("POST", s.generateServiceCredentials()))

	mux.HandleFunc(fwdapi.CONTROL_ENDPOINT,
		s.authenticate("POST", s.generateControlCredentials()))

	mux.HandleFunc(fwdapi.STATISTICS_ENDPOINT,
		s.authenticate("GET", s.getStatistics()))

}

func (s *cncServer) runCommandHTTPServer(serverCert tls.Certificate) {
	log.Printf("Running Command and Control API HTTPS listener on port %d",
		s.cfg.GetControlListenPort())

	certPool, err := authority.MakeCertPool()
	if err != nil {
		log.Fatalf("While making certpool: %v", err)
	}

	tlsConfig := &tls.Config{
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()

	s.routes(mux)

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", s.cfg.GetControlListenPort()),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}
