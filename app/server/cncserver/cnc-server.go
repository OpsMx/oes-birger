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

// Package cncserver implements all the control endpoints needed to
// request various types of secrets and statistics about the running
// controller.
package cncserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/OpsMx/go-app-base/version"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/oklog/ulid/v2"
	"github.com/opsmx/oes-birger/internal/ca"
	"github.com/opsmx/oes-birger/internal/fwdapi"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/opsmx/oes-birger/internal/logging"
	"github.com/opsmx/oes-birger/internal/util"
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

type cncAgentStatsReporter interface {
	GetStatistics() interface{}
}

// CNCServer holds the context for a specific instance of a command and control http server.
type CNCServer struct {
	cfg           cncConfig
	agentReporter cncAgentStatsReporter
	version       string
	clock         jwt.Clock
}

// MakeCNCServer creates a new CNC server from the provided config.
func MakeCNCServer(
	config cncConfig,
	agents cncAgentStatsReporter,
	vers string,
	clock jwt.Clock,
) *CNCServer {
	return &CNCServer{
		cfg:           config,
		agentReporter: agents,
		version:       vers,
		clock:         clock,
	}
}

func (s *CNCServer) authenticate(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Method != method {
			err := fmt.Errorf("only '%s' is accepted (not '%s')", method, r.Method)
			util.FailRequest(ctx, w, err, http.StatusMethodNotAllowed)
			return
		}

		names, err := ca.GetCertificateNameFromCert(r.TLS.PeerCertificates[0])
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusForbidden)
			return
		}
		if names.Purpose != ca.CertificatePurposeControl {
			err := fmt.Errorf("certificate is not authorized for 'control': %s", names.Purpose)
			util.FailRequest(ctx, w, err, http.StatusForbidden)
			return
		}

		h(w, r)
	}
}

func (s *CNCServer) generateKubectlComponents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Set("content-type", "application/json")

		var req fwdapi.KubeConfigRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		err = req.Validate()
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		name := ca.CertificateName{
			Name:    req.Name,
			Type:    "kubernetes",
			Agent:   req.AgentName,
			Purpose: ca.CertificatePurposeService,
		}
		ca64, user64, key64, err := s.authority.GenerateCertificate(name)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
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
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}
		n, err := w.Write(json)
		if err != nil {
			log.Printf("generateKubectlComponents: error while writing: %v", err)
			return
		}
		if n != len(json) {
			log.Printf("generateKubectlComponents: failed to write entire message: %d of %d written", n, len(json))
			return
		}
	}
}

func (s *CNCServer) generateAgentManifestComponents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := logging.WithContext(ctx).Sugar()
		w.Header().Set("content-type", "application/json")

		var req fwdapi.ManifestRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		err = req.Validate()
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		jwt, err := jwtutil.MakeAgentJWT(req.AgentName, s.clock)
		if err != nil {
			logger.Errorf("MakeAgentJWT failed: %v", err)
			util.FailRequest(ctx, w, err, http.StatusInternalServerError)
			return
		}
		ret := fwdapi.ManifestResponse{
			AgentName:      req.AgentName,
			ServerHostname: s.cfg.GetAgentHostname(),
			ServerPort:     s.cfg.GetAgentAdvertisePort(),
			AgentVersion:   version.GitBranch(),
			AgentToken:     jwt,
		}
		if version.BuildType() != "release" {
			ret.AgentVersion = "latest"
		}
		json, err := json.Marshal(ret)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}
		n, err := w.Write(json)
		if err != nil {
			log.Printf("generateAgentManifestComponents: error while writing: %v", err)
			return
		}
		if n != len(json) {
			log.Printf("generateAgentManifestComponents: failed to write entire message: %d of %d written", n, len(json))
			return
		}
	}
}

func (s *CNCServer) generateServiceCredentials() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Set("content-type", "application/json")

		var req fwdapi.ServiceCredentialRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		err = req.Validate(ctx)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		token, err := jwtutil.MakeServiceJWT(req.Type, req.Name, req.AgentName, s.clock)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		ret := fwdapi.ServiceCredentialResponse{
			AgentName: req.AgentName,
			Name:      req.Name,
			Type:      req.Type,
			URL:       s.cfg.GetServiceURL(),
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
			ret.CredentialType = "basic"
			ret.Credential = fwdapi.BasicCredentialResponse{
				Username: username,
				Password: token,
			}
		}
		json, err := json.Marshal(ret)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}
		n, err := w.Write(json)
		if err != nil {
			log.Printf("generateServiceCredentials: error while writing: %v", err)
			return
		}
		if n != len(json) {
			log.Printf("generateServiceCredentials: failed to write entire message: %d of %d written", n, len(json))
			return
		}
	}
}

func (s *CNCServer) generateControlCredentials() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Set("content-type", "application/json")

		var req fwdapi.ControlCredentialsRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		err = req.Validate()
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		token, err := jwtutil.MakeServiceJWT(req.Type, req.Name, req.AgentName, s.clock)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}

		ret := fwdapi.ControlCredentialsResponse{
			Name:  req.Name,
			URL:   s.cfg.GetControlURL(),
			Token: jwt,
		}
		json, err := json.Marshal(ret)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}
		n, err := w.Write(json)
		if err != nil {
			log.Printf("generateControlCredentials: error while writing: %v", err)
			return
		}
		if n != len(json) {
			log.Printf("generateControlCredentials: failed to write entire message: %d of %d written", n, len(json))
			return
		}
	}
}

func (s *CNCServer) getStatistics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Set("content-type", "application/json")

		ret := fwdapi.StatisticsResponse{
			ServerTime:      ulid.Now(),
			Version:         s.version,
			ConnectedAgents: s.agentReporter.GetStatistics(),
		}
		json, err := json.Marshal(ret)
		if err != nil {
			util.FailRequest(ctx, w, err, http.StatusBadRequest)
			return
		}
		n, err := w.Write(json)
		if err != nil {
			log.Printf("getStatistics: error while writing: %v", err)
			return
		}
		if n != len(json) {
			log.Printf("getStatistics: failed to write entire message: %d of %d written", n, len(json))
			return
		}
	}
}

func (s *CNCServer) routes(mux *http.ServeMux) {
	mux.HandleFunc(fwdapi.KubeconfigEndpoint,
		s.authenticate("POST", s.generateKubectlComponents()))

	mux.HandleFunc(fwdapi.ManifestEndpoint,
		s.authenticate("POST", s.generateAgentManifestComponents()))

	mux.HandleFunc(fwdapi.ServiceEndpoint,
		s.authenticate("POST", s.generateServiceCredentials()))

	mux.HandleFunc(fwdapi.ControlEndpoint,
		s.authenticate("POST", s.generateControlCredentials()))

	mux.HandleFunc(fwdapi.StatisticsEndpoint,
		s.authenticate("GET", s.getStatistics()))

}

// RunServer will start the HTTPS server and serve requests.
func (s *CNCServer) RunServer(serverCert *tls.Certificate) {

	mux := http.NewServeMux()
	s.routes(mux)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.cfg.GetControlListenPort()),
		Handler: mux,
	}

	if serverCert != nil {
		log.Printf("Running Command and Control API HTTPS listener on port %d", s.cfg.GetControlListenPort())
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*serverCert},
			MinVersion:   tls.VersionTLS13,
		}
		srv.TLSConfig = tlsConfig
		log.Fatal(srv.ListenAndServeTLS("", ""))
	} else {
		log.Printf("Running Command and Control API HTTP listener on port %d", s.cfg.GetControlListenPort())
		log.Fatal(srv.ListenAndServe())
	}
}
