package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/oklog/ulid/v2"
	"github.com/opsmx/oes-birger/pkg/ca"
	"github.com/opsmx/oes-birger/pkg/fwdapi"
)

func httpError(err error) []byte {
	ret := &fwdapi.HttpErrorResponse{
		Error: &fwdapi.HttpErrorMessage{
			Message: fmt.Sprintf("Unable to process request: %v", err),
		},
	}
	json, err := json.Marshal(ret)
	if err != nil {
		return []byte(`{"error":{"message":"Unknown Error"}}`)
	}
	return json
}

func cncGenerateKubectlComponents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	statusCode, err := authenticate(r, "POST")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(statusCode)
		return
	}

	var req fwdapi.KubeConfigRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = req.Validate()
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	name := ca.CertificateName{
		Name:    req.Name,
		Type:    "kubernetes",
		Agent:   req.AgentName,
		Purpose: ca.CertificatePurposeService,
	}
	ca64, user64, key64, err := authority.GenerateCertificate(name)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ret := fwdapi.KubeConfigResponse{
		AgentName:       req.AgentName,
		Name:            req.Name,
		ServerURL:       config.getServiceURL(),
		UserCertificate: user64,
		UserKey:         key64,
		CACert:          ca64,
	}
	json, err := json.Marshal(ret)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write(json)
}

func authenticate(r *http.Request, method string) (int, error) {
	names, err := ca.GetCertificateNameFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		return http.StatusForbidden, err
	}
	if names.Purpose != ca.CertificatePurposeControl {
		return http.StatusForbidden, fmt.Errorf("identity is not authorized for 'control': %v", names)
	}
	if r.Method != method {
		return http.StatusMethodNotAllowed, fmt.Errorf("only '%s' is accepted (not '%s')", method, r.Method)
	}
	return -1, nil
}

func cncGenerateAgentManifestComponents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	statusCode, err := authenticate(r, "POST")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(statusCode)
		return
	}

	var req fwdapi.ManifestRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = req.Validate()
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	name := ca.CertificateName{
		Agent:   req.AgentName,
		Purpose: ca.CertificatePurposeAgent,
	}
	ca64, user64, key64, err := authority.GenerateCertificate(name)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ret := fwdapi.ManifestResponse{
		AgentName:        req.AgentName,
		ServerHostname:   *config.AgentHostname,
		ServerPort:       config.AgentPort,
		AgentCertificate: user64,
		AgentKey:         key64,
		CACert:           ca64,
	}
	json, err := json.Marshal(ret)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write(json)
}

func cncGetStatistics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	statusCode, err := authenticate(r, "GET")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(statusCode)
		return
	}

	ret := fwdapi.StatisticsResponse{
		ServerTime:      ulid.Now(),
		ConnectedAgents: agents.GetStatistics(),
	}
	json, err := json.Marshal(ret)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write(json)
}

func cncGenerateServiceCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	statusCode, err := authenticate(r, "POST")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(statusCode)
		return
	}

	var req fwdapi.ServiceCredentialRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = req.Validate()
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var key jwk.Key
	var ok bool
	if key, ok = jwtKeyset.LookupKeyID(jwtCurrentKey); !ok {
		w.Write(httpError(fmt.Errorf("unable to find service key '%s'", jwtCurrentKey)))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := MakeJWT(key, req.Type, req.Name, req.AgentName)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(statusCode)
		return
	}

	ret := fwdapi.ServiceCredentialResponse{
		AgentName: req.AgentName,
		Name:      req.Name,
		Type:      req.Type,
		Username:  fmt.Sprintf("%s.%s", req.Name, req.AgentName),
		Password:  token,
		URL:       config.getServiceURL(),
		CACert:    authority.GetCACert(),
	}
	json, err := json.Marshal(ret)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write(json)
}

func cncGenerateControlCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	statusCode, err := authenticate(r, "POST")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(statusCode)
		return
	}

	var req fwdapi.ControlCredentialsRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	name := ca.CertificateName{
		Name:    req.Name,
		Purpose: ca.CertificatePurposeAgent,
	}
	ca64, user64, key64, err := authority.GenerateCertificate(name)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ret := fwdapi.ControlCredentialsResponse{
		Name:        req.Name,
		URL:         config.getControlURL(),
		Certificate: user64,
		Key:         key64,
		CACert:      ca64,
	}
	json, err := json.Marshal(ret)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write(json)
}

func runCommandHTTPServer(serverCert tls.Certificate) {
	log.Printf("Running Command and Control API HTTPS listener on port %d", config.ControlPort)

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

	mux.HandleFunc(fwdapi.KUBECONFIG_ENDPOINT, cncGenerateKubectlComponents)
	mux.HandleFunc(fwdapi.MANIFEST_ENDPOINT, cncGenerateAgentManifestComponents)
	mux.HandleFunc(fwdapi.SERVICE_ENDPOINT, cncGenerateServiceCredentials)
	mux.HandleFunc(fwdapi.CONTROL_ENDPOINT, cncGenerateControlCredentials)
	mux.HandleFunc(fwdapi.STATISTICS_ENDPOINT, cncGetStatistics)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.ControlPort),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	server.ListenAndServeTLS("", "")
}
