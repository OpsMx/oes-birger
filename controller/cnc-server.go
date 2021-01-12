package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type kubeConfigRequest struct {
	Identity string `json:"identity"`
}

type kubeConfigResponse struct {
	Identity        string `json:"identity"`
	ServerURL       string `json:"serverUrl"`
	UserCertificate string `json:"userCertificate"`
	UserKey         string `json:"userKey"`
	CACert          string `json:"caCert"`
}

type manifestRequest struct {
	Identity string `json:"identity"`
}

type manifestResponse struct {
	Identity         string `json:"identity"`
	ServerHostname   string `json:"serverHostname"`
	ServerPort       uint16 `json:"serverPort"`
	AgentCertificate string `json:"agentCertificate"`
	AgentKey         string `json:"agnetKey"`
	CACert           string `json:"caCert"`
}

type httpErrorMessage struct {
	Message string `json:"message"`
}

type httpErrorResponse struct {
	Error *httpErrorMessage `json:"error"`
}

func httpError(err error) []byte {
	ret := &httpErrorResponse{
		Error: &httpErrorMessage{
			Message: fmt.Sprintf("Unable to process request: %v", err),
		},
	}
	json, err := json.Marshal(ret)
	if err != nil {
		return []byte("{\"error\":{\"message\":\"Unknown Error\"}}")
	}
	return json
}

func cncGenerateKubectlComponents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	names := strings.Split(r.TLS.PeerCertificates[0].Subject.CommonName, ".")
	if names[1] != "command" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req kubeConfigRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	serverURL := fmt.Sprintf("https://%s:%d", config.ServerNames[0], config.APIPort)

	ca64, user64, key64, err := authority.GenerateCertificate(req.Identity, "client")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
	}
	ret := kubeConfigResponse{
		Identity:        req.Identity,
		ServerURL:       serverURL,
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

func cncGenerateAgentManifestComponents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	names := strings.Split(r.TLS.PeerCertificates[0].Subject.CommonName, ".")
	if names[1] != "command" {
		w.Write(httpError(fmt.Errorf("identity does not end with 'command': %v", names)))
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		w.Write(httpError(fmt.Errorf("only 'POST' is accepted")))
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req manifestRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ca64, user64, key64, err := authority.GenerateCertificate(req.Identity, "agent")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
	}
	ret := manifestResponse{
		Identity:         req.Identity,
		ServerHostname:   config.ServerNames[0],
		ServerPort:       config.GRPCPort,
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

func runCommandHTTPServer(serverCert tls.Certificate) {
	log.Printf("Running Command and Control API HTTPS listener on port %d", config.CNCPort)

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
	tlsConfig.BuildNameToCertificate()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/generateKubectlComponents", cncGenerateKubectlComponents)
	mux.HandleFunc("/api/v1/generateAgentManifestComponents", cncGenerateAgentManifestComponents)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.CNCPort),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	server.ListenAndServeTLS("", "")
}
