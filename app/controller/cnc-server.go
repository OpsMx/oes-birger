package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/oklog/ulid/v2"
	"github.com/opsmx/oes-birger/app/controller/agent"
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
	AgentKey         string `json:"agentKey"`
	CACert           string `json:"caCert"`
}

type statisticsResponse struct {
	ServerTime      uint64      `json:"serverTime"`
	ConnectedAgents interface{} `json:"connectedAgents"`
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
	statusCode, err := authenticate(r, "POST")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(statusCode)
	}

	var req kubeConfigRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ca64, user64, key64, err := authority.GenerateCertificate(req.Identity, "client")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
	}
	ret := kubeConfigResponse{
		Identity:        req.Identity,
		ServerURL:       config.getKubernetesURL(),
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
	names := strings.Split(r.TLS.PeerCertificates[0].Subject.CommonName, ".")
	if names[1] != "command" {
		return http.StatusForbidden, fmt.Errorf("identity does not end with 'command': %v", names)
	}
	if r.Method != method {
		return http.StatusMethodNotAllowed, fmt.Errorf("only '%s' is accepted", method)
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

	var req manifestRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ca64, user64, key64, err := authority.GenerateCertificate(req.Identity, "agent")
	if err != nil {
		w.Write(httpError(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ret := manifestResponse{
		Identity:         req.Identity,
		ServerHostname:   config.getAgentHostname(),
		ServerPort:       config.getAgentPort(),
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

	ret := statisticsResponse{
		ServerTime:      ulid.Now(),
		ConnectedAgents: agent.GetStatistics(),
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
	log.Printf("Running Command and Control API HTTPS listener on port %d", config.CommandPort)

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
	//tlsConfig.BuildNameToCertificate()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/generateKubectlComponents", cncGenerateKubectlComponents)
	mux.HandleFunc("/api/v1/generateAgentManifestComponents", cncGenerateAgentManifestComponents)
	mux.HandleFunc("/api/v1/getAgentStatistics", cncGetStatistics)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.CommandPort),
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	server.ListenAndServeTLS("", "")
}
