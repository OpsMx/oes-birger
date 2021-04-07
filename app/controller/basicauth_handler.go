package main

import (
	"log"
	"net/http"

	"github.com/opsmx/oes-birger/app/controller/agent"
)

func basicAuthAPIHandler(serviceType string, w http.ResponseWriter, r *http.Request) {
	var authPassword string
	var ok bool
	if _, authPassword, ok = r.BasicAuth(); !ok {
		log.Printf("No credentials provided, endpointType %s", serviceType)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Pull fields from the password, and if they validate, compare to the
	// username.
	endpointType, endpointName, agentIdentity, err := ValidateJWT(jwtKeyset, authPassword)
	if err != nil {
		log.Printf("%v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ep := agent.AgentSearch{
		Identity:     agentIdentity,
		EndpointType: endpointType,
		EndpointName: endpointName,
	}
	runAPIHandler(ep, w, r)
}
