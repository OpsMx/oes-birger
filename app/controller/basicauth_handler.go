package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/opsmx/oes-birger/app/controller/agent"
)

func getAuthParts(username string) (epType string, epName string, agent string, err error) {
	items := strings.Split(username, ".")
	if len(items) != 3 {
		return "", "", "", fmt.Errorf("username has invalid format")
	}
	return items[0], items[1], items[2], nil
}

func basicAuthAPIHandler(serviceType string, w http.ResponseWriter, r *http.Request) {
	var authPassword string
	var ok bool
	if _, authPassword, ok = r.BasicAuth(); !ok {
		log.Printf("No credentials provided, endpointType %s", serviceType)
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
