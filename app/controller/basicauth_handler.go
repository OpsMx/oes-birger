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
	var authUsername string
	var authPassword string
	var ok bool
	if authUsername, authPassword, ok = r.BasicAuth(); !ok {
		log.Printf("No credentials provided, epType %s", serviceType)
	}

	// Pull fields from the username, which is of the format
	// eptype.epname.agentid
	usernameType, usernameName, usernameAgent, err := getAuthParts(authUsername)
	if err != nil {
		log.Printf("%v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Pull fields from the password, and if they validate, compare to the
	// username.
	epType, epName, agentIdentity, err := ValidateJWT(jwtKeyset, authPassword)
	if err != nil {
		log.Printf("%v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if usernameType != epType {
		log.Printf("usernameType %s does not match JWT field %s", usernameType, epType)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if usernameName != epName {
		log.Printf("usernameName %s does not match JWT field %s", usernameName, epName)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if usernameAgent != agentIdentity {
		log.Printf("usernameAgent %s does not match JWT field %s", usernameAgent, agentIdentity)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ep := agent.AgentSearch{
		Identity:     agentIdentity,
		EndpointType: epType,
		EndpointName: epName,
	}
	runAPIHandler(ep, w, r)
}
