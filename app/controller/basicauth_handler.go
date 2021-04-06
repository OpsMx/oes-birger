package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/opsmx/oes-birger/app/controller/agent"
	"github.com/opsmx/oes-birger/pkg/tunnel"
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
	apiRequestCounter.WithLabelValues(agentIdentity).Inc()

	transactionID := ulidContext.Ulid()

	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.HttpRequest{
		Id:      transactionID,
		Type:    ep.EndpointType,
		Name:    ep.EndpointName,
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: makeHeaders(r.Header),
		Body:    body,
	}
	message := &HTTPMessage{Out: make(chan *tunnel.AgentToControllerWrapper), Cmd: req}
	sessionID, found := agents.Send(ep, message)
	if !found {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	ep.Session = sessionID

	cleanClose := false
	notify := r.Context().Done()
	go func() {
		<-notify
		if !cleanClose {
			agents.Cancel(ep, transactionID)
		}
	}()

	seenHeader := false
	isChunked := false
	flusher := w.(http.Flusher)
	for {
		in, more := <-message.Out
		if !more {
			if !seenHeader {
				log.Printf("Request timed out sending to agent")
				w.WriteHeader(http.StatusBadGateway)
			}
			cleanClose = true
			return
		}

		switch x := in.Event.(type) {
		case *tunnel.AgentToControllerWrapper_HttpResponse:
			resp := in.GetHttpResponse()
			seenHeader = true
			isChunked = resp.ContentLength < 0
			for name := range w.Header() {
				r.Header.Del(name)
			}
			for _, header := range resp.Headers {
				for _, value := range header.Values {
					w.Header().Add(header.Name, value)
				}
			}
			w.WriteHeader(int(resp.Status))
			if resp.ContentLength == 0 {
				cleanClose = true
				return
			}
		case *tunnel.AgentToControllerWrapper_HttpChunkedResponse:
			resp := in.GetHttpChunkedResponse()
			if !seenHeader {
				log.Printf("Error: got ChunkedResponse before HttpResponse")
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if len(resp.Body) == 0 {
				cleanClose = true
				return
			}
			w.Write(resp.Body)
			if isChunked {
				flusher.Flush()
			}
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %T", x)
		}
	}
}
