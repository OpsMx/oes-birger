package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

//
// AgentConnectionNotification defines the data sent to a target webhook destination
//
type AgentConnectionNotification struct {
	Identity             string   `json:"identity,omitempty"`
	Protocols            []string `json:"protocols,omitempty"`
	Session              string   `json:"session,omitempty"`
	KubernetesNamespaces []string `json:"namespaces,omitempty"`
	CommandNames         []string `json:"commandNames,omitEmpty"`
}

//
// Runner holds state for the specific runner.
type Runner struct {
	url string
	rc  chan *AgentConnectionNotification
}

//
// NewRunner returns a new webhook runner.  Call `Close` when done.
func NewRunner(url string) *Runner {
	return &Runner{
		url: url,
		rc:  make(chan *AgentConnectionNotification),
	}
}

//
// Close will close the webhook goroutine down.
//
func (wr *Runner) Close() {
	close(wr.rc)
}

//
// Send will queue a webhook request.  It will run at some time in the
// future, perhaps on a new goroutine.  There is no return status,
// and errors are logged but otherwise silently ignored.
//
func (wr *Runner) Send(msg *AgentConnectionNotification) {
	wr.rc <- msg
}

//
// Run starts a goroutine to process incoming web requests.
//
func (wr *Runner) Run() {
	for {
		event, more := <-wr.rc
		if !more {
			return
		}
		go wr.perform(event)
	}
}

//
// Perform an actual web request
//
func (wr *Runner) perform(msg *AgentConnectionNotification) {
	log.Printf("Webhook request: %v", msg)
	jsonString, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Unable to marshal json: %v", err)
		return
	}
	resp, err := http.Post(wr.url, "application/json", bytes.NewBuffer(jsonString))
	if err != nil {
		log.Printf("Unable to send web request: %v", err)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("Webhook returned %s", resp.Status)
	}
}
