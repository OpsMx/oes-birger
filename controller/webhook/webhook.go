package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

//
// Request defines the data sent to a target webhook destination
//
type Request struct {
	Name       string   `json:"name,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`
	Kubeconfig string   `json:"kubeconfig,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

//
// Runner holds state for the specific runner.
type Runner struct {
	url string
	rc  chan *Request
}

//
// NewRunner returns a new webhook runner.  Use `Channel` to get the channel to send on, and
// `Close` when done.
func NewRunner(url string) *Runner {
	return &Runner{
		url: url,
		rc:  make(chan *Request),
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
func (wr *Runner) Send(msg *Request) {
	wr.rc <- msg
}

//
// Run starts a goroutine to process incoming web requests.
//
func (wr *Runner) Run() {
	go func() {
		for {
			event, more := <-wr.rc
			if !more {
				return
			}
			go wr.perform(event)
		}
	}()
}

//
// Perform an actual web request
//
func (wr *Runner) perform(msg *Request) {
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
