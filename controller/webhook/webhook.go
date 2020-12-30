package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

//
// WebhookRequest defines the data sent to a target webhook destination
//
type WebhookRequest struct {
	Name       string   `json:"name"`
	Kubeconfig string   `json:"kubeconfig"`
	Namespaces []string `json:"namespaces"`
}

//
// WebhookRunner holds state for the specific runner.
type WebhookRunner struct {
	url string
	rc  chan *WebhookRequest
}

//
// NewRunner returns a new webhook runner.  Use `Channel` to get the channel to send on, and
// `Close` when done.
func NewRunner(url string) *WebhookRunner {
	return &WebhookRunner{
		url: url,
		rc:  make(chan *WebhookRequest),
	}
}

//
// Close will close the webhook goroutine down.
//
func (wr *WebhookRunner) Close() {
	close(wr.rc)
}

//
// Send will queue a webhook request.  It will run at some time in the
// future, perhaps on a new goroutine.  There is no return status,
// and errors are logged but otherwise silently ignored.
//
func (wr *WebhookRunner) Send(msg *WebhookRequest) {
	wr.rc <- msg
}

//
// Run starts a goroutine to process incoming web requests.
//
func (wr *WebhookRunner) Run() {
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
func (wr *WebhookRunner) perform(msg *WebhookRequest) {
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
