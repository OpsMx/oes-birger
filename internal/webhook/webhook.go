/*
 * Copyright 2021 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//
// Package webhook will
package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

//
// Runner holds state for the specific runner.
type Runner struct {
	url string
	rc  chan interface{}
}

//
// NewRunner returns a new webhook runner.  Call `Close` when done.
func NewRunner(url string) *Runner {
	return &Runner{
		url: url,
		rc:  make(chan interface{}),
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
func (wr *Runner) Send(msg interface{}) {
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
func (wr *Runner) perform(msg interface{}) {
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
