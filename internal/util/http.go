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

// Package util is a kitchen sink.  Sorry.
package util

import (
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

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
		return []byte(`{"error":{"message":"Unknown Error"}}`)
	}
	return json
}

// FailRequest marks a request as failed.  This will set the provided status code,
// and write to the message body a JSON format error message.  The http.ResponseWriter
// should not have been used, or be used after calling FailRequest.
func FailRequest(w http.ResponseWriter, err error, code int) {
	w.WriteHeader(code)
	errmsg := httpError(err)
	n, err := w.Write(errmsg)
	if err != nil {
		zap.S().Warnf("failed to write message in FailRequest: %v", err)
	}
	if n != len(errmsg) {
		zap.S().Warnf("failed to write entire message in FailRequest: %d of %d bytes written", n, len(errmsg))
	}
}
