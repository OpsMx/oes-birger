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
// Package util is a kitchen sink.  Sorry.
//
package util

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/opsmx/oes-birger/pkg/fwdapi"
)

func HTTPError(err error) []byte {
	ret := &fwdapi.HTTPErrorResponse{
		Error: &fwdapi.HTTPErrorMessage{
			Message: fmt.Sprintf("Unable to process request: %v", err),
		},
	}
	json, err := json.Marshal(ret)
	if err != nil {
		return []byte(`{"error":{"message":"Unknown Error"}}`)
	}
	return json
}

func FailRequest(w http.ResponseWriter, err error, code int) {
	w.WriteHeader(code)
	errmsg := HTTPError(err)
	n, err := w.Write(errmsg)
	if err != nil {
		log.Printf("failed to write message in FailRequest: %v", err)
	}
	if n != len(errmsg) {
		log.Printf("failed to write entire message in FailRequest: %d of %d bytes written", n, len(errmsg))
	}
}
