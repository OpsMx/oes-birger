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

package tunnel

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/opsmx/oes-birger/internal/jwtutil"
)

var (
	emptyBytes              = []byte("")
	mutatedHeaders          = []string{"X-Spinnaker-User"}
	strippedOutgoingHeaders = []string{"Authorization"}
)

func containsFolded(l []string, t string) bool {
	for i := 0; i < len(l); i++ {
		if strings.EqualFold(l[i], t) {
			return true
		}
	}
	return false
}

// MakeHeaders copies from http headers to protobuf's format, possibly with mutation
func MakeHeaders(headers map[string][]string) (ret []*HttpHeader, err error) {
	ret = make([]*HttpHeader, 0)
	for name, values := range headers {
		if containsFolded(mutatedHeaders, name) {
			// only handle the first item in the list, which is typical here
			value := values[0]
			mutated := value
			if jwtutil.MutationIsRegistered() {
				mutatedBytes, err := jwtutil.MutateHeader(value, nil)
				if err != nil {
					return nil, err
				}
				mutated = string(mutatedBytes)
			}
			ret = append(ret, &HttpHeader{Name: name, Values: []string{mutated}})
		} else if !containsFolded(strippedOutgoingHeaders, name) {
			ret = append(ret, &HttpHeader{Name: name, Values: values})
		}
	}
	return ret, nil
}

// CopyHeaders will copy the headers from a tunnel request to the http request, possibly
// with unmutation
func CopyHeaders(req *OpenHTTPTunnelRequest, httpRequest *http.Request) {
	for _, header := range req.Headers {
		for _, value := range header.Values {
			httpRequest.Header.Add(header.Name, value)
		}
	}
}

func makeChunkedResponse(id string, data []byte) *MessageWrapper {
	return &MessageWrapper{
		Event: &MessageWrapper_HttpTunnelControl{
			HttpTunnelControl: &HttpTunnelControl{
				ControlType: &HttpTunnelControl_HttpTunnelChunkedResponse{
					HttpTunnelChunkedResponse: &HttpTunnelChunkedResponse{
						Id:   id,
						Body: data,
					},
				},
			},
		},
	}
}

// MakeBadGatewayResponse will generate a 502 HTTP status code and return it,
// to indicate there is no such endpoint in the agent.
func MakeBadGatewayResponse(id string) *MessageWrapper {
	return &MessageWrapper{
		Event: &MessageWrapper_HttpTunnelControl{
			HttpTunnelControl: &HttpTunnelControl{
				ControlType: &HttpTunnelControl_HttpTunnelResponse{
					HttpTunnelResponse: &HttpTunnelResponse{
						Id:            id,
						Status:        http.StatusBadGateway,
						ContentLength: 0,
					},
				},
			},
		},
	}
}

func makeResponse(id string, response *http.Response) (*MessageWrapper, error) {
	headers, err := MakeHeaders(response.Header)
	if err != nil {
		return nil, err
	}
	return &MessageWrapper{
		Event: &MessageWrapper_HttpTunnelControl{
			HttpTunnelControl: &HttpTunnelControl{
				ControlType: &HttpTunnelControl_HttpTunnelResponse{
					HttpTunnelResponse: &HttpTunnelResponse{
						Id:            id,
						Status:        int32(response.StatusCode),
						ContentLength: response.ContentLength,
						Headers:       headers,
					},
				},
			},
		},
	}, nil
}

// RunHTTPRequest will make a HTTP request, and send the data to the remote end.
func RunHTTPRequest(client *http.Client, req *OpenHTTPTunnelRequest, httpRequest *http.Request, dataflow chan *MessageWrapper, baseURL string) {
	log.Printf("Sending HTTP request: %s to %v", req.Method, baseURL+req.URI)
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		log.Printf("Failed to execute request for %s to %s: %v", req.Method, baseURL+req.URI, err)
		dataflow <- MakeBadGatewayResponse(req.Id)
		return
	}

	// First, send the headers.
	response, err := makeResponse(req.Id, httpResponse)
	if err != nil {
		log.Printf("Failed to unmutate headers: %v", err)
		dataflow <- MakeBadGatewayResponse(req.Id)
		return
	}
	dataflow <- response

	// Now, send one or more data packet.
	for {
		buf := make([]byte, 10240)
		n, err := httpResponse.Body.Read(buf)
		if n > 0 {
			dataflow <- makeChunkedResponse(req.Id, buf[:n])
		}
		if err == io.EOF {
			dataflow <- makeChunkedResponse(req.Id, emptyBytes)
			return
		}
		if err == context.Canceled {
			log.Printf("Context cancelled, request ID %s", req.Id)
			return
		}
		if err != nil {
			log.Printf("Got error on HTTP read: %v", err)
			// todo: send an error message somehow.  For now, just send EOF
			dataflow <- makeChunkedResponse(req.Id, emptyBytes)
			return
		}
	}
}

// MakeHTTPTunnelCancelRequest will make a wrapped request to cancel a specific transaction id
func MakeHTTPTunnelCancelRequest(id string) *MessageWrapper_HttpTunnelControl {
	return &MessageWrapper_HttpTunnelControl{
		HttpTunnelControl: &HttpTunnelControl{
			ControlType: &HttpTunnelControl_CancelRequest{
				CancelRequest: &CancelRequest{Id: id},
			},
		},
	}
}

// MakeHTTPTunnelOpenTunnelRequest will make a wrapped request to open an http tunnel
func MakeHTTPTunnelOpenTunnelRequest(req *OpenHTTPTunnelRequest) *MessageWrapper_HttpTunnelControl {
	return &MessageWrapper_HttpTunnelControl{
		HttpTunnelControl: &HttpTunnelControl{
			ControlType: &HttpTunnelControl_OpenHTTPTunnelRequest{
				OpenHTTPTunnelRequest: req,
			},
		},
	}
}
