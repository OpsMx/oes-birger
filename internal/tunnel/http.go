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
	"net/http"
	"strings"

	"github.com/OpsMx/go-app-base/httputil"
	"github.com/opsmx/oes-birger/internal/jwtutil"
	"go.uber.org/zap"
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
		if jwtutil.MutationIsRegistered() && containsFolded(mutatedHeaders, name) {
			// only handle the first item in the list, which is typical here
			value := values[0]
			mutated, err := jwtutil.MutateHeader(value, nil)
			if err != nil {
				return nil, err
			}
			ret = append(ret, &HttpHeader{Name: name, Values: []string{string(mutated)}})
		} else if !containsFolded(strippedOutgoingHeaders, name) {
			ret = append(ret, &HttpHeader{Name: name, Values: values})
		}
	}
	return ret, nil
}

// CopyHeaders will copy the headers from a tunnel request to the http request, possibly
// with unmutation.
func CopyHeaders(headers []*HttpHeader, out *http.Header) error {
	for _, header := range headers {
		if jwtutil.MutationIsRegistered() && containsFolded(mutatedHeaders, header.Name) {
			// only handle the first value here as well
			value := header.Values[0]
			unmutated, err := jwtutil.UnmutateHeader([]byte(value), nil)
			if err != nil {
				return err
			}
			out.Add(header.Name, unmutated)
		} else {
			for _, value := range header.Values {
				out.Add(header.Name, value)
			}
		}
	}
	return nil
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

func makeResponse(id string, response *http.Response) (ret *MessageWrapper, err error) {
	headers, err := MakeHeaders(response.Header)
	if err != nil {
		return
	}
	ret = &MessageWrapper{
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
	}
	return
}

// RunHTTPRequest will make a HTTP request, and send the data to the remote end.
func RunHTTPRequest(client *http.Client, req *OpenHTTPTunnelRequest, httpRequest *http.Request, dataflow chan *MessageWrapper, baseURL string) {
	requestURI := baseURL + req.URI
	zap.S().Debugf("Sending HTTP request: %s to %s", req.Method, requestURI)
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		zap.S().Warnw("failed to execute request",
			"method", req.Method,
			"uri", baseURL+req.URI,
			"error", err)
		dataflow <- MakeBadGatewayResponse(req.Id)
		return
	}

	defer httpResponse.Body.Close()

	// First, send the headers.
	response, err := makeResponse(req.Id, httpResponse)
	if err != nil {
		zap.S().Warnf("Failed to unmutate headers: %v", err)
		dataflow <- MakeBadGatewayResponse(req.Id)
		return
	}
	dataflow <- response

	if !httputil.StatusCodeOK(httpResponse.StatusCode) {
		zap.S().Warnw("non-2xx status for request", "method", req.Method, "url", requestURI)
	}

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
			zap.S().Debugf("Context cancelled, request ID %s", req.Id)
			return
		}
		if err != nil {
			zap.S().Warnf("Got error on HTTP read: %v", err)
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
