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
)

var (
	emptyBytes = []byte("")
)

func makeHeaders(headers map[string][]string) []*HttpHeader {
	ret := make([]*HttpHeader, 0)
	for name, values := range headers {
		if name != "Authorization" {
			ret = append(ret, &HttpHeader{Name: name, Values: values})
		}
	}
	return ret
}

// CopyHeaders will copy the headers from a tunnel request to the http request.
func CopyHeaders(req *OpenHTTPTunnelRequest, httpRequest *http.Request) {
	for _, header := range req.Headers {
		for _, value := range header.Values {
			httpRequest.Header.Add(header.Name, value)
		}
	}
}

func makeChunkedResponse(id string, data []byte) *AgentToControllerWrapper {
	return &AgentToControllerWrapper{
		Event: &AgentToControllerWrapper_HttpTunnelChunkedResponse{
			HttpTunnelChunkedResponse: &HttpTunnelChunkedResponse{
				Id:   id,
				Body: data,
			},
		},
	}
}

// MakeBadGatewayResponse will generate a 502 HTTP status code and return it,
// to indicate there is no such endpoint in the agent.
func MakeBadGatewayResponse(id string) *AgentToControllerWrapper {
	return &AgentToControllerWrapper{
		Event: &AgentToControllerWrapper_HttpTunnelResponse{
			HttpTunnelResponse: &HttpTunnelResponse{
				Id:            id,
				Status:        http.StatusBadGateway,
				ContentLength: 0,
			},
		},
	}
}

func makeResponse(id string, response *http.Response) *AgentToControllerWrapper {
	return &AgentToControllerWrapper{
		Event: &AgentToControllerWrapper_HttpTunnelResponse{
			HttpTunnelResponse: &HttpTunnelResponse{
				Id:            id,
				Status:        int32(response.StatusCode),
				ContentLength: response.ContentLength,
				Headers:       makeHeaders(response.Header),
			},
		},
	}
}

// RunHTTPRequest will make a HTTP request, and send the data to the remote end.
func RunHTTPRequest(client *http.Client, req *OpenHTTPTunnelRequest, httpRequest *http.Request, dataflow chan *AgentToControllerWrapper, baseURL string) {
	log.Printf("Sending HTTP request: %s to %v", req.Method, baseURL+req.URI)
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		log.Printf("Failed to execute request for %s to %s: %v", req.Method, baseURL+req.URI, err)
		dataflow <- MakeBadGatewayResponse(req.Id)
		return
	}

	// First, send the headers.
	resp := makeResponse(req.Id, httpResponse)
	dataflow <- resp

	// Now, send one or more data packet.
	for {
		buf := make([]byte, 10240)
		n, err := httpResponse.Body.Read(buf)
		if n > 0 {
			resp := makeChunkedResponse(req.Id, buf[:n])
			dataflow <- resp
		}
		if err == io.EOF {
			resp := makeChunkedResponse(req.Id, emptyBytes)
			dataflow <- resp
			return
		}
		if err == context.Canceled {
			log.Printf("Context cancelled, request ID %s", req.Id)
			return
		}
		if err != nil {
			log.Printf("Got error on HTTP read: %v", err)
			// todo: send an error message somehow.  For now, just send EOF
			resp := makeChunkedResponse(req.Id, emptyBytes)
			dataflow <- resp
			return
		}
	}
}
