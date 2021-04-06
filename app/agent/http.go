package main

import (
	"context"
	"io"
	"log"
	"net/http"

	"github.com/opsmx/oes-birger/pkg/tunnel"
)

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		if name != "Authorization" {
			ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
		}
	}
	return ret
}

func copyHeaders(req *tunnel.HttpRequest, httpRequest *http.Request) {
	for _, header := range req.Headers {
		for _, value := range header.Values {
			httpRequest.Header.Add(header.Name, value)
		}
	}
}

func makeChunkedResponse(id string, data []byte) *tunnel.AgentToControllerWrapper {
	return &tunnel.AgentToControllerWrapper{
		Event: &tunnel.AgentToControllerWrapper_HttpChunkedResponse{
			HttpChunkedResponse: &tunnel.HttpChunkedResponse{
				Id:   id,
				Body: data,
			},
		},
	}
}

func makeBadGatewayResponse(id string) *tunnel.AgentToControllerWrapper {
	return &tunnel.AgentToControllerWrapper{
		Event: &tunnel.AgentToControllerWrapper_HttpResponse{
			HttpResponse: &tunnel.HttpResponse{
				Id:            id,
				Status:        http.StatusBadGateway,
				ContentLength: 0,
			},
		},
	}
}

func makeResponse(id string, response *http.Response) *tunnel.AgentToControllerWrapper {
	return &tunnel.AgentToControllerWrapper{
		Event: &tunnel.AgentToControllerWrapper_HttpResponse{
			HttpResponse: &tunnel.HttpResponse{
				Id:            id,
				Status:        int32(response.StatusCode),
				ContentLength: response.ContentLength,
				Headers:       makeHeaders(response.Header),
			},
		},
	}
}

func runHTTPRequest(client *http.Client, req *tunnel.HttpRequest, httpRequest *http.Request, dataflow chan *tunnel.AgentToControllerWrapper, baseURL string) {
	log.Printf("Sending HTTP request: %s to %v", req.Method, baseURL+req.URI)
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		log.Printf("Failed to execute request for %s to %s: %v", req.Method, baseURL+req.URI, err)
		dataflow <- makeBadGatewayResponse(req.Id)
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
