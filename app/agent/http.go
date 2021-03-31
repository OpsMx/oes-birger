package main

import (
	"net/http"

	"github.com/opsmx/oes-birger/pkg/tunnel"
)

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
	}
	return ret
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
