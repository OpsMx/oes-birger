package main

import (
	"net/http"

	"github.com/opsmx/grpc-bidir/pkg/tunnel"
)

func makeHeaders(headers map[string][]string) []*tunnel.HttpHeader {
	ret := make([]*tunnel.HttpHeader, 0)
	for name, values := range headers {
		ret = append(ret, &tunnel.HttpHeader{Name: name, Values: values})
	}
	return ret
}

func makeChunkedResponse(id string, target string, data []byte) *tunnel.AgentToControllerWrapper {
	return &tunnel.AgentToControllerWrapper{
		Event: &tunnel.AgentToControllerWrapper_HttpChunkedResponse{
			HttpChunkedResponse: &tunnel.HttpChunkedResponse{
				Id:     id,
				Target: target,
				Body:   data,
			},
		},
	}
}

func makeBadGatewayResponse(id string, target string) *tunnel.AgentToControllerWrapper {
	return &tunnel.AgentToControllerWrapper{
		Event: &tunnel.AgentToControllerWrapper_HttpResponse{
			HttpResponse: &tunnel.HttpResponse{
				Id:            id,
				Target:        target,
				Status:        http.StatusBadGateway,
				ContentLength: 0,
			},
		},
	}
}

func makeResponse(id string, target string, response *http.Response) *tunnel.AgentToControllerWrapper {
	return &tunnel.AgentToControllerWrapper{
		Event: &tunnel.AgentToControllerWrapper_HttpResponse{
			HttpResponse: &tunnel.HttpResponse{
				Id:            id,
				Target:        target,
				Status:        int32(response.StatusCode),
				ContentLength: response.ContentLength,
				Headers:       makeHeaders(response.Header),
			},
		},
	}
}
