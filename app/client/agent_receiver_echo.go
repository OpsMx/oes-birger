/*
 * Copyright 2023 OpsMx, Inc.
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

package main

import (
	"context"
	"io"
	"net/http"

	"github.com/opsmx/oes-birger/internal/logging"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
	"go.uber.org/zap"
)

// AgentReceiverEcho takes an agent-side connection and sends the request to the
// controller, which then contacts the remote HTTP server.  That is, the client
// requesting work is connecting to the AGENT in this echoer.
type AgentReceiverEcho struct {
	client   pb.TunnelServiceClient
	streamID string
	ep       serviceconfig.SearchSpec
}

func MakeAgentReceiverEcho(ctx context.Context, client pb.TunnelServiceClient, ep serviceconfig.SearchSpec, streamID string) serviceconfig.EchoRequester {
	e := &AgentReceiverEcho{
		client:   client,
		streamID: streamID,
		ep:       ep,
	}
	return e
}

func (e *AgentReceiverEcho) Shutdown(ctx context.Context) {
}

func (e *AgentReceiverEcho) Headers(ctx context.Context, h *pb.TunnelHeaders) error {
	return nil
}

func (e *AgentReceiverEcho) Data(ctx context.Context, data []byte) error {
	return nil
}

func (e *AgentReceiverEcho) Fail(ctx context.Context, code int, err error) error {
	return nil
}

func (e *AgentReceiverEcho) Done(ctx context.Context) error {
	return nil
}

func (e *AgentReceiverEcho) Cancel(ctx context.Context) error {
	return nil
}

func (e *AgentReceiverEcho) RunRequestCancel(ctx context.Context, cl context.CancelFunc, logger *zap.SugaredLogger) {
	logger.Info("ReunRequestCancel cancel() called")
	cl()
}

func (e *AgentReceiverEcho) RunRequest(ctx context.Context, dest serviceconfig.Destination, body []byte, w http.ResponseWriter, r *http.Request) {
	ctx, cancel := getHeaderContext(ctx, 0)
	logger := logging.WithContext(ctx).Sugar()
	defer e.RunRequestCancel(ctx, cancel, logger)
	headersSent := false
	flusher := w.(http.Flusher)

	pbh, err := serviceconfig.HTTPHeadersToPB(r.Header)
	if err != nil {
		logger.Infow("unable to convert headers")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	pbr := &pb.TunnelRequest{
		StreamId: e.streamID,
		Name:     e.ep.ServiceName,
		Type:     e.ep.ServiceType,
		Method:   r.Method,
		URI:      r.RequestURI,
		Body:     body,
		Headers:  pbh,
	}
	logger.Infow("Request details", pbr)

	stream, err := e.client.RunRequest(ctx, pbr)
	if err != nil {
		logger.Infow("unable to process request, agent won't close!", "error", err)
		w.WriteHeader(http.StatusBadGateway)
		// return
	}

	for {
		// read and process another message
		msg, err := stream.Recv()
		if err == io.EOF {
			logger.Infow("stream EOF, agent won't close!", err)
			if !headersSent {
				w.WriteHeader(http.StatusBadGateway)
			}
			continue
			// return
		}
		if err != nil {
			logger.Infow("error on stream, agent won't close!", "error", err)
			if !headersSent {
				w.WriteHeader(http.StatusBadGateway)
			}
			continue
			// return
		}
		switch msg.Event.(type) {
		case *pb.StreamFlow_Data:
			data := msg.GetData().Data
			n, err := w.Write(data)
			logger.Infow("Got data on stream", data, err)
			if err != nil {
				logger.Infow("send to client: %v, agent won't close!", err)
				continue
				// return
			}
			if n != len(data) {
				logger.Infow("short send to client: wrote %d, wanted to write %d bytes", n, len(data))
				// continue
				return
			}
			flusher.Flush()
		case *pb.StreamFlow_Headers:
			headers := msg.GetHeaders()
			headersSent = true
			logger.Infow("Got Headers: %v", headers)
			for name := range w.Header() {
				w.Header().Del(name)
			}
			for _, header := range headers.Headers {
				for _, value := range header.Values {
					w.Header().Add(header.Name, value)
				}
			}
			w.WriteHeader(int(headers.StatusCode))
		case *pb.StreamFlow_Cancel:
			logger.Infow("stream canceled, agent wont close!", msg)
			if !headersSent {
				w.WriteHeader(http.StatusBadGateway)
			}
			continue
			// return
		case *pb.StreamFlow_Done:
			logger.Infow("stream done, agent wont close!", msg)
			if !headersSent {
				w.WriteHeader(http.StatusBadGateway)
			}
			continue
			// return
		}
	}
}
