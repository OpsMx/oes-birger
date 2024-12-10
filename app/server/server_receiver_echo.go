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
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/opsmx/oes-birger/internal/logging"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
)

type ServerReceiverEcho struct {
	sync.Mutex
	streamID    string
	ep          serviceconfig.SearchSpec
	headersChan chan *pb.TunnelHeaders
	dataChan    chan []byte
	doneChan    chan bool
	failChan    chan int
	closed      bool
}

func MakeServerReceiverEcho(ctx context.Context, ep serviceconfig.SearchSpec, streamID string) *ServerReceiverEcho {
	e := &ServerReceiverEcho{
		streamID:    streamID,
		ep:          ep,
		headersChan: make(chan *pb.TunnelHeaders),
		dataChan:    make(chan []byte),
		doneChan:    make(chan bool),
		failChan:    make(chan int),
	}
	return e
}

func (e *ServerReceiverEcho) Shutdown(ctx context.Context) {
	e.Lock()
	defer e.Unlock()
	e.closed = true
	close(e.dataChan)
	close(e.headersChan)
	close(e.doneChan)
	close(e.failChan)
}

func (e *ServerReceiverEcho) Headers(ctx context.Context, h *pb.TunnelHeaders) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return fmt.Errorf("session closed")
	}
	e.headersChan <- h
	return nil
}

func (e *ServerReceiverEcho) Data(ctx context.Context, data []byte) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return fmt.Errorf("session closed")
	}
	e.dataChan <- data
	return nil
}

func (e *ServerReceiverEcho) Fail(ctx context.Context, code int, err error) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return fmt.Errorf("session closed")
	}
	e.failChan <- code
	return nil
}

func (e *ServerReceiverEcho) Done(ctx context.Context) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return fmt.Errorf("session closed")
	}
	e.doneChan <- true
	return nil
}

func (e *ServerReceiverEcho) Cancel(ctx context.Context) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return fmt.Errorf("session closed")
	}
	e.doneChan <- true
	return nil
}

func (e *ServerReceiverEcho) RunRequest(ctx context.Context, dest serviceconfig.Destination, body []byte, w http.ResponseWriter, r *http.Request) {
	logger := logging.WithContext(ctx).Sugar()
	headersSent := false
	flusher := w.(http.Flusher)
	interMessageTime := 10 * time.Second
	t := time.NewTimer(10 * interMessageTime)
	logger.Infow("Entered run request of server")
	pbh, err := serviceconfig.HTTPHeadersToPB(r.Header)

	if err != nil {
		logger.Infow("unable to convert headers")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	session, ok := dest.(*AgentContext)
	if !ok {
		logger.Infow("coding error: expected AgentContext, got ", dest)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	session.requestChan <- serviceRequest{
		req: &pb.TunnelRequest{
			StreamId: e.streamID,
			Name:     e.ep.ServiceName,
			Type:     e.ep.ServiceType,
			Method:   r.Method,
			URI:      r.RequestURI,
			Body:     body,
			Headers:  pbh,
		},
		echo: e,
	}
	for {
		select {
		case <-t.C:
			logger.Infof("stream timed out")
			return
		case <-r.Context().Done():
			logger.Infof("client closed, stopping data flow", ctx.Err())
			// TODO: send cancel event over gRPC
			return
		case <-e.doneChan:
			logger.Infow("request done")
			return
		case code := <-e.failChan:
			if !headersSent {
				w.WriteHeader(code)
			}
			logger.Infow("request failed", code)
			return
		case data := <-e.dataChan:
			t.Reset(interMessageTime)
			n, err := w.Write(data)
			logger.Infow("Got response")
			if err != nil {
				// TODO: send cancel over gRPC
				logger.Infow("send to client", err.Error())
				return
			}
			if n != len(data) {
				// TODO: send cancel over gRPC
				logger.Infow("short send to client: wrote %d, wanted to write %d bytes", n, len(data))
				return
			}
			flusher.Flush()
		case headers := <-e.headersChan:
			t.Reset(interMessageTime)
			headersSent = true
			logger.Infow("Got Headers")
			for name := range w.Header() {
				w.Header().Del(name)
			}
			for _, header := range headers.Headers {
				for _, value := range header.Values {
					w.Header().Add(header.Name, value)
				}
			}
			w.WriteHeader(int(headers.StatusCode))
		}
	}
}
