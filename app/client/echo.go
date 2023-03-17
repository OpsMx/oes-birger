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
	"sync"

	"github.com/opsmx/oes-birger/internal/serviceconfig"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
)

type AgentEcho struct {
	sync.Mutex
	streamID    string
	c           pb.TunnelServiceClient
	msgChan     chan *pb.StreamFlow
	headersSent bool
	closed      bool
}

func MakeEcho(ctx context.Context, c pb.TunnelServiceClient, streamID string, doneChan chan bool) serviceconfig.HTTPEcho {
	e := &AgentEcho{
		streamID: streamID,
		c:        c,
		msgChan:  make(chan *pb.StreamFlow),
	}
	go e.RunDataSender(ctx)
	return e
}

func (e *AgentEcho) Shutdown(ctx context.Context) {
	e.Lock()
	defer e.Unlock()
	if !e.closed {
		e.closed = true
		e.msgChan <- pb.StreamflowWrapDoneMsg()
		close(e.msgChan)
	}
}

// TODO: return any errors to "caller"
func (e *AgentEcho) RunDataSender(ctx context.Context) {
	ctx, logger := loggerFromContext(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := e.c.DataFlowAgentToController(ctx)
	if err != nil {
		logger.Errorf("e.c.DataFlowAgentToController(): %v", err)
		return
	}

	defer func() {
		_, err := stream.CloseAndRecv()
		if err != nil && err != io.EOF {
			logger.Info("stream.CloseAndRecv error: %v", err)
		}
	}()

	err = stream.Send(pb.StreamflowWrapStreamID(e.streamID))
	if err != nil {
		logger.Errorf("Cannot send stream id: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			logger.Infof("Run() context done")
		case msg, more := <-e.msgChan:
			if !more {
				return
			}
			if msg != nil {
				err := stream.Send(msg)
				if err != nil {
					logger.Errorf("stream.Send(): %v", err)
				}
			}
		}
	}
}

func (e *AgentEcho) Headers(ctx context.Context, h *pb.TunnelHeaders) error {
	e.Lock()
	defer e.Unlock()
	e.msgChan <- pb.StreamflowWrapHeaderMsg(h)
	e.headersSent = true
	return nil
}

func (e *AgentEcho) Data(ctx context.Context, data []byte) error {
	d := &pb.Data{
		Data: data,
	}
	e.msgChan <- pb.StreamflowWrapDataMsg(d)
	return nil
}

func (e *AgentEcho) Fail(ctx context.Context, code int, err error) error {
	e.Lock()
	defer e.Unlock()
	if !e.headersSent {
		h := &pb.TunnelHeaders{
			StreamId:   e.streamID,
			StatusCode: int32(code),
		}
		e.msgChan <- pb.StreamflowWrapHeaderMsg(h)
	}
	e.msgChan <- pb.StreamflowWrapDoneMsg()
	return nil
}

func (e *AgentEcho) Done(ctx context.Context) error {
	e.Lock()
	defer e.Unlock()
	if !e.closed {
		e.closed = true
		e.msgChan <- pb.StreamflowWrapDoneMsg()
		close(e.msgChan)
	}
	return nil
}

func (e *AgentEcho) Cancel(ctx context.Context) error {
	e.Lock()
	defer e.Unlock()
	if !e.closed {
		e.closed = true
		e.msgChan <- pb.StreamflowWrapCancelMsg()
		close(e.msgChan)
	}
	return nil
}
