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
	"go.uber.org/zap"
)

type AgentSenderEcho struct {
	sync.Mutex
	streamID    string
	c           pb.TunnelServiceClient
	msgChan     chan *pb.StreamFlow
	headersSent bool
	closed      bool
}

func MakeAgentSenderEcho(ctx context.Context, c pb.TunnelServiceClient, streamID string, doneChan chan bool) serviceconfig.Echo {
	e := &AgentSenderEcho{
		streamID: streamID,
		c:        c,
		msgChan:  make(chan *pb.StreamFlow),
	}
	go e.RunDataSender(ctx)
	return e
}

func (e *AgentSenderEcho) Shutdown(ctx context.Context) {
	e.Lock()
	defer e.Unlock()
	if !e.closed {
		e.closed = true
		e.msgChan <- pb.StreamflowWrapDoneMsg()
		close(e.msgChan)
	}
}

func RunDataSenderCancel(ctx context.Context, cl context.CancelFunc, logger *zap.SugaredLogger) {
	logger.Info("RunDataSenderCancel cancel() called")
	cl()
}

// TODO: return any errors to "caller"
func (e *AgentSenderEcho) RunDataSender(ctx context.Context) {
	ctx, logger := loggerFromContext(ctx)
	ctx, cancel := context.WithCancel(ctx)
	logger.Infow("Entered run data sender")
	defer RunDataSenderCancel(ctx, cancel, logger)

	stream, err := e.c.DataFlowAgentToController(ctx)
	if err != nil {
		logger.Infow("error e.c.DataFlowAgentToController()", err.Error())
		return
	}

	defer func() {
		_, err := stream.CloseAndRecv()
		if err != nil && err != io.EOF {
			logger.Infow("stream.CloseAndRecv error", err.Error())
		}
	}()

	err = stream.Send(pb.StreamflowWrapStreamID(e.streamID))
	if err != nil {
		logger.Infow("Cannot send stream id", err.Error())
		return
	}

	for {
		select {
		case <-ctx.Done():
			logger.Infof("Run() context done with reason:", ctx.Err())
		case msg, more := <-e.msgChan:
			if msg != nil {
				err := stream.Send(msg)
				if err != nil {
					logger.Errorf("stream.Send(): %v", err)
				}
			}
			if !more {
				return
			}
		}
	}
}

func (e *AgentSenderEcho) Headers(ctx context.Context, h *pb.TunnelHeaders) error {
	e.Lock()
	defer e.Unlock()
	e.msgChan <- pb.StreamflowWrapHeaderMsg(h)
	e.headersSent = true
	return nil
}

func (e *AgentSenderEcho) Data(ctx context.Context, data []byte) error {
	d := &pb.Data{
		Data: data,
	}
	e.msgChan <- pb.StreamflowWrapDataMsg(d)
	return nil
}

func (e *AgentSenderEcho) Fail(ctx context.Context, code int, err error) error {
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

func (e *AgentSenderEcho) Done(ctx context.Context) error {
	e.Lock()
	defer e.Unlock()
	if !e.closed {
		e.closed = true
		e.msgChan <- pb.StreamflowWrapDoneMsg()
		close(e.msgChan)
	}
	return nil
}

func (e *AgentSenderEcho) Cancel(ctx context.Context) error {
	e.Lock()
	defer e.Unlock()
	if !e.closed {
		e.closed = true
		e.msgChan <- pb.StreamflowWrapCancelMsg()
		close(e.msgChan)
	}
	return nil
}
