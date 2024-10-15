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
	"sync"

	pb "github.com/opsmx/oes-birger/internal/tunnel"
)

type ServerSenderEcho struct {
	sync.Mutex
	streamID    string
	msgChan     chan *pb.StreamFlow
	headersSent bool
	closed      bool
}

func MakeServerSenderEcho(ctx context.Context) *ServerSenderEcho {
	e := &ServerSenderEcho{
		msgChan: make(chan *pb.StreamFlow, 10),
	}
	return e
}

func (e *ServerSenderEcho) trySend(msg *pb.StreamFlow) {
	select {
	case e.msgChan <- msg:
	default:
	}
}

func (e *ServerSenderEcho) Shutdown(ctx context.Context) {
	e.Lock()
	defer e.Unlock()
	if !e.closed {
		e.closed = true
		e.trySend(pb.StreamflowWrapDoneMsg())
		close(e.msgChan)
	}
}

func (e *ServerSenderEcho) Headers(ctx context.Context, h *pb.TunnelHeaders) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return nil
	}
	e.trySend(pb.StreamflowWrapHeaderMsg(h))
	e.headersSent = true
	return nil
}

func (e *ServerSenderEcho) Data(ctx context.Context, data []byte) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return nil
	}
	d := &pb.Data{
		Data: data,
	}
	e.trySend(pb.StreamflowWrapDataMsg(d))
	return nil
}

func (e *ServerSenderEcho) Fail(ctx context.Context, code int, err error) error {
	fmt.Printf("inside Fail function")
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return nil
	}
	if !e.headersSent {
		h := &pb.TunnelHeaders{
			StreamId:   e.streamID,
			StatusCode: int32(code),
		}
		e.trySend(pb.StreamflowWrapHeaderMsg(h))
	}
	e.trySend(pb.StreamflowWrapDoneMsg())
	e.closed = true
	close(e.msgChan)
	return nil
}

func (e *ServerSenderEcho) Done(ctx context.Context) error {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return nil
	}
	e.trySend(pb.StreamflowWrapDoneMsg())
	e.closed = true
	close(e.msgChan)
	return nil
}

func (e *ServerSenderEcho) Cancel(ctx context.Context) error {
	fmt.Printf("inside Cancel function")
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return nil
	}
	e.trySend(pb.StreamflowWrapCancelMsg())
	e.closed = true
	close(e.msgChan)
	return nil
}
