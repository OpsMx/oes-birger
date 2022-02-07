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

import "time"

// GRPCEventStream is a generic placeholder for either a GRPC client or server which
// handles the MessageWrapper type.  This allows generically defining a "send message of
// subtype X" without caring if it's a client or server.
type GRPCEventStream interface {
	Send(*MessageWrapper) error
	Recv() (*MessageWrapper, error)
}

// MakePingResponse will format a response to a PingRequest, able to be sent directly over
// the tunnel.
func MakePingResponse(req *PingRequest) *MessageWrapper {
	resp := &MessageWrapper{
		Event: &MessageWrapper_PingResponse{
			PingResponse: &PingResponse{Ts: uint64(time.Now().UnixNano()), EchoedTs: req.Ts},
		},
	}
	return resp
}
