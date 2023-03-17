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

package serviceconfig

import (
	"context"

	pb "github.com/opsmx/oes-birger/internal/tunnel"
)

// HTTPEcho is an interface that makes generic http services possible.  For
// the "agent" side and "controller" side, different implementations can handle
// an incoming or outgoing HTTP client and the underlying RPC calls needed to
// exchange data.
//
// Data flow is Headers(), zero or more Data() calls with at least 1 byte of
// data, and then a Done() call.  If any failure is to be indicated, Fail()
// can be called at any time, and it will ensure that the RPC level protocol
// is properly handled.
//
// After Done() is called, no other calls should be made.
// After Fail() is called, no other calls should be made.
type HTTPEcho interface {
	// Headers is called once to send the appropriate headers.
	Headers(ctx context.Context, h *pb.TunnelHeaders) error
	// Data is called one or more times to send data.
	Data(ctx context.Context, data []byte) error
	// Fail can be called to indicate no more calls will be made.  This may happen
	// without calling Headers() or Data(), or after calling one or both.  If
	// headers have been sent, this should send a EOF Data frame.
	Fail(ctx context.Context, httpCode int, err error) error
	// Done indicates the session ended.  If headers have not been sent,
	// this is an error.  Data may not be called, and Done should send
	// an EOF Data frame.
	Done(ctx context.Context) error
	// Cancel terminates a session without handling any error codes, or other
	// cleanup.  The HTTP request (in or out) should be terminated immediately.
	Cancel(context context.Context) error
	// Shutdown cleans anything up if needed.  It should not do anything that can
	// cause an error, since it doesn't return one.
	Shutdown(context context.Context)
}
