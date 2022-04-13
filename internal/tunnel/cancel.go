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

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

var cancelRegistry = struct {
	sync.Mutex
	m map[string]context.CancelFunc
}{m: make(map[string]context.CancelFunc)}

// RegisterCancelFunction will associate a cancel function to be called by CallCancelFunction,
// based on the provided id.
func RegisterCancelFunction(id string, cancel context.CancelFunc) {
	cancelRegistry.Lock()
	defer cancelRegistry.Unlock()
	cancelRegistry.m[id] = cancel
}

// UnregisterCancelFunction will remove a remembered cancel function.
func UnregisterCancelFunction(id string) {
	cancelRegistry.Lock()
	defer cancelRegistry.Unlock()
	delete(cancelRegistry.m, id)
}

// CallCancelFunction will call the function associated with the id, if any.
func CallCancelFunction(id string) {
	cancelRegistry.Lock()
	defer cancelRegistry.Unlock()
	cancel, ok := cancelRegistry.m[id]
	if ok {
		cancel()
		zap.S().Debugf("Cancelling request %s", id)
	}
}
