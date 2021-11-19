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

import "testing"

var cancelCalled bool

func cancelFunction() {
	cancelCalled = true
}

func reset() {
	cancelCalled = false
}

// Test that we can call the cancel function when asked to.
func TestCancel(t *testing.T) {
	reset()
	RegisterCancelFunction("cf1", cancelFunction)
	CallCancelFunction("cf1")
	if !cancelCalled {
		t.Failed()
	}
}

// Test that we can call the cancel function when asked to.
func TestCancelUnknownId(t *testing.T) {
	reset()
	RegisterCancelFunction("cf1", cancelFunction)
	CallCancelFunction("cf2")
	if cancelCalled {
		t.Failed()
	}
}
