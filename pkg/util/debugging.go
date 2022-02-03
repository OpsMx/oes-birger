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

//
// Package util is a kitchen sink.  Sorry.
//
package util

import "log"

// Debugging set to true will cause additional logging.
var Debugging = false

// Debug will print what it's passed, but only if Debugging is true.
func Debug(f string, v ...interface{}) {
	if Debugging {
		log.Printf(f, v...)
	}
}
