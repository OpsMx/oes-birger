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

package updater

import (
	"os"
	"syscall"
)

// HashSelf will generate a hash of the currently running binary.
func HashSelf() (string, error) {
	selfPath := os.Args[0]

	hash, err := HashFile(selfPath)
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

// RestartSelf will replace the currently running binary with the specified binary.
func RestartSelf(path string) error {
	if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
		return err
	}
	return nil
}
