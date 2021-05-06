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
// Package updater will handle updating a binary, and perhaps other files.
// A "hash" is used to indicate a specific file the controller wants us to run,
// and if updating is enabled, we will replace the currently running binary
// with a new version.
//
package updater

import (
	"encoding/base64"
	"io"
	"os"

	"golang.org/x/crypto/sha3"
)

// Hash holds the name of the altorithm used and the hash bytes.
type Hash struct {
	// Name is the algorithm used.
	Name string `json:"name,omitempty"`

	// Hash is a base64 encoded string with padding
	Hash string `json:"hash,omitempty"`
}

func (h *Hash) String() string {
	return h.Name + ":" + h.Hash
}

// Equals will compare one hash to another, returning true if so.
func (h *Hash) Equals(b *Hash) bool {
	return h.Name == b.Name && h.Hash == b.Hash
}

//
// HashFile will generate a cryptographic hash of the given file, and
// return a struct that contains the algorithm used, and the hash
// []bytes.
//
func HashFile(filename string) (*Hash, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return HashReader(f)
}

// HashReader will take an io.Reader, and completely consume
// the contents, returning the hashed value.
func HashReader(reader io.Reader) (*Hash, error) {
	hasher := sha3.New512()
	hash := &Hash{
		Name: "sha3-512",
	}

	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}

	h := hasher.Sum(nil)
	hash.Hash = base64.StdEncoding.EncodeToString(h)
	return hash, nil
}
