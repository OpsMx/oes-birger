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

package jwtutil

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// LoadTestKeys is a helper method to load test keys, which obviously should
// not be used in production...
func LoadTestKeys(t *testing.T) jwk.Set {
	keyset := jwk.NewSet()
	if err := keyset.AddKey(makekey(t, "key1", "this is a key")); err != nil {
		panic(err)
	}
	if err := keyset.AddKey(makekey(t, "key2", "this is a key2")); err != nil {
		panic(err)
	}
	return keyset
}

func makekey(t *testing.T, name string, content string) jwk.Key {
	key, err := jwk.FromRaw([]byte(content))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if err := key.Set(jwk.KeyIDKey, name); err != nil {
		panic(err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.HS256); err != nil {
		panic(err)
	}
	return key
}
