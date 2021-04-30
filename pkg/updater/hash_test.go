package updater

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

import (
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	hash, err := HashReader(strings.NewReader("abc"))
	if err != nil {
		t.Error(err)
	}
	if hash.Name != "sha3-512" {
		t.Fatalf("expected name to be sha512")
	}
	expected := "t1GFCxpXFopWk82SS2sJbgj2IYJ0RPcNiE9dAkDScS4Q4RbpGSrzyRp+xXZH45NAVzQLTPQI1aVlkvgnTuxT8A=="
	if expected != hash.Hash {
		t.Fatalf("Hash is not correct")
	}
}

func TestEqualsActuallyEqual(t *testing.T) {
	h1 := &Hash{Name: "foo", Hash: "bar"}
	h2 := &Hash{Name: "foo", Hash: "bar"}
	if !h1.Equals(h2) {
		t.Fatalf("Expected %s to equal %s", h1, h2)
	}
}

func TestEqualsNameDiffers(t *testing.T) {
	h1 := &Hash{Name: "foo", Hash: "bar"}
	h2 := &Hash{Name: "xxx", Hash: "bar"}
	if h1.Equals(h2) {
		t.Fatalf("Expected %s to not equal %s", h1, h2)
	}
}

func TestEqualsHashDiffers(t *testing.T) {
	h1 := &Hash{Name: "foo", Hash: "bar"}
	h2 := &Hash{Name: "foo", Hash: "xxx"}
	if h1.Equals(h2) {
		t.Fatalf("Expected %s to not equal %s", h1, h2)
	}
}
