/*
 * Copyright 2022 OpsMx, Inc.
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
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/skandragon/jwtregistry/v2"
)

// Process header mutation.  This is currently only done on X-Spinnaker-User header
// fields.
//
// On an incoming request to the controller on any service port, if there is
// an X-Spinnaker-User header, it will be modified to be a JWT token instead.
// This JWT will have a defined lifetime (default 15 minutes), and will be passed
// to the agent over GRPC as the new header value.
//
// On receiving this header from any agent, the JWT will be validated, and if
// found to be secure and valid, the actual service will be called with the
// decoded value.
//
// Example:
//
// orca -> controller (mutates header) -> agent -> clouddriver
// clouddriver -> agent -> controller (unmutates header) -> front50
//
// This allows splitting Clouddrivers off to remote locations while still ensuring
// they only contact our internal, secure components with requests sent to them.

const (
	mutateRegistryName = "header-mutation"
	mutateIssuer       = "opsmx-header-mutation"
	mutateValidity     = 15 * time.Minute
)

var (
	mutationRegistered = false
)

// RegisterMutationKeyset registers (or re-registers) a new keyset and signing key name.
func RegisterMutationKeyset(keyset jwk.Set, signingKeyName string) error {
	mutationRegistered = true
	return jwtregistry.Register(mutateRegistryName, mutateIssuer,
		jwtregistry.WithKeyset(keyset),
		jwtregistry.WithSigningKeyName(signingKeyName),
		jwtregistry.WithSigningValidityPeriod(mutateValidity),
	)
}

// UnregisterMutationKeyset removes the registration.  This is mostly for testing.
func UnregisterMutationKeyset() {
	mutationRegistered = false
	jwtregistry.Delete(mutateRegistryName)
}

// MutationIsRegistered indicates if RegisterMutationKeyset was called at least once.
func MutationIsRegistered() bool {
	return mutationRegistered
}

// MutateHeader will take a header value (as a string) and return a JWT which we
// can later use in UnmutateHeader to recover the original string value.
func MutateHeader(data string, clock jwt.Clock) (signed []byte, err error) {
	signed, err = jwtregistry.Sign(mutateRegistryName, map[string]string{"u": data}, clock)
	return
}

// UnmutateHeader checks the mutated data and returns the unmutated original content.
func UnmutateHeader(tokenString []byte, clock jwt.Clock) (username string, err error) {
	claims, err := jwtregistry.Validate(mutateRegistryName, tokenString, clock)
	if err != nil {
		return
	}
	username, ok := claims["u"]
	if !ok {
		err = fmt.Errorf("u field not found in claims")
		return
	}
	return
}
