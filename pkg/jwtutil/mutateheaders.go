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
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
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

// MutateHeader will take a header value (as a string) and return a JWT which we
// can later use in UnmutateHeader to recover the original string value.
func MutateHeader(key jwk.Key, inception time.Time, expirty time.Time, data string) (signed string, err error) {
	t := jwt.New()

	if err = t.Set(jwt.IssuerKey, opsmxIssuerString); err != nil {
		return
	}

	if err = t.Set(jwt.IssuedAtKey, inception.Unix()); err != nil {
		return
	}
	if err = t.Set(jwt.ExpirationKey, expirty.Unix()); err != nil {
		return
	}

	if err = t.Set("u", data); err != nil {
		return
	}

	signedBytes, err := jwt.Sign(t, jwa.HS256, key)
	if err != nil {
		return "", err
	}
	return string(signedBytes), nil
}

// UnmutateHeader checks the mutated data and returns the unmutated original content.
func UnmutateHeader(keyset jwk.Set, tokenString string, clock jwt.Clock) (username string, err error) {
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithValidate(true),
		jwt.WithIssuer(opsmxIssuerString),
		jwt.WithKeySet(keyset),
		jwt.WithRequiredClaim("u"),
		jwt.WithClock(clock),
	)
	if err != nil {
		return
	}
	if username, err = getField(token, "u"); err != nil {
		return
	}
	return
}
