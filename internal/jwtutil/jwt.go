/*
 * Copyright 2021 OpsMx.
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
// Package jwtutil simplifies generating properly formatted web tokens for our use.
//
package jwtutil

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/skandragon/jwtregistry"
)

const (
	jwtEndpointTypeKey      = "t"
	jwtEndpointNameKey      = "n"
	jwtAgentKey             = "a"
	serviceauthIssuer       = "opsmx"
	serviceauthRegistryName = "service-auth"
)

// RegisterServiceauthKeyset registers (or re-registers) a new keyset and signing key name.
func RegisterServiceauthKeyset(keyset jwk.Set, signingKeyName string) error {
	return jwtregistry.Register(serviceauthRegistryName, serviceauthIssuer,
		jwtregistry.WithKeyset(keyset),
		jwtregistry.WithSigningKeyName(signingKeyName),
	)
}

// MakeJWT will return a token with provided type, name, and agent name embedded in the claims.
func MakeJWT(epType string, epName string, agent string, clock jwt.Clock) (string, error) {
	claims := map[string]string{
		jwtEndpointTypeKey: epType,
		jwtEndpointNameKey: epName,
		jwtAgentKey:        agent,
	}

	signed, err := jwtregistry.Sign(serviceauthRegistryName, claims, clock)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// ValidateJWT will validate and return the enbedded claims.
func ValidateJWT(tokenString string, clock jwt.Clock) (epType string, epName string, agent string, err error) {
	claims, err := jwtregistry.Validate(serviceauthRegistryName, []byte(tokenString), clock)
	if err != nil {
		return
	}
	var found bool
	if epType, found = claims[jwtEndpointTypeKey]; !found {
		err = fmt.Errorf("no '%s' key in JWT claims", jwtEndpointTypeKey)
	}
	if epName, found = claims[jwtEndpointNameKey]; !found {
		err = fmt.Errorf("no '%s' key in JWT claims", jwtEndpointNameKey)
	}
	if agent, found = claims[jwtAgentKey]; !found {
		err = fmt.Errorf("no '%s' key in JWT claims", jwtAgentKey)
	}
	return
}
