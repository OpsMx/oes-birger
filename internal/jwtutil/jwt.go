/*
 * Copyright 2021-2023 OpsMx, Inc.
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

// Package jwtutil simplifies generating properly formatted web tokens for our use.
package jwtutil

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/skandragon/jwtregistry/v2"
)

const (
	jwtEndpointTypeKey      = "t"
	jwtEndpointNameKey      = "n"
	jwtAgentKey             = "a"
	issuer                  = "opsmx"
	agentIssuer             = "opsmx-agent-auth"
	serviceauthRegistryName = "service-auth"
	agentRegistryName       = "agent-auth"
	claimOpsmxAgentName     = "opsmx.agent.name"
)

// RegisterServiceKeyset registers (or re-registers) a new keyset and signing key name.
func RegisterServiceKeyset(keyset jwk.Set, signingKeyName string) error {
	return jwtregistry.Register(serviceauthRegistryName,
		issuer,
		jwtregistry.WithKeyset(keyset),
		jwtregistry.WithSigningKeyName(signingKeyName),
	)
}

// RegisterAgentKeyset registers (or re-registers) a new keyset and signing key name.
func RegisterAgentKeyset(keyset jwk.Set, signingKeyName string) error {
	return jwtregistry.Register(agentRegistryName,
		agentIssuer,
		jwtregistry.WithKeyset(keyset),
		jwtregistry.WithSigningKeyName(signingKeyName),
	)
}

// MakeServiceJWT will return a token with provided type, name, and agent name embedded in the claims.
func MakeServiceJWT(epType string, epName string, agent string, clock jwt.Clock) (string, error) {
	claims := map[string]string{
		jwtEndpointTypeKey: epType,
		jwtEndpointNameKey: epName,
		jwtAgentKey:        agent,
	}
	return sign(serviceauthRegistryName, claims, clock)
}

// MakeAgentJWT will return a token with provided type, name, and agent name embedded in the claims.
func MakeAgentJWT(agent string, clock jwt.Clock) (string, error) {
	claims := map[string]string{
		claimOpsmxAgentName: agent,
	}
	return sign(agentRegistryName, claims, clock)
}

func sign(registry string, claims map[string]string, clock jwt.Clock) (string, error) {
	signed, err := jwtregistry.Sign(registry, claims, clock)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// ValidateServiceJWT will validate and return the enbedded claims.
func ValidateServiceJWT(tokenString string, clock jwt.Clock) (epType string, epName string, agent string, err error) {
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

// ValidateAgentJWT will validate and return the enbedded claims.
func ValidateAgentJWT(tokenString string, clock jwt.Clock) (string, error) {
	claims, err := jwtregistry.Validate(agentRegistryName, []byte(tokenString), clock)
	if err != nil {
		return "", err
	}
	agent, found := claims[claimOpsmxAgentName]
	if found {
		return agent, nil
	}
	return "", fmt.Errorf("no '%s' key in JWT claims", claimOpsmxAgentName)
}
