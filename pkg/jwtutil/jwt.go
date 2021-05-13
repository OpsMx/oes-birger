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

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	jwtEndpointTypeKey = "t"
	jwtEndpointNameKey = "n"
	jwtAgentKey        = "a"
)

// MakeJWT will return a token with provided type, name, and agent name embeded in the claims.
func MakeJWT(key jwk.Key, epType string, epName string, agent string) (string, error) {
	t := jwt.New()

	err := t.Set(jwt.IssuerKey, "opsmx")
	if err != nil {
		return "", err
	}

	err = t.Set(jwtEndpointTypeKey, epType)
	if err != nil {
		return "", err
	}

	err = t.Set(jwtEndpointNameKey, epName)
	if err != nil {
		return "", err
	}

	err = t.Set(jwtAgentKey, agent)
	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(t, jwa.HS256, key)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func getField(token jwt.Token, name string) (string, error) {
	if i, ok := token.Get(name); ok {
		return i.(string), nil
	}
	return "", fmt.Errorf("missing %s", name)
}

// ValidateJWT will validate and return the enbedded claims.
func ValidateJWT(keyset jwk.Set, tokenString string) (epType string, epName string, agent string, err error) {
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithValidate(true),
		jwt.WithKeySet(keyset),
	)
	if err != nil {
		return
	}
	if epType, err = getField(token, jwtEndpointTypeKey); err != nil {
		return "", "", "", err
	}
	if epName, err = getField(token, jwtEndpointNameKey); err != nil {
		return "", "", "", err
	}
	if agent, err = getField(token, jwtAgentKey); err != nil {
		return "", "", "", err
	}
	return
}
