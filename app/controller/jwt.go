package main

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

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	JWTEndpointTypeKey = "t"
	JWTEndpointNameKey = "n"
	JWTAgentKey        = "a"
)

func MakeJWT(key jwk.Key, epType string, epName string, agent string) (string, error) {
	t := jwt.New()
	t.Set(jwt.IssuerKey, "opsmx")
	t.Set(JWTEndpointTypeKey, epType)
	t.Set(JWTEndpointNameKey, epName)
	t.Set(JWTAgentKey, agent)

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

func ValidateJWT(keyset jwk.Set, tokenString string) (epType string, epName string, agent string, err error) {
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithValidate(true),
		jwt.WithKeySet(keyset),
	)
	if err != nil {
		return
	}
	if epType, err = getField(token, JWTEndpointTypeKey); err != nil {
		return "", "", "", err
	}
	if epName, err = getField(token, JWTEndpointNameKey); err != nil {
		return "", "", "", err
	}
	if agent, err = getField(token, JWTAgentKey); err != nil {
		return "", "", "", err
	}
	return
}
