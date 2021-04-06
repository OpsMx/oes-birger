package main

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
