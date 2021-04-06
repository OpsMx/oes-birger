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

func ValidateJWT(keyset jwk.Set, tokenString string) (epType string, epName string, agent string, err error) {
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithValidate(true),
		jwt.WithKeySet(keyset),
	)
	if err != nil {
		return
	}
	if itype, ok := token.Get(JWTEndpointTypeKey); ok {
		epType = itype.(string)
	} else {
		return "", "", "", fmt.Errorf("missing epType")
	}
	if iname, ok := token.Get(JWTEndpointNameKey); ok {
		epName = iname.(string)
	} else {
		return "", "", "", fmt.Errorf("missing epName")
	}
	if iagent, ok := token.Get(JWTAgentKey); ok {
		agent = iagent.(string)
	} else {
		return "", "", "", fmt.Errorf("missing agent")
	}
	return
}
