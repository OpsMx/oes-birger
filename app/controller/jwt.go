package main

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func MakeJWT(key jwk.Key, epType string, epName string, agent string) (string, error) {
	t := jwt.New()
	t.Set(jwt.IssuerKey, "opsmx")
	t.Set("t", epType)
	t.Set("n", epName)
	t.Set("a", agent)

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
	if itype, ok := token.Get("t"); ok {
		epType = itype.(string)
	} else {
		return "", "", "", fmt.Errorf("missing epType")
	}
	if iname, ok := token.Get("n"); ok {
		epName = iname.(string)
	} else {
		return "", "", "", fmt.Errorf("missing epName")
	}
	if iagent, ok := token.Get("a"); ok {
		agent = iagent.(string)
	} else {
		return "", "", "", fmt.Errorf("missing agent")
	}
	return
}
