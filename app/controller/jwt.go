package main

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func MakeJWT(key jwk.Key, username string, agent string) (string, error) {
	t := jwt.New()
	t.Set(jwt.IssuerKey, "opsmx")
	t.Set("username", username)
	t.Set("agent", agent)

	signed, err := jwt.Sign(t, jwa.HS256, key)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func ValidateJWT(keyset jwk.Set, tokenString string) (username string, agent string, err error) {
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithValidate(true),
		jwt.WithKeySet(keyset),
	)
	if err != nil {
		return
	}
	if iname, ok := token.Get("username"); ok {
		username = iname.(string)
	} else {
		return "", "", fmt.Errorf("missing username")
	}
	if iagent, ok := token.Get("agent"); ok {
		agent = iagent.(string)
	} else {
		return "", "", fmt.Errorf("missing agent")
	}
	return
}
