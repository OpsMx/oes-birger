package main

import (
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
)

func makekey(t *testing.T, name string, content string) jwk.Key {
	key, err := jwk.New([]byte(content))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	key.Set(jwk.KeyIDKey, name)
	return key
}

func loadkeys(t *testing.T) jwk.Set {
	keyset := jwk.NewSet()
	keyset.Add(makekey(t, "key1", "this is a key"))
	keyset.Add(makekey(t, "key2", "this is a key2"))
	return keyset
}

func TestMakeJWT(t *testing.T) {
	keyset := loadkeys(t)
	tests := []struct {
		name     string
		keyid    string
		keyset   jwk.Set
		username string
		agent    string
		want     string
		wantErr  bool
	}{
		{
			"key1",
			"key1",
			keyset,
			"bob",
			"agent1",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhZ2VudCI6ImFnZW50MSIsImlzcyI6Im9wc214IiwidXNlcm5hbWUiOiJib2IifQ.9cJIQwYIp9pnA7y8zfc2qo0SAMjYPzzYVF-WE1buLEQ",
			false,
		},
		{
			"key2",
			"key2",
			keyset,
			"bob",
			"agent1",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIiLCJ0eXAiOiJKV1QifQ.eyJhZ2VudCI6ImFnZW50MSIsImlzcyI6Im9wc214IiwidXNlcm5hbWUiOiJib2IifQ.fLQZV45Sx3kQ4P1np6g1xklEoYnA-Fv1XYU7kp9EO5A",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key jwk.Key
			var ok bool
			if key, ok = tt.keyset.LookupKeyID(tt.keyid); !ok {
				t.Errorf("key not found: %s", tt.keyid)
				t.FailNow()
			}
			got, err := MakeJWT(key, tt.username, tt.agent)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakeJWT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	keyset := loadkeys(t)
	tests := []struct {
		name         string
		keyset       jwk.Set
		token        string
		wantUsername string
		wantAgent    string
		wantErr      bool
	}{
		{
			"valid",
			keyset,
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhZ2VudCI6ImFnZW50MSIsImlzcyI6Im9wc214IiwidXNlcm5hbWUiOiJib2IifQ.9cJIQwYIp9pnA7y8zfc2qo0SAMjYPzzYVF-WE1buLEQ",
			"bob",
			"agent1",
			false,
		},
		{
			"invalid1",
			keyset,
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhZ2VudCI6ImFnZW50MSIsImlzcyI6Im9wc214IiwidXNlcm5hbWUiOiJib2IifQ.",
			"",
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUsername, gotAgent, err := ValidateJWT(tt.keyset, tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUsername != tt.wantUsername {
				t.Errorf("ValidateJWT() gotUsername = %v, want %v", gotUsername, tt.wantUsername)
			}
			if gotAgent != tt.wantAgent {
				t.Errorf("ValidateJWT() gotAgent = %v, want %v", gotAgent, tt.wantAgent)
			}
		})
	}
}
