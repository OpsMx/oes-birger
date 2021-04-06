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
		name    string
		keyid   string
		keyset  jwk.Set
		epType  string
		epName  string
		agent   string
		want    string
		wantErr bool
	}{
		{
			"key1",
			"key1",
			keyset,
			"artifactory",
			"bob",
			"agent1",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaXNzIjoib3BzbXgiLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.TdshkeQ7ScSkWWkkl8QRMZ4ZmoJWQkqNiDceKCIH8ms",
			false,
		},
		{
			"key2",
			"key2",
			keyset,
			"jenkins",
			"bob",
			"agent1",
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaXNzIjoib3BzbXgiLCJuIjoiYm9iIiwidCI6ImplbmtpbnMifQ.QvTMDpqsmC8KsUt5J3bvSAp9noLOYjboMiyinWR7uVA",
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
			got, err := MakeJWT(key, tt.epType, tt.epName, tt.agent)
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
		name      string
		keyset    jwk.Set
		token     string
		wantType  string
		wantName  string
		wantAgent string
		wantErr   bool
	}{
		{
			"valid",
			keyset,
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaXNzIjoib3BzbXgiLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.TdshkeQ7ScSkWWkkl8QRMZ4ZmoJWQkqNiDceKCIH8ms",
			"artifactory",
			"bob",
			"agent1",
			false,
		},
		{
			"invalid1",
			keyset,
			"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJhIjoiYWdlbnQxIiwiaXNzIjoib3BzbXgiLCJuIjoiYm9iIiwidCI6ImFydGlmYWN0b3J5In0.",
			"",
			"",
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotName, gotAgent, err := ValidateJWT(tt.keyset, tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotType != tt.wantType {
				t.Errorf("ValidateJWT() gotType = %v, want %v", gotType, tt.wantType)
			}
			if gotName != tt.wantName {
				t.Errorf("ValidateJWT() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotAgent != tt.wantAgent {
				t.Errorf("ValidateJWT() gotAgent = %v, want %v", gotAgent, tt.wantAgent)
			}
		})
	}
}
