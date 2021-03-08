package updater

import (
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	hash, err := HashReader(strings.NewReader("abc"))
	if err != nil {
		t.Error(err)
	}
	if hash.Name != "sha3-512" {
		t.Fatalf("expected name to be sha512")
	}
	expected := "t1GFCxpXFopWk82SS2sJbgj2IYJ0RPcNiE9dAkDScS4Q4RbpGSrzyRp+xXZH45NAVzQLTPQI1aVlkvgnTuxT8A=="
	if expected != hash.Hash {
		t.Fatalf("Hash is not correct")
	}
}
