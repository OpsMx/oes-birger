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

func TestEqualsActuallyEqual(t *testing.T) {
	h1 := &Hash{Name: "foo", Hash: "bar"}
	h2 := &Hash{Name: "foo", Hash: "bar"}
	if !h1.Equals(h2) {
		t.Fatalf("Expected %s to equal %s", h1, h2)
	}
}

func TestEqualsNameDiffers(t *testing.T) {
	h1 := &Hash{Name: "foo", Hash: "bar"}
	h2 := &Hash{Name: "xxx", Hash: "bar"}
	if h1.Equals(h2) {
		t.Fatalf("Expected %s to not equal %s", h1, h2)
	}
}

func TestEqualsHashDiffers(t *testing.T) {
	h1 := &Hash{Name: "foo", Hash: "bar"}
	h2 := &Hash{Name: "foo", Hash: "xxx"}
	if h1.Equals(h2) {
		t.Fatalf("Expected %s to not equal %s", h1, h2)
	}
}
