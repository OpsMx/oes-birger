package updater

import (
	"crypto"
	_ "crypto/sha512" // Needed to explicitly load sha512.
	"io"
	"os"
)

// Hash holds the name of the altorithm used and the hash bytes.
type Hash struct {
	Name string `json:"name,omitempty"`
	Hash []byte `json:"hash,omitempty"`
}

//
// HashFile will generate a cryptographic hash of the given file, and
// return a struct that contains the algorithm used, and the hash
// []bytes.
//
func HashFile(filename string) (*Hash, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return HashReader(f)
}

// HashReader will take an io.Reader, and completely consume
// the contents, returning the hashed value.
func HashReader(reader io.Reader) (*Hash, error) {
	hasher := crypto.SHA512.New()
	hash := &Hash{
		Name: "sha512",
	}

	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}

	h := hasher.Sum(nil)
	hash.Hash = h
	return hash, nil
}
