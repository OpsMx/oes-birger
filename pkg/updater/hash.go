package updater

import (
	"encoding/base64"
	"io"
	"os"

	"golang.org/x/crypto/sha3"
)

// Hash holds the name of the altorithm used and the hash bytes.
type Hash struct {
	// Name is the algorithm used.
	Name string `json:"name,omitempty"`

	// Hash is a base64 encoded string with padding
	Hash string `json:"hash,omitempty"`
}

func (h *Hash) String() string {
	return h.Name + ":" + h.Hash
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
	hasher := sha3.New512()
	hash := &Hash{
		Name: "sha3-512",
	}

	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}

	h := hasher.Sum(nil)
	hash.Hash = base64.StdEncoding.EncodeToString(h)
	return hash, nil
}
