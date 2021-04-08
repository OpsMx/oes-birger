package updater

import "os"

func HashSelf() (string, error) {
	selfPath := os.Args[0]

	hash, err := HashFile(selfPath)
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}
