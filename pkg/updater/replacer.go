package updater

import (
	"os"
	"syscall"
)

func HashSelf() (string, error) {
	selfPath := os.Args[0]

	hash, err := HashFile(selfPath)
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

func RestartSelf(path string) error {
	if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
		return err
	}
	return nil
}
