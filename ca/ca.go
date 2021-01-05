package ca

import (
	"crypto/tls"
	"log"
)

//
// CA holds the state for the certificate authority.
//
type CA struct {
	config *CAConfig
	caCert tls.Certificate
}

//
// Config holds the filenames for a CA, and has mappings for loading from
// YAML.
//
type Config struct {
	CACertFile string `yaml:"caCertFile"`
	CAKeyFile  string `yaml:"caKeyFile"`
}

//
// MakeCAConfig returns a defaults-populated CA Config.
//
func MakeCAConfig() *Config {
	return &Config{
		CACertFile: "/app/secrets/ca/tls.cert",
		CAKeyFile:  "/app/secrets/ca/tls.key",
	}
}

//
// MakeCA will return a CA based on the configuration passed in.  Note that
// this follows the GO "Make returns a new object" naming, and does not
// actually create a new CA.  This loads the certificate from the filenames
// in the configuration.
//
func MakeCA(config Config) (*CA, error) {
	caCert, err := tls.LoadX509KeyPair(config.CACertFile, config.CAKeyFile)
	if err != nil {
		log.Fatalf("Unable to load CA cetificate or key: %v", err)
	}

	ca := &CA{
		config: config,
		caCert: caCert,
	}
	return ca, nil
}

//
// GetCACertificate returns the public certificate for the CA.
//
func (ca *CA) GetCACertificate() []byte {
	return ca.caCert.Certificate[0]
}
