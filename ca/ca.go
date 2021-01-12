package ca

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/opsmx/grpc-bidir/kubeconfig"
	"gopkg.in/yaml.v2"
)

//
// CA holds the state for the certificate authority.
//
type CA struct {
	config *Config
	caCert tls.Certificate
}

//
// Config holds the filenames for a CA, and has mappings for loading from
// YAML or JSON.
//
type Config struct {
	CACertFile string `yaml:"caCertFile,omitempty" json:"caCertFile,omitempty"`
	CAKeyFile  string `yaml:"caKeyFile,omitempty" json:"caKeyFile,omitempty"`
}

// TODO: this may not be needed...
func deepcopy(dst interface{}, src interface{}) error {
	j, err := json.Marshal(src)
	if err != nil {
		return err
	}
	err = json.Unmarshal(j, &dst)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) applyDefaults() {
	if len(c.CACertFile) == 0 {
		c.CACertFile = "/app/secrets/ca/tls.crt"
	}
	if len(c.CAKeyFile) == 0 {
		c.CAKeyFile = "/app/secrets/ca/tls.key"
	}
}

func (c *CA) loadCertificate() error {
	caCert, err := tls.LoadX509KeyPair(c.config.CACertFile, c.config.CAKeyFile)
	if err != nil {
		return fmt.Errorf("Unable to load CA cetificate or key: %v", err)
	}
	c.caCert = caCert
	return nil
}

//
// MakeCA will return a CA based on the configuration passed in.  Note that
// this follows the GO "Make*() returns a new object" naming, and does not
// actually create a new CA.  This loads the certificate from the filenames
// in the configuration.
//
func MakeCA(c *Config) (*CA, error) {
	var config Config
	err := deepcopy(config, *c)
	if err != nil {
		return nil, err
	}
	config.applyDefaults()

	ca := &CA{
		config: &config,
	}

	err = ca.loadCertificate()
	if err != nil {
		return nil, err
	}
	return ca, nil
}

//
// GetCACertificate returns the public certificate for the CA.
//
func (c *CA) GetCACertificate() []byte {
	return c.caCert.Certificate[0]
}

//
// MakeServerCert will generate a new server certificate, signed with the authority,
// with a validity period of 1 year.  The DNS names will be applied.
//
func (c *CA) MakeServerCert(names []string) (*tls.Certificate, error) {
	now := time.Now().UTC()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"OpsMX API Forwarder"},
			Country:      []string{"US"},
			Province:     []string{},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:   now,
		NotAfter:    now.AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		DNSNames:    names,
	}
	certPrivKey, err := rsa.GenerateKey(crand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// we now have a certificate and private key.  Now, sign the cert with the CA.

	caCert, err := x509.ParseCertificate(c.caCert.Certificate[0])

	certBytes, err := x509.CreateCertificate(crand.Reader, cert, caCert, &certPrivKey.PublicKey, c.caCert.PrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}
	return &serverCert, nil
}

//
// MakeKubectlConfig will generate a new client certificate with the specified
// clientName, configured to connect to the specified serverUrl, and will provide
// the CA certificate as a trusted authprity.
//
func (c *CA) MakeKubectlConfig(clientName string, serverURL string) (string, error) {
	ca64, cert64, certPrivKey64, err := c.GenerateCertificate(clientName, "client")
	if err != nil {
		return "", err
	}
	y, err := makeKubeConfig("forwarder", ca64, cert64, certPrivKey64, serverURL)
	if err != nil {
		return "", nil
	}
	return y, nil
}

//
// GenerateCertificate will make a new certificate, and return a base64 encoded
// string for the certificate, key, and authority certificate.
//
func (c *CA) GenerateCertificate(name string, suffix string) (string, string, string, error) {
	now := time.Now().UTC()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   name + "." + suffix,
			Organization: []string{"OpsMX API Forwarder Client"},
			Country:      []string{"US"},
			Province:     []string{},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:   now,
		NotAfter:    now.AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(crand.Reader, 4096)
	if err != nil {
		return "", "", "", err
	}

	// we now have a certificate and private key.  Now, sign the cert with the CA.

	caCert, err := x509.ParseCertificate(c.caCert.Certificate[0])
	if err != nil {
		return "", "", "", err
	}

	certBytes, err := x509.CreateCertificate(crand.Reader, cert, caCert, &certPrivKey.PublicKey, c.caCert.PrivateKey)
	if err != nil {
		return "", "", "", err
	}

	ca64 := bytesTo64("CERTIFICATE", c.caCert.Certificate[0])
	cert64 := bytesTo64("RSA PUBLIC KEY", x509.MarshalPKCS1PrivateKey(certPrivKey))
	certPrivKey64 := bytesTo64("CERTIFICATE", certBytes)

	return ca64, cert64, certPrivKey64, nil
}

func bytesTo64(prefix string, data []byte) string {
	p := new(bytes.Buffer)
	pem.Encode(p, &pem.Block{
		Type:  prefix,
		Bytes: data,
	})
	return base64.StdEncoding.EncodeToString(p.Bytes())
}

func makeKubeConfig(name string, ca64 string, cert64 string, certPrivKey64 string, serverURL string) (string, error) {
	k := kubeconfig.KubeConfig{
		APIVersion: "v1",
		Kind:       "Config",
		Contexts: []kubeconfig.Context{
			{
				Name: name,
				Context: kubeconfig.ContextDetails{
					User:    name,
					Cluster: name,
				},
			},
		},
		Users: []kubeconfig.User{
			{
				Name: name,
				User: kubeconfig.UserDetails{
					ClientCertificateData: cert64,
					ClientKeyData:         certPrivKey64,
				},
			},
		},
		Clusters: []kubeconfig.Cluster{
			{
				Name: name,
				Cluster: kubeconfig.ClusterDetails{
					Server:                   serverURL,
					CertificateAuthorityData: ca64,
				},
			},
		},
		CurrentContext: name,
	}

	s, err := yaml.Marshal(k)
	if err != nil {
		return "", nil
	}
	return string(s), nil
}

func (c *CA) MakeCertPool() (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	for _, cert := range c.caCert.Certificate {
		x, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse certificate ASN.1: %v", err)
		}
		caCertPool.AddCert(x)
		caCertPool.AppendCertsFromPEM(cert)
	}
	return caCertPool, nil
}
