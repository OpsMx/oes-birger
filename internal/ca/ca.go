/*
 * Copyright 2021 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package ca implements a simple certificate authority.
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

	"go.uber.org/zap"
)

const (
	defaultTLSCertificatePath = "/app/secrets/ca/tls.crt"
	defaultTLSKeyPath         = "/app/secrets/ca/tls.key"
)

// CertificateIssuer implements a generic CA
type CertificateIssuer interface {
	GenerateCertificate(CertificateName) (string, string, string, error)
	GetCACert() (string, error)
}

// CertPoolGenerator implements a method to make a TLS x509 certificate pool for servers
type CertPoolGenerator interface {
	MakeCertPool() (*x509.CertPool, error)
}

// CA holds the state for the certificate authority.
type CA struct {
	config *Config
	caCert tls.Certificate
}

// Config holds the filenames for a CA, and has mappings for loading from
// YAML or JSON.
type Config struct {
	CACertFile string `yaml:"caCertFile,omitempty" json:"caCertFile,omitempty"`
	CAKeyFile  string `yaml:"caKeyFile,omitempty" json:"caKeyFile,omitempty"`
}

func (c *Config) applyDefaults() {
	if len(c.CACertFile) == 0 {
		c.CACertFile = defaultTLSCertificatePath
	}
	if len(c.CAKeyFile) == 0 {
		c.CAKeyFile = defaultTLSKeyPath
	}
}

func (c *CA) loadCertificate() error {
	caCert, err := tls.LoadX509KeyPair(c.config.CACertFile, c.config.CAKeyFile)
	if err != nil {
		return fmt.Errorf("unable to load CA cetificate or key: %v", err)
	}
	c.caCert = caCert
	return nil
}

// LoadCAFromFile will load an existing authority.
func LoadCAFromFile(c Config) (*CA, error) {
	c.applyDefaults()

	ca := &CA{
		config: &c,
	}

	err := ca.loadCertificate()
	if err != nil {
		return nil, err
	}
	err = ValidateCACert(ca.caCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// MakeCAFromData does approximately the same thing as LoadCAFromFile() except the CA
// contents are loaded from PEM strings.
func MakeCAFromData(certPEM []byte, certPrivKeyPEM []byte) (*CA, error) {
	caCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, err
	}
	ca := &CA{caCert: caCert}
	err = ValidateCACert(ca.caCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// ValidateCACert performs some basic checks on the CA cert, like validity
// period and that it can sign certs.
func ValidateCACert(certbytes []byte) error {
	pc, err := x509.ParseCertificate(certbytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}
	if len(pc.Subject.Organization) > 0 {
		zap.L().Info("CA loaded",
			zap.String("name", pc.Subject.Organization[0]),
			zap.Time("expires", pc.NotAfter))
	}
	if !pc.IsCA {
		return fmt.Errorf("CA certificate does not appear to be a proper CA (!IsCA)")
	}
	now := time.Now()
	if pc.NotAfter.Before(now) {
		return fmt.Errorf("CA certificate has expired (NotAfter %v)", pc.NotAfter)
	}
	if pc.NotBefore.After(now) {
		return fmt.Errorf("CA certificate has not started yet (NotBefore %v)", pc.NotBefore)
	}
	return nil
}

// GetCACertificate returns the public certificate for the CA.
func (c *CA) GetCACertificate() []byte {
	return c.caCert.Certificate[0]
}

func toPEM(data []byte, t string) ([]byte, error) {
	p := &bytes.Buffer{}
	err := pem.Encode(p, &pem.Block{
		Type:  t,
		Bytes: data,
	})
	if err != nil {
		return []byte{}, nil
	}
	return p.Bytes(), nil
}

// MakeCertificateAuthority generates a new certificate authority key, and self-signs it.
func MakeCertificateAuthority() ([]byte, []byte, error) {
	now := time.Now().UTC()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"OpsMx API Forwarder CA"},
			Country:      []string{"US"},
		},
		NotBefore:             now.Add(-10 * time.Second),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	empty := []byte{}

	priv, err := rsa.GenerateKey(crand.Reader, 4096)
	if err != nil {
		return empty, empty, err
	}

	// Self-sign the CA key.
	certBytes, err := x509.CreateCertificate(crand.Reader, rootTemplate, rootTemplate, &priv.PublicKey, priv)
	if err != nil {
		return empty, empty, err
	}

	certPEM, err := toPEM(certBytes, "CERTIFICATE")
	if err != nil {
		return []byte{}, []byte{}, err
	}

	certPrivKeyPEM, err := toPEM(x509.MarshalPKCS1PrivateKey(priv), "RSA PRIVATE KEY")
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return certPEM, certPrivKeyPEM, nil
}

// MakeServerCert will generate a new server certificate, signed with the authority,
// with a validity period of 1 year.  The DNS names will be applied.
func (c *CA) MakeServerCert(names []string) (*tls.Certificate, error) {
	now := time.Now().UTC()

	caCert, err := x509.ParseCertificate(c.caCert.Certificate[0])
	if err != nil {
		return nil, err
	}

	certPrivKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"OpsMx API Forwarder Server Certificate"},
			Country:      []string{"US"},
		},
		NotBefore:   now.Add(-10 * time.Second),
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:    names,
	}

	certBytes, err := x509.CreateCertificate(crand.Reader, certTemplate, caCert, &certPrivKey.PublicKey, c.caCert.PrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM, err := toPEM(certBytes, "CERTIFICATE")
	if err != nil {
		return nil, err
	}

	certPrivKeyPEM, err := toPEM(x509.MarshalPKCS1PrivateKey(certPrivKey), "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, err
	}

	return &serverCert, nil
}

// CertificateName holds the items we will encode in the certificate, so we can determine what
// endpoint is being requested.
type CertificateName struct {
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	Agent   string `json:"agent,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// Certificate purposes, intended to be on CertificateName.Purpose
const (
	CertificatePurposeControl = "control"
	CertificatePurposeAgent   = "agent"
	CertificatePurposeService = "service"
)

// GetCertificateNameFromCert extracts the CertificateName from the certificate, or returns
// an error if not found.
func GetCertificateNameFromCert(cert *x509.Certificate) (*CertificateName, error) {
	if len(cert.Subject.OrganizationalUnit) < 1 {
		return nil, fmt.Errorf("Subject OrganizationalUnit does not appear to be a JSON token")
	}
	ou := cert.Subject.OrganizationalUnit[0]
	var name CertificateName
	err := json.Unmarshal([]byte(ou), &name)
	if err != nil {
		return nil, err
	}
	return &name, nil
}

// GenerateCertificate will make a new certificate, and return a base64 encoded
// string for the certificate, key, and authority certificate.
func (c *CA) GenerateCertificate(name CertificateName) (string, string, string, error) {
	now := time.Now().UTC()
	jsonName, err := json.Marshal(name)
	if err != nil {
		return "", "", "", err
	}
	json := string(jsonName)
	orgName := fmt.Sprintf("OpsMx Tunnel Certificate: %s-%s-%s", name.Agent, name.Name, name.Type)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:         orgName,
			Organization:       []string{orgName},
			OrganizationalUnit: []string{json},
		},
		NotBefore:   now,
		NotAfter:    now.AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(crand.Reader, 2048)
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

	ca64, err := c.GetCACert()
	if err != nil {
		return "", "", "", err
	}

	cert64, err := bytesTo64("CERTIFICATE", certBytes)
	if err != nil {
		return "", "", "", err
	}

	certPrivKey64, err := bytesTo64("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(certPrivKey))
	if err != nil {
		return "", "", "", err
	}

	return ca64, cert64, certPrivKey64, nil
}

// GetCACert returns the authority certificate encoded as base64.
func (c *CA) GetCACert() (string, error) {
	return bytesTo64("CERTIFICATE", c.caCert.Certificate[0])
}

func bytesTo64(prefix string, data []byte) (string, error) {
	p, err := toPEM(data, prefix)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

// MakeCertPool will return a certificate pool with our CA installed.
func (c *CA) MakeCertPool() (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	for _, cert := range c.caCert.Certificate {
		x, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %v", err)
		}
		caCertPool.AddCert(x)
		caCertPool.AppendCertsFromPEM(cert)
	}
	return caCertPool, nil
}
