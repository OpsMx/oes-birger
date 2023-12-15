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

// Package ca handles some simple certificate authority stuff like ensuring
// that a loaded CA cert is likely to work to validate server certificates.
package ca

import (
	"crypto/x509"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// CertificateIssuer implements a generic CA

// CertPoolGenerator implements a method to make a TLS x509 certificate pool for servers
type CertPoolGenerator interface {
	MakeCertPool() (*x509.CertPool, error)
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
