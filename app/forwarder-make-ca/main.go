package main

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

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/opsmx/oes-birger/internal/ca"
)

var (
	namespace         = flag.String("namespace", "", "The namespace to place the secrets into")
	caSecretName      = flag.String("caSecretName", "ca-secret", "the name of the CA secret")
	withKubernetes    = flag.Bool("withKubernetes", true, "also generate kubernetes manifests")
	controlSecretName = flag.String("controlSecretName", "oes-control-secret", "the name of the secret for the control secret")
	alsoAgentNamed    = flag.String("alsoAgentNamed", "", "also create an agent credential, in agent-cert.pem and agent-key.pem")
)

func maybePrintNamespace(f *os.File) {
	if namespace != nil && len(*namespace) > 0 {
		fmt.Fprintf(f, "  namespace: %s\n", *namespace)
	}
}

func check(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func main() {
	flag.Parse()

	cacert, caPrivateKey, err := ca.MakeCertificateAuthority()
	check(err)

	ca64 := base64.StdEncoding.EncodeToString(cacert)
	caPrivateKey64 := base64.StdEncoding.EncodeToString(caPrivateKey)

	authority, err := ca.MakeCAFromData(cacert, caPrivateKey)
	check(err)

	name := ca.CertificateName{
		Name:    "oes",
		Purpose: ca.CertificatePurposeControl,
	}
	ca64too, cert64, certPrivKey64, err := authority.GenerateCertificate(name)
	check(err)
	if ca64too != ca64 {
		log.Fatal("Code error, returned CA cert base64 doesn't match generated CA cert")
	}

	if *withKubernetes {
		log.Printf("Writing controller-secrets.yaml")
		f, err := os.OpenFile("controller-secrets.yaml", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		check(err)
		fmt.Fprintln(f, "apiVersion: v1")
		fmt.Fprintln(f, "kind: Secret")
		fmt.Fprintln(f, "type: kubernetes.io/tls")
		fmt.Fprintln(f, "metadata:")
		maybePrintNamespace(f)
		fmt.Fprintf(f, "  name: %s\n", *caSecretName)
		fmt.Fprintln(f, "data:")
		fmt.Fprintf(f, "  tls.crt: %s\n", ca64)
		fmt.Fprintf(f, "  tls.key: %s\n", caPrivateKey64)

		fmt.Fprintln(f, "---")

		fmt.Fprintln(f, "apiVersion: v1")
		fmt.Fprintln(f, "kind: Secret")
		fmt.Fprintln(f, "type: kubernetes.io/tls")
		fmt.Fprintln(f, "metadata:")
		maybePrintNamespace(f)
		fmt.Fprintf(f, "  name: %s\n", *controlSecretName)
		fmt.Fprintln(f, "data:")
		fmt.Fprintf(f, "  tls.crt: %s\n", cert64)
		fmt.Fprintf(f, "  tls.key: %s\n", certPrivKey64)

		err = f.Close()
		check(err)
	}

	cert, err := base64.StdEncoding.DecodeString(cert64)
	check(err)
	log.Printf("Writing control certificate to control-cert.pem")
	err = os.WriteFile("control-cert.pem", cert, 0600)
	check(err)

	key, err := base64.StdEncoding.DecodeString(certPrivKey64)
	check(err)
	log.Printf("Writing control key to control-key.pem")
	err = os.WriteFile("control-key.pem", key, 0600)
	check(err)

	log.Printf("Writing authority certificate to ca-cert.pem")
	err = os.WriteFile("ca-cert.pem", cacert, 0600)
	check(err)

	cakey, err := base64.StdEncoding.DecodeString(caPrivateKey64)
	check(err)
	log.Printf("Writing authority key to ca-key.pem")
	err = os.WriteFile("ca-key.pem", cakey, 0600)
	check(err)

	if *alsoAgentNamed != "" {
		name := ca.CertificateName{
			Agent:   *alsoAgentNamed,
			Purpose: ca.CertificatePurposeAgent,
		}
		_, user64, key64, err := authority.GenerateCertificate(name)
		check(err)

		cert, err := base64.StdEncoding.DecodeString(user64)
		check(err)
		log.Printf("Writing agent certificate to agent-cert.pem")
		err = os.WriteFile("agent-cert.pem", cert, 0600)
		check(err)

		key, err := base64.StdEncoding.DecodeString(key64)
		check(err)
		log.Printf("Writing agent key to agent-key.pem")
		err = os.WriteFile("agent-key.pem", key, 0600)
		check(err)
	}
}
