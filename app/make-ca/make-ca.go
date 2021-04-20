package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/opsmx/oes-birger/pkg/ca"
)

var (
	namespace         = flag.String("namespace", "", "The namespace to place the secrets into")
	caSecretName      = flag.String("caSecretName", "ca-secret", "the name of the CA secret")
	controlSecretName = flag.String("controlSecretName", "oes-control-secret", "the name of the secret for the control secret")
)

func maybePrintNamespace(f *os.File) {
	if namespace != nil && len(*namespace) > 0 {
		fmt.Fprintf(f, "  namespace: %s\n", *namespace)
	}
}

func main() {
	flag.Parse()

	cacert, caPrivateKey, err := ca.MakeCertificateAuthority()
	if err != nil {
		log.Fatalf("%v", err)
	}

	ca64 := base64.StdEncoding.EncodeToString(cacert)
	caPrivateKey64 := base64.StdEncoding.EncodeToString(caPrivateKey)

	authority, err := ca.MakeCAFromData(cacert, caPrivateKey)
	if err != nil {
		log.Fatalf("%v", err)
	}

	name := ca.CertificateName{
		Name:    "oes",
		Purpose: ca.CertificatePurposeControl,
	}
	ca64too, cert64, certPrivKey64, err := authority.GenerateCertificate(name)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if ca64too != ca64 {
		log.Fatal("Code error, returned CA cert base64 doesn't match generated CA cert")
	}

	log.Printf("Writing controller-secrets.yaml")
	f, err := os.OpenFile("controller-secrets.yaml", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Panicf("%v", err)
	}
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
	if err != nil {
		log.Panicf("%v", err)
	}

	cert, err := base64.StdEncoding.DecodeString(cert64)
	if err != nil {
		log.Panicf("%v", err)
	}
	key, err := base64.StdEncoding.DecodeString(certPrivKey64)
	if err != nil {
		log.Panicf("%v", err)
	}

	log.Printf("Writing control secret to control-cert.pem")
	err = os.WriteFile("control-cert.pem", []byte(cert), 0600)
	if err != nil {
		log.Panicf("%v", err)
	}

	log.Printf("Writing control key to control-key.pem")
	err = os.WriteFile("control-key.pem", []byte(key), 0600)
	if err != nil {
		log.Panicf("%v", err)
	}

	log.Printf("Writing authority certificate to ca-cert.pem")
	err = os.WriteFile("ca-cert.pem", cacert, 0600)
	if err != nil {
		log.Panicf("%v", err)
	}
}
