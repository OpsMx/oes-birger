package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"

	"github.com/opsmx/grpc-bidir/pkg/ca"
)

var (
	namespace         = flag.String("namespace", "", "The namespace to place the secrets into")
	caSecretName      = flag.String("caSecretName", "ca-secret", "the name of the CA secret")
	commandSecretName = flag.String("commandSecretName", "oes-command-secret", "the name of the secret for the command secret")
)

func maybePrintNamespace() {
	if namespace != nil && len(*namespace) > 0 {
		fmt.Printf("  namespace: %s\n", *namespace)
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

	ca64too, cert64, certPrivKey64, err := authority.GenerateCertificate("oes", "command")
	if err != nil {
		log.Fatalf("%v", err)
	}
	if ca64too != ca64 {
		log.Fatal("Code error, returned CA cert base64 doesn't match generated CA cert")
	}

	fmt.Println("apiVersion: v1")
	fmt.Println("kind: Secret")
	fmt.Println("type: kubernetes.io/tls")
	fmt.Println("metadata:")
	maybePrintNamespace()
	fmt.Printf("  name: %s\n", *caSecretName)
	fmt.Println("data:")
	fmt.Printf("  tls.crt: %s\n", ca64)
	fmt.Printf("  tls.key: %s\n", caPrivateKey64)

	fmt.Println("---")

	fmt.Println("apiVersion: v1")
	fmt.Println("kind: Secret")
	fmt.Println("type: kubernetes.io/tls")
	fmt.Println("metadata:")
	maybePrintNamespace()
	fmt.Printf("  name: %s\n", *commandSecretName)
	fmt.Println("data:")
	fmt.Printf("  tls.crt: %s\n", cert64)
	fmt.Printf("  tls.key: %s\n", certPrivKey64)
}
