package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/larwef/arcane"
)

const (
	senderPk     = "test/data/signed1.key"
	senderCert   = "test/data/signed1.crt"
	receiverCert = "test/data/signed2.crt"
)

func main() {
	sealer := &arcane.Sealer{
		PrivateKey:   parsePrivateKey(senderPk),
		Cert:         parseCert(senderCert),
		ReceiverCert: parseCert(receiverCert),
	}

	message, err := sealer.Seal([]byte("This is a test."))
	if err != nil {
		log.Fatal(err)
	}

	b, err := json.MarshalIndent(&message, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
}

func parsePrivateKey(path string) *rsa.PrivateKey {
	privKeyFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Unable to get private %q key for test: %v", path, err)
	}

	privKeyBytes, err := ioutil.ReadAll(privKeyFile)
	if err != nil {
		log.Fatalf("Unable to get private %q key for test: %v", path, err)
	}

	privBlock, _ := pem.Decode(privKeyBytes)

	privKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatalf("Unable to get private %q key for test: %v", path, err)
	}

	return privKey
}

func parseCert(path string) *x509.Certificate {
	certFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Unable to get certificate key %q for test: %v", path, err)
	}

	certBytes, err := ioutil.ReadAll(certFile)
	if err != nil {
		log.Fatalf("Unable to get certificate key %q for test: %v", path, err)
	}

	certBlock, _ := pem.Decode(certBytes)

	pubKey, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatalf("Unable to get certificate key %q for test: %v", path, err)
	}

	return pubKey
}
