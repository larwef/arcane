package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
)

func main() {
	keyPath := flag.String("keypath", "", "Path where the generated private key should be put.")
	flag.Parse()

	// Generate private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	// Write private key to file.
	privateKeyFile, err := os.Create(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	defer privateKeyFile.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(privateKeyFile, privBlock); err != nil {
		log.Fatalf("Error encoding private key: %v\n", err)
	}

	// Write public key to file.
	publicKeyFile, err := os.Create(*keyPath + ".pub")
	if err != nil {
		log.Fatal(err)
	}
	defer privateKeyFile.Close()

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}

	if err := pem.Encode(publicKeyFile, pubBlock); err != nil {
		log.Fatalf("Error encoding public key: %v\n", err)
	}
}
