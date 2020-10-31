package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	certpath := flag.String("certpath", "", "Path where cert and key file should be put. Dont include file suffix.")
	serial := flag.Int64("serial", 0, "Serialnumber as int.")
	isCa := flag.Bool("isca", false, "Set true if the certificate should be a ca")
	parentPath := flag.String("parentpath", "", "Set this if using a parent to generate cert.")
	bits := flag.Int("bits", 2048, "RSA key size.")

	flag.Parse()

	var keyUsage x509.KeyUsage
	if *isCa {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(*serial),
		Subject: pkix.Name{
			Organization: []string{"Legit Company INC."},
			Country:      []string{"NO"},
			Province:     []string{""},
			Locality:     []string{"Drammen"},
			PostalCode:   []string{"3041"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		IsCA:                  *isCa,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              keyUsage,
		BasicConstraintsValid: *isCa,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		log.Fatal(err)
	}

	var parentCert *x509.Certificate
	var parentKey *rsa.PrivateKey
	if *parentPath != "" {
		parentCert, parentKey = getCaCertAndKey(*parentPath+".crt", *parentPath+".key")
	} else {
		parentCert, parentKey = cert, certPrivKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parentCert, &certPrivKey.PublicKey, parentKey)
	if err != nil {
		log.Fatal(err)
	}

	certFile, err := os.Create(*certpath + ".crt")
	if err != nil {
		log.Fatal(err)
	}

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		log.Fatal(err)
	}

	keyFile, err := os.Create(*certpath + ".key")
	if err != nil {
		log.Fatal(err)
	}

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	}); err != nil {
		log.Fatal(err)
	}

}

func getCaCertAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey) {
	caCertFile, err := os.Open(certPath)
	if err != nil {
		log.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(loadPem(caCertFile).Bytes)
	if err != nil {
		log.Fatal(err)
	}

	caKeyFile, err := os.Open(keyPath)
	if err != nil {
		log.Fatal(err)
	}

	caKey, err := x509.ParsePKCS1PrivateKey(loadPem(caKeyFile).Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return caCert, caKey
}

func loadPem(r io.Reader) *pem.Block {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	pemBlock, _ := pem.Decode(b)

	return pemBlock
}
