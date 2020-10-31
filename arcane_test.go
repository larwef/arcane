package arcane

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	caPk         = parsePrivateKey("test/data/ca.key")
	signedPk1    = parsePrivateKey("test/data/signed1.key")
	signedPk2    = parsePrivateKey("test/data/signed2.key")
	signedPk3    = parsePrivateKey("test/data/signed3.key")
	selfSignedPk = parsePrivateKey("test/data/selfSigned.key")

	caCert         = parseCert("test/data/ca.crt")
	signedCert1    = parseCert("test/data/signed1.crt")
	signedCert2    = parseCert("test/data/signed2.crt")
	signedCert3    = parseCert("test/data/signed3.crt")
	selfSignedCert = parseCert("test/data/selfSigned.crt")
)

func TestSealerAndOpener(t *testing.T) {
	tests := []struct {
		name        string
		sealer      *Sealer
		opener      *Opener
		payload     []byte
		expectedErr error
	}{
		{
			name:        "Simple test",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk2},
			payload:     []byte("This is a test payload."),
			expectedErr: nil,
		},
		{
			name:        "Empty payload",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk2},
			payload:     nil,
			expectedErr: nil,
		},
		{
			name:        "Long payload",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk2},
			payload:     []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent libero arcu, tempus et nunc nec, rhoncus scelerisque ligula. Suspendisse convallis commodo porttitor. Donec auctor ornare nibh vel luctus. Nullam id augue vel sapien placerat porta vitae ut ante. In dictum, dui a placerat viverra, nunc nunc elementum nulla, sed feugiat eros quam sagittis sapien. Quisque dictum commodo est, a lobortis lorem aliquam ut. Integer quis mi pharetra, hendrerit risus non, ullamcorper magna. Vivamus suscipit, massa sit amet mattis vulputate, nulla augue lobortis lorem, nec gravida justo ante in nisl. Etiam a efficitur ipsum, at imperdiet nulla. Curabitur condimentum bibendum dui, vel commodo massa lobortis pharetra. Nulla quis dui ut lectus congue finibus. Suspendisse rhoncus cursus velit eu vulputate. Aenean gravida lorem id lobortis faucibus. Curabitur commodo magna ipsum, non aliquet diam commodo eget. Phasellus vitae arcu nisi. In sed nulla eu massa dictum porta id sit amet turpis. Nam bibendum scelerisque vulputate. Morbi a tincidunt tellus, ut ultrices sapien. Nullam convallis vehicula fermentum. Nulla facilisi. Vestibulum auctor nunc nec vestibulum elementum. Nulla nisl leo, laoreet a mattis nec, tempor ac enim. Suspendisse porttitor augue nisl, ut aliquam velit lacinia quis. Etiam eu ultrices leo. Pellentesque nec elit ut massa iaculis sagittis eget nec orci. Aenean egestas finibus nunc, a dapibus diam egestas vel. Morbi a porttitor turpis. Donec efficitur lorem ut ipsum imperdiet luctus. Nullam bibendum feugiat nisl, ac ullamcorper lorem. Nulla sollicitudin dictum tellus, a ultricies tellus consequat a. Etiam fermentum, arcu non semper placerat, mauris ex vulputate nibh, id pellentesque augue ipsum ut felis. Mauris et ex eu est cursus fringilla. Duis neque magna, consequat a volutpat et, tincidunt quis nisi. Suspendisse maximus rhoncus feugiat. Sed eget libero vel eros ultrices aliquet ac sed arcu. Sed ac tortor vehicula, eleifend leo eu, tristique est. Fusce magna libero, gravida et ligula at, placerat congue mauris. Nulla ut leo posuere, gravida sapien sed, posuere ante. Aliquam quis interdum nunc. Integer quis imperdiet dolor. Aliquam lorem nisl, cursus sit amet porta ut, tempus vel eros. Suspendisse hendrerit, purus ut interdum pharetra, nibh mauris ullamcorper sapien, at ornare odio sapien nec nunc. Nullam sed eleifend ex. Aliquam dolor justo, hendrerit sed libero in, fringilla scelerisque nunc. Maecenas non ante auctor orci varius tincidunt. Donec eu sagittis diam, a imperdiet ligula. Etiam tempor feugiat ex, eget porttitor nulla dapibus sit amet. Donec imperdiet lectus vel tellus molestie, ac mattis nunc sodales. Cras vel consectetur sapien. Suspendisse non velit id risus cursus congue. Morbi tristique, libero at tempus lobortis, velit orci pharetra lacus, ut auctor neque enim id tortor. Curabitur scelerisque id elit eu gravida. Suspendisse sodales, nunc eu dapibus sodales, urna tortor eleifend metus, eget posuere dui turpis non lacus. Vestibulum elementum dolor diam, non tempor lacus aliquam nec. Nullam rhoncus neque sem. Sed eget rhoncus ante, id lacinia nunc. Vivamus aliquam ultricies libero consectetur ultricies. Aenean pellentesque ut nisi at sagittis. Quisque feugiat tortor fermentum sapien suscipit, at tincidunt sem dignissim. Curabitur vitae dolor odio. Fusce cursus ipsum ut congue vehicula. Etiam tempus, eros id blandit posuere, mi erat tincidunt lectus, at pellentesque est turpis non odio. Fusce et dapibus urna. Fusce rutrum bibendum ligula, a mattis nulla pretium eu. Sed id neque posuere, vulputate nulla id, vehicula erat. Suspendisse varius a turpis et pharetra. Nunc non lectus at ligula rutrum varius sit amet a dui. Vestibulum porttitor enim congue posuere imperdiet. Fusce sit amet tortor at purus hendrerit auctor non ut est. Sed convallis elit id malesuada luctus. Maecenas tellus nulla, hendrerit et nunc eget, consectetur tincidunt quam. Aliquam sagittis mi pretium metus fermentum tempor quis sed justo. Duis sit amet nibh eleifend, aliquet mi a, varius urna. Morbi porttitor libero a ullamcorper elementum. Maecenas auctor magna in nulla luctus malesuada. Mauris risus felis, laoreet sit amet placerat vitae, porttitor at est. Nulla dolor nisi, vestibulum sit amet scelerisque sit amet, laoreet vel enim. Vivamus posuere quis tortor id eleifend. Cras eu eros ex. Nullam fringilla efficitur faucibus. Donec urna massa, fermentum et odio ut, congue facilisis tortor. Proin sem felis, porttitor eu nunc at, condimentum vulputate magna. Aliquam egestas sem ex, id tempor ligula sollicitudin eget. Sed in nisi ut lorem pulvinar commodo vel non sapien. Fusce eu hendrerit ligula. Phasellus est nibh, fermentum quis vulputate sit amet, molestie id nunc. Integer mattis ultrices orci vitae mattis. Integer in sodales ex. Vestibulum varius tincidunt lorem, sit amet dictum est ultrices non. Vestibulum dignissim accumsan lobortis. Nulla facilisi. Aliquam dignissim mollis varius. Vestibulum eget turpis eget nulla hendrerit faucibus at sit amet libero. Etiam a porttitor diam, faucibus tincidunt ex. Pellentesque eget sodales enim. Sed vitae nunc lacinia, viverra urna et, finibus leo. Vestibulum eget dui sed magna posuere fringilla quis sit amet velit. Aliquam vitae arcu ac lacus posuere volutpat non aliquet ipsum. Maecenas sed consectetur lacus. Nullam sodales maximus metus. Donec sed porta ipsum. Praesent suscipit eros quis ante facilisis aliquam. Integer turpis neque, fermentum vel tellus quis, commodo fringilla ipsum. Nullam viverra semper facilisis. Donec volutpat, ipsum in varius scelerisque, metus nisi fringilla ex, non iaculis dolor velit in felis. Mauris quis vehicula nunc. Vestibulum venenatis scelerisque risus ac pulvinar. Nunc quis purus nisl. Maecenas volutpat id turpis a ornare. Morbi sed suscipit diam. Duis blandit euismod tortor, sed sollicitudin mauris condimentum sed. Suspendisse blandit nunc a lacus aliquam, eget blandit leo viverra. Phasellus dictum sed tellus id sagittis. Quisque ante sem, volutpat sodales suscipit ut, faucibus eu diam. Nullam eu dapibus justo. Curabitur ultrices finibus lectus, sit amet lacinia quam facilisis eu. Duis faucibus est non ligula maximus blandit. Phasellus vestibulum urna ligula, quis faucibus lacus efficitur et. Sed vel accumsan ante. Quisque placerat ante eget lacinia consequat. Nullam efficitur scelerisque mauris, nec aliquet leo ornare tempus. Mauris sagittis quam neque, in rhoncus lectus varius id. Donec eget varius eros. Duis quis est mattis, imperdiet lectus vitae, accumsan eros. Donec a sem ipsum. Donec venenatis tortor elit, sed efficitur mi scelerisque at. Donec imperdiet congue vulputate. In mollis nisi eget magna vehicula, id tempor justo luctus. Praesent dictum nisi velit, et vestibulum quam mollis at. Integer scelerisque enim eleifend turpis sodales, quis semper mauris cursus. Suspendisse pharetra odio sit amet augue sodales, eu convallis quam faucibus. Fusce hendrerit molestie lacus sit amet tempus. In eu ipsum non nisl sollicitudin maximus quis ac nulla. Mauris vel neque eget mi ultricies cursus."),
			expectedErr: nil,
		},
		{
			name:        "Wrong opener",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk3},
			payload:     []byte("This is a test payload."),
			expectedErr: rsa.ErrDecryption,
		},
	}

	for _, test := range tests {
		message, err := test.sealer.Seal(test.payload)
		assert.NoError(t, err)

		payload, err := test.opener.Open(message)
		if test.expectedErr != nil {
			assert.Equal(t, test.expectedErr, err)
			assert.Nil(t, payload)
			continue
		}

		assert.NoError(t, err)
		assert.Equal(t, test.payload, payload)
	}
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
