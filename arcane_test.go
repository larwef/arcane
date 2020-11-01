package arcane

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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

	emptyCertPool *x509.CertPool // No certificates in pool.
	caCertPool    *x509.CertPool // Only ca certificate in pool.
	leafCertPool  *x509.CertPool // Pool with leaf certs. Including self signed certificate.
)

func init() {
	emptyCertPool = x509.NewCertPool()
	caCertPool = x509.NewCertPool()
	leafCertPool = x509.NewCertPool()

	caCertPool.AddCert(caCert)
	leafCertPool.AddCert(signedCert1)
	leafCertPool.AddCert(signedCert2)
	leafCertPool.AddCert(signedCert3)
	leafCertPool.AddCert(selfSignedCert)
}

func TestSealerAndOpener(t *testing.T) {
	systemCertPool, err := x509.SystemCertPool()
	assert.NoError(t, err)

	systemCertPool.AddCert(caCert)

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
			opener:      &Opener{signedPk2, caCertPool},
			payload:     []byte("This is a test payload."),
			expectedErr: nil,
		},
		{
			name:        "Empty cert pool",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk2, emptyCertPool},
			payload:     []byte("This is a test payload."),
			expectedErr: ErrUntrustedCert,
		},
		{
			name:        "With self signed fail",
			sealer:      &Sealer{selfSignedPk, selfSignedCert, signedCert2},
			opener:      &Opener{signedPk2, caCertPool},
			payload:     []byte("This is a test payload."),
			expectedErr: ErrUntrustedCert,
		},
		{
			name:        "With self signed success",
			sealer:      &Sealer{selfSignedPk, selfSignedCert, signedCert2},
			opener:      &Opener{signedPk2, leafCertPool},
			payload:     []byte("This is a test payload."),
			expectedErr: nil,
		},
		{
			name:        "Same sender and receiver",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert1},
			opener:      &Opener{signedPk1, caCertPool},
			payload:     []byte("This is a test payload."),
			expectedErr: nil,
		},
		{
			name:        "Empty payload",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk2, caCertPool},
			payload:     nil,
			expectedErr: nil,
		},
		{
			name:        "Long payload",
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk2, caCertPool},
			payload:     []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent libero arcu, tempus et nunc nec, rhoncus scelerisque ligula. Suspendisse convallis commodo porttitor. Donec auctor ornare nibh vel luctus. Nullam id augue vel sapien placerat porta vitae ut ante. In dictum, dui a placerat viverra, nunc nunc elementum nulla, sed feugiat eros quam sagittis sapien. Quisque dictum commodo est, a lobortis lorem aliquam ut. Integer quis mi pharetra, hendrerit risus non, ullamcorper magna. Vivamus suscipit, massa sit amet mattis vulputate, nulla augue lobortis lorem, nec gravida justo ante in nisl. Etiam a efficitur ipsum, at imperdiet nulla. Curabitur condimentum bibendum dui, vel commodo massa lobortis pharetra. Nulla quis dui ut lectus congue finibus. Suspendisse rhoncus cursus velit eu vulputate. Aenean gravida lorem id lobortis faucibus. Curabitur commodo magna ipsum, non aliquet diam commodo eget. Phasellus vitae arcu nisi. In sed nulla eu massa dictum porta id sit amet turpis. Nam bibendum scelerisque vulputate. Morbi a tincidunt tellus, ut ultrices sapien. Nullam convallis vehicula fermentum. Nulla facilisi. Vestibulum auctor nunc nec vestibulum elementum. Nulla nisl leo, laoreet a mattis nec, tempor ac enim. Suspendisse porttitor augue nisl, ut aliquam velit lacinia quis. Etiam eu ultrices leo. Pellentesque nec elit ut massa iaculis sagittis eget nec orci. Aenean egestas finibus nunc, a dapibus diam egestas vel. Morbi a porttitor turpis. Donec efficitur lorem ut ipsum imperdiet luctus. Nullam bibendum feugiat nisl, ac ullamcorper lorem. Nulla sollicitudin dictum tellus, a ultricies tellus consequat a. Etiam fermentum, arcu non semper placerat, mauris ex vulputate nibh, id pellentesque augue ipsum ut felis. Mauris et ex eu est cursus fringilla. Duis neque magna, consequat a volutpat et, tincidunt quis nisi. Suspendisse maximus rhoncus feugiat. Sed eget libero vel eros ultrices aliquet ac sed arcu. Sed ac tortor vehicula, eleifend leo eu, tristique est. Fusce magna libero, gravida et ligula at, placerat congue mauris. Nulla ut leo posuere, gravida sapien sed, posuere ante. Aliquam quis interdum nunc. Integer quis imperdiet dolor. Aliquam lorem nisl, cursus sit amet porta ut, tempus vel eros. Suspendisse hendrerit, purus ut interdum pharetra, nibh mauris ullamcorper sapien, at ornare odio sapien nec nunc. Nullam sed eleifend ex. Aliquam dolor justo, hendrerit sed libero in, fringilla scelerisque nunc. Maecenas non ante auctor orci varius tincidunt. Donec eu sagittis diam, a imperdiet ligula. Etiam tempor feugiat ex, eget porttitor nulla dapibus sit amet. Donec imperdiet lectus vel tellus molestie, ac mattis nunc sodales. Cras vel consectetur sapien. Suspendisse non velit id risus cursus congue. Morbi tristique, libero at tempus lobortis, velit orci pharetra lacus, ut auctor neque enim id tortor. Curabitur scelerisque id elit eu gravida. Suspendisse sodales, nunc eu dapibus sodales, urna tortor eleifend metus, eget posuere dui turpis non lacus. Vestibulum elementum dolor diam, non tempor lacus aliquam nec. Nullam rhoncus neque sem. Sed eget rhoncus ante, id lacinia nunc. Vivamus aliquam ultricies libero consectetur ultricies. Aenean pellentesque ut nisi at sagittis. Quisque feugiat tortor fermentum sapien suscipit, at tincidunt sem dignissim. Curabitur vitae dolor odio. Fusce cursus ipsum ut congue vehicula. Etiam tempus, eros id blandit posuere, mi erat tincidunt lectus, at pellentesque est turpis non odio. Fusce et dapibus urna. Fusce rutrum bibendum ligula, a mattis nulla pretium eu. Sed id neque posuere, vulputate nulla id, vehicula erat. Suspendisse varius a turpis et pharetra. Nunc non lectus at ligula rutrum varius sit amet a dui. Vestibulum porttitor enim congue posuere imperdiet. Fusce sit amet tortor at purus hendrerit auctor non ut est. Sed convallis elit id malesuada luctus. Maecenas tellus nulla, hendrerit et nunc eget, consectetur tincidunt quam. Aliquam sagittis mi pretium metus fermentum tempor quis sed justo. Duis sit amet nibh eleifend, aliquet mi a, varius urna. Morbi porttitor libero a ullamcorper elementum. Maecenas auctor magna in nulla luctus malesuada. Mauris risus felis, laoreet sit amet placerat vitae, porttitor at est. Nulla dolor nisi, vestibulum sit amet scelerisque sit amet, laoreet vel enim. Vivamus posuere quis tortor id eleifend. Cras eu eros ex. Nullam fringilla efficitur faucibus. Donec urna massa, fermentum et odio ut, congue facilisis tortor. Proin sem felis, porttitor eu nunc at, condimentum vulputate magna. Aliquam egestas sem ex, id tempor ligula sollicitudin eget. Sed in nisi ut lorem pulvinar commodo vel non sapien. Fusce eu hendrerit ligula. Phasellus est nibh, fermentum quis vulputate sit amet, molestie id nunc. Integer mattis ultrices orci vitae mattis. Integer in sodales ex. Vestibulum varius tincidunt lorem, sit amet dictum est ultrices non. Vestibulum dignissim accumsan lobortis. Nulla facilisi. Aliquam dignissim mollis varius. Vestibulum eget turpis eget nulla hendrerit faucibus at sit amet libero. Etiam a porttitor diam, faucibus tincidunt ex. Pellentesque eget sodales enim. Sed vitae nunc lacinia, viverra urna et, finibus leo. Vestibulum eget dui sed magna posuere fringilla quis sit amet velit. Aliquam vitae arcu ac lacus posuere volutpat non aliquet ipsum. Maecenas sed consectetur lacus. Nullam sodales maximus metus. Donec sed porta ipsum. Praesent suscipit eros quis ante facilisis aliquam. Integer turpis neque, fermentum vel tellus quis, commodo fringilla ipsum. Nullam viverra semper facilisis. Donec volutpat, ipsum in varius scelerisque, metus nisi fringilla ex, non iaculis dolor velit in felis. Mauris quis vehicula nunc. Vestibulum venenatis scelerisque risus ac pulvinar. Nunc quis purus nisl. Maecenas volutpat id turpis a ornare. Morbi sed suscipit diam. Duis blandit euismod tortor, sed sollicitudin mauris condimentum sed. Suspendisse blandit nunc a lacus aliquam, eget blandit leo viverra. Phasellus dictum sed tellus id sagittis. Quisque ante sem, volutpat sodales suscipit ut, faucibus eu diam. Nullam eu dapibus justo. Curabitur ultrices finibus lectus, sit amet lacinia quam facilisis eu. Duis faucibus est non ligula maximus blandit. Phasellus vestibulum urna ligula, quis faucibus lacus efficitur et. Sed vel accumsan ante. Quisque placerat ante eget lacinia consequat. Nullam efficitur scelerisque mauris, nec aliquet leo ornare tempus. Mauris sagittis quam neque, in rhoncus lectus varius id. Donec eget varius eros. Duis quis est mattis, imperdiet lectus vitae, accumsan eros. Donec a sem ipsum. Donec venenatis tortor elit, sed efficitur mi scelerisque at. Donec imperdiet congue vulputate. In mollis nisi eget magna vehicula, id tempor justo luctus. Praesent dictum nisi velit, et vestibulum quam mollis at. Integer scelerisque enim eleifend turpis sodales, quis semper mauris cursus. Suspendisse pharetra odio sit amet augue sodales, eu convallis quam faucibus. Fusce hendrerit molestie lacus sit amet tempus. In eu ipsum non nisl sollicitudin maximus quis ac nulla. Mauris vel neque eget mi ultricies cursus."),
			expectedErr: nil,
		},
		{
			name:        "Wrong opener", // Trying to open a message addressed to someone else.
			sealer:      &Sealer{signedPk1, signedCert1, signedCert2},
			opener:      &Opener{signedPk3, caCertPool},
			payload:     []byte("This is a test payload."),
			expectedErr: ErrUnableToGetEncryptionKey,
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

func TestOpener_Open(t *testing.T) {
	tests := []struct {
		name        string
		opener      *Opener
		message     *Message
		expectedErr error
	}{
		{
			name:   "Test Ok",
			opener: &Opener{signedPk2, caCertPool},
			message: &Message{
				Header: Header{
					SealerCert:   base64Decode("MIIEWDCCAkCgAwIBAgIBZTANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wHhcNMjAxMDMxMjAxNDM4WhcNMjMxMDMxMjAxNDM4WjBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL75yIXDMATDviotxLwXz80MSrUcqH0OrfK3G3hl5wHrJ8x1PCP/TRTo6PYcUWDyrC5wDPUrFoZ2whyB+4SDkB7CKd/g8CTZeUyNE0wYOjzvgoUeeLa57wBj69cXcYEAndCuxNVJI1fbN+t7YmhHnd6jFIo+/X2gKIq6PwxkPIGrgQzb8H68OkDacw6R6eayYRG1p6R5+sV0qa83RyJBxRg2eflg2KwIcmd4dHO05uSs2t4XZq9AapBa4p7QZ0LSYTxTlGX1Me9t6nnS8zLymGxNFv5iXGxlDSBnnn75nFewm15AVyUz1WCe58V91yc5pqRvRc90wTA3ODmV2ntI9bAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggIBAHXvqPebyIgkn5XJ121rt0HdXK/I/wJhaIy6tMl2ZTtCcmd5nbEdXrUfKgmv4bWHwqIUzcis4iNoWOWNioxiT1M6aUKdMR7DyugoBofBulWMyhW3qYStiHXIEyaYQvkBHgkzA9CgoKNNXkw3cEvFi8komcGS0QIDfcIERr+zwKpqiNxKVPthdNY6qFgDHj5e5whdPEGpDI1DVmoLB0aMMpYeBspq3zkotgqHCpy0xAxZBA5gwUvAtNPPDJJAZz5o0AedBuxNWHIyXreDPqr008iG/ZKM3QI9IH3b4BrgkIm3sNGiG+dIcyrBzEqdn9e6xtjz7QRLHRoyb0SKZsb/2ulgdzWNpP1rUMwwzYE4XdRCNbhAGxw3o8SwmCmD5VbdrWGY7afRxEmFDCZTAwyFcxdop2rMpsaZD89/gmqihOVlDwAwOw/5J8ljpePUDocMSZuxcNqqVhSM/lbnUdpla/lBpa2fa/RkZ9ri0Z8/nlLci2CHxCz0ALpf/blNOGF33GsNXmTEuFmg2/ikRhIcF4sX2YQCH5AOnBuaTe/6NqBwECbhP9/fdsF9a/AAmPe3YHvsP6lvWrZPCOwg5BX6sTxjPW/apgvuDcHL1noWaiNB126b6i3b5ohoTIveAApoe6t3QDePry3HllRLe2ux5CqdorX0A7gYpn3+Ht7GwZVD"),
					Signature:    base64Decode("B88OIetvZMTIhM2tKMNDTDD1XvAIQvZVCTtdtE3yYwzdRDV7Xzo007Q+ECraboWdEr+GWFtOJKZLvwiRX72C0+Gtk+HIk2JIf5gxfTT5uDNRVaMiUpi/u6QkzCRtureuODY3c0UFx2LSlXlXYkBkNKVDk24NOWTc0nIs4sXL4fQaPoBKALyuyB8hKV5mY+fcGUxsio+Unz85Zl3iFz3pc680kBj0erQHz9gO6SILLJD3/sVd6ojRDoCBgjDFg9FXmmxdFYnG8VwmWUx18XlDPTw4vsZF0uppRuY5O22+5JlpEJ2ubtQ1b+Mq0vB7ylB7QNPBozIe2rKzKll7NCDrhg=="),
					EncryptedKey: base64Decode("ZfW58ZiINe3PFhP9vy1qqbOJ3Q4WUhhKj/a9ay+Iwk/Y0XLt/KMpOgxOMLLKnbK4GgenrycQ7saqjPlLzIzUpospptlNB/cVamITQWrBhMEvVmrvfpG6tBBjBZsd+OBDc4+Ez1N6qfNQYh168/UnxRc2d5KIPjRIBYvur97ryR56vQz5Eg9wm7Ny142N4dtHkeaFnMeRAcumOxXpDCen8uskORg8Ewm4uY4sCen5BFG3NWIzIV0uGqrlr18LoTFMf4mzpxpbNKVPoQpjaadvC5jytjRlnii5OT0WnF62tZIdvxXAgg/uUWwbQeoqDGN4vP9a2AXVFYFtDHGYsgAoCQ=="),
				},
				Payload: base64Decode("9g9f6E7/NVQzlZ/FK1l20FHqoE6vvcCOQE3IpdQLrjaxJ2IgZx1VmCBZJg=="),
			},
			expectedErr: nil,
		},
		{
			name:   "Payload tampered",
			opener: &Opener{signedPk2, caCertPool},
			message: &Message{
				Header: Header{
					SealerCert:   base64Decode("MIIEWDCCAkCgAwIBAgIBZTANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wHhcNMjAxMDMxMjAxNDM4WhcNMjMxMDMxMjAxNDM4WjBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL75yIXDMATDviotxLwXz80MSrUcqH0OrfK3G3hl5wHrJ8x1PCP/TRTo6PYcUWDyrC5wDPUrFoZ2whyB+4SDkB7CKd/g8CTZeUyNE0wYOjzvgoUeeLa57wBj69cXcYEAndCuxNVJI1fbN+t7YmhHnd6jFIo+/X2gKIq6PwxkPIGrgQzb8H68OkDacw6R6eayYRG1p6R5+sV0qa83RyJBxRg2eflg2KwIcmd4dHO05uSs2t4XZq9AapBa4p7QZ0LSYTxTlGX1Me9t6nnS8zLymGxNFv5iXGxlDSBnnn75nFewm15AVyUz1WCe58V91yc5pqRvRc90wTA3ODmV2ntI9bAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggIBAHXvqPebyIgkn5XJ121rt0HdXK/I/wJhaIy6tMl2ZTtCcmd5nbEdXrUfKgmv4bWHwqIUzcis4iNoWOWNioxiT1M6aUKdMR7DyugoBofBulWMyhW3qYStiHXIEyaYQvkBHgkzA9CgoKNNXkw3cEvFi8komcGS0QIDfcIERr+zwKpqiNxKVPthdNY6qFgDHj5e5whdPEGpDI1DVmoLB0aMMpYeBspq3zkotgqHCpy0xAxZBA5gwUvAtNPPDJJAZz5o0AedBuxNWHIyXreDPqr008iG/ZKM3QI9IH3b4BrgkIm3sNGiG+dIcyrBzEqdn9e6xtjz7QRLHRoyb0SKZsb/2ulgdzWNpP1rUMwwzYE4XdRCNbhAGxw3o8SwmCmD5VbdrWGY7afRxEmFDCZTAwyFcxdop2rMpsaZD89/gmqihOVlDwAwOw/5J8ljpePUDocMSZuxcNqqVhSM/lbnUdpla/lBpa2fa/RkZ9ri0Z8/nlLci2CHxCz0ALpf/blNOGF33GsNXmTEuFmg2/ikRhIcF4sX2YQCH5AOnBuaTe/6NqBwECbhP9/fdsF9a/AAmPe3YHvsP6lvWrZPCOwg5BX6sTxjPW/apgvuDcHL1noWaiNB126b6i3b5ohoTIveAApoe6t3QDePry3HllRLe2ux5CqdorX0A7gYpn3+Ht7GwZVD"),
					Signature:    base64Decode("B88OIetvZMTIhM2tKMNDTDD1XvAIQvZVCTtdtE3yYwzdRDV7Xzo007Q+ECraboWdEr+GWFtOJKZLvwiRX72C0+Gtk+HIk2JIf5gxfTT5uDNRVaMiUpi/u6QkzCRtureuODY3c0UFx2LSlXlXYkBkNKVDk24NOWTc0nIs4sXL4fQaPoBKALyuyB8hKV5mY+fcGUxsio+Unz85Zl3iFz3pc680kBj0erQHz9gO6SILLJD3/sVd6ojRDoCBgjDFg9FXmmxdFYnG8VwmWUx18XlDPTw4vsZF0uppRuY5O22+5JlpEJ2ubtQ1b+Mq0vB7ylB7QNPBozIe2rKzKll7NCDrhg=="),
					EncryptedKey: base64Decode("ZfW58ZiINe3PFhP9vy1qqbOJ3Q4WUhhKj/a9ay+Iwk/Y0XLt/KMpOgxOMLLKnbK4GgenrycQ7saqjPlLzIzUpospptlNB/cVamITQWrBhMEvVmrvfpG6tBBjBZsd+OBDc4+Ez1N6qfNQYh168/UnxRc2d5KIPjRIBYvur97ryR56vQz5Eg9wm7Ny142N4dtHkeaFnMeRAcumOxXpDCen8uskORg8Ewm4uY4sCen5BFG3NWIzIV0uGqrlr18LoTFMf4mzpxpbNKVPoQpjaadvC5jytjRlnii5OT0WnF62tZIdvxXAgg/uUWwbQeoqDGN4vP9a2AXVFYFtDHGYsgAoCQ=="),
				},
				Payload: base64Decode("VGhpcyBpcyBhIHRhbXBlcmVkIHBheWxvYWQh"),
			},
			expectedErr: ErrUnableToDecryptPayload,
		},
		{
			name:   "Wrong encryptedKey",
			opener: &Opener{signedPk2, caCertPool},
			message: &Message{
				Header: Header{
					SealerCert:   base64Decode("MIIEWDCCAkCgAwIBAgIBZTANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wHhcNMjAxMDMxMjAxNDM4WhcNMjMxMDMxMjAxNDM4WjBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL75yIXDMATDviotxLwXz80MSrUcqH0OrfK3G3hl5wHrJ8x1PCP/TRTo6PYcUWDyrC5wDPUrFoZ2whyB+4SDkB7CKd/g8CTZeUyNE0wYOjzvgoUeeLa57wBj69cXcYEAndCuxNVJI1fbN+t7YmhHnd6jFIo+/X2gKIq6PwxkPIGrgQzb8H68OkDacw6R6eayYRG1p6R5+sV0qa83RyJBxRg2eflg2KwIcmd4dHO05uSs2t4XZq9AapBa4p7QZ0LSYTxTlGX1Me9t6nnS8zLymGxNFv5iXGxlDSBnnn75nFewm15AVyUz1WCe58V91yc5pqRvRc90wTA3ODmV2ntI9bAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggIBAHXvqPebyIgkn5XJ121rt0HdXK/I/wJhaIy6tMl2ZTtCcmd5nbEdXrUfKgmv4bWHwqIUzcis4iNoWOWNioxiT1M6aUKdMR7DyugoBofBulWMyhW3qYStiHXIEyaYQvkBHgkzA9CgoKNNXkw3cEvFi8komcGS0QIDfcIERr+zwKpqiNxKVPthdNY6qFgDHj5e5whdPEGpDI1DVmoLB0aMMpYeBspq3zkotgqHCpy0xAxZBA5gwUvAtNPPDJJAZz5o0AedBuxNWHIyXreDPqr008iG/ZKM3QI9IH3b4BrgkIm3sNGiG+dIcyrBzEqdn9e6xtjz7QRLHRoyb0SKZsb/2ulgdzWNpP1rUMwwzYE4XdRCNbhAGxw3o8SwmCmD5VbdrWGY7afRxEmFDCZTAwyFcxdop2rMpsaZD89/gmqihOVlDwAwOw/5J8ljpePUDocMSZuxcNqqVhSM/lbnUdpla/lBpa2fa/RkZ9ri0Z8/nlLci2CHxCz0ALpf/blNOGF33GsNXmTEuFmg2/ikRhIcF4sX2YQCH5AOnBuaTe/6NqBwECbhP9/fdsF9a/AAmPe3YHvsP6lvWrZPCOwg5BX6sTxjPW/apgvuDcHL1noWaiNB126b6i3b5ohoTIveAApoe6t3QDePry3HllRLe2ux5CqdorX0A7gYpn3+Ht7GwZVD"),
					Signature:    base64Decode("B88OIetvZMTIhM2tKMNDTDD1XvAIQvZVCTtdtE3yYwzdRDV7Xzo007Q+ECraboWdEr+GWFtOJKZLvwiRX72C0+Gtk+HIk2JIf5gxfTT5uDNRVaMiUpi/u6QkzCRtureuODY3c0UFx2LSlXlXYkBkNKVDk24NOWTc0nIs4sXL4fQaPoBKALyuyB8hKV5mY+fcGUxsio+Unz85Zl3iFz3pc680kBj0erQHz9gO6SILLJD3/sVd6ojRDoCBgjDFg9FXmmxdFYnG8VwmWUx18XlDPTw4vsZF0uppRuY5O22+5JlpEJ2ubtQ1b+Mq0vB7ylB7QNPBozIe2rKzKll7NCDrhg=="),
					EncryptedKey: base64Decode("HSkFWxSTeFzJ8LNRRIDC2+d23Im4soS6L4PW2cLojx6fIehf9mQ0veYcfduR/Vz8gI0ZFLKTjHFadHIbKXKSzliyTjxPuQJNQb8AxM5ZpFvvsF3hb5SgesYo/htiiVHc9stDOpduTrx/h2IMXGtbugQZ/l5OC9xtmHrEYH4apCIwonriiAO1fkRvznmfvtrjdMcjAJPVbOatwZAIuSabf8JAbWeu77N57qOQnZJvz+E98IoLybV0v2eENVSiDhkC/sPVn4KVdMw8fRlkO6yt+hf0dpzBlrVDF+Sil0+yyJ4mGGM55dWzX4Wa/ZuHxyZo0OYGDihGYa4sLOjpFOTjwg=="),
				},
				Payload: base64Decode("9g9f6E7/NVQzlZ/FK1l20FHqoE6vvcCOQE3IpdQLrjaxJ2IgZx1VmCBZJg=="),
			},
			expectedErr: ErrUnableToDecryptPayload,
		},
		{
			name:   "Wrong certificate",
			opener: &Opener{signedPk2, caCertPool},
			message: &Message{
				Header: Header{
					SealerCert:   base64Decode("MIIEWDCCAkCgAwIBAgIBZzANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wHhcNMjAxMDMxMjAxNDQwWhcNMjMxMDMxMjAxNDQwWjBWMQswCQYDVQQGEwJOTzEJMAcGA1UECBMAMRAwDgYDVQQHEwdEcmFtbWVuMQ0wCwYDVQQREwQzMDQxMRswGQYDVQQKExJMZWdpdCBDb21wYW55IElOQy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSexiD1ePwgQLuly172em8BqOP667NsGJ3++2MhxfazKLtx+cmmb4Zhq0jbify3KG+T2KRx2CaeSe+C3n1Ji99ilcM3kJfXozXXZ/6yzORrdP2GhhjFRIlBAtoKNwvAfwxIJk2inKkzojuNlnZd5HqvLmqUvJhV5AJHqefKPLXjh/R8Hqbw23v1KuVB0FV/qU1Lu4smtyn0TogCvGbs3hc0BkLKkA0KvLYnUXlUX5i6YFQd8KJnQicTuqEUV6W0cYM+8dt27TwqYLkn/a4Mgzs7TXOovYNtWTL1XItf/S+PWXu5KVbSYoPT/4kU6UAo9ebhm0kAHxbfTmHSOTsO5WXAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggIBAJSBBJ9pgSK4imcs1ka7tFFImnJsdrh2D5zayyx4QHhqcvU3euyt7PgB7xfIS7eOmcp5rn/uy68gQBd2+lvGSL2r5crLcdgM9c1PSGkZJa0z4WrO+YKC44CBy+Ro5cl4uGRuOTi+zcVTSx8GpEuRXPIQqbrV8t4mAfn1sbYQHefOg87Zy7UYKixEdZqabRoUMVeWo2KWOvcyo6hlIlyRNr9tO1ZEQUP7w0PQJEC4uZD7++/BJoNGSCkOV25IJkpD1zgnjet4ACppCTowNpiHiRficyUVQ8jcdXD+Eklll8lfY25jkadhYzFwHheZoiJ3ntxvQ0bPJbzT09HtOAZ+2AupWhjRlD3FACygesTDkCHIvZpJA2vmJTRf1zfiODtM3wjAUnPK9NbbtOTsTVN/RovYPgdXmxMswbtx41LyVeD2coPzE8rd/Tk5DxRHfIN/tGcBoH+xbKm+/YlQU0bZEQ2X/GzvWMYgi3bo5BmPzWD1Rb6tzDA53Lf63gjVOdJx8YmXomYv6dNt6jPesuo8grQv0xkFI1BA18cyd5FDQJ+3vl7NGTdasfUN9UvVv+pw0XtYJX40PefWLVFkEbrP/8iEWuekB+Oo1R/tZK4dw4j5cTsjVwH7P6fYxQeqXjaz0/b9QM7aSgJGBfLwK1K8AdW+UYty/uch8MluheVhikIw"),
					Signature:    base64Decode("B88OIetvZMTIhM2tKMNDTDD1XvAIQvZVCTtdtE3yYwzdRDV7Xzo007Q+ECraboWdEr+GWFtOJKZLvwiRX72C0+Gtk+HIk2JIf5gxfTT5uDNRVaMiUpi/u6QkzCRtureuODY3c0UFx2LSlXlXYkBkNKVDk24NOWTc0nIs4sXL4fQaPoBKALyuyB8hKV5mY+fcGUxsio+Unz85Zl3iFz3pc680kBj0erQHz9gO6SILLJD3/sVd6ojRDoCBgjDFg9FXmmxdFYnG8VwmWUx18XlDPTw4vsZF0uppRuY5O22+5JlpEJ2ubtQ1b+Mq0vB7ylB7QNPBozIe2rKzKll7NCDrhg=="),
					EncryptedKey: base64Decode("ZfW58ZiINe3PFhP9vy1qqbOJ3Q4WUhhKj/a9ay+Iwk/Y0XLt/KMpOgxOMLLKnbK4GgenrycQ7saqjPlLzIzUpospptlNB/cVamITQWrBhMEvVmrvfpG6tBBjBZsd+OBDc4+Ez1N6qfNQYh168/UnxRc2d5KIPjRIBYvur97ryR56vQz5Eg9wm7Ny142N4dtHkeaFnMeRAcumOxXpDCen8uskORg8Ewm4uY4sCen5BFG3NWIzIV0uGqrlr18LoTFMf4mzpxpbNKVPoQpjaadvC5jytjRlnii5OT0WnF62tZIdvxXAgg/uUWwbQeoqDGN4vP9a2AXVFYFtDHGYsgAoCQ=="),
				},
				Payload: base64Decode("9g9f6E7/NVQzlZ/FK1l20FHqoE6vvcCOQE3IpdQLrjaxJ2IgZx1VmCBZJg=="),
			},
			expectedErr: ErrInvalidSignature,
		},
	}

	for _, test := range tests {
		_, err := test.opener.Open(test.message)
		assert.Equal(t, test.expectedErr, err)
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

func base64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatalf("Unable to decode base64 string: %s", s)
	}

	return b
}
