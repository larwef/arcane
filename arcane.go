package arcane

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
)

var (
	// ErrUnableToGetEncryptionKey is returned when Opener is not able to decrypt the encryption key.
	ErrUnableToGetEncryptionKey = errors.New("unable to get encryption key used to encrypt the message")
	// ErrUnableToParseSealerCert is returned if Opener is not able to parse the certificate sent by Sealer.
	ErrUnableToParseSealerCert = errors.New("unable to parse certificate used to seal message")
	// ErrUntrustedCert is returned if the certificate sent by the sealer is not trusted.
	ErrUntrustedCert = errors.New("sealer certificate is not trusted")
	// ErrInvalidSignature is returned if signature is not valid.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrUnableToDecryptPayload is returned if Opener is not able to decrypt payload.
	ErrUnableToDecryptPayload = errors.New("unable to decrypt payload")
)

// Header is ...
type Header struct {
	SealerCert   []byte `json:"sealerCert"`
	Signature    []byte `json:"signature"`
	EncryptedKey []byte `json:"encryptedKey"`
}

// Message is ...
type Message struct {
	Header  Header `json:"header"`
	Payload []byte `json:"payload"`
}

// Sealer is used to encrypt and sign a message.
type Sealer struct {
	PrivateKey   *rsa.PrivateKey
	Cert         *x509.Certificate
	ReceiverCert *x509.Certificate
}

// Seal encrypts and signs a payload.
func (s *Sealer) Seal(payload []byte) (*Message, error) {
	// Make a signature.
	h := sha256.New()
	if _, err := h.Write(payload); err != nil {
		return nil, err
	}

	sign, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	// Generate random encryption key.
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		return nil, err
	}

	// Encrypt message.
	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

	// Encrypt the encryption key using the receivers public key.
	receiverPubKey, ok := s.ReceiverCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("receiver public key was not an rsa key")
	}

	encryptedEncryptionKey, err := rsa.EncryptPKCS1v15(rand.Reader, receiverPubKey, encryptionKey)
	if err != nil {
		return nil, err
	}

	return &Message{
		Header: Header{
			SealerCert:   s.Cert.Raw,
			Signature:    sign,
			EncryptedKey: encryptedEncryptionKey,
		},
		Payload: encryptedPayload,
	}, nil
}

// Opener is used to open a encrypted and signed message,
type Opener struct {
	PrivateKey *rsa.PrivateKey
	CertPool   *x509.CertPool
}

// Open opens a *Message and returns the payload if no errors are encountered.
func (o *Opener) Open(message *Message) ([]byte, error) {
	// Validate sealer certificate.
	sealerCert, err := x509.ParseCertificate(message.Header.SealerCert)
	if err != nil {
		return nil, ErrUnableToParseSealerCert
	}

	if _, err := sealerCert.Verify(x509.VerifyOptions{
		Roots:     o.CertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, ErrUntrustedCert
	}

	// Get key used to encrypt message.
	var decryptedKey []byte
	decryptedKey, err = rsa.DecryptPKCS1v15(rand.Reader, o.PrivateKey, message.Header.EncryptedKey)
	if err != nil {
		return nil, ErrUnableToGetEncryptionKey
	}

	// Decrypt message.
	c, err := aes.NewCipher(decryptedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := message.Payload[:nonceSize], message.Payload[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrUnableToDecryptPayload
	}

	// Validate signature.
	pubKey, ok := sealerCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key was not an rsa key")
	}

	h := sha256.New()
	if _, err := h.Write(plaintext); err != nil {
		return nil, err
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), message.Header.Signature); err != nil {
		return nil, ErrInvalidSignature
	}

	return plaintext, nil
}
