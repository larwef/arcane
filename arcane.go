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
}

// Open opens a *Message and returns the payload if no errors are encountered.
func (o *Opener) Open(message *Message) ([]byte, error) {
	// Get key used to decrypt message.
	var decryptedKey []byte
	if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, o.PrivateKey, message.Header.EncryptedKey, decryptedKey); err != nil {
		return nil, err
	}

	decryptedKey, err := rsa.DecryptPKCS1v15(rand.Reader, o.PrivateKey, message.Header.EncryptedKey)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	sealerCert, err := x509.ParseCertificate(message.Header.SealerCert)
	if err != nil {
		return nil, err
	}

	// TODO: Validate sender public sertificate.

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
		return nil, err
	}

	return plaintext, nil
}
