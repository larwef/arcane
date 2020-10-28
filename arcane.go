package arcane

import (
	"io"
	"time"
)

// Header is ...
type Header struct {
	Created      time.Time
	Expires      time.Time
	PublicKey    string
	Signature    string
	EncryptedKey string
}

// Message is ...
type Message struct {
	Header  Header
	Payload []byte
}

// Sealer is used to encrypt and sign a message.
type Sealer struct {
}

// Seal encrypts and signs a payload.
func (s *Sealer) Seal(r io.Reader) (*Message, error) {
	return nil, nil
}

// Opener is used to open a encrypted and signed message,
type Opener struct {
}

// Open opens a *Message and returns the payload if no errors are encountered.
func (o *Opener) Open() ([]byte, error) {
	return nil, nil
}
