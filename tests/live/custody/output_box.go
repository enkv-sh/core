package custody

import (
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/nacl/box"
)

// OutputBoxFixture owns only the synthetic GitHub endpoint key. It never
// returns a private key or decrypted payload to the Core test assembly.
type OutputBoxFixture struct {
	public, private *[32]byte
	closed          bool
}

func NewOutputBoxFixture() (*OutputBoxFixture, error) {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &OutputBoxFixture{public: public, private: private}, nil
}

func (f *OutputBoxFixture) PublicKey() [32]byte {
	if f == nil || f.closed {
		return [32]byte{}
	}
	return *f.public
}

func (f *OutputBoxFixture) Matches(ciphertext, expected []byte) bool {
	if f == nil || f.closed || len(expected) > 64<<10 || len(ciphertext) > (64<<10)+box.AnonymousOverhead {
		return false
	}
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, f.public, f.private)
	defer clear(plaintext)
	return ok && bytes.Equal(plaintext, expected)
}

func (f *OutputBoxFixture) Close() {
	if f == nil || f.closed {
		return
	}
	clear(f.private[:])
	clear(f.public[:])
	f.closed = true
}
