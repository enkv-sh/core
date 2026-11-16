package installedarchive

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"enkv.sh/crypto/testsupport/fixturekeys"
)

var errAuthority = errors.New("installed archive authority route mismatch")

// DecryptAuthority serves the current synthetic Authority from the closed test
// key corpus. The independent parent checks its expected public key first.
func (a Archive) DecryptAuthority(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != 384 {
		return nil, errAuthority
	}
	var key *rsa.PrivateKey
	for _, encoded := range fixturekeys.PrivateKeys {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errAuthority
		}
		keyAny, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		if err != nil {
			return nil, errAuthority
		}
		candidate, ok := keyAny.(*rsa.PrivateKey)
		if !ok {
			return nil, errAuthority
		}
		public, err := x509.MarshalPKIXPublicKey(&candidate.PublicKey)
		if err != nil {
			return nil, errAuthority
		}
		if bytes.Equal(public, a.AuthorityBinding.SPKI) {
			key = candidate
			break
		}
	}
	if key == nil {
		return nil, errAuthority
	}
	packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, nil)
	if err != nil || len(packet) == 0 || len(packet) > 100 {
		clear(packet)
		return nil, errAuthority
	}
	return packet, nil
}
