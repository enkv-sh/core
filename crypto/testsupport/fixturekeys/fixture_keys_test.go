package fixturekeys

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func parseSyntheticRSAKey(t *testing.T, encoded string) *rsa.PrivateKey {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal("synthetic key is not base64", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal("synthetic key is not PKCS8", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() != 3072 || key.E != 65537 || key.Size() != 384 {
		t.Fatal("synthetic key does not implement the RSA3072 authority packet profile")
	}
	if err := key.Validate(); err != nil {
		t.Fatal("synthetic RSA key is invalid", err)
	}
	return key
}

func syntheticPublicIdentity(t *testing.T, key *rsa.PrivateKey) [32]byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("synthetic RSA public key is not SPKI", err)
	}
	return sha256.Sum256(spki)
}

// full_only: false
func TestSyntheticAuthorityKeyMatchesInstalledArchive(t *testing.T) {
	if len(PrivateKeys) == 0 {
		t.Fatal("installed archive requires the first synthetic private key")
	}
	key := parseSyntheticRSAKey(t, PrivateKeys[0])
	// Independently derived through OpenSSL's DER public export and checked
	// against both current archive authority SPKIs. No private bytes are oracle
	// output, and additional fixture keys do not change this archive identity.
	want := "8b1d7dd5ad68e47ad279105e55d47b3b7b4dc10f87ed7258f85b4d6324e0557d"
	identity := syntheticPublicIdentity(t, key)
	if hex.EncodeToString(identity[:]) != want {
		t.Fatal("first synthetic key no longer matches the installed archive authority")
	}
}

// full_only: false
func TestSyntheticFixtureKeysValidateIndependentAuthorityPackets(t *testing.T) {
	if len(PrivateKeys) == 0 {
		t.Fatal("synthetic fixture key set is empty")
	}
	packet := bytes.Repeat([]byte{0x5a}, 100)
	identities := make(map[[32]byte]bool)
	var firstCiphertext []byte
	for i, encoded := range PrivateKeys {
		t.Run(fmt.Sprintf("key=%d", i), func(t *testing.T) {
			key := parseSyntheticRSAKey(t, encoded)
			identity := syntheticPublicIdentity(t, key)
			if identities[identity] {
				t.Fatal("synthetic fixtures reuse one RSA identity")
			}
			identities[identity] = true
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, packet, nil)
			if err != nil || len(ciphertext) != 384 {
				t.Fatal("synthetic authority packet encryption failed", err)
			}
			plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, nil)
			if err != nil || !bytes.Equal(plain, packet) {
				t.Fatal("synthetic authority packet did not round trip", err)
			}
			if i == 0 {
				firstCiphertext = ciphertext
			} else if _, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, firstCiphertext, nil); err == nil {
				t.Fatal("unrelated fixture key decrypted the archive authority packet")
			}
		})
	}
}
