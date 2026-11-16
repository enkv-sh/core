package custody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// PublicSurface contains bytes available outside private custody.
type PublicSurface struct {
	Name string
	Body []byte
}

type DictionaryObserver struct {
	guesses [][]byte
}

// NewDictionaryObserver fixes low-entropy guesses before fixture preparation.
// It receives no custody key, private sink, or selected plaintext result.
func NewDictionaryObserver() DictionaryObserver {
	return DictionaryObserver{guesses: [][]byte{
		[]byte("enkv first secret test value"),
		[]byte("enkv first secret test valuf"),
		[]byte("enkv first secret test valug"),
	}}
}

// Check examines only the supplied public bytes. Failure text excludes values.
func (observer DictionaryObserver) Check(surfaces []PublicSurface) error {
	if len(observer.guesses) == 0 || len(surfaces) == 0 {
		return errors.New("missing dictionary or public surfaces")
	}
	for _, surface := range surfaces {
		if surface.Name == "" || len(surface.Body) == 0 {
			return errors.New("empty public surface")
		}
		for _, guess := range observer.guesses {
			if len(guess) == 0 || len(guess) != len(observer.guesses[0]) {
				return errors.New("invalid dictionary")
			}
			digest := sha256.Sum256(guess)
			for _, material := range [][]byte{guess, digest[:]} {
				for _, encoded := range [][]byte{material, []byte(hex.EncodeToString(material)), []byte(base64.StdEncoding.EncodeToString(material))} {
					if bytes.Contains(surface.Body, encoded) {
						return errors.New("public dictionary disclosure in " + surface.Name)
					}
				}
			}
		}
	}
	return nil
}
