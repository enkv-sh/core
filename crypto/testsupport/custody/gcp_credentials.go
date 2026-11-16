package custody

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// WriteGCPServiceAccountCredential keeps synthetic private key and credential
// encoding inside custody. Callers retain only a private file path and email.
func WriteGCPServiceAccountCredential(path, email string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || email == "" {
		return errors.New("test GCP credential path or email refused")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return errors.New("test GCP credential directory refused")
	}
	der, err := base64.StdEncoding.DecodeString(fixturePrivateKeys[0])
	if err != nil {
		return err
	}
	defer clear(der)
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(privateKey)
	body, err := json.Marshal(map[string]string{"type": "service_account", "client_email": email, "private_key": string(privateKey), "token_uri": "https://oauth2.googleapis.com/token"})
	if err != nil {
		return err
	}
	defer clear(body)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(body)
	if writeErr == nil && written != len(body) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Close())
}
