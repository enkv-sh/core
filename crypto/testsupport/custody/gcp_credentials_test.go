package custody

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestGCPServiceAccountCredentialPrivateFileAndEncoding(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("private directory")
	}
	path := filepath.Join(directory, "writer.json")
	email := "writer@fixture-project.iam.gserviceaccount.com"
	if err := WriteGCPServiceAccountCredential(path, email); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private credential file mode")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var fields map[string]string
	if json.Unmarshal(body, &fields) != nil || len(fields) != 4 || fields["type"] != "service_account" || fields["client_email"] != email || fields["token_uri"] != "https://oauth2.googleapis.com/token" {
		t.Fatal("credential public fields")
	}
	block, rest := pem.Decode([]byte(fields["private_key"]))
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("PKCS8 envelope")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal("PKCS8 private fixture")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 || key.Validate() != nil {
		t.Fatal("RSA fixture cannot sign OAuth")
	}
	if err := WriteGCPServiceAccountCredential(path, "other@fixture-project.iam.gserviceaccount.com"); !errors.Is(err, os.ErrExist) {
		t.Fatal("credential replacement admitted", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if string(after) != string(body) {
		t.Fatal("refusal changed original credential")
	}
}

// full_only: false
func TestGCPServiceAccountCredentialRefusesUnownedPaths(t *testing.T) {
	for _, damage := range []string{"relative", "empty-email", "public-parent", "existing-symlink", "missing-parent"} {
		t.Run(damage, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil || os.Chmod(directory, 0700) != nil {
				t.Fatal("private directory")
			}
			path := filepath.Join(directory, "credential.json")
			email := "consumer@fixture-project.iam.gserviceaccount.com"
			switch damage {
			case "relative":
				path = "credential.json"
			case "empty-email":
				email = ""
			case "public-parent":
				if os.Chmod(directory, 0755) != nil {
					t.Fatal("parent mode")
				}
			case "existing-symlink":
				if os.Symlink(filepath.Join(directory, "missing-target"), path) != nil {
					t.Fatal("symlink setup")
				}
			case "missing-parent":
				path = filepath.Join(directory, "missing", "credential.json")
			}
			if WriteGCPServiceAccountCredential(path, email) == nil {
				t.Fatal("unowned path admitted")
			}
			if damage == "existing-symlink" {
				if _, err := os.Lstat(filepath.Join(directory, "missing-target")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("symlink followed")
				}
			} else if damage != "relative" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed construction published credential")
				}
			}
		})
	}
}
