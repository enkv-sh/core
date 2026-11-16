package compositionaws

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	privatecrypto "enkv.sh/crypto"
)

func standardCredentialEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_KEY"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAAAAAAAAAAAA")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "private-standard-secret")
}

// full_only: false
func TestDefaultCredentialsShareExactCellRoutes(t *testing.T) {
	standardCredentialEnvironment(t)
	c := localConfig(t)
	c.KeyAccess = c.KeyAccess[:1]
	old := c.KeyAccess[0].Credentials
	got, err := LoadDefaultConfig(context.Background(), c)
	if err != nil || got.Store.Credentials == nil || got.Store.Credentials != got.Trust.Credentials || len(got.KeyAccess) != 1 || got.KeyAccess[0].Credentials != got.Store.Credentials {
		t.Fatal("standard source was not shared across exact routes", err)
	}
	if c.KeyAccess[0].Credentials != old {
		t.Fatal("credential installation changed caller routes")
	}
	value, err := got.Store.Credentials.Retrieve(context.Background())
	if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "private-standard-secret" {
		t.Fatal("standard environment source was not selected", err)
	}
	cell, err := New(got)
	if err != nil {
		t.Fatal("standard cell did not construct", err)
	}
	cell.Crypto.(*privatecrypto.Runtime).Close()
}

// full_only: false
func TestDefaultReaderAndReconstructionNeedNoCredentialFile(t *testing.T) {
	standardCredentialEnvironment(t)
	r := readerConfig(t)
	r.Candidate.Credentials = nil
	reader, err := NewDefaultReader(context.Background(), r)
	if err != nil {
		t.Fatal("standard GET-only Reader did not construct", err)
	}
	reader.Close()
	c := reconstructionConfig(t)
	c.Candidate.Credentials = nil
	c.KeyAccess.Credentials = nil
	c.Normal.Credentials = nil
	reconstruction, err := NewDefaultReconstruction(context.Background(), c)
	if err != nil {
		t.Fatal("standard reconstruction did not construct", err)
	}
	reconstruction.Close()
	if c.Candidate.Credentials != nil || c.KeyAccess.Credentials != nil || c.Normal.Credentials != nil {
		t.Fatal("standard reconstruction changed caller config")
	}
}
