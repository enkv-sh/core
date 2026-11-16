package compositiongcp

import (
	"os"
	"path/filepath"
	"testing"

	privatecrypto "enkv.sh/crypto"
)

func standardCredentialEnvironment(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adc.json")
	body := []byte(`{"type":"authorized_user","client_id":"synthetic-client","client_secret":"synthetic-secret","refresh_token":"synthetic-refresh","quota_project_id":"quota-project","universe_domain":"googleapis.com"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}

// full_only: false
func TestDefaultCredentialsShareExactCellRoutes(t *testing.T) {
	standardCredentialEnvironment(t)
	ctx, c := localConfig(t)
	c.KeyAccess = c.KeyAccess[:1]
	old := c.KeyAccess[0].Client
	got, err := LoadDefaultConfig(ctx, c)
	if err != nil || got.Store.Client == nil || got.Store.Client != got.Trust.Client || len(got.KeyAccess) != 1 || got.KeyAccess[0].Client != got.Store.Client {
		t.Fatal("ADC client was not shared across exact routes", err)
	}
	if c.KeyAccess[0].Client != old {
		t.Fatal("credential installation changed caller routes")
	}
	cell, err := New(ctx, got)
	if err != nil {
		t.Fatal("standard cell did not construct", err)
	}
	cell.Crypto.(*privatecrypto.Runtime).Close()
}

// full_only: false
func TestDefaultReaderAndReconstructionNeedNoCredentialFile(t *testing.T) {
	standardCredentialEnvironment(t)
	ctx, r := readerConfig(t)
	r.Candidate.Client = nil
	reader, err := NewDefaultReader(ctx, r)
	if err != nil {
		t.Fatal("standard GET-only Reader did not construct", err)
	}
	reader.Close()
	ctx, c := reconstructionConfig(t)
	c.Candidate.Client = nil
	c.KeyAccess.Client = nil
	c.Normal.Client = nil
	reconstruction, err := NewDefaultReconstruction(ctx, c)
	if err != nil {
		t.Fatal("standard reconstruction did not construct", err)
	}
	reconstruction.Close()
	if c.Candidate.Client != nil || c.KeyAccess.Client != nil || c.Normal.Client != nil {
		t.Fatal("standard reconstruction changed caller config")
	}
}
