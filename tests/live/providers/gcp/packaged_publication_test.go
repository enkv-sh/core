package core

import (
	"encoding/json"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestInstalledPackagedGCPPublicationCandidateCharges(t *testing.T) {
	packagedPublicationCandidateCharges(t, contract.GCP)
}
func packagedOutputEnvironment(t testing.TB) {
	t.Helper()
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"access_token":"native-output-token","token_type":"Bearer","expires_in":3600}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(tokenServer.Close)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("private controlled GCP credential directory", err)
	}
	path := filepath.Join(directory, "service-account.json")
	if err := custody.WriteGCPServiceAccountCredential(path, "writer@fixture-project.iam.gserviceaccount.com"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var source map[string]string
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	source["token_uri"] = tokenServer.URL
	source["quota_project_id"] = "fixture-quota"
	body, err = json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}
