package gcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestDefaultCredentialsQuotaProjectReachesService(t *testing.T) {
	for _, tc := range []struct {
		name, file, environment, want string
		refused                       bool
	}{
		{name: "absent"},
		{name: "file", file: "file-project", want: "file-project"},
		{name: "environment-precedence", file: "file-project", environment: "environment-project", want: "environment-project"},
		{name: "malformed-file", file: "private\r\nheader", refused: true},
		{name: "malformed-environment", file: "file-project", environment: "private project", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", tc.environment)
			var tokens, sends int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tokens++
				if _, err := fmt.Fprint(w, `{"access_token":"captured-token","token_type":"Bearer","expires_in":3600}`); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			fields, _ := serviceAccountJSON(t)
			fields["token_uri"] = server.URL
			fields["quota_project_id"] = tc.file
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", serviceAccountPath(t, fields))
			source, err := LoadDefaultCredentials(context.Background())
			if tc.refused {
				if err != ErrCredentials || source != nil || tokens != 0 {
					t.Fatal("malformed quota project retained a source or reached authentication")
				}
				return
			}
			if err != nil {
				t.Fatal("selected ADC refused")
			}
			// The selected context must not change when ambient configuration changes.
			t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "replacement-project")
			client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				sends++
				if r.Header.Get("X-Goog-User-Project") != tc.want || r.Header.Get("Authorization") != "Bearer captured-token" {
					t.Error("service did not retain selected bearer and quota project")
				}
				return apiFailure(401, "authError"), nil
			}), source)
			ctx, ok := client.begin(context.Background(), "cloudkms.googleapis.com", maxJSON)
			if !ok {
				t.Fatal("credential capture refused")
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudkms.googleapis.com/v1/projects/fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Goog-User-Project", "caller-project")
			request.Header.Set("Authorization", "Bearer caller-token")
			reply, err := client.http.Do(request)
			if err != nil {
				t.Fatal("service request failed before controlled denial")
			}
			if err := reply.Body.Close(); err != nil {
				t.Error(err)
			}
			if reply, err := client.http.Do(request); err == nil {
				if err := reply.Body.Close(); err != nil {
					t.Error(err)
				}
				t.Error("service denial permitted a second send")
			}
			if tokens != 1 || sends != 1 {
				t.Fatal("capture or service was replayed")
			}
		})
	}
}

// full_only: false
func TestDefaultCredentialsLocalUserADCCapturesOneBearer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", home)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "")
	path := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"type":"authorized_user","client_id":"fixture-client","client_secret":"fixture-secret","refresh_token":"fixture-refresh","quota_project_id":"user-project"}`), 0600); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	var tokens, sends int
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		tokens++
		if r.Method != http.MethodPost || r.URL.String() != tokenURL {
			t.Error("ADC authentication endpoint changed")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "fixture-refresh" || r.Form.Get("client_id") != "fixture-client" || r.Form.Get("client_secret") != "fixture-secret" {
			t.Error("ADC did not retain selected local user")
		}
		return response(200, `{"access_token":"user-token","token_type":"Bearer","expires_in":3600}`), nil
	})
	source, err := LoadDefaultCredentials(context.Background())
	if err != nil {
		t.Fatal("local user ADC refused without a credential-file argument")
	}
	store, err := NewStore(context.Background(), config(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sends++
		if r.Header.Get("Authorization") != "Bearer user-token" || r.Header.Get("X-Goog-User-Project") != "user-project" {
			t.Error("local user credentials changed at service dispatch")
		}
		return apiFailure(401, "authError"), nil
	}), source)))
	if err != nil {
		t.Fatal(err)
	}
	result := store.Create(context.Background(), childKey(store), []byte("plain"))
	if result.Status != contract.WriteRefused || result.Reason != contract.ReasonAccess || tokens != 1 || sends != 1 {
		t.Fatal("service denial changed or repeated local ADC capture")
	}
}
