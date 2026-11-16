package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/providers/gcp"
	"google.golang.org/api/storage/v1"
)

// full_only: false
func TestGCPPublicCleanupListsOnlyTheBoundPrefix(t *testing.T) {
	credentials := &gcpSetupCredential{}
	requests := 0
	s := newGCPControlledSetup(t, credentials, func(r *http.Request) (*http.Response, error) {
		requests++
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Host != "storage.us-central1.rep.googleapis.com" ||
			r.URL.EscapedPath() != "/storage/v1/b/test-bucket/o" || q.Get("prefix") != "test-run/" ||
			q.Get("maxResults") != "128" || q.Get("projection") != "noAcl" ||
			r.Header.Get("Authorization") != "Bearer synthetic-access-token" {
			t.Error("LIST escaped its bound regional bucket, prefix, or credential")
		}
		if requests == 1 && q.Get("pageToken") != "" || requests == 2 && q.Get("pageToken") != "next" || requests > 2 {
			t.Error("LIST changed the exact page-token sequence")
		}
		result := &storage.Objects{Kind: "storage#objects", Items: []*storage.Object{{Bucket: "test-bucket", Name: "test-run/HEAD", Size: 1, Generation: 1}}}
		if requests == 1 {
			result.NextPageToken = "next"
		}
		body, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		return gcpSetupReply(http.StatusOK, string(body)), nil
	})
	first, err := s.listPrefix(context.Background(), "test-run/", "")
	if err != nil || len(first.Keys) != 1 || first.Keys[0] != "test-run/HEAD" || first.Next != "next" {
		t.Fatalf("first LIST result: %+v %v", first, err)
	}
	second, err := s.listPrefix(context.Background(), "test-run/", first.Next)
	if err != nil || len(second.Keys) != 1 || second.Next != "" || requests != 2 || credentials.calls != 2 {
		t.Fatalf("second LIST result: %+v %v requests=%d credentials=%d", second, err, requests, credentials.calls)
	}
	if _, err := s.listPrefix(context.Background(), "foreign/", ""); err == nil || requests != 2 {
		t.Fatal("foreign prefix reached the provider")
	}
}

// full_only: false
func TestGCPPublicCleanupRefusesUnprovedListReplies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"foreign_key", http.StatusOK, `{"kind":"storage#objects","items":[{"bucket":"test-bucket","name":"test-run/foreign","size":"1","generation":"1"}]}`},
		{"zero_size", http.StatusOK, `{"kind":"storage#objects","items":[{"bucket":"test-bucket","name":"test-run/HEAD","size":"0","generation":"1"}]}`},
		{"denied", http.StatusForbidden, `{"error":{"code":403}}`},
		{"over_limit", http.StatusOK, strings.Repeat("x", operatorPrefixBodyLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credentials := &gcpSetupCredential{}
			requests := 0
			s := newGCPControlledSetup(t, credentials, func(*http.Request) (*http.Response, error) {
				requests++
				return gcpSetupReply(tc.status, tc.body), nil
			})
			if _, err := s.listPrefix(context.Background(), "test-run/", ""); err == nil || requests != 1 || credentials.calls != 1 {
				t.Fatalf("unproved LIST reply accepted or replayed: %v requests=%d credentials=%d", err, requests, credentials.calls)
			}
		})
	}
}

// full_only: false
func TestGCPPublicCleanupRejectsForeignShapedRunKey(t *testing.T) {
	setup := &gcpSetup{head: "test-run/HEAD", objects: "test-run/" + strings.Repeat("1", 64) + "/"}
	cleaner := &livePrefixCleaner{ValidKey: setup.validKey}
	if cleaner.ValidKey(setup.objects + "foreign/0/" + strings.Repeat("2", 64)) {
		t.Fatal("cleaner can adopt a foreign-shaped key for conditional deletion")
	}
}

// full_only: false
func TestGCPPublicCapturedCleanupUsesObjectBounds(t *testing.T) {
	checkPublicCapturedCleanupProvider(t, func(t *testing.T, prefix string, domain contract.ID, key string, body []byte) *livePrefixCleaner {
		credentials := &gcpSetupCredential{}
		deleted := false
		transport := gcpInboxTransport(t, func(r *http.Request) (*http.Response, error) {
			if r.Host != "storage.us-central1.rep.googleapis.com" || r.Header.Get("Authorization") != "Bearer synthetic-access-token" {
				t.Error("cleanup escaped its credential route")
			}
			switch r.Method {
			case http.MethodGet:
				if r.URL.EscapedPath() != "/download/storage/v1/b/fixture-bucket/o/"+strings.ReplaceAll(key, "/", "%2F") {
					t.Error("cleanup read changed exact key")
				}
				if deleted {
					return gcpSetupReply(http.StatusNotFound, `{"error":{"code":404}}`), nil
				}
				response := gcpSetupReply(http.StatusOK, string(body))
				response.Header.Set("X-Goog-Generation", "27")
				return response, nil
			case http.MethodDelete:
				if deleted || r.URL.EscapedPath() != "/storage/v1/b/fixture-bucket/o/"+strings.ReplaceAll(key, "/", "%2F") || r.URL.Query().Get("ifGenerationMatch") != "27" || r.URL.Query().Get("generation") != "27" {
					t.Error("conditional cleanup changed exact key or token")
				}
				deleted = true
				return gcpSetupReply(http.StatusNoContent, ""), nil
			default:
				t.Error("unexpected cleanup method")
				return gcpSetupReply(http.StatusBadRequest, ""), nil
			}
		})
		client, err := gcp.NewLocalResponderClient(transport, credentials)
		if err != nil {
			t.Fatal(err)
		}
		store, err := gcp.NewStore(context.Background(), gcp.StoreConfig{Client: client, Domain: domain, Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "fixture-bucket", Prefix: prefix, CredentialRoute: "test-credential"})
		if err != nil {
			t.Fatal(err)
		}
		setup, err := newGCPSetup(context.Background(), credentials, transport, "fixture-bucket", prefix, domain,
			"https://storage.us-central1.rep.googleapis.com/storage/v1/", "https://us-central1-cloudkms.googleapis.com/")
		if err != nil {
			t.Fatal(err)
		}
		return &livePrefixCleaner{Store: store, ValidKey: setup.validKey, Delete: setup.delete}
	})
}
