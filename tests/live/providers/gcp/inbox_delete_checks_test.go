package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/providers/gcp"
)

func gcpInboxTransport(t *testing.T, reply gcpSetupRoundTrip) *http.Transport {
	t.Helper()
	return testtrust.PublicHTTPSTransport(t, []string{"storage.us-central1.rep.googleapis.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := reply(r)
		if err != nil {
			connection, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr != nil {
				t.Error(hijackErr)
				return
			}
			_ = connection.Close()
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Error(err)
			return
		}
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(response.StatusCode)
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
}

// full_only: false
func TestGCPInboxDeleteUsesAPIPathAndQualifiedFinalReply(t *testing.T) {
	domain := contract.Hash([]byte("inbox-domain"))
	inbox := contract.Hash([]byte("inbox-id"))
	key, err := format.GeneratedResultKey("fixture", domain, inbox)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		sendErr    error
		wantStatus contract.WriteStatus
	}{
		{"final", 204, "", nil, contract.WriteAcknowledged},
		{"ok", 200, "", nil, contract.WriteUnknown},
		{"accepted", 202, "", nil, contract.WriteUnknown},
		{"partial", 206, "", nil, contract.WriteUnknown},
		{"other-success", 299, "", nil, contract.WriteUnknown},
		{"denied", 403, `{"error":{"code":403}}`, nil, contract.WriteRefused},
		{"changed", 412, `{"error":{"code":412,"errors":[{"reason":"conditionNotMet"}]}}`, nil, contract.WritePrecondition},
		{"lost", 0, "", errors.New("controlled lost reply"), contract.WriteUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credentials := &gcpSetupCredential{}
			reads, deletes := 0, 0
			client, err := gcp.NewLocalResponderClient(gcpInboxTransport(t, gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Host != "storage.us-central1.rep.googleapis.com" || r.Header.Get("Authorization") != "Bearer synthetic-access-token" {
					t.Error("request changed the selected host or credential")
				}
				switch r.Method {
				case http.MethodGet:
					reads++
					if r.URL.EscapedPath() != "/download/storage/v1/b/fixture-bucket/o/"+strings.ReplaceAll(key, "/", "%2F") {
						t.Errorf("media GET route: %s", r.URL)
					}
					response := gcpSetupReply(200, "selected handoff")
					response.Header.Set("X-Goog-Generation", "27")
					return response, nil
				case http.MethodDelete:
					deletes++
					if r.URL.EscapedPath() != "/storage/v1/b/fixture-bucket/o/"+strings.ReplaceAll(key, "/", "%2F") || r.URL.Query().Get("ifGenerationMatch") != "27" {
						t.Errorf("API DELETE route or condition: %s", r.URL)
					}
					if tc.sendErr != nil {
						return nil, tc.sendErr
					}
					return gcpSetupReply(tc.status, tc.body), nil
				default:
					t.Errorf("unexpected request method: %s", r.Method)
					return nil, errors.New("unexpected request")
				}
			})), credentials)
			if err != nil {
				t.Fatal(err)
			}
			store, err := gcp.NewStore(context.Background(), gcp.StoreConfig{Client: client, Domain: domain, Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "fixture-bucket", Prefix: "fixture", CredentialRoute: "test-credential"})
			if err != nil {
				t.Fatal(err)
			}
			read := store.Read(context.Background(), key, 64)
			if read.Status != contract.ReadOK || string(read.Body) != "selected handoff" || read.Token != (contract.Token{Family: contract.GCP, Value: "27"}) {
				t.Fatalf("observed handoff: %+v", read)
			}
			result := store.DeleteIfToken(context.Background(), key, read.Token)
			if result.Status != tc.wantStatus || reads != 1 || deletes != 1 || credentials.calls != 2 {
				t.Fatalf("delete result=%+v reads=%d deletes=%d credentials=%d", result, reads, deletes, credentials.calls)
			}
		})
	}
}

// full_only: false
func TestGCPInboxDeleteFactControlsColdRelease(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		clean  bool
	}{{"qualified", 204, true}, {"nonfinal", 202, false}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGeneratedProviderRelease(t, t.Context(), contract.GCP, tc.clean, func(domain contract.ID, prefix, key string, body []byte) contract.Store {
				credentials := &gcpSetupCredential{}
				reads, deletes := 0, 0
				client, err := gcp.NewLocalResponderClient(gcpInboxTransport(t, gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
					switch r.Method {
					case http.MethodGet:
						reads++
						if r.URL.EscapedPath() != "/download/storage/v1/b/fixture-bucket/o/"+strings.ReplaceAll(key, "/", "%2F") {
							t.Errorf("provider inbox GET route: %s", r.URL)
						}
						response := gcpSetupReply(200, string(body))
						response.Header.Set("X-Goog-Generation", "27")
						return response, nil
					case http.MethodDelete:
						deletes++
						if r.URL.EscapedPath() != "/storage/v1/b/fixture-bucket/o/"+strings.ReplaceAll(key, "/", "%2F") || r.URL.Query().Get("ifGenerationMatch") != "27" {
							t.Errorf("provider inbox DELETE route: %s", r.URL)
						}
						return gcpSetupReply(tc.status, ""), nil
					default:
						t.Errorf("unexpected provider method: %s", r.Method)
						return nil, errors.New("unexpected request")
					}
				})), credentials)
				if err != nil {
					t.Fatal(err)
				}
				adapter, err := gcp.NewStore(context.Background(), gcp.StoreConfig{Client: client, Domain: domain, Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "fixture-bucket", Prefix: prefix, CredentialRoute: "test-credential"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if reads != 1 || deletes != 1 || credentials.calls != 2 {
						t.Errorf("provider requests=%d/%d credentials=%d", reads, deletes, credentials.calls)
					}
				})
				return adapter
			})
		})
	}
}
