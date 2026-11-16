package recovery

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestGCPReadRelayPreservesRequestsAndSeparatesParentFaults(t *testing.T) {
	normal := "projects/p/locations/us-central1/keyRings/r/cryptoKeys/normal/cryptoKeyVersions/1"
	authority := "projects/p/locations/us-central1/keyRings/r/cryptoKeys/authority/cryptoKeyVersions/1"
	var sends, mutations atomic.Uint64
	origin, certificate := startAWSRecoveryServer(t, []string{"storage.us-central1.rep.googleapis.com", "us-central1-cloudkms.googleapis.com", "oauth2.googleapis.com"}, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		sends.Add(1)
		body, err := io.ReadAll(q.Body)
		if err != nil {
			t.Error(err)
		}
		defer clear(body)
		if q.Header.Get("X-Test-Signed") != "preserved" || q.Header.Get("Authorization") != "Bearer synthetic" || q.Host == "" {
			t.Error("request headers/host changed")
		}
		if q.URL.Path == "/token" && !bytes.Equal(body, []byte("private-synthetic-assertion")) {
			t.Error("authentication bytes changed")
		}
		if q.URL.Path == "/download/storage/v1/b/bucket/o/prefix/a/b" && (q.URL.RawPath != "/download/storage/v1/b/bucket/o/prefix/a%2Fb" || q.URL.RawQuery != "alt=media&prettyPrint=false") {
			t.Error("path/query changed")
		}
		w.WriteHeader(200)
	}))
	transport, err := newGCPReadTransport(relayTestTransport(t, origin.Listener.Addr().String(), certificate), "bucket", "prefix", "us-central1", normal, "", 10, 20<<10, 1024)
	if err != nil {
		t.Fatal(err)
	}
	config := GCPRelayConfig{Bucket: "bucket", Prefix: "prefix", Region: "us-central1", Normal: installedarchive.SigningResource{Selector: normal, Region: "us-central1"}, AuthoritySelector: authority, Requests: 10, BodyBytes: 20 << 10, ResponseBytes: 1024, Policy: ResponderPolicy{DenySecretOrdinal: 2}, AfterPublic: func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		mutations.Add(1)
		return nil
	}}
	relay, err := newGCPReadRelay(t, config, transport)
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := GCPResponderTransport(relay.Address(), relay.Certificate())
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.CloseIdleConnections()
	for _, row := range []struct {
		method, host, path, raw, query, body string
		status                               int
	}{
		{"POST", "oauth2.googleapis.com", "/token", "", "", "private-synthetic-assertion", 200},
		{"GET", "storage.us-central1.rep.googleapis.com", "/download/storage/v1/b/bucket/o/prefix/a/b", "/download/storage/v1/b/bucket/o/prefix/a%2Fb", "alt=media&prettyPrint=false", "", 200},
		{"GET", "us-central1-cloudkms.googleapis.com", "/v1/" + normal + "/publicKey", "", "alt=json&prettyPrint=false", "", 200},
		{"POST", "us-central1-cloudkms.googleapis.com", "/v1/" + authority + ":asymmetricDecrypt", "", "alt=json&prettyPrint=false", `{"ciphertext":"AA=="}`, 200},
		{"POST", "us-central1-cloudkms.googleapis.com", "/v1/" + authority + ":asymmetricDecrypt", "", "alt=json&prettyPrint=false", `{"ciphertext":"AA=="}`, 403},
		{"DELETE", "storage.us-central1.rep.googleapis.com", "/download/storage/v1/b/bucket/o/prefix/x", "", "", "", 403},
		{"POST", "us-central1-cloudkms.googleapis.com", "/v1/" + normal + ":asymmetricSign", "", "alt=json&prettyPrint=false", `{}`, 403},
		{"GET", "us-central1-cloudkms.googleapis.com", "/unknown", "", "", "", 403},
		{"POST", "us-central1-cloudkms.googleapis.com", "/v1/" + normal + ":asymmetricDecrypt", "", "alt=json&prettyPrint=false", `{"ciphertext":"AA=="}`, 403},
	} {
		q, err := http.NewRequestWithContext(t.Context(), row.method, "https://"+row.host+row.path, bytes.NewBufferString(row.body))
		if err != nil {
			t.Fatal(err)
		}
		q.URL.RawPath, q.URL.RawQuery, q.Host = row.raw, row.query, row.host
		q.Header.Set("Authorization", "Bearer synthetic")
		q.Header.Set("X-Test-Signed", "preserved")
		response, err := inbound.RoundTrip(q)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != row.status {
			t.Fatal("relay disposition differs", response.StatusCode, row.status)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	evidence := relay.Evidence()
	if sends.Load() != 4 || evidence.Sent.Authentication != 1 || evidence.Sent.Reads != 1 || evidence.Sent.NormalLookups != 1 || evidence.Sent.AuthorityDecrypts != 1 || evidence.Injected.AuthorityDecrypts != 1 || evidence.Attempted.AuthorityDecrypts != 2 || evidence.Refused.Delete != 1 || evidence.Refused.Sign != 1 || evidence.Refused.OtherDecrypts != 1 || mutations.Load() != 1 || relay.ExternalMutations() != 1 {
		t.Fatal("parent/upstream epochs differ", evidence)
	}
}
