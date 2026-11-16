package recovery

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// full_only: false
func TestGCPReadTransportCountsPhysicalAuthAndBoundPrivateTargets(t *testing.T) {
	key := "projects/p/locations/us-central1/keyRings/r/cryptoKeys/authority/cryptoKeyVersions/1"
	normal := "projects/p/locations/us-central1/keyRings/r/cryptoKeys/normal/cryptoKeyVersions/1"
	var sends atomic.Uint64
	server, certificate := startAWSRecoveryServer(t, []string{"storage.us-central1.rep.googleapis.com", "us-central1-cloudkms.googleapis.com", "oauth2.googleapis.com"}, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		sends.Add(1)
		body, err := io.ReadAll(q.Body)
		if err != nil {
			t.Error(err)
		}
		if q.URL.Host != "" || q.Header.Get("X-Signed-Test") != "preserved" {
			t.Error("request changed")
		}
		if q.URL.Path == "/token" && !bytes.Equal(body, []byte("local-auth-body")) {
			t.Error("authentication body changed")
		}
		if strings.HasSuffix(q.URL.Path, ":asymmetricDecrypt") && !bytes.Equal(body, []byte(`{"ciphertext":"AA==","ciphertextCrc32c":"1"}`)) {
			t.Error("private body changed")
		}
		clear(body)
		if _, err = w.Write([]byte(`{"encrypted":true}`)); err != nil {
			t.Error(err)
		}
	}))
	transport, err := newGCPReadTransport(relayTestTransport(t, server.Listener.Addr().String(), certificate), "bucket", "prefix", "us-central1", normal, "", 3, 4096, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	for _, row := range []struct{ method, url, body string }{
		{"POST", "https://oauth2.googleapis.com/token", "local-auth-body"},
		{"GET", "https://us-central1-cloudkms.googleapis.com/v1/" + normal + "/publicKey?alt=json&prettyPrint=false", ""},
		{"POST", "https://us-central1-cloudkms.googleapis.com/v1/" + key + ":asymmetricDecrypt?alt=json&prettyPrint=false", `{"ciphertext":"AA==","ciphertextCrc32c":"1"}`},
	} {
		q, err := http.NewRequestWithContext(t.Context(), row.method, row.url, bytes.NewBufferString(row.body))
		if err != nil {
			t.Fatal(err)
		}
		q.Header.Set("Authorization", "Bearer local-token")
		q.Header.Set("X-Signed-Test", "preserved")
		response, err := transport.RoundTrip(q)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil || response.Body.Close() != nil || len(body) == 0 {
			t.Fatal("response unavailable")
		}
		clear(body)
	}
	evidence := transport.Evidence()
	if sends.Load() != 3 || evidence.Sent.Authentication != 1 || evidence.Sent.NormalLookups != 1 || evidence.Sent.AuthorityDecrypts != 1 || evidence.ReservedRequests != 3 {
		t.Fatal("physical request count differs", evidence.Sent)
	}
	if err := CheckGCPPrivateRequests(evidence, key); err != nil {
		t.Fatal(err)
	}
	if CheckGCPPrivateRequests(evidence, "different-Authority") == nil {
		t.Fatal("non-authority decrypt accepted")
	}
	damaged := evidence
	damaged.DecryptResources = nil
	if CheckGCPPrivateRequests(damaged, key) == nil {
		t.Fatal("missing private request evidence accepted")
	}
	q, err := http.NewRequestWithContext(t.Context(), "GET", "https://us-central1-cloudkms.googleapis.com/v1/"+normal+"/publicKey?alt=json&prettyPrint=false", nil)
	if err != nil {
		t.Fatal(err)
	}
	q.Header.Set("Authorization", "Bearer local-token")
	if response, err := transport.RoundTrip(q); err == nil || response != nil || sends.Load() != 3 {
		t.Fatal("finite cap sent another request")
	}
}

// full_only: false
func TestGCPReadTransportRefusesMutationAndUnknownBeforeSend(t *testing.T) {
	var sends atomic.Uint64
	server, certificate := startAWSRecoveryServer(t, []string{"us-central1-cloudkms.googleapis.com"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { sends.Add(1); w.WriteHeader(200) }))
	normal := "projects/p/locations/us-central1/keyRings/r/cryptoKeys/normal/cryptoKeyVersions/1"
	transport, err := newGCPReadTransport(relayTestTransport(t, server.Listener.Addr().String(), certificate), "bucket", "prefix", "us-central1", normal, "", 3, 4096, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	for _, row := range []struct{ name, method, url string }{
		{"sign", "POST", "https://us-central1-cloudkms.googleapis.com/v1/" + normal + ":asymmetricSign?alt=json&prettyPrint=false"},
		{"IAM", "POST", "https://us-central1-cloudkms.googleapis.com/v1/" + normal + ":setIamPolicy?alt=json&prettyPrint=false"},
		{"write", "POST", "https://storage.us-central1.rep.googleapis.com/upload/storage/v1/b/bucket/o"},
		{"delete", "DELETE", "https://storage.us-central1.rep.googleapis.com/download/storage/v1/b/bucket/o/prefix/x?alt=media&prettyPrint=false"},
		{"missing-sdk-field", "GET", "https://storage.us-central1.rep.googleapis.com/download/storage/v1/b/bucket/o/prefix/x?alt=media"},
		{"duplicate-sdk-field", "GET", "https://storage.us-central1.rep.googleapis.com/download/storage/v1/b/bucket/o/prefix/x?alt=media&prettyPrint=false&prettyPrint=false"},
		{"changed-sdk-field", "GET", "https://storage.us-central1.rep.googleapis.com/download/storage/v1/b/bucket/o/prefix/x?alt=media&prettyPrint=true"},
		{"listing", "GET", "https://storage.us-central1.rep.googleapis.com/download/storage/v1/b/bucket/o/prefix/x?prefix=x"},
		{"other-host", "GET", "https://us-central1-cloudkms.googleapis.com.evil/v1/" + normal + "/publicKey"},
		{"HTTP", "GET", "http://us-central1-cloudkms.googleapis.com/v1/" + normal + "/publicKey"},
		{"other-anchor", "GET", "https://us-central1-cloudkms.googleapis.com/v1/projects/p/locations/us-central1/keyRings/r/cryptoKeys/other/cryptoKeyVersions/1/publicKey"},
	} {
		t.Run(row.name, func(t *testing.T) {
			q, err := http.NewRequestWithContext(t.Context(), row.method, row.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			q.Header.Set("Authorization", "Bearer local-token")
			response, err := transport.RoundTrip(q)
			if err == nil || response != nil || sends.Load() != 0 {
				t.Fatal("forbidden request reached upstream")
			}
		})
	}
	evidence := transport.Evidence()
	if evidence.ReservedRequests != 0 || evidence.Sent != (RecoveryCounts{}) || evidence.Attempted.Sign != 1 || evidence.Attempted.IAMChanges != 1 || evidence.Attempted.StoreWrites != 1 || evidence.Attempted.Delete != 1 || evidence.Attempted.Discovery != 4 {
		t.Fatal("refusal accounting differs", evidence)
	}
}
