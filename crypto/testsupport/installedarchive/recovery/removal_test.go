package recovery

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestParentRemovalRelayBindsExactObservedObject(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(map[contract.Family]string{contract.AWS: "aws", contract.GCP: "gcp"}[family], func(t *testing.T) {
			host, path, raw, query, token := "s3.us-east-1.amazonaws.com", "/bucket/prefix/a/b", "/bucket/prefix/a%2Fb", "x-id=DeleteObject", `"observed"`
			if family == contract.GCP {
				host, path, raw, query, token = "storage.us-central1.rep.googleapis.com", "/storage/v1/b/bucket/o/prefix/a/b", "/storage/v1/b/bucket/o/prefix%2Fa%2Fb", "alt=json&ifGenerationMatch=24&prettyPrint=false", "24"
			}
			var sends atomic.Uint64
			origin, certificate := startAWSRecoveryServer(t, []string{host}, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				sends.Add(1)
				if q.Method != http.MethodDelete || q.Host != host || q.URL.Path != path || q.URL.RawPath != raw || q.URL.RawQuery != query || q.Header.Get("Authorization") != "synthetic signed request" || q.Header.Get("X-Test-Signed") != "exact" || q.ContentLength != 0 || family == contract.AWS && q.Header.Get("If-Match") != token {
					t.Error("conditional mutation request changed")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			removal := &ExactRemoval{Key: "prefix/a/b", Token: contract.Token{Family: family, Value: token}}
			outbound := relayTestTransport(t, origin.Listener.Addr().String(), certificate)
			var relay parentReadRelay
			var err error
			if family == contract.AWS {
				config := relayTestConfig()
				config.Removal = removal
				relay, err = newAWSReadRelay(t, config, outbound)
			} else {
				normal := "projects/p/locations/us-central1/keyRings/r/cryptoKeys/normal/cryptoKeyVersions/1"
				transport, e := newGCPReadTransport(outbound, "bucket", "prefix", "us-central1", normal, "", 3, 4096, 1024)
				if e != nil {
					t.Fatal(e)
				}
				relay, err = newGCPReadRelay(t, GCPRelayConfig{Bucket: "bucket", Prefix: "prefix", Region: "us-central1", Normal: installedarchive.SigningResource{Selector: normal, Region: "us-central1"}, AuthoritySelector: strings.Replace(normal, "/normal/", "/authority/", 1), Requests: 3, BodyBytes: 4096, ResponseBytes: 1024, Removal: removal}, transport)
			}
			if err != nil {
				t.Fatal(err)
			}
			inbound := relayTestTransport(t, relay.Address(), relay.Certificate())
			defer inbound.CloseIdleConnections()
			send := func(target, condition, parameters string) int {
				q, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, "https://"+host+target, nil)
				if err != nil {
					t.Fatal(err)
				}
				q.Host, q.URL.RawPath, q.URL.RawQuery = host, raw, parameters
				q.Header.Set("Authorization", "synthetic signed request")
				q.Header.Set("X-Test-Signed", "exact")
				q.Header.Set("If-Match", condition)
				response, err := inbound.RoundTrip(q)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := response.Body.Close(); err != nil {
						t.Fatal(err)
					}
				}()
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal(err)
				}
				return response.StatusCode
			}
			if status := send(path, token, query); status != 204 || sends.Load() != 1 {
				t.Fatal("exact mutation refused", status)
			}
			for _, target := range []string{path + "-other", strings.Replace(path, "prefix/", "prefix-sibling/", 1), strings.Replace(path, "a/b", "HEAD", 1)} {
				if send(target, token, query) != 403 || sends.Load() != 1 {
					t.Fatal("forged mutation sent upstream")
				}
			}
			wrongQuery := query + "&extra=1"
			if family == contract.GCP {
				wrongQuery = "alt=json&ifGenerationMatch=25&prettyPrint=false"
			}
			if send(path, "wrong", wrongQuery) != 403 || sends.Load() != 1 {
				t.Fatal("wrong observed condition sent upstream")
			}
			evidence := relay.Evidence()
			if evidence.Sent.Delete != 1 || evidence.Attempted.Delete != 5 || evidence.Refused.Delete != 4 || evidence.Failures != 0 || evidence.Sent.Unknown != 0 {
				t.Fatal("physical mutation counts differ", evidence)
			}
		})
	}
}
