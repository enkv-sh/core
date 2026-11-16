package gcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// These literals substitute synthetic coordinates in the observed complete
// ASCII envelope: "No such object: ", bucket, "/", logical key, no newline.
// The child keys use domain ID {1}, object ID {2} and configuration ID {4},
// each encoded as 64 lowercase hexadecimal digits. No response supplies a target.
const (
	mediaHeadKey             = "fixture/HEAD"
	mediaRootKey             = "fixture/0100000000000000000000000000000000000000000000000000000000000000/root/0/0200000000000000000000000000000000000000000000000000000000000000"
	mediaConfigurationKey    = "fixture/0100000000000000000000000000000000000000000000000000000000000000/configuration/0400000000000000000000000000000000000000000000000000000000000000"
	mediaHeadAbsent          = "No such object: fixture-bucket/fixture/HEAD"
	mediaRootAbsent          = "No such object: fixture-bucket/fixture/0100000000000000000000000000000000000000000000000000000000000000/root/0/0200000000000000000000000000000000000000000000000000000000000000"
	mediaConfigurationAbsent = "No such object: fixture-bucket/fixture/0100000000000000000000000000000000000000000000000000000000000000/configuration/0400000000000000000000000000000000000000000000000000000000000000"
)

func checkMediaGET(t *testing.T, req *http.Request, key string) {
	t.Helper()
	if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "storage.us-central1.rep.googleapis.com" ||
		req.URL.Path != "/download/storage/v1/b/fixture-bucket/o/"+key || req.URL.Query().Get("alt") != "media" ||
		req.URL.Query().Has("generation") || req.Header.Get("Range") != "" || req.Header.Get("Accept-Encoding") != "identity" ||
		req.Header.Get("Authorization") != "Bearer fixture-token" {
		t.Fatal("media GET changed target, credential or request shape")
	}
}

// full_only: false
func TestMediaAbsenceRequiresExactTargetAndCompletePhysical404(t *testing.T) {
	for _, tc := range []struct {
		name, body, damage string
		status             int
		want               contract.ReadStatus
		reason             contract.Reason
	}{
		{"exact", mediaHeadAbsent, "", 404, contract.ReadMissing, contract.ReasonNone},
		{"unknown-length", mediaHeadAbsent, "unknown-length", 404, contract.ReadMissing, contract.ReasonNone},
		{"generation-is-not-absence-authority", mediaHeadAbsent, "generation", 404, contract.ReadMissing, contract.ReasonNone},
		{"wrong-bucket", "No such object: another-bucket/fixture/HEAD", "", 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"same-length-wrong-key", "No such object: fixture-bucket/fixture/HEAE", "", 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"prefix-only", "No such object: fixture-bucket/fixture/", "", 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"trailing-newline", mediaHeadAbsent + "\n", "", 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"encoded-spelling", "No such object: fixture-bucket/fixture%2FHEAD", "", 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"arbitrary-text", "object is absent", "", 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"physical-503", mediaHeadAbsent, "", 503, contract.ReadUnavailable, contract.ReasonTransport},
		{"physical-401", mediaHeadAbsent, "", 401, contract.ReadUnavailable, contract.ReasonAccess},
		{"physical-403", mediaHeadAbsent, "", 403, contract.ReadUnavailable, contract.ReasonAccess},
		{"physical-200-without-generation", mediaHeadAbsent, "", 200, contract.ReadInvalid, contract.ReasonMalformed},
		{"physical-200-with-generation", mediaHeadAbsent, "generation", 200, contract.ReadOK, contract.ReasonNone},
		{"declared-length-mismatch", mediaHeadAbsent, "length-mismatch", 404, contract.ReadUnavailable, contract.ReasonTransport},
		{"body-error-after-exact-bytes", mediaHeadAbsent, "body-error", 404, contract.ReadUnavailable, contract.ReasonTransport},
		{"oversize-error", mediaHeadAbsent + strings.Repeat("x", maxJSON), "", 404, contract.ReadUnavailable, contract.ReasonTransport},
		{"nonidentity-encoding", mediaHeadAbsent, "encoding", 404, contract.ReadUnavailable, contract.ReasonTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, creds := newStore(t, func(req *http.Request) (*http.Response, error) {
				calls++
				checkMediaGET(t, req, mediaHeadKey)
				out := response(tc.status, tc.body)
				out.Header.Set("Content-Type", "text/html; charset=UTF-8")
				switch tc.damage {
				case "unknown-length":
					out.ContentLength = -1
				case "generation":
					out.Header.Set("X-Goog-Generation", "24")
				case "length-mismatch":
					out.ContentLength++
				case "body-error":
					out.ContentLength = -1
					out.Body = io.NopCloser(&interruptedBody{body: tc.body})
				case "encoding":
					out.Header.Set("Content-Encoding", "gzip")
				}
				return out, nil
			})
			got := s.Read(context.Background(), mediaHeadKey, 512)
			wantBody, wantToken := "", (contract.Token{})
			if tc.want == contract.ReadOK {
				wantBody, wantToken = tc.body, contract.Token{Family: contract.GCP, Value: "24"}
			}
			if got.Status != tc.want || got.Reason != tc.reason || string(got.Body) != wantBody || got.Token != wantToken || calls != 1 || creds.calls != 1 {
				t.Fatalf("status=%d reason=%d body-bytes=%d token=%+v sends=%d credential captures=%d", got.Status, got.Reason, len(got.Body), got.Token, calls, creds.calls)
			}
		})
	}
}

// full_only: false
func TestMediaAbsenceAcrossStoreAndPublicReaders(t *testing.T) {
	ctx := context.Background()
	root := contract.Ref{Kind: contract.RootKind, Domain: contract.ID{1}, Object: contract.ID{2}, Digest: contract.ID{3}, Format: contract.CanonicalSchema, Length: 4}
	for _, target := range []struct {
		name, key, body string
	}{
		{"store-head", mediaHeadKey, mediaHeadAbsent},
		{"store-child", mediaRootKey, mediaRootAbsent},
		{"public-head", mediaHeadKey, mediaHeadAbsent},
		{"public-child", mediaRootKey, mediaRootAbsent},
		{"candidate-head", mediaHeadKey, mediaHeadAbsent},
		{"candidate-configuration", mediaConfigurationKey, mediaConfigurationAbsent},
		{"candidate-root", mediaRootKey, mediaRootAbsent},
	} {
		for _, exact := range []bool{true, false} {
			name := target.name + "/exact"
			if !exact {
				name = target.name + "/wrong-target"
			}
			t.Run(name, func(t *testing.T) {
				calls, creds := 0, &credentials{}
				client := makeClient(roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					checkMediaGET(t, req, target.key)
					body := target.body
					if !exact {
						body = body[:len(body)-1] + "1"
					}
					out := response(http.StatusNotFound, body)
					out.Header.Set("Content-Type", "text/html; charset=UTF-8")
					return out, nil
				}), creds)
				c := config(client)
				c.Domain = contract.ID{1}
				var got contract.ReadResult
				switch {
				case strings.HasPrefix(target.name, "store-"):
					s, err := NewStore(ctx, c)
					if err != nil {
						t.Fatal(err)
					}
					got = s.Read(ctx, target.key, 4)
				case strings.HasPrefix(target.name, "public-"):
					r, err := NewPublicReader(ctx, c)
					if err != nil {
						t.Fatal(err)
					}
					defer r.Close()
					got = r.Read(ctx, target.key, 4)
				default:
					r, err := NewCandidateReader(ctx, candidateConfig(client))
					if err != nil {
						t.Fatal(err)
					}
					switch target.name {
					case "candidate-head":
						got = r.ReadHEAD(ctx)
					case "candidate-configuration":
						got = r.ReadConfiguration(ctx, contract.ID{1}, contract.ID{4})
					case "candidate-root":
						got = r.ReadRoot(ctx, root)
					}
				}
				want, reason := contract.ReadMissing, contract.ReasonNone
				if !exact {
					want, reason = contract.ReadInvalid, contract.ReasonMalformed
				}
				if got.Status != want || got.Reason != reason || len(got.Body) != 0 || got.Token != (contract.Token{}) || calls != 1 || creds.calls != 1 {
					t.Fatalf("status=%d reason=%d body-bytes=%d token=%+v sends=%d credential captures=%d", got.Status, got.Reason, len(got.Body), got.Token, calls, creds.calls)
				}
			})
		}
	}
}

// full_only: false
func TestMediaAbsenceTelemetryPreservesReadFailureFacts(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	calls := 0
	s, creds := newStore(t, func(req *http.Request) (*http.Response, error) {
		calls++
		checkMediaGET(t, req, mediaHeadKey)
		out := response(http.StatusNotFound, mediaHeadAbsent)
		switch calls {
		case 2:
			out = response(http.StatusNotFound, "No such object: fixture-bucket/fixture/HEAE")
		case 3:
			out.ContentLength++
		}
		return out, nil
	})
	for _, want := range []struct {
		status contract.ReadStatus
		reason contract.Reason
	}{
		{contract.ReadMissing, contract.ReasonNone},
		{contract.ReadInvalid, contract.ReasonMalformed},
		{contract.ReadUnavailable, contract.ReasonTransport},
	} {
		got := s.Read(ctx, mediaHeadKey, 512)
		if got.Status != want.status || got.Reason != want.reason || len(got.Body) != 0 || got.Token != (contract.Token{}) {
			t.Errorf("read status=%d reason=%d body-bytes=%d token=%+v", got.Status, got.Reason, len(got.Body), got.Token)
		}
	}
	data := snapshot()
	if calls != 3 || creds.calls != 3 || telemetrySum(data, telemetry.OperationCalls, telemetry.OpStoreRead, "", "") != 3 ||
		telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreRead, "", "") != 3 {
		t.Error("read telemetry changed call or physical-send counts")
	}
	for _, result := range []string{"read_missing", "read_invalid", "read_unavailable"} {
		if telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreRead, result, "") != 1 {
			t.Errorf("read telemetry lost %s result", result)
		}
	}
	assertSafeTelemetry(t, data)
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "No such object:") {
		t.Error("raw response body entered telemetry")
	}
}
