package awsprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// full_only: false
func TestStoreConstructionProfileTwoIsRouteIndependent(t *testing.T) {
	c := testStoreConfig()
	for i := range c.Domain {
		c.Domain[i] = byte(i + 1)
	}
	c.Bucket, c.Prefix = "enkv-example", "team/prod"
	first, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction made a request")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	d := first.Descriptor()
	if got := hex.EncodeToString(d.Identity[:]); got != "b701f21d1695852674fa5f8e1ee463db6ae6b91e9d859b3b6aabbda254bb3ebb" {
		t.Fatalf("store identity=%s", got)
	}
	if got := hex.EncodeToString(d.Coordinate[:]); got != "29b5d5b9d05d8bf39537e9d82710ee8c47a932895712d6430c29adef8de9531f" {
		t.Fatalf("coordinate=%s", got)
	}
	if got := hex.EncodeToString(d.NonBody[:]); got != "5acc5518ff443eb4374d44ab2796af5107eaaea6d7a0fa1dfa06fbafa7be587a" {
		t.Fatalf("nonbody=%s", got)
	}
	c.CredentialRoute = contract.Hash([]byte("other route"))
	c.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		t.Fatal("construction accessed credentials")
		return aws.Credentials{}, nil
	})
	second, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction made a request")
		return nil, nil
	}))
	if err != nil || first.Descriptor() != second.Descriptor() {
		t.Fatalf("route changed persistent construction: err=%v", err)
	}
	c.ExpectedBucketOwner = "210987654321"
	third, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction made a request")
		return nil, nil
	}))
	if err != nil || third.Descriptor().Identity == first.Descriptor().Identity || third.Descriptor().NonBody == first.Descriptor().NonBody {
		t.Fatalf("owner did not change persistent construction: err=%v", err)
	}
}

// full_only: false
func TestStoreConstructionFieldsBindPersistentIdentities(t *testing.T) {
	c := testStoreConfig()
	first, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("construction made a request"); return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	want := first.Descriptor()
	if id, err := contract.StoreConfigurationID(first.StoreConfiguration()); err != nil || id != want.Identity {
		t.Fatal("published construction does not match Store identity", err)
	}
	for _, tc := range []struct {
		name                              string
		mutate                            func(*StoreConfig)
		coordinateChanges, nonbodyChanges bool
	}{
		{"domain", func(c *StoreConfig) { c.Domain[0] ^= 1 }, true, false},
		{"bucket", func(c *StoreConfig) { c.Bucket = "another-bucket" }, true, false},
		{"prefix", func(c *StoreConfig) { c.Prefix = "another/prefix" }, true, false},
		{"region", func(c *StoreConfig) { c.Region = "us-west-2" }, true, false},
		{"owner", func(c *StoreConfig) { c.ExpectedBucketOwner = "210987654321" }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := c
			tc.mutate(&changed)
			other, err := newStore(changed, roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("construction made a request"); return nil, nil }))
			if err != nil {
				t.Fatal(err)
			}
			got := other.Descriptor()
			if got.Identity == want.Identity || (got.Coordinate != want.Coordinate) != tc.coordinateChanges || (got.NonBody != want.NonBody) != tc.nonbodyChanges {
				t.Fatal("changed construction has incorrect identity commitments")
			}
		})
	}
}

// full_only: false
func TestStoreNormalizesExactErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		code      string
		wantRead  contract.ReadStatus
		wantWrite contract.WriteStatus
	}{
		{"precondition", 412, "PreconditionFailed", contract.ReadUnavailable, contract.WritePrecondition},
		{"other-precondition", 412, "OtherPolicy", contract.ReadUnavailable, contract.WriteUnknown},
		{"conflict", 409, "ConditionalRequestConflict", contract.ReadUnavailable, contract.WriteConflict},
		{"access", 403, "AccessDenied", contract.ReadUnavailable, contract.WriteUnknown},
		{"missing", 404, "NoSuchKey", contract.ReadMissing, contract.WriteUnknown},
		{"bucket-missing", 404, "NoSuchBucket", contract.ReadUnavailable, contract.WriteUnknown},
		{"server", 500, "InternalError", contract.ReadUnavailable, contract.WriteUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return response(tc.status, "<Error><Code>"+tc.code+"</Code><Message>private diagnostic</Message></Error>", nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			// An error envelope is larger than this selected object. Its status
			// must not depend on the object's byte limit.
			if got := s.Read(context.Background(), s.Descriptor().HeadKey, 1); got.Status != tc.wantRead || len(got.Body) != 0 {
				t.Fatalf("read %+v", got)
			}
			if calls != 1 {
				t.Fatalf("read retries: calls=%d", calls)
			}
			if got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"old"`}, []byte("candidate")); got.Status != tc.wantWrite {
				t.Fatalf("write %+v", got)
			}
			if calls != 2 {
				t.Fatalf("hidden retries: calls=%d", calls)
			}
		})
	}
}

// full_only: false
func TestStoreConditionalPreconditionRequiresCompleteResponse(t *testing.T) {
	for _, operation := range []string{"create", "cas", "delete"} {
		for _, name := range []string{"bodyless", "unknown-length", "empty-error", "empty-code", "matching-code", "contradictory-code", "malformed", "truncated", "body-error", "encoded", "oversized"} {
			t.Run(operation+"/"+name, func(t *testing.T) {
				calls := 0
				var body *countedBody
				s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					wantMethod, wantMatch, wantAbsent := http.MethodPut, `"original"`, ""
					switch operation {
					case "create":
						wantMatch, wantAbsent = "", "*"
					case "delete":
						wantMethod = http.MethodDelete
					}
					if r.Method != wantMethod || r.Header.Get("If-Match") != wantMatch || r.Header.Get("If-None-Match") != wantAbsent || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
						t.Error("conditional request lost its original predicate", r.Method, r.Header)
					}
					envelope := ""
					switch name {
					case "empty-error":
						envelope = "<Error/>"
					case "empty-code":
						envelope = "<Error><Code></Code><Message></Message></Error>"
					case "matching-code", "truncated", "body-error", "encoded":
						envelope = "<Error><Code>PreconditionFailed</Code></Error>"
					case "contradictory-code":
						envelope = "<Error><Code>AccessDenied</Code></Error>"
					case "malformed":
						envelope = "<Error><Code>PreconditionFailed"
					case "oversized":
						envelope = "<Error><Code>PreconditionFailed</Code><Message>" + strings.Repeat("x", maxErrorResponse) + "</Message></Error>"
					}
					out := response(http.StatusPreconditionFailed, envelope, nil)
					switch name {
					case "unknown-length":
						out.ContentLength = -1
						out.Header.Del("Content-Length")
					case "truncated":
						out.ContentLength++
					case "body-error":
						out.Body = &failingBody{data: []byte(envelope)}
					case "encoded":
						out.Header.Set("Content-Encoding", "gzip")
					}
					body = &countedBody{ReadCloser: out.Body}
					out.Body = body
					return out, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				var got contract.WriteResult
				token := contract.Token{Family: contract.AWS, Value: `"original"`}
				switch operation {
				case "create":
					got = s.Create(context.Background(), testResultKey(), []byte("frozen"))
				case "cas":
					got = s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, token, []byte("frozen"))
				case "delete":
					got = s.DeleteIfToken(context.Background(), testResultKey(), token)
				}
				want := contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
				switch name {
				case "contradictory-code", "malformed":
					want = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
				case "truncated", "body-error", "encoded", "oversized":
					want = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				}
				if got != want || calls != 1 || body == nil || !body.closed || body.bytes > maxErrorResponse+1 {
					t.Fatalf("result=%+v want=%+v calls=%d response=%+v", got, want, calls, body)
				}
			})
		}
	}
}

// full_only: false
func TestReadRequiresCompleteSameResponseObservation(t *testing.T) {
	for _, mode := range []string{"valid", "missing-token", "oversized", "oversized-unknown-length", "oversized-body-error", "oversized-body-error-unknown-length", "truncated", "truncated-declared-oversized", "encoded", "partial", "body-error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/fixture-bucket/enkv/domain/HEAD" || r.URL.Query().Get("versionId") != "" || r.Header.Get("Range") != "" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
					t.Error("not exact GET")
				}
				resp := response(200, "body", http.Header{"Etag": []string{"\"opaque-etag\""}})
				switch mode {
				case "missing-token":
					resp.Header.Del("Etag")
				case "oversized":
					resp = response(200, strings.Repeat("a", 33), resp.Header)
				case "oversized-unknown-length":
					resp = response(200, strings.Repeat("a", 33), resp.Header)
					resp.ContentLength = -1
					resp.Header.Del("Content-Length")
				case "oversized-body-error", "oversized-body-error-unknown-length":
					resp.ContentLength = 64
					resp.Header.Set("Content-Length", "64")
					resp.Body = &failingBody{data: []byte(strings.Repeat("a", 33))}
					if mode == "oversized-body-error-unknown-length" {
						resp.ContentLength = -1
						resp.Header.Del("Content-Length")
					}
				case "truncated":
					resp.ContentLength = 6
					resp.Header.Set("Content-Length", "6")
				case "truncated-declared-oversized":
					resp.ContentLength = 33
					resp.Header.Set("Content-Length", "33")
					resp.Body = &failingBody{data: []byte("body")}
				case "encoded":
					resp.Header.Set("Content-Encoding", "gzip")
				case "partial":
					resp.Header.Set("Content-Range", "bytes 0-3/9")
				case "body-error":
					resp.Body = &failingBody{data: []byte("bo")}
				}
				return resp, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 32)
			if mode == "valid" {
				if got.Status != contract.ReadOK || string(got.Body) != "body" || got.Token.Value != "\"opaque-etag\"" {
					t.Fatalf("observation %+v", got)
				}
			} else {
				wantStatus, wantReason := contract.ReadInvalid, contract.ReasonMalformed
				switch mode {
				case "truncated", "truncated-declared-oversized", "body-error", "oversized-body-error", "oversized-body-error-unknown-length":
					wantStatus, wantReason = contract.ReadUnavailable, contract.ReasonTransport
				}
				if got.Status != wantStatus || got.Reason != wantReason || len(got.Body) != 0 || got.Token.Value != "" {
					t.Fatalf("observation %s: %+v", mode, got)
				}
			}
			if calls != 1 {
				t.Fatalf("body reopened: %d", calls)
			}
		})
	}
}

// full_only: false
func TestReadRequiresOneExactStrongETag(t *testing.T) {
	max := `"` + strings.Repeat("e", 254) + `"`
	for _, tc := range []struct {
		name   string
		values []string
		want   string
	}{
		{name: "empty-opaque", values: []string{`""`}, want: `""`},
		{name: "opaque-comma-and-asterisk", values: []string{`"a,*"`}, want: `"a,*"`},
		{name: "maximum-length", values: []string{max}, want: max},
		{name: "missing"},
		{name: "bare-wildcard", values: []string{"*"}},
		{name: "weak", values: []string{`W/"weak"`}},
		{name: "unquoted", values: []string{"bare"}},
		{name: "list", values: []string{`"one", "two"`}},
		{name: "leading-space", values: []string{` "outer"`}},
		{name: "trailing-tab", values: []string{"\"outer\"\t"}},
		{name: "interior-space", values: []string{`"not valid"`}},
		{name: "interior-control", values: []string{"\"not\x1fvalid\""}},
		{name: "interior-delete", values: []string{"\"not\x7fvalid\""}},
		{name: "interior-quote", values: []string{`"not"valid"`}},
		{name: "oversized", values: []string{`"` + strings.Repeat("e", 255) + `"`}},
		{name: "duplicate-different", values: []string{`"one"`, `"two"`}},
		{name: "duplicate-identical", values: []string{`"same"`, `"same"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(200, "body", http.Header{"Etag": tc.values}), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 32)
			if tc.want != "" {
				if got.Status != contract.ReadOK || got.Token.Value != tc.want || string(got.Body) != "body" {
					t.Fatalf("valid observation differs: %+v", got)
				}
			} else if got.Status != contract.ReadInvalid || got.Reason != contract.ReasonMalformed || got.Token != (contract.Token{}) || len(got.Body) != 0 {
				t.Fatalf("invalid ETag observation: %+v", got)
			}
			if calls != 1 {
				t.Fatalf("requests=%d", calls)
			}
		})
	}
}

// full_only: false
func TestObservedETagReachesIfMatchUnchanged(t *testing.T) {
	const etag = `"opaque,*"`
	calls := 0
	s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.Method {
		case http.MethodGet:
			return response(200, "head", http.Header{"Etag": []string{etag}}), nil
		case http.MethodPut:
			if r.Header.Get("If-Match") != etag || r.Header.Values("If-Match")[0] != etag {
				t.Fatalf("If-Match changed: %q", r.Header.Values("If-Match"))
			}
			return response(200, "", nil), nil
		default:
			t.Fatalf("unexpected method %s", r.Method)
			return nil, errors.New("unexpected method")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	observed := s.Read(context.Background(), s.Descriptor().HeadKey, 32)
	if observed.Status != contract.ReadOK || observed.Token.Value != etag {
		t.Fatal("observed token differs", observed)
	}
	if got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, observed.Token, []byte("candidate")); got.Status != contract.WriteAcknowledged || calls != 2 {
		t.Fatalf("CAS result=%+v requests=%d", got, calls)
	}
}

// full_only: false
func TestStoreConditionalDeleteBindsObservedETag(t *testing.T) {
	const etag = `"opaque,*"`
	calls := 0
	s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodDelete || r.URL.Scheme != "https" || r.URL.Host != "s3.us-east-1.amazonaws.com" ||
			r.URL.Path != "/fixture-bucket/"+testResultKey() || r.URL.RawQuery != "x-id=DeleteObject" {
			t.Fatalf("unexpected delete target: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("If-Match") != etag || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" ||
			r.Header.Get("Authorization") == "" || r.ContentLength > 0 {
			t.Fatal("conditional delete lost its observed ETag, owner, or empty-body shape")
		}
		return response(http.StatusNoContent, "", nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.DeleteIfToken(context.Background(), testResultKey(), contract.Token{Family: contract.AWS, Value: etag}); got.Status != contract.WriteAcknowledged || calls != 1 {
		t.Fatalf("delete result=%+v calls=%d", got, calls)
	}
	for _, token := range []contract.Token{{Family: contract.GCP, Value: etag}, {Family: contract.AWS, Value: "bare"}} {
		if got := s.DeleteIfToken(context.Background(), testResultKey(), token); got.Status != contract.WriteRefused {
			t.Fatal("invalid delete token reached the service", got)
		}
	}
	if calls != 1 {
		t.Fatalf("refused delete reached HTTP: %d", calls)
	}
}

// full_only: false
func TestStoreDeleteRequiresFinalEmptyResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		length int64
		want   contract.WriteStatus
	}{
		{"complete", 204, "", 0, contract.WriteAcknowledged},
		{"ok", 200, "", 0, contract.WriteUnknown},
		{"accepted", 202, "", 0, contract.WriteUnknown},
		{"partial", 206, "", 0, contract.WriteUnknown},
		{"other-success", 299, "", 0, contract.WriteUnknown},
		{"body", 204, "unexpected", 10, contract.WriteUnknown},
		{"truncated", 204, "", 1, contract.WriteUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodDelete {
					t.Fatalf("method=%s", r.Method)
				}
				out := response(tc.status, tc.body, nil)
				out.ContentLength = tc.length
				return out, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.DeleteIfToken(context.Background(), testResultKey(), contract.Token{Family: contract.AWS, Value: `"current"`})
			if got.Status != tc.want || calls != 1 {
				t.Fatalf("result=%+v sends=%d", got, calls)
			}
		})
	}
}

// full_only: false
func TestStoreWriteRequiresFinalEmptyResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		length int64
		want   contract.WriteStatus
	}{
		{"complete", 200, "", 0, contract.WriteAcknowledged},
		{"created", 201, "", 0, contract.WriteUnknown},
		{"accepted", 202, "", 0, contract.WriteUnknown},
		{"partial", 206, "", 0, contract.WriteUnknown},
		{"other-success", 299, "", 0, contract.WriteUnknown},
		{"body", 200, "unexpected", 10, contract.WriteUnknown},
		{"truncated", 200, "", 1, contract.WriteUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPut {
					t.Fatalf("method=%s", r.Method)
				}
				out := response(tc.status, tc.body, nil)
				out.ContentLength = tc.length
				return out, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.Create(context.Background(), testResultKey(), []byte("body"))
			if got.Status != tc.want || calls != 1 {
				t.Fatalf("result=%+v sends=%d", got, calls)
			}
		})
	}
}

// full_only: false
func TestStoreConditionalDeleteClassifiesRacesWithoutSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
		want   contract.WriteStatus
		reason contract.Reason
	}{
		{"changed", 412, "PreconditionFailed", contract.WritePrecondition, contract.ReasonCondition},
		{"conflict", 409, "ConditionalRequestConflict", contract.WriteConflict, contract.ReasonCondition},
		{"missing-after-read", 404, "NoSuchKey", contract.WritePrecondition, contract.ReasonCondition},
		{"missing-bucket-after-read", 404, "NoSuchBucket", contract.WritePrecondition, contract.ReasonCondition},
		{"access", 403, "AccessDenied", contract.WriteUnknown, contract.ReasonAccess},
		{"transport", 500, "InternalError", contract.WriteUnknown, contract.ReasonTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(tc.status, "<Error><Code>"+tc.code+"</Code></Error>", nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.DeleteIfToken(context.Background(), testResultKey(), contract.Token{Family: contract.AWS, Value: `"current"`})
			if got.Status != tc.want || got.Reason != tc.reason || got.Status == contract.WriteAcknowledged || calls != 1 {
				t.Fatalf("result=%+v calls=%d", got, calls)
			}
		})
	}
}

// full_only: false
func TestStoreConditionalDeleteRetainsSameByteRepresentationCondition(t *testing.T) {
	calls := 0
	s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method == http.MethodGet {
			return response(200, "same bytes", http.Header{"Etag": {`"same-representation"`}}), nil
		}
		if r.Method != http.MethodDelete || r.Header.Get("If-Match") != `"same-representation"` {
			t.Fatal("delete replaced the original observed representation condition")
		}
		return response(204, "", nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	first := s.Read(context.Background(), testResultKey(), 32)
	recreated := s.Read(context.Background(), testResultKey(), 32)
	if first.Status != contract.ReadOK || recreated.Status != contract.ReadOK || !bytes.Equal(first.Body, recreated.Body) || first.Token != recreated.Token {
		t.Fatal("same-byte representation fixture differs")
	}
	got := s.DeleteIfToken(context.Background(), testResultKey(), first.Token)
	if got.Status != contract.WriteAcknowledged || got.NotSent || calls != 3 {
		t.Fatal("adapter invented an incarnation fence or retried", got, calls)
	}
}

// full_only: false
func TestIncompleteOrOversizedErrorEnvelopeIsUnavailable(t *testing.T) {
	for _, mode := range []string{"oversized", "oversized-unknown-length", "truncated", "body-error", "encoded", "uncompressed"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			var body *countedBody
			s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				r := response(404, "<Error><Code>NoSuchKey</Code></Error>", nil)
				switch mode {
				case "oversized", "oversized-unknown-length":
					r = response(404, "<Error><Code>NoSuchKey</Code><Message>"+strings.Repeat("x", 32<<10)+"</Message></Error>", nil)
					if mode == "oversized-unknown-length" {
						r.ContentLength = -1
						r.Header.Del("Content-Length")
					}
				case "truncated":
					r.ContentLength++
					r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
				case "body-error":
					r.Body = &failingBody{data: []byte("<Error><Code>NoSuchKey</Code></Error>")}
				case "encoded":
					r.Header.Set("Content-Encoding", "gzip")
				case "uncompressed":
					r.Uncompressed = true
				}
				body = &countedBody{ReadCloser: r.Body}
				r.Body = body
				return r, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 1)
			if got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonTransport || len(got.Body) != 0 || got.Token.Value != "" {
				t.Fatalf("error envelope %s: %+v", mode, got)
			}
			if calls != 1 || body == nil || !body.closed || body.bytes > (16<<10)+1 {
				t.Fatalf("calls=%d body=%+v", calls, body)
			}
		})
	}
}

func testStoreConfig() StoreConfig {
	return StoreConfig{Region: "us-east-1", Bucket: "fixture-bucket", ExpectedBucketOwner: "123456789012", Prefix: "enkv/domain", Domain: contract.Hash([]byte("domain")), CredentialRoute: contract.Hash([]byte("fixture route")), Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret"}, nil
	}), Timeout: time.Second}
}

// full_only: false
func TestStoreSerializesSingleConditionalWrite(t *testing.T) {
	body := []byte("complete frozen body")
	for _, head := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "cas"}[head], func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				wantPath := "/fixture-bucket/" + testImmutableKey("member", 0)
				if head {
					wantPath = "/fixture-bucket/enkv/domain/HEAD"
				}
				if r.Method != "PUT" || r.URL.Scheme != "https" || r.URL.Host != "s3.us-east-1.amazonaws.com" || r.URL.Path != wantPath || r.URL.RawQuery != "x-id=PutObject" {
					t.Errorf("unexpected target: %s %s", r.Method, r.URL)
				}
				if r.ContentLength != int64(len(body)) || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
					t.Error("missing length/owner")
				}
				got, e := io.ReadAll(r.Body)
				if e != nil || !bytes.Equal(got, body) {
					t.Error("body changed")
				}
				h := sha256.Sum256(body)
				if r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(h[:]) {
					t.Error("missing checksum")
				}
				if r.Header.Get("Authorization") == "" || r.Header.Get("Content-Encoding") != "" {
					t.Error("unsigned or transformed write")
				}
				if head {
					if r.Header.Get("If-Match") != "\"opaque\"" || r.Header.Get("If-None-Match") != "" {
						t.Error("wrong CAS condition")
					}
				} else if r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "" {
					t.Error("wrong create condition")
				}
				return response(200, "", http.Header{"Etag": []string{"\"new\""}}), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			var got contract.WriteResult
			if head {
				got = s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: "\"opaque\""}, body)
			} else {
				got = s.Create(context.Background(), testImmutableKey("member", 0), body)
			}
			if got.Status != contract.WriteAcknowledged || calls != 1 {
				t.Fatalf("result=%+v calls=%d", got, calls)
			}
		})
	}
}
func testImmutableKey(kind string, index int) string {
	c := testStoreConfig()
	object := contract.Hash([]byte("immutable object"))
	return fmt.Sprintf("%s/%x/%s/%d/%x", c.Prefix, c.Domain, kind, index, object)
}

func testResultKey() string {
	c := testStoreConfig()
	object := contract.Hash([]byte("retained result object"))
	return fmt.Sprintf("%s/%x/result/%x", c.Prefix, c.Domain, object)
}

// full_only: false
func TestStoreKindBoundsUseFormatLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		limit int
	}{
		{"head", testStoreConfig().Prefix + "/HEAD", 65_536},
		{"recipient", testImmutableKey("recipient", 31), 98_304},
		{"root", testImmutableKey("root", 0), 262_144},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := bytes.Repeat([]byte{'b'}, tc.limit)
			readBody := body
			var written []byte
			cas := false
			credentials, requests := 0, 0
			config := testStoreConfig()
			original := config.Credentials
			config.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				credentials++
				return original.Retrieve(ctx)
			})
			s, err := newStore(config, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.URL.Path != "/fixture-bucket/"+tc.key {
					t.Fatalf("unexpected object target: %s", r.URL.Path)
				}
				switch r.Method {
				case http.MethodGet:
					return response(http.StatusOK, string(readBody), http.Header{"Etag": []string{`"bounded"`}}), nil
				case http.MethodPut:
					if cas {
						if r.Header.Get("If-Match") != `"bounded"` || r.Header.Get("If-None-Match") != "" {
							t.Error("HEAD CAS condition differs")
						}
					} else if r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "" {
						t.Error("create-only condition differs")
					}
					var readErr error
					written, readErr = io.ReadAll(r.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					return response(http.StatusOK, "", nil), nil
				default:
					t.Fatalf("unexpected method: %s", r.Method)
					return nil, nil
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if got := s.Read(ctx, tc.key, uint32(tc.limit)); got.Status != contract.ReadOK || !bytes.Equal(got.Body, body) || got.Token.Value != `"bounded"` || requests != 1 {
				t.Fatalf("exact-limit read: status=%d reason=%d bytes=%d requests=%d", got.Status, got.Reason, len(got.Body), requests)
			}
			for _, limit := range []uint32{0, uint32(tc.limit + 1)} {
				beforeCredentials, beforeRequests := credentials, requests
				if got := s.Read(ctx, tc.key, limit); got.Status != contract.ReadInvalid || got.Reason != contract.ReasonConstruction || len(got.Body) != 0 || got.Token.Value != "" {
					t.Errorf("invalid read limit %d: status=%d reason=%d bytes=%d", limit, got.Status, got.Reason, len(got.Body))
				}
				if credentials != beforeCredentials || requests != beforeRequests {
					t.Errorf("invalid read limit %d reached credentials/HTTP: %d/%d", limit, credentials-beforeCredentials, requests-beforeRequests)
				}
			}
			readBody = append(bytes.Clone(body), 'x')
			beforeRequests := requests
			if got := s.Read(ctx, tc.key, uint32(tc.limit)); got.Status != contract.ReadInvalid || got.Reason != contract.ReasonMalformed || len(got.Body) != 0 || got.Token.Value != "" || requests != beforeRequests+1 {
				t.Errorf("oversized response: status=%d reason=%d bytes=%d requests=%d", got.Status, got.Reason, len(got.Body), requests-beforeRequests)
			}
			if tc.name == "head" {
				request, err := contract.NewHeadCreateRequest(s.Descriptor(), body)
				if err != nil {
					t.Fatal(err)
				}
				beforeRequests = requests
				if got := s.CreateHead(ctx, request); got.Status != contract.WriteAcknowledged || !bytes.Equal(written, body) || requests != beforeRequests+1 {
					t.Fatalf("exact-limit HEAD create: %+v bytes=%d requests=%d", got, len(written), requests-beforeRequests)
				}
				cas = true
			}
			write := func(value []byte) contract.WriteResult {
				if cas {
					return s.CompareAndSwap(ctx, tc.key, contract.Token{Family: contract.AWS, Value: `"bounded"`}, value)
				}
				return s.Create(ctx, tc.key, value)
			}
			beforeRequests = requests
			if got := write(body); got.Status != contract.WriteAcknowledged || !bytes.Equal(written, body) || requests != beforeRequests+1 {
				t.Fatalf("exact-limit write: %+v bytes=%d requests=%d", got, len(written), requests-beforeRequests)
			}
			for _, value := range [][]byte{nil, readBody} {
				beforeCredentials, beforeRequests := credentials, requests
				if got := write(value); got.Status != contract.WriteRefused || got.Reason != contract.ReasonLimit {
					t.Errorf("invalid write length %d: %+v", len(value), got)
				}
				if credentials != beforeCredentials || requests != beforeRequests {
					t.Errorf("invalid write length %d reached credentials/HTTP: %d/%d", len(value), credentials-beforeCredentials, requests-beforeRequests)
				}
			}
		})
	}
}

// full_only: false
func TestStoreRejectsNoncanonicalOrForeignImmutableKeysBeforeCredentials(t *testing.T) {
	c := testStoreConfig()
	credentials := 0
	requests := 0
	c.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { credentials++; return aws.Credentials{}, nil })
	s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) { requests++; return nil, io.ErrUnexpectedEOF }))
	if err != nil {
		t.Fatal(err)
	}
	key := testImmutableKey("member", 0)
	for _, bad := range []string{
		c.Prefix + "/member/0/id",
		strings.Replace(key, fmt.Sprintf("%x", c.Domain), strings.Repeat("1", 64), 1),
		testImmutableKey("other", 0), testImmutableKey("root", 1), testImmutableKey("member", 32), testImmutableKey("recipient", 32),
		strings.Replace(key, "/0/", "/00/", 1),
		key[:len(key)-64] + strings.Repeat("0", 64),
		key[:len(key)-64] + strings.ToUpper(key[len(key)-64:]),
	} {
		if got := s.Read(context.Background(), bad, 1024); got.Status != contract.ReadInvalid {
			t.Fatalf("read accepted %q: %+v", bad, got)
		}
		if got := s.Create(context.Background(), bad, []byte("body")); got.Status != contract.WriteRefused {
			t.Fatalf("create accepted %q: %+v", bad, got)
		}
	}
	if credentials != 0 || requests != 0 {
		t.Fatalf("rejected key reached credentials/HTTP: %d/%d", credentials, requests)
	}
}

// full_only: false
func TestStoreLostReplyIsUnknownWithoutRetry(t *testing.T) {
	calls := 0
	s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		return nil, errors.New("accepted then reply lost")
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"old"`}, []byte("candidate"))
	if got.Status != contract.WriteUnknown || got.NotSent || calls != 1 {
		t.Fatalf("result=%+v calls=%d", got, calls)
	}
}

// full_only: false
func TestStoreBeforeSendTransportRefusalIsDistinctFromLostReply(t *testing.T) {
	for _, operation := range []string{"compare-and-swap", "conditional-delete"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected provider entry")
			}))
			if err != nil {
				t.Fatal(err)
			}
			s.client.Transport = boundedTransport{host: "wrong.invalid", next: s.client.Transport}
			token := contract.Token{Family: contract.AWS, Value: `"old"`}
			var got contract.WriteResult
			if operation == "conditional-delete" {
				got = s.DeleteIfToken(context.Background(), testResultKey(), token)
			} else {
				got = s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, token, []byte("candidate"))
			}
			if got.Status != contract.WriteUnknown || got.Reason != contract.ReasonTransport || !got.NotSent || calls != 0 {
				t.Fatalf("result=%+v provider entries=%d", got, calls)
			}
		})
	}
}

// full_only: false
func TestStoreMalformedAcknowledgmentIsUnknown(t *testing.T) {
	for _, mode := range []string{"truncated", "overlong", "encoded"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				r := response(200, "", nil)
				switch mode {
				case "truncated":
					r.ContentLength = 7
					r.Header.Set("Content-Length", "7")
				case "overlong":
					r = response(200, strings.Repeat("x", (16<<10)+1), nil)
				case "encoded":
					r.Header.Set("Content-Encoding", "gzip")
				}
				return r, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"old"`}, []byte("candidate"))
			if got.Status != contract.WriteUnknown || calls != 1 {
				t.Fatalf("malformed %s: %+v calls=%d", mode, got, calls)
			}
		})
	}
}

// full_only: false
func TestZeroStoreRefusesWithoutPanic(t *testing.T) {
	s := new(Store)
	if got := s.Read(context.Background(), "/HEAD", 10); got.Status != contract.ReadInvalid {
		t.Fatalf("zero read: %+v", got)
	}
	if got := s.CompareAndSwap(context.Background(), "/HEAD", contract.Token{Family: contract.AWS, Value: `"old"`}, []byte("body")); got.Status != contract.WriteRefused {
		t.Fatalf("zero write: %+v", got)
	}
}

// full_only: false
func TestRetainedResultObjectsUseBoundedCreateOnlyPaths(t *testing.T) {
	// ResultCore, payload and transfer add 991 bytes to the 65,536-byte raw limit.
	const maxResultLength = contract.GeneratedResultRecordMaxLength
	body := bytes.Repeat([]byte{'r'}, maxResultLength)
	c := testStoreConfig()
	coordinate := contract.Hash([]byte("accepted result coordinate"))
	key, err := format.GeneratedResultKey(c.Prefix, c.Domain, coordinate)
	if err != nil || key != fmt.Sprintf("%s/%x/result/%x", c.Prefix, c.Domain, coordinate) {
		t.Fatal("result coordinate", err)
	}
	calls, credentials := 0, 0
	originalCredentials := c.Credentials
	c.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		credentials++
		return originalCredentials.Retrieve(ctx)
	})
	s, err := newStore(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/fixture-bucket/"+key {
			t.Fatal("result request target differs", r.URL.Path)
		}
		if r.Method == http.MethodPut {
			if r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "" {
				t.Fatal("result create lost its absent condition")
			}
			got, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("result create body differs", err)
			}
			return response(200, "", http.Header{"Etag": []string{`"result-token"`}}), nil
		}
		if r.Method != http.MethodGet {
			t.Fatal("unexpected result method", r.Method)
		}
		return response(200, string(body), http.Header{"Etag": []string{`"result-token"`}}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Create(context.Background(), key, body); got.Status != contract.WriteAcknowledged {
		t.Fatal("result create", got)
	}
	if got := s.Read(context.Background(), key, uint32(maxResultLength)); got.Status != contract.ReadOK || !bytes.Equal(got.Body, body) {
		t.Fatal("result read", got.Status, got.Reason)
	}
	beforeCredentials := credentials
	for _, bad := range []string{
		"foreign/" + key,
		strings.Replace(key, fmt.Sprintf("%x", c.Domain), strings.Repeat("1", 64), 1),
		key[:len(key)-64] + strings.Repeat("0", 64),
		key[:len(key)-64] + strings.ToUpper(key[len(key)-64:]),
		key[:len(key)-1], key + "/extra", key[:len(key)-64] + strings.Repeat("g", 64),
		key[:len(key)-64] + strings.Repeat("a", 4096),
		strings.Replace(key, "/result/", "/result/0/", 1),
		strings.Replace(key, "/result/", "/unknown/", 1),
	} {
		if got := s.Read(context.Background(), bad, 1); got.Status != contract.ReadInvalid {
			t.Fatal("result read accepted invalid key", bad)
		}
		if got := s.Create(context.Background(), bad, []byte{1}); got.Status != contract.WriteRefused {
			t.Fatal("result create accepted invalid key", bad)
		}
	}
	for _, length := range []int{0, maxResultLength + 1} {
		if got := s.Read(context.Background(), key, uint32(length)); got.Status != contract.ReadInvalid {
			t.Fatal("result read accepted invalid limit", length)
		}
		if got := s.Create(context.Background(), key, make([]byte, length)); got.Status != contract.WriteRefused {
			t.Fatal("result create accepted invalid length", length)
		}
	}
	// A valid CAS body size must not mask the create-only result path guard.
	if got := s.CompareAndSwap(context.Background(), key, contract.Token{Family: contract.AWS, Value: `"result-token"`}, []byte("candidate")); got.Status != contract.WriteRefused || got.Reason != contract.ReasonConstruction {
		t.Fatal("result coordinate admitted mutable replacement", got)
	}
	if calls != 2 || credentials != beforeCredentials {
		t.Fatal("refused result request reached credentials or HTTP", calls, credentials, beforeCredentials)
	}
}
