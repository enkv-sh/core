package awsprovider

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

func candidateConfig() CandidateReadConfig {
	store := testStoreConfig()
	return CandidateReadConfig{Region: store.Region, Bucket: store.Bucket, Prefix: store.Prefix,
		CredentialRoute: store.CredentialRoute, Credentials: store.Credentials, Timeout: store.Timeout}
}

// full_only: false
func TestCandidateReaderExactPublicReadsAndOwnerGuard(t *testing.T) {
	c := candidateConfig()
	domain, storeID := contract.Hash([]byte("candidate domain")), contract.Hash([]byte("candidate helper"))
	helperKey, err := contract.StoreConfigurationKeyForID(contract.AWS, c.Prefix, domain, storeID)
	if err != nil {
		t.Fatal(err)
	}
	rootBody := []byte("root")
	ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: domain,
		Object: contract.Hash([]byte("candidate root")), Digest: contract.Hash(rootBody), Length: uint32(len(rootBody))}
	rootKey, err := format.Key(c.Prefix, ref)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{c.Prefix + "/HEAD", helperKey, rootKey, c.Prefix + "/HEAD"}
	owners := []string{"", "", "", "123456789012"}
	bodies := []string{"head", "cfg", "root", "head"}
	calls := 0
	r, err := newCandidateReader(c, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls >= len(paths) {
			t.Fatal("candidate reader made an extra request")
		}
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "s3.us-east-1.amazonaws.com" ||
			req.URL.Path != "/"+c.Bucket+"/"+paths[calls] || req.URL.RawQuery != "x-id=GetObject" ||
			req.Header.Get("X-Amz-Expected-Bucket-Owner") != owners[calls] || req.Header.Get("Range") != "" || req.Header.Get("Authorization") == "" {
			t.Fatalf("candidate request %d differs: %s %s owner=%q", calls, req.Method, req.URL, req.Header.Get("X-Amz-Expected-Bucket-Owner"))
		}
		body := bodies[calls]
		calls++
		return response(http.StatusOK, body, http.Header{"Etag": []string{`"selected"`}}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.CandidateLocation(); got != c.location() {
		t.Fatal("candidate source changed independently supplied location", got)
	}
	head := r.ReadHEAD(context.Background())
	if head.Status != contract.ReadOK || string(head.Body) != "head" || head.Token.Value != `"selected"` {
		t.Fatal("initial HEAD lost body/token", head)
	}
	if got := r.ReadConfiguration(context.Background(), domain, storeID); got.Status != contract.ReadOK || string(got.Body) != "cfg" {
		t.Fatal("helper read differed", got)
	}
	if got := r.ReadRoot(context.Background(), ref); got.Status != contract.ReadOK || string(got.Body) != "root" {
		t.Fatal("root read differed", got)
	}
	if got := r.ReadHEADGuarded(context.Background(), "123456789012"); got.Status != contract.ReadOK || string(got.Body) != "head" || got.Token != head.Token {
		t.Fatal("guarded HEAD differed", got)
	}
	if string(head.Body) != "head" || calls != 4 {
		t.Fatal("later read changed earlier body or request count", calls)
	}
	if got := r.CandidateLocation(); got != c.location() {
		t.Fatal("later read changed candidate location", got)
	}
	if got := r.ReadRoot(context.Background(), contract.Ref{}); got.Status != contract.ReadInvalid || calls != 4 {
		t.Fatal("invalid root reached provider", got, calls)
	}
}

// full_only: false
func TestCandidateReaderOwnerIsNeverDroppedAfterRefusal(t *testing.T) {
	c := candidateConfig()
	c.ExpectedBucketOwner = "123456789012"
	calls := 0
	r, err := newCandidateReader(c, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("X-Amz-Expected-Bucket-Owner") != c.ExpectedBucketOwner {
			t.Fatal("supplied owner was omitted")
		}
		return response(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>", nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.CandidateLocation(); got.ExpectedOwner != c.ExpectedBucketOwner {
		t.Fatal("supplied owner missing from candidate location")
	}
	if got := r.ReadHEAD(context.Background()); got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonAccess || len(got.Body) != 0 || got.Token.Valid() {
		t.Fatal("guarded 403 was not preserved", got)
	}
	if got := r.ReadHEADGuarded(context.Background(), "210987654321"); got.Status != contract.ReadInvalid || calls != 1 {
		t.Fatal("different owner reached S3", got, calls)
	}
}

// full_only: false
func TestCandidateReaderBoundsAndPreflightRefusals(t *testing.T) {
	for _, mode := range []string{"oversize", "truncated", "missing-etag", "encoded"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				resp := response(http.StatusOK, "head", http.Header{"Etag": []string{`"selected"`}})
				switch mode {
				case "oversize":
					resp = response(http.StatusOK, strings.Repeat("a", contract.MaxHeadLength+1), resp.Header)
				case "truncated":
					resp.ContentLength++
				case "missing-etag":
					resp.Header.Del("Etag")
				case "encoded":
					resp.Header.Set("Content-Encoding", "gzip")
				}
				return resp, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := r.ReadHEAD(context.Background())
			wantStatus, wantReason := contract.ReadInvalid, contract.ReasonMalformed
			if mode == "truncated" {
				wantStatus, wantReason = contract.ReadUnavailable, contract.ReasonTransport
			}
			if got.Status != wantStatus || got.Reason != wantReason || len(got.Body) != 0 || got.Token.Valid() || calls != 1 {
				t.Fatal("failed public read changed evidence or was replayed", mode, got, calls)
			}
		})
	}
	calls := 0
	r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusOK, "head", http.Header{"Etag": []string{`"selected"`}}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := r.ReadHEAD(ctx); got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonLimit || calls != 0 {
		t.Fatal("canceled read made a request", got, calls)
	}
	for _, bad := range []CandidateReadConfig{
		func() CandidateReadConfig { c := candidateConfig(); c.Bucket = "bad..bucket"; return c }(),
		func() CandidateReadConfig { c := candidateConfig(); c.Prefix = "team/../prod"; return c }(),
		func() CandidateReadConfig { c := candidateConfig(); c.ExpectedBucketOwner = "123"; return c }(),
		func() CandidateReadConfig { c := candidateConfig(); c.CredentialRoute = contract.ID{}; return c }(),
	} {
		if _, err := newCandidateReader(bad, roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid construction reached HTTP")
			return nil, nil
		})); err == nil {
			t.Fatal("invalid candidate location was admitted")
		}
	}
}

// full_only: false
func TestCandidateReaderEachPhysicalLimit(t *testing.T) {
	domain, storeID := contract.Hash([]byte("candidate domain")), contract.Hash([]byte("candidate helper"))
	for _, tc := range []struct {
		name  string
		limit int
		read  func(*CandidateReader, context.Context, contract.Ref) contract.ReadResult
	}{
		{"head", contract.MaxHeadLength, func(r *CandidateReader, ctx context.Context, _ contract.Ref) contract.ReadResult {
			return r.ReadHEAD(ctx)
		}},
		{"helper", contract.MaxStoreConfigurationLength, func(r *CandidateReader, ctx context.Context, _ contract.Ref) contract.ReadResult {
			return r.ReadConfiguration(ctx, domain, storeID)
		}},
		{"root", contract.MaxRootLength, func(r *CandidateReader, ctx context.Context, ref contract.Ref) contract.ReadResult {
			return r.ReadRoot(ctx, ref)
		}},
	} {
		for _, extra := range []int{0, 1} {
			name := tc.name + "/exact"
			if extra != 0 {
				name = tc.name + "/first-over"
			}
			t.Run(name, func(t *testing.T) {
				body := strings.Repeat("b", tc.limit+extra)
				ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: domain,
					Object: contract.Hash([]byte("candidate root")), Digest: contract.Hash([]byte(body[:tc.limit])), Length: uint32(tc.limit)}
				calls := 0
				r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Method != http.MethodGet || req.Header.Get("Range") != "" {
						t.Fatal("bounded candidate read changed request")
					}
					return response(http.StatusOK, body, http.Header{"Etag": []string{`"bounded"`}}), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				got := tc.read(r, context.Background(), ref)
				if extra == 0 && (got.Status != contract.ReadOK || len(got.Body) != tc.limit) ||
					extra != 0 && (got.Status == contract.ReadOK || len(got.Body) != 0 || got.Token.Valid()) || calls != 1 {
					t.Fatalf("boundary result=%+v calls=%d", got, calls)
				}
			})
		}
	}
}

// full_only: false
func TestCandidateReaderTelemetryKeepsPublicFailureFacts(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	calls := 0
	r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(http.StatusOK, "head", http.Header{"Etag": []string{`"selected"`}}), nil
		}
		return response(http.StatusForbidden, "<Error><Code>AccessDenied</Code><Message>private diagnostic</Message></Error>", nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.ReadHEAD(ctx); got.Status != contract.ReadOK {
		t.Fatal(got)
	}
	if got := r.ReadHEAD(ctx); got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonAccess || len(got.Body) != 0 {
		t.Fatal(got)
	}
	data := snapshot()
	if calls != 2 || telemetrySum(data, telemetry.OperationCalls, telemetry.OpStoreRead, "", "") != 2 ||
		telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreRead, "read_ok", "") != 1 ||
		telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreRead, "read_unavailable", "") != 1 ||
		telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreRead, "", "") != 2 {
		t.Fatal("candidate read telemetry lost call or failure facts")
	}
	assertSafeTelemetry(t, data)
}

// full_only: false
func TestCandidateReaderSuppliedOwnerCoversEveryPublicRead(t *testing.T) {
	c := candidateConfig()
	c.ExpectedBucketOwner = "123456789012"
	domain, storeID := contract.Hash([]byte("candidate domain")), contract.Hash([]byte("candidate helper"))
	ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: domain,
		Object: storeID, Digest: storeID, Length: 4}
	for _, read := range []struct {
		name string
		call func(*CandidateReader) contract.ReadResult
	}{
		{"head", func(r *CandidateReader) contract.ReadResult { return r.ReadHEAD(context.Background()) }},
		{"helper", func(r *CandidateReader) contract.ReadResult {
			return r.ReadConfiguration(context.Background(), domain, storeID)
		}},
		{"root", func(r *CandidateReader) contract.ReadResult { return r.ReadRoot(context.Background(), ref) }},
		{"guarded-head", func(r *CandidateReader) contract.ReadResult {
			return r.ReadHEADGuarded(context.Background(), c.ExpectedBucketOwner)
		}},
	} {
		t.Run(read.name, func(t *testing.T) {
			calls := 0
			r, err := newCandidateReader(c, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet || req.Header.Get("X-Amz-Expected-Bucket-Owner") != c.ExpectedBucketOwner {
					t.Fatal("public read dropped owner guard")
				}
				return response(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>", nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := read.call(r)
			if got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonAccess || len(got.Body) != 0 || got.Token.Valid() || calls != 1 {
				t.Fatal("guarded refusal was retried or lost", got, calls)
			}
		})
	}
}

// full_only: false
func TestCandidateReaderCancellationAfterPhysicalResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		cancel()
		return response(http.StatusOK, "head", http.Header{"Etag": []string{`"selected"`}}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := r.ReadHEAD(ctx)
	if got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonLimit || len(got.Body) != 0 || got.Token.Valid() || calls != 1 {
		t.Fatal("canceled candidate read returned or retried bytes", got, calls)
	}
}

// full_only: false
func TestCandidateReaderRejectsNonRootAndInvalidLengthBeforeAccess(t *testing.T) {
	calls := 0
	r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		t.Fatal("invalid public reference reached provider")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := contract.Hash([]byte("candidate root"))
	ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: id, Object: id, Digest: id, Length: 4}
	for _, change := range []func(*contract.Ref){
		func(ref *contract.Ref) { ref.Kind = contract.ValueEntryPageKind },
		func(ref *contract.Ref) { ref.Index = 1 },
		func(ref *contract.Ref) { ref.Format-- },
		func(ref *contract.Ref) { ref.Length = 0 },
		func(ref *contract.Ref) { ref.Length = contract.MaxRootLength + 1 },
		func(ref *contract.Ref) { ref.Domain = contract.ID{} },
		func(ref *contract.Ref) { ref.Object = contract.ID{} },
		func(ref *contract.Ref) { ref.Digest = contract.ID{} },
	} {
		bad := ref
		change(&bad)
		got := r.ReadRoot(context.Background(), bad)
		if got.Status != contract.ReadInvalid || got.Reason != contract.ReasonConstruction || len(got.Body) != 0 || got.Token.Valid() {
			t.Fatal("invalid root reference admitted", got)
		}
	}
	for _, ids := range [][2]contract.ID{{{}, id}, {id, {}}} {
		got := r.ReadConfiguration(context.Background(), ids[0], ids[1])
		if got.Status != contract.ReadInvalid || got.Reason != contract.ReasonConstruction || len(got.Body) != 0 || got.Token.Valid() {
			t.Fatal("unbound helper admitted", got)
		}
	}
	var nilContext context.Context
	if got := r.ReadHEAD(nilContext); got.Status != contract.ReadInvalid || got.Reason != contract.ReasonConstruction {
		t.Fatal("nil context admitted", got)
	}
	for _, name := range []string{"Read", "Create", "CreateHead", "CompareAndSwap", "DeleteIfToken", "Sign", "Decrypt", "List"} {
		if _, has := reflect.TypeOf(r).MethodByName(name); has {
			t.Fatal("candidate reader exposes another authority", name)
		}
	}
	if calls != 0 {
		t.Fatal("invalid reference sent a request", calls)
	}
}

// full_only: false
func TestCandidateReaderDeadlineDuringPhysicalReadDoesNotRetry(t *testing.T) {
	calls := 0
	r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got := r.ReadHEAD(ctx)
	if got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonLimit || len(got.Body) != 0 || got.Token.Valid() || calls != 1 {
		t.Fatal("deadline changed evidence or repeated request", got, calls)
	}
}

// full_only: false
func TestCandidateReaderRejectsShortRootResponse(t *testing.T) {
	calls := 0
	r, err := newCandidateReader(candidateConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusOK, "root", http.Header{"Etag": []string{`"selected"`}}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := contract.Hash([]byte("candidate root"))
	ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: id, Object: id, Digest: id, Length: 5}
	got := r.ReadRoot(context.Background(), ref)
	if got.Status != contract.ReadInvalid || got.Reason != contract.ReasonMalformed || len(got.Body) != 0 || got.Token.Valid() || calls != 1 {
		t.Fatal("short root returned partial selected bytes", got, calls)
	}
}
