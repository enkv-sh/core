package gcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func config(client *Client) StoreConfig {
	return StoreConfig{Client: client, Domain: contract.Hash([]byte("domain")), Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "fixture-bucket", Prefix: "fixture", CredentialRoute: "fixture-route"}
}

// full_only: false
func TestStoreConstructionProfileTwoIsRouteIndependent(t *testing.T) {
	client := makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction made a request")
		return nil, nil
	}), &credentials{})
	c := config(client)
	for i := range c.Domain {
		c.Domain[i] = byte(i + 1)
	}
	c.Bucket, c.Prefix = "enkv-example-bucket", "team/prod"
	first, err := NewStore(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	d := first.Descriptor()
	if got := hex.EncodeToString(d.Identity[:]); got != "9be3ffa7419691e01b00331965a7311b2371b072570ed988e1aeb86cac4d220f" {
		t.Fatalf("store identity=%s", got)
	}
	if got := hex.EncodeToString(d.Coordinate[:]); got != "bf6121a944b1ec436b680e174d68f8fb02013951040b2d546b54265f25a68a10" {
		t.Fatalf("coordinate=%s", got)
	}
	if got := hex.EncodeToString(d.NonBody[:]); got != "84c8f0c26839fa4be50114f92a65040e62389a44d2e786c02365488306f35102" {
		t.Fatalf("nonbody=%s", got)
	}
	c.CredentialRoute = "another-local-route"
	c.Client = makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction made a request")
		return nil, nil
	}), &credentials{})
	second, err := NewStore(context.Background(), c)
	if err != nil || second.Descriptor() != d {
		t.Fatalf("route changed persistent construction: err=%v", err)
	}
	c.Bucket = "another-bucket"
	third, err := NewStore(context.Background(), c)
	if err != nil || third.Descriptor().Identity == d.Identity || third.Descriptor().Coordinate == d.Coordinate {
		t.Fatalf("bucket did not change persistent construction: err=%v", err)
	}
}

// full_only: false
func TestStoreConstructionFieldsBindPersistentIdentities(t *testing.T) {
	c := config(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("construction made a request"); return nil, nil }), &credentials{}))
	first, err := NewStore(context.Background(), c)
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
		{"bucket", func(c *StoreConfig) { c.Bucket = "another-bucket" }, true, true},
		{"prefix", func(c *StoreConfig) { c.Prefix = "another/prefix" }, true, false},
		{"region", func(c *StoreConfig) {
			c.Region = "us-east1"
			c.Endpoint = "https://storage.us-east1.rep.googleapis.com/storage/v1/"
		}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := c
			tc.mutate(&changed)
			other, err := NewStore(context.Background(), changed)
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

func newStore(t *testing.T, f roundTripFunc) (*Store, *credentials) {
	t.Helper()
	creds := &credentials{}
	s, err := NewStore(context.Background(), config(makeClient(f, creds)))
	if err != nil {
		t.Fatal(err)
	}
	return s, creds
}
func childKey(s *Store) string {
	id := contract.Hash([]byte("page"))
	return s.config.Prefix + "/" + hex.EncodeToString(s.config.Domain[:]) + "/member/0/" + hex.EncodeToString(id[:])
}

// full_only: false
func TestRequiredSupportObjectsUseBoundedStorePaths(t *testing.T) {
	for _, kind := range []string{"support", "admin-index"} {
		for _, index := range []int{0, 255} {
			t.Run(kind+"/"+strconv.Itoa(index), func(t *testing.T) {
				body := strings.Repeat("r", 98200)
				var key string
				calls := 0
				s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
					calls++
					if r.Method == http.MethodDelete {
						if r.URL.Query().Get("ifGenerationMatch") != "24" {
							t.Fatal("selected child delete lost its observed token")
						}
						return response(http.StatusNoContent, ""), nil
					}
					if r.Method == http.MethodPost {
						if r.URL.Query().Get("ifGenerationMatch") != "0" {
							t.Fatal("support create lost its absent condition")
						}
						if _, err := io.Copy(io.Discard, r.Body); err != nil {
							t.Fatal(err)
						}
						return response(200, fmt.Sprintf(`{"bucket":"fixture-bucket","name":%q,"generation":"24","size":%q,"crc32c":%q}`, key, strconv.Itoa(len(body)), crcBase64([]byte(body)))), nil
					}
					if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/o/"+key) {
						t.Fatal("support read target differs", r.Method, r.URL.Path)
					}
					reply := response(200, body)
					reply.Header.Set("X-Goog-Generation", "24")
					return reply, nil
				})
				key = strings.Replace(childKey(s), "/member/0/", fmt.Sprintf("/%s/%d/", kind, index), 1)
				if got := s.Create(context.Background(), key, []byte(body)); got.Status != contract.WriteAcknowledged {
					t.Fatal("support create", got)
				}
				if got := s.Read(context.Background(), key, uint32(len(body))); got.Status != contract.ReadOK || string(got.Body) != body || got.Token.Value != "24" {
					t.Fatal("support read", got.Status, got.Reason)
				}
				if got := s.DeleteIfToken(context.Background(), key, contract.Token{Family: contract.GCP, Value: "24"}); got.Status != contract.WriteAcknowledged {
					t.Fatal("selected child delete", got)
				}
				beforeCredentials := creds.calls
				if got := s.Read(context.Background(), key, contract.MaxRequiredSupportPageLength+1); got.Status != contract.ReadInvalid {
					t.Fatal("support read accepted excess limit")
				}
				if got := s.Create(context.Background(), key, make([]byte, contract.MaxRequiredSupportPageLength+1)); got.Status != contract.WriteRefused {
					t.Fatal("support create accepted excess bytes")
				}
				for _, invalid := range []string{"256", "00", "-1"} {
					bad := strings.Replace(key, fmt.Sprintf("/%s/%d/", kind, index), "/"+kind+"/"+invalid+"/", 1)
					if got := s.Read(context.Background(), bad, 1); got.Status != contract.ReadInvalid {
						t.Fatal("support read accepted invalid index", invalid)
					}
					if got := s.Create(context.Background(), bad, []byte{1}); got.Status != contract.WriteRefused {
						t.Fatal("support create accepted invalid index", invalid)
					}
					if got := s.DeleteIfToken(context.Background(), bad, contract.Token{Family: contract.GCP, Value: "24"}); got.Status != contract.WriteRefused {
						t.Fatal("selected child delete accepted invalid index", invalid)
					}
				}
				if calls != 3 || creds.calls != beforeCredentials {
					t.Fatal("refused support request reached credentials or HTTP", calls, creds.calls, beforeCredentials)
				}
			})
		}
	}
}

// full_only: false
func TestStoreRequestsUseExactConditionalMultipart(t *testing.T) {
	calls := 0
	var s *Store
	body := []byte("complete state bytes")
	s, _ = newStore(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/upload/storage/v1/b/fixture-bucket/o" {
			t.Fatalf("unexpected target: %s %s", r.Method, r.URL)
		}
		q := r.URL.Query()
		expected := "0"
		key := childKey(s)
		if calls == 2 {
			expected = "23"
			key = s.Descriptor().HeadKey
		}
		if q.Get("ifGenerationMatch") != expected || q.Get("uploadType") != "multipart" || q.Get("ifMetagenerationMatch") != "" {
			t.Fatalf("query: %v", q)
		}
		if r.GetBody != nil || !r.Close || r.ContentLength <= int64(len(body)) {
			t.Fatal("request replay/length policy")
		}
		if r.Header.Get("Authorization") != "Bearer fixture-token" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatal("missing explicit request headers")
		}
		kind, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || kind != "multipart/related" {
			t.Fatal("not JSON multipart")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != int(r.ContentLength) {
			t.Fatal("wire body length differs")
		}
		reader := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
		metadata, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err = json.NewDecoder(metadata).Decode(&fields); err != nil {
			t.Fatal(err)
		}
		if fields["name"] != key || fields["crc32c"] != crcBase64(body) || fields["cacheControl"] != "private, no-store, no-transform" || fields["contentEncoding"] != nil {
			t.Fatalf("metadata: %v", fields)
		}
		media, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(media)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatal("media differs")
		}
		if _, err = reader.NextPart(); err != io.EOF {
			t.Fatal("extra media part")
		}
		return response(200, fmt.Sprintf(`{"bucket":"fixture-bucket","name":%q,"generation":"24","size":%q,"crc32c":%q}`, key, strconv.Itoa(len(body)), crcBase64(body))), nil
	})
	if got := s.Create(context.Background(), childKey(s), body); got.Status != contract.WriteAcknowledged {
		t.Fatal(got)
	}
	if got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "23"}, body); got.Status != contract.WriteAcknowledged {
		t.Fatal(got)
	}
	if calls != 2 {
		t.Fatalf("physical sends: %d", calls)
	}
}

// full_only: false
func TestStoreCreateRequiresFinalObjectResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   contract.WriteStatus
	}{
		{"complete", 200, contract.WriteAcknowledged},
		{"created", 201, contract.WriteUnknown},
		{"accepted", 202, contract.WriteUnknown},
		{"partial", 206, contract.WriteUnknown},
		{"other-success", 299, contract.WriteUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("plain")
			var key string
			calls := 0
			s, _ := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/upload/storage/v1/b/fixture-bucket/o" {
					t.Fatalf("create route: %s %s", r.Method, r.URL)
				}
				return response(tc.status, fmt.Sprintf(`{"bucket":"fixture-bucket","name":%q,"generation":"24","size":"5","crc32c":%q}`, key, crcBase64(body))), nil
			})
			key = childKey(s)
			got := s.Create(context.Background(), key, body)
			if got.Status != tc.want || calls != 1 {
				t.Fatalf("result=%+v sends=%d", got, calls)
			}
		})
	}
}

// full_only: false
func TestStoreConditionalDeleteBindsObservedGeneration(t *testing.T) {
	var key string
	calls := 0
	s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodDelete || r.URL.EscapedPath() != "/storage/v1/b/fixture-bucket/o/"+strings.ReplaceAll(key, "/", "%2F") ||
			r.URL.Query().Get("ifGenerationMatch") != "24" || r.URL.Query().Get("alt") != "json" ||
			r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Fatalf("conditional delete request: %s %s", r.Method, r.URL)
		}
		return response(http.StatusNoContent, ""), nil
	})
	key = childKey(s)
	result := s.DeleteIfToken(context.Background(), key, contract.Token{Family: contract.GCP, Value: "24"})
	if result.Status != contract.WriteAcknowledged || calls != 1 || creds.calls != 1 {
		t.Fatal("exact conditional delete was not acknowledged", result, calls, creds.calls)
	}
	before := creds.calls
	for _, token := range []contract.Token{{Family: contract.AWS, Value: "24"}, {Family: contract.GCP, Value: "024"}, {Family: contract.GCP, Value: "0"}} {
		if got := s.DeleteIfToken(context.Background(), key, token); got.Status != contract.WriteRefused {
			t.Fatal("invalid delete token accepted", token, got)
		}
	}
	if calls != 1 || creds.calls != before {
		t.Fatal("refused delete reached credentials or HTTP")
	}
}

// full_only: false
func TestStoreConditionalDeleteRetainsOriginalGenerationAfterSameByteChange(t *testing.T) {
	calls := 0
	s, _ := newStore(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method == http.MethodGet {
			out := response(200, "same bytes")
			out.Header.Set("X-Goog-Generation", strconv.Itoa(23+calls))
			return out, nil
		}
		if r.Method != http.MethodDelete || r.URL.Query().Get("ifGenerationMatch") != "24" {
			t.Fatal("delete replaced its original observed generation")
		}
		return apiFailure(412, "conditionNotMet"), nil
	})
	key := childKey(s)
	first := s.Read(context.Background(), key, 32)
	recreated := s.Read(context.Background(), key, 32)
	if first.Status != contract.ReadOK || recreated.Status != contract.ReadOK || !bytes.Equal(first.Body, recreated.Body) || first.Token.Value != "24" || recreated.Token.Value != "25" {
		t.Fatal("same-byte new-generation fixture differs")
	}
	got := s.DeleteIfToken(context.Background(), key, first.Token)
	if got.Status != contract.WritePrecondition || got.Reason != contract.ReasonCondition || got.NotSent || calls != 3 {
		t.Fatal("changed-generation delete did not preserve conflict", got, calls)
	}
}

// full_only: false
func TestStoreConditionalDeleteLostReplyRemainsUnknown(t *testing.T) {
	calls := 0
	s, _ := newStore(t, func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })
	got := s.DeleteIfToken(context.Background(), childKey(s), contract.Token{Family: contract.GCP, Value: "24"})
	if got.Status != contract.WriteUnknown || got.Reason != contract.ReasonTransport || got.NotSent || calls != 1 {
		t.Fatal("delete lost reply retried or became definitive", got, calls)
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
			s, _ := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodDelete || !strings.HasPrefix(r.URL.EscapedPath(), "/storage/v1/") {
					t.Fatalf("delete route: %s %s", r.Method, r.URL)
				}
				out := response(tc.status, tc.body)
				out.ContentLength = tc.length
				return out, nil
			})
			got := s.DeleteIfToken(context.Background(), childKey(s), contract.Token{Family: contract.GCP, Value: "24"})
			if got.Status != tc.want || calls != 1 {
				t.Fatalf("result=%+v sends=%d", got, calls)
			}
		})
	}
}

// full_only: false
func TestStoreRejectsWrongCoordinatesBeforeCredentials(t *testing.T) {
	s, creds := newStore(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })
	for _, key := range []string{"elsewhere/HEAD", s.config.Prefix + "/../HEAD", strings.Replace(childKey(s), "/member/0/", "/member/00/", 1), strings.Replace(childKey(s), "/member/0/", "/root/1/", 1), strings.Replace(childKey(s), "/member/0/", "/member/32/", 1), childKey(s) + "/extra"} {
		if s.Read(context.Background(), key, 64).Status != contract.ReadInvalid {
			t.Fatal(key)
		}
		if s.Create(context.Background(), key, []byte("x")).Status != contract.WriteRefused {
			t.Fatal(key)
		}
	}
	if s.Create(context.Background(), s.Descriptor().HeadKey, []byte("x")).Status != contract.WriteRefused {
		t.Fatal("created HEAD")
	}
	for _, token := range []contract.Token{{Family: contract.AWS, Value: "23"}, {Family: contract.GCP, Value: "01"}, {Family: contract.GCP, Value: "0"}, {Family: contract.GCP, Value: "9223372036854775808"}} {
		if s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, token, []byte("x")).Status != contract.WriteRefused {
			t.Fatal(token)
		}
	}
	if creds.calls != 0 {
		t.Fatal("invalid target accessed credentials")
	}
}

// full_only: false
func TestReadSameResponseGenerationAndNoResume(t *testing.T) {
	for _, tc := range []struct {
		name, generation string
		status           int
		body             string
		contentLength    int64
		want             contract.ReadStatus
	}{
		{"complete", "42", 200, "body", 4, contract.ReadOK}, {"missing generation", "", 200, "body", 4, contract.ReadInvalid}, {"leading zero", "042", 200, "body", 4, contract.ReadInvalid}, {"metageneration is insufficient", "", 200, "body", 4, contract.ReadInvalid}, {"partial body", "42", 200, "bad", 10, contract.ReadUnavailable}, {"range response", "42", 206, "body", 4, contract.ReadInvalid}, {"too large", "42", 200, "12345", 5, contract.ReadInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, _ := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/download/storage/v1/b/fixture-bucket/o/fixture/HEAD" || r.URL.Query().Get("alt") != "media" || r.URL.Query().Has("generation") || r.Header.Get("Range") != "" {
					t.Fatalf("read request: %s %s", r.Method, r.URL)
				}
				out := response(tc.status, tc.body)
				out.ContentLength = tc.contentLength
				if tc.generation != "" {
					out.Header.Set("X-Goog-Generation", tc.generation)
				}
				out.Header.Set("X-Goog-Metageneration", "99")
				return out, nil
			})
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 4)
			if got.Status != tc.want {
				t.Fatal(got)
			}
			if tc.want == contract.ReadOK && (string(got.Body) != "body" || got.Token.Value != "42") {
				t.Fatal(got)
			}
			if calls != 1 {
				t.Fatalf("sends: %d", calls)
			}
		})
	}
}

// full_only: false
func TestStoreFailureMappingAndOnePhysicalSend(t *testing.T) {
	for _, tc := range []struct {
		status int
		reason string
		read   contract.ReadStatus
		write  contract.WriteStatus
	}{
		{404, "notFound", contract.ReadMissing, contract.WriteRefused}, {403, "forbidden", contract.ReadUnavailable, contract.WriteRefused}, {401, "authError", contract.ReadUnavailable, contract.WriteRefused}, {412, "conditionNotMet", contract.ReadUnavailable, contract.WritePrecondition}, {412, "retentionPolicyNotMet", contract.ReadUnavailable, contract.WriteRefused}, {429, "rateLimitExceeded", contract.ReadUnavailable, contract.WriteUnknown}, {500, "backendError", contract.ReadUnavailable, contract.WriteUnknown}, {503, "backendError", contract.ReadUnavailable, contract.WriteUnknown},
	} {
		t.Run(fmt.Sprint(tc.status, tc.reason), func(t *testing.T) {
			calls := 0
			s, _ := newStore(t, func(*http.Request) (*http.Response, error) { calls++; return apiFailure(tc.status, tc.reason), nil })
			if got := s.Read(context.Background(), s.Descriptor().HeadKey, 64); got.Status != tc.read {
				t.Fatal(got)
			}
			if got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "9"}, []byte("candidate")); got.Status != tc.write {
				t.Fatal(got)
			}
			if calls != 2 {
				t.Fatalf("sends: %d", calls)
			}
		})
	}
}

// full_only: false
func TestWriteFailureRetainsBeforeSendProof(t *testing.T) {
	op := &operation{}
	ctx := context.WithValue(context.Background(), operationKey{}, op)
	before := writeFailure(ctx, io.ErrUnexpectedEOF)
	op.sent.Add(1)
	after := writeFailure(ctx, io.ErrUnexpectedEOF)
	if before.Status != contract.WriteUnknown || before.Reason != contract.ReasonTransport || !before.NotSent || after.Status != contract.WriteUnknown || after.NotSent {
		t.Fatal("before-send and lost-reply facts were merged", before, after)
	}
}

// full_only: false
func TestLostWriteReplyAndBadAcknowledgmentRemainUnknown(t *testing.T) {
	for _, mode := range []string{"lost reply", "truncated JSON", "wrong generation", "noncanonical generation", "wrong bucket", "wrong name", "wrong size", "wrong checksum", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			var s *Store
			s, _ = newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "lost reply" {
					return nil, io.ErrUnexpectedEOF
				}
				if mode == "truncated JSON" {
					return response(200, `{"generation":`), nil
				}
				if mode == "redirect" {
					out := response(307, "")
					out.Header.Set("Location", "https://storage.us-central1.rep.googleapis.com/elsewhere")
					return out, nil
				}
				fields := map[string]string{"generation": "10", "bucket": "fixture-bucket", "name": s.Descriptor().HeadKey, "size": "9", "crc32c": crcBase64([]byte("candidate"))}
				field := strings.TrimPrefix(mode, "wrong ")
				if field == "checksum" {
					field = "crc32c"
				}
				fields[field] = "0"
				if mode == "noncanonical generation" {
					fields["generation"] = "010"
				}
				out, _ := json.Marshal(fields)
				return response(200, string(out)), nil
			})
			if got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "9"}, []byte("candidate")); got.Status != contract.WriteUnknown {
				t.Fatal(got)
			}
			if calls != 1 {
				t.Fatalf("sends: %d", calls)
			}
		})
	}
}

// full_only: false
func TestWriteErrorRequiresPhysicalStatusAgreement(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		code       string
		want       contract.WriteStatus
		wantReason contract.Reason
	}{
		{"503 body 412", 503, "412", contract.WriteUnknown, contract.ReasonMalformed},
		{"503 body 403", 503, "403", contract.WriteUnknown, contract.ReasonMalformed},
		{"503 body 404", 503, "404", contract.WriteUnknown, contract.ReasonMalformed},
		{"412 body 503", 412, "503", contract.WriteUnknown, contract.ReasonMalformed},
		{"412 body zero", 412, "0", contract.WriteUnknown, contract.ReasonMalformed},
		{"403 body zero", 403, "0", contract.WriteUnknown, contract.ReasonMalformed},
		{"412 body null", 412, "null", contract.WriteUnknown, contract.ReasonMalformed},
		{"412 body string", 412, `"412"`, contract.WriteUnknown, contract.ReasonMalformed},
		{"exact 412", 412, "412", contract.WritePrecondition, contract.ReasonCondition},
	} {
		for _, method := range []string{"create", "compare and swap"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				calls := 0
				s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
					calls++
					generation := "0"
					if method == "compare and swap" {
						generation = "42"
					}
					if r.Method != "POST" || r.URL.Path != "/upload/storage/v1/b/fixture-bucket/o" || r.URL.Query().Get("ifGenerationMatch") != generation || r.URL.Query().Get("uploadType") != "multipart" {
						t.Fatalf("write request: %s %s", r.Method, r.URL)
					}
					return response(tc.status, fmt.Sprintf(`{"error":{"code":%s,"errors":[{"reason":"conditionNotMet"}]}}`, tc.code)), nil
				})
				var got contract.WriteResult
				if method == "create" {
					got = s.Create(context.Background(), childKey(s), []byte("candidate"))
				} else {
					got = s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "42"}, []byte("candidate"))
				}
				if got.Status != tc.want || got.Reason != tc.wantReason {
					t.Fatalf("got %+v, want status %v reason %v", got, tc.want, tc.wantReason)
				}
				if calls != 1 || creds.calls != 1 {
					t.Fatalf("sends=%d credential resolutions=%d", calls, creds.calls)
				}
			})
		}
	}
}

// full_only: false
func TestMediaErrorPreservesPhysicalStatus(t *testing.T) {
	for _, tc := range []struct {
		status, code int
		want         contract.ReadStatus
		wantReason   contract.Reason
	}{
		{503, 412, contract.ReadUnavailable, contract.ReasonTransport},
		{503, 403, contract.ReadUnavailable, contract.ReasonTransport},
		{503, 404, contract.ReadUnavailable, contract.ReasonTransport},
		{403, 404, contract.ReadUnavailable, contract.ReasonAccess},
		{404, 503, contract.ReadInvalid, contract.ReasonMalformed},
	} {
		t.Run(fmt.Sprintf("HTTP %d body %d", tc.status, tc.code), func(t *testing.T) {
			calls := 0
			s, _ := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Query().Get("alt") != "media" {
					t.Fatalf("read request: %s %s", r.Method, r.URL)
				}
				return response(tc.status, fmt.Sprintf(`{"error":{"code":%d,"errors":[{"reason":"conditionNotMet"}]}}`, tc.code)), nil
			})
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 64)
			if got.Status != tc.want || got.Reason != tc.wantReason || calls != 1 {
				t.Fatalf("result=%+v sends=%d", got, calls)
			}
		})
	}
}

// full_only: false
func TestIncompleteWriteErrorCannotProveRejection(t *testing.T) {
	for _, status := range []int{403, 404, 412} {
		for _, unknownLength := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTP %d unknown length %t", status, unknownLength), func(t *testing.T) {
				calls := 0
				s, _ := newStore(t, func(*http.Request) (*http.Response, error) {
					calls++
					body := fmt.Sprintf(`{"error":{"code":%d,"errors":[{"reason":"conditionNotMet"}]}}`, status)
					out := response(status, body)
					out.ContentLength++
					if unknownLength {
						out.ContentLength = -1
						out.Body = io.NopCloser(&interruptedBody{body: body})
					}
					return out, nil
				})
				got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "42"}, []byte("candidate"))
				if got.Status != contract.WriteUnknown || got.Reason != contract.ReasonTransport || calls != 1 {
					t.Fatalf("result=%+v sends=%d", got, calls)
				}
			})
		}
	}
}

// full_only: false
func TestReadSeparatesExcessBytesFromUnavailableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name          string
		body          string
		contentLength int64
		interrupted   bool
		want          contract.ReadStatus
		wantReason    contract.Reason
	}{
		{"complete exact", "body", 4, false, contract.ReadOK, contract.ReasonNone},
		{"complete exact unknown length", "body", -1, false, contract.ReadOK, contract.ReasonNone},
		{"complete plus one", "12345", 5, false, contract.ReadInvalid, contract.ReasonMalformed},
		{"complete plus many", "12345678901234567890", 20, false, contract.ReadInvalid, contract.ReasonMalformed},
		{"complete plus one unknown length", "12345", -1, false, contract.ReadInvalid, contract.ReasonMalformed},
		{"complete plus many unknown length", "12345678901234567890", -1, false, contract.ReadInvalid, contract.ReasonMalformed},
		{"short advertised body", "bad", 20, false, contract.ReadUnavailable, contract.ReasonTransport},
		{"interrupted body", "bad", 20, true, contract.ReadUnavailable, contract.ReasonTransport},
		{"interrupted unknown length", "bad", -1, true, contract.ReadUnavailable, contract.ReasonTransport},
		{"interrupted with excess bytes", "12345", 20, true, contract.ReadUnavailable, contract.ReasonTransport},
		{"interrupted excess unknown length", "12345", -1, true, contract.ReadUnavailable, contract.ReasonTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, _ := newStore(t, func(*http.Request) (*http.Response, error) {
				calls++
				out := response(200, tc.body)
				out.ContentLength = tc.contentLength
				out.Header.Set("X-Goog-Generation", "42")
				if tc.interrupted {
					out.Body = io.NopCloser(&interruptedBody{body: tc.body})
				}
				return out, nil
			})
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 4)
			if got.Status != tc.want || got.Reason != tc.wantReason || calls != 1 {
				t.Fatalf("result=%+v sends=%d", got, calls)
			}
			if tc.want != contract.ReadOK && (len(got.Body) != 0 || got.Token != (contract.Token{})) {
				t.Fatalf("failed read returned bytes or token: %+v", got)
			}
		})
	}
}

// full_only: false
func TestImmutableCollisionReadUsesPlannedLength(t *testing.T) {
	planned := []byte("planned immutable bytes")
	for _, extra := range []int{0, 1, 128} {
		for _, unknownLength := range []bool{false, true} {
			t.Run(fmt.Sprintf("extra %d unknown length %t", extra, unknownLength), func(t *testing.T) {
				calls := 0
				var s *Store
				s, _ = newStore(t, func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						if r.Method != "POST" || r.URL.Query().Get("ifGenerationMatch") != "0" {
							t.Fatalf("create request: %s %s", r.Method, r.URL)
						}
						return apiFailure(412, "conditionNotMet"), nil
					}
					if calls != 2 || r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/o/"+childKey(s)) || r.URL.Query().Get("alt") != "media" {
						t.Fatalf("readback request: %s %s", r.Method, r.URL)
					}
					out := response(200, string(planned)+strings.Repeat("x", extra))
					out.Header.Set("X-Goog-Generation", "42")
					if unknownLength {
						out.ContentLength = -1
					}
					return out, nil
				})
				if got := s.Create(context.Background(), childKey(s), planned); got.Status != contract.WritePrecondition {
					t.Fatal(got)
				}
				got := s.Read(context.Background(), childKey(s), uint32(len(planned)))
				if extra == 0 {
					if got.Status != contract.ReadOK || string(got.Body) != string(planned) {
						t.Fatal(got)
					}
				} else if got.Status != contract.ReadInvalid || got.Reason != contract.ReasonMalformed {
					t.Fatal(got)
				}
				if calls != 2 {
					t.Fatalf("sends=%d", calls)
				}
			})
		}
	}
}

// full_only: false
func TestRetainedResultObjectsUseBoundedCreateOnlyPaths(t *testing.T) {
	// ResultCore, payload and transfer add 991 bytes to the 65,536-byte raw limit.
	const maxResultLength = contract.GeneratedResultRecordMaxLength
	body := bytes.Repeat([]byte{'r'}, maxResultLength)
	var key string
	calls := 0
	s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method == http.MethodPost {
			if r.URL.Query().Get("ifGenerationMatch") != "0" {
				t.Fatal("result create lost its absent condition")
			}
			_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				t.Fatal(err)
			}
			reader := multipart.NewReader(r.Body, params["boundary"])
			metadata, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.NewDecoder(metadata).Decode(&fields); err != nil || fields["name"] != key {
				t.Fatal("result create target differs", err)
			}
			media, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(media)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("result create body differs", err)
			}
			return response(200, fmt.Sprintf(`{"bucket":"fixture-bucket","name":%q,"generation":"24","size":%q,"crc32c":%q}`, key, strconv.Itoa(len(body)), crcBase64(body))), nil
		}
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/o/"+key) {
			t.Fatal("result read target differs", r.Method, r.URL.Path)
		}
		reply := response(200, string(body))
		reply.Header.Set("X-Goog-Generation", "24")
		return reply, nil
	})
	coordinate := contract.Hash([]byte("accepted result coordinate"))
	var err error
	key, err = format.GeneratedResultKey(s.config.Prefix, s.config.Domain, coordinate)
	if err != nil || key != fmt.Sprintf("%s/%x/result/%x", s.config.Prefix, s.config.Domain, coordinate) {
		t.Fatal("result coordinate", err)
	}
	if got := s.Create(context.Background(), key, body); got.Status != contract.WriteAcknowledged {
		t.Fatal("result create", got)
	}
	if got := s.Read(context.Background(), key, uint32(maxResultLength)); got.Status != contract.ReadOK || !bytes.Equal(got.Body, body) {
		t.Fatal("result read", got.Status, got.Reason)
	}
	beforeCredentials := creds.calls
	for _, bad := range []string{
		"foreign/" + key,
		strings.Replace(key, fmt.Sprintf("%x", s.config.Domain), strings.Repeat("1", 64), 1),
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
	if got := s.CompareAndSwap(context.Background(), key, contract.Token{Family: contract.GCP, Value: "24"}, body); got.Status != contract.WriteRefused {
		t.Fatal("result coordinate admitted mutable replacement", got)
	}
	if calls != 2 || creds.calls != beforeCredentials {
		t.Fatal("refused result request reached credentials or HTTP", calls, creds.calls, beforeCredentials)
	}
}
