package awsprovider

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// full_only: false
func TestStoreListPageUsesExactScope(t *testing.T) {
	c := testStoreConfig()
	prefix := c.Prefix + "/" + hex.EncodeToString(c.Domain[:]) + "/"
	key := prefix + "foreign+name%2Fpart"
	calls := 0
	s, err := newStore(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/"+c.Bucket || r.URL.Host != "s3."+c.Region+".amazonaws.com" ||
			q.Get("list-type") != "2" || q.Get("prefix") != prefix || q.Get("max-keys") != "256" || q.Get("encoding-type") != "url" || q.Get("continuation-token") != "old+cursor" ||
			q.Get("delimiter") != "" || q.Get("fetch-owner") != "" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != c.ExpectedBucketOwner {
			t.Fatalf("unexpected bounded list request: %s %s", r.Method, r.URL)
		}
		body := fmt.Sprintf(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><Prefix>%s</Prefix><KeyCount>1</KeyCount><MaxKeys>256</MaxKeys><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated><ContinuationToken>old+cursor</ContinuationToken><NextContinuationToken>next+cursor</NextContinuationToken><Contents><Key>%s</Key><Size>3</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`, c.Bucket, url.PathEscape(prefix), url.PathEscape(key))
		return response(http.StatusOK, body, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	lister, ok := any(s).(contract.BoundedEnumerationStore)
	if !ok {
		t.Fatal("Store has no bounded enumeration capability")
	}
	got := lister.ListPage(context.Background(), "old+cursor")
	if got.Status != contract.ListPageOK || got.Reason != contract.ReasonNone || !reflect.DeepEqual(got.Keys, []string{key}) || got.NextCursor != "next+cursor" || calls != 1 {
		t.Fatalf("page=%+v calls=%d", got, calls)
	}
}

func listReply(c StoreConfig, keys []string, cursor, next string) string {
	prefix := c.Prefix + "/" + hex.EncodeToString(c.Domain[:]) + "/"
	var body strings.Builder
	fmt.Fprintf(&body, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>256</MaxKeys><EncodingType>url</EncodingType><IsTruncated>%t</IsTruncated>`, c.Bucket, url.PathEscape(prefix), len(keys), next != "")
	if cursor != "" {
		fmt.Fprintf(&body, "<ContinuationToken>%s</ContinuationToken>", html.EscapeString(cursor))
	}
	if next != "" {
		fmt.Fprintf(&body, "<NextContinuationToken>%s</NextContinuationToken>", html.EscapeString(next))
	}
	for _, key := range keys {
		fmt.Fprintf(&body, "<Contents><Key>%s</Key></Contents>", url.PathEscape(key))
	}
	body.WriteString("</ListBucketResult>")
	return body.String()
}

// full_only: false
func TestStoreListPageAcceptsCompleteBoundedPages(t *testing.T) {
	c := testStoreConfig()
	prefix := c.Prefix + "/" + hex.EncodeToString(c.Domain[:]) + "/"
	maximum := make([]string, 256)
	for i := range maximum {
		start := prefix + strconv.Itoa(i) + "/"
		maximum[i] = start + strings.Repeat("k", 1024-len(start))
	}
	for _, tc := range []struct {
		name, cursor, next, declaration string
		keys                            []string
	}{
		{name: "empty"},
		{name: "empty-continuation", next: "next"},
		{name: "short-continuation", keys: []string{prefix + "foreign"}, next: "next"},
		{name: "maximum", keys: maximum, cursor: strings.Repeat("c", 4096), next: strings.Repeat("n", 4096)},
		{name: "utf8-and-escaped-identities", keys: []string{prefix + "é", prefix + "e\u0301", prefix + "+%2B%2F"}},
		{name: "utf8-bom", declaration: "\xef\xbb\xbf", keys: []string{prefix + "key"}},
		{name: "utf8-bom-declaration", declaration: "\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"UTF-8\"?>", keys: []string{prefix + "key"}},
		{name: "key-feff", keys: []string{prefix + "before\ufeffafter"}},
		{name: "declaration", declaration: `<?xml version="1.0" encoding="UTF-8"?>`, keys: []string{prefix + "key"}},
		{name: "single-quoted-declaration", declaration: "<?xml version='1.0' encoding='utf-8' standalone='yes'?>", keys: []string{prefix + "key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, err := newStore(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Query().Get("continuation-token") != tc.cursor {
					t.Fatal("cursor changed")
				}
				return response(200, tc.declaration+listReply(c, tc.keys, tc.cursor, tc.next), nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.ListPage(context.Background(), tc.cursor)
			if got.Status != contract.ListPageOK || got.Reason != contract.ReasonNone || len(got.Keys) != len(tc.keys) || got.NextCursor != tc.next || calls != 1 {
				t.Fatalf("page status=%d reason=%d keys=%d next=%d calls=%d", got.Status, got.Reason, len(got.Keys), len(got.NextCursor), calls)
			}
			for i, key := range got.Keys {
				if key != tc.keys[i] {
					t.Fatalf("key %d changed", i)
				}
			}
		})
	}
}

// full_only: false
func TestStoreListPageRejectsMalformedOrExcessResponse(t *testing.T) {
	c := testStoreConfig()
	prefix := c.Prefix + "/" + hex.EncodeToString(c.Domain[:]) + "/"
	valid := listReply(c, []string{prefix + "key"}, "", "")
	cases := []struct {
		name, body string
		limit      bool
	}{
		{"empty", "", false},
		{"truncated", strings.TrimSuffix(valid, "</ListBucketResult>"), false},
		{"trailing", valid + "<Other/>", false},
		{"trailing-text", valid + "garbage", false},
		{"duplicate-prolog-bom", "\xef\xbb\xbf\xef\xbb\xbf" + valid, false},
		{"bom-after-whitespace", " \n\xef\xbb\xbf" + valid, false},
		{"bom-after-declaration", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\xef\xbb\xbf" + valid, false},
		{"malformed-declaration", "<?xml garbage?>" + valid, false},
		{"duplicate-declaration", `<?xml version="1.0"?><?xml version="1.0"?>` + valid, false},
		{"late-declaration", " \n<?xml version=\"1.0\"?>" + valid, false},
		{"body-declaration", strings.Replace(valid, "<Contents>", `<?xml version="1.0"?><Contents>`, 1), false},
		{"wrong-bucket", strings.Replace(valid, c.Bucket, "another-bucket", 1), false},
		{"wrong-prefix", strings.Replace(valid, url.PathEscape(prefix), "foreign%2F", 1), false},
		{"wrong-key-scope", listReply(c, []string{"foreign/key"}, "", ""), false},
		{"wrong-encoding", strings.Replace(valid, "<EncodingType>url", "<EncodingType>plain", 1), false},
		{"wrong-count", strings.Replace(valid, "<KeyCount>1", "<KeyCount>2", 1), false},
		{"wrong-maximum", strings.Replace(valid, "<MaxKeys>256", "<MaxKeys>1000", 1), false},
		{"missing-required", strings.Replace(valid, "<KeyCount>1</KeyCount>", "", 1), false},
		{"duplicate-field", strings.Replace(valid, "<KeyCount>1</KeyCount>", "<KeyCount>1</KeyCount><KeyCount>1</KeyCount>", 1), false},
		{"foreign-namespace-field", strings.Replace(valid, "<KeyCount>1</KeyCount>", `<x:KeyCount xmlns:x="urn:foreign">1</x:KeyCount>`, 1), false},
		{"duplicate-key-field", strings.Replace(valid, "</Key>", "</Key><Key>another</Key>", 1), false},
		{"duplicate-key", listReply(c, []string{prefix + "key", prefix + "key"}, "", ""), false},
		{"missing-key", strings.Replace(valid, "<Key>"+url.PathEscape(prefix+"key")+"</Key>", "", 1), false},
		{"unknown-field", strings.Replace(valid, "<Contents>", "<Unexpected/><Contents>", 1), false},
		{"nested-key", strings.Replace(valid, "</Key>", "<Unexpected/></Key>", 1), false},
		{"bad-escape", strings.Replace(valid, url.PathEscape(prefix+"key"), url.PathEscape(prefix)+"bad%XX", 1), false},
		{"escaped-invalid-utf8", strings.Replace(valid, url.PathEscape(prefix+"key"), url.PathEscape(prefix)+"bad%FF", 1), false},
		{"invalid-utf8", strings.Replace(valid, "key</Key>", "\xff</Key>", 1), false},
		{"unexpected-cursor-echo", strings.Replace(valid, "</Name>", "</Name><ContinuationToken>other</ContinuationToken>", 1), false},
		{"missing-next", strings.Replace(valid, "<IsTruncated>false", "<IsTruncated>true", 1), false},
		{"unexpected-next", strings.Replace(valid, "</Name>", "</Name><NextContinuationToken>next</NextContinuationToken>", 1), false},
		{"long-key", listReply(c, []string{prefix + strings.Repeat("k", 1025-len(prefix))}, "", ""), true},
		{"long-cursor", listReply(c, nil, "", strings.Repeat("n", 4097)), true},
		{"entry-overflow", listReply(c, func() []string {
			keys := make([]string, 257)
			for i := range keys {
				keys[i] = prefix + strconv.Itoa(i)
			}
			return keys
		}(), "", ""), true},
		{"body-overflow", strings.Repeat(" ", contract.StoreListResponseBytes+1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var observed *countedBody
			s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				out := response(200, tc.body, nil)
				observed = &countedBody{ReadCloser: out.Body}
				out.Body = observed
				return out, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.ListPage(context.Background(), "")
			wantReason := contract.ReasonMalformed
			if tc.limit {
				wantReason = contract.ReasonLimit
			}
			if got.Status != contract.ListPageInvalid || got.Reason != wantReason || got.Keys != nil || got.NextCursor != "" || calls != 1 || observed == nil || !observed.closed || observed.bytes > contract.StoreListResponseBytes+1 {
				t.Fatalf("response admitted or partial page returned: status=%d reason=%d keys=%d calls=%d", got.Status, got.Reason, len(got.Keys), calls)
			}
		})
	}
}

// full_only: false
func TestStoreListPageBoundsInputsAndNeverRetries(t *testing.T) {
	for _, mode := range []string{"oversized-cursor", "invalid-cursor", "canceled", "lost-reply", "denied", "redirect", "error-overflow"} {
		t.Run(mode, func(t *testing.T) {
			c := testStoreConfig()
			credentials, calls := 0, 0
			source := c.Credentials
			c.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) { credentials++; return source.Retrieve(ctx) })
			s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				switch mode {
				case "denied":
					return response(403, "<Error><Code>AccessDenied</Code></Error>", nil), nil
				case "redirect":
					return response(302, "", http.Header{"Location": {"https://foreign.invalid/bucket"}}), nil
				case "error-overflow":
					return response(500, strings.Repeat("e", maxErrorResponse+1), nil), nil
				}
				return nil, errors.New("reply lost")
			}))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cursor := ""
			if mode == "canceled" {
				cancel()
			}
			if mode == "oversized-cursor" {
				cursor = strings.Repeat("c", 4097)
			}
			if mode == "invalid-cursor" {
				cursor = "\xff"
			}
			got := s.ListPage(ctx, cursor)
			wantCalls := 1
			if mode == "oversized-cursor" || mode == "invalid-cursor" || mode == "canceled" {
				wantCalls = 0
			}
			if got.Status == contract.ListPageOK || got.Keys != nil || got.NextCursor != "" || calls != wantCalls || credentials != wantCalls || mode == "denied" && got.Reason != contract.ReasonAccess {
				t.Fatalf("page=%+v calls=%d credentials=%d", got, calls, credentials)
			}
		})
	}
}

// full_only: false
func TestStoreListPageAcceptsOptionalObjectMetadataAndExactBodyLimit(t *testing.T) {
	c := testStoreConfig()
	prefix := c.Prefix + "/" + hex.EncodeToString(c.Domain[:]) + "/"
	body := listReply(c, []string{prefix + "key"}, "", "")
	body = strings.Replace(body, "</Contents>", `<LastModified>2026-10-24T00:00:00.000Z</LastModified><ETag>&quot;tag&quot;</ETag><Size>8</Size><StorageClass>STANDARD</StorageClass><ChecksumAlgorithm>CRC32</ChecksumAlgorithm><ChecksumAlgorithm>SHA256</ChecksumAlgorithm><ChecksumType>FULL_OBJECT</ChecksumType><Owner><ID>owner</ID><DisplayName>display</DisplayName></Owner><RestoreStatus><IsRestoreInProgress>false</IsRestoreInProgress><RestoreExpiryDate>2026-10-25T00:00:00.000Z</RestoreExpiryDate></RestoreStatus></Contents>`, 1)
	body += strings.Repeat(" ", contract.StoreListResponseBytes-len(body))
	s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, body, nil), nil }))
	if err != nil {
		t.Fatal(err)
	}
	got := s.ListPage(context.Background(), "")
	if got.Status != contract.ListPageOK || !reflect.DeepEqual(got.Keys, []string{prefix + "key"}) {
		t.Fatal("bounded optional metadata refused", got.Status, got.Reason)
	}
	if got := s.Read(context.Background(), prefix+"foreign", 1); got.Status != contract.ReadInvalid {
		t.Fatal("listing broadened object read reach")
	}
}
