package gcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestStoreListPageUsesExactScope(t *testing.T) {
	var prefix, key string
	calls := 0
	s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
		calls++
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/storage/v1/b/fixture-bucket/o" || r.URL.Host != "storage.us-central1.rep.googleapis.com" ||
			q.Get("prefix") != prefix || q.Get("maxResults") != "256" || q.Get("pageToken") != "old+cursor" || q.Get("fields") != "items(name),nextPageToken" ||
			q.Get("delimiter") != "" || q.Get("versions") != "" || q.Get("softDeleted") != "" || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Fatalf("unexpected bounded list request: %s %s", r.Method, r.URL)
		}
		return response(http.StatusOK, fmt.Sprintf(`{"items":[{"name":%q}],"nextPageToken":"next+cursor"}`, key)), nil
	})
	prefix = s.config.Prefix + "/" + hex.EncodeToString(s.config.Domain[:]) + "/"
	key = prefix + "foreign+name%2Fpart"
	lister, ok := any(s).(contract.BoundedEnumerationStore)
	if !ok {
		t.Fatal("Store has no bounded enumeration capability")
	}
	got := lister.ListPage(context.Background(), "old+cursor")
	if got.Status != contract.ListPageOK || got.Reason != contract.ReasonNone || !reflect.DeepEqual(got.Keys, []string{key}) || got.NextCursor != "next+cursor" || calls != 1 || creds.calls != 1 {
		t.Fatalf("page=%+v calls=%d credentials=%d", got, calls, creds.calls)
	}
}

func listReply(keys []string, next string) string {
	var body strings.Builder
	body.WriteString(`{"items":[`)
	for i, key := range keys {
		if i != 0 {
			body.WriteByte(',')
		}
		encoded, _ := json.Marshal(key)
		body.WriteString(`{"name":`)
		body.Write(encoded)
		body.WriteByte('}')
	}
	body.WriteByte(']')
	if next != "" {
		encoded, _ := json.Marshal(next)
		body.WriteString(`,"nextPageToken":`)
		body.Write(encoded)
	}
	body.WriteByte('}')
	return body.String()
}

// full_only: false
func TestStoreListPageAcceptsCompleteBoundedPages(t *testing.T) {
	for _, mode := range []string{"empty", "empty-object", "empty-continuation", "short-continuation", "maximum", "utf8-and-escaped-identities", "surrogate-pair", "body-limit"} {
		t.Run(mode, func(t *testing.T) {
			var body, prefix string
			calls := 0
			cursor, next := "", ""
			s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Query().Get("pageToken") != cursor {
					t.Fatal("cursor changed")
				}
				return response(200, body), nil
			})
			prefix = s.config.Prefix + "/" + hex.EncodeToString(s.config.Domain[:]) + "/"
			var keys []string
			switch mode {
			case "empty-continuation":
				next = "next"
			case "short-continuation":
				keys, next = []string{prefix + "foreign"}, "next"
			case "maximum":
				keys = make([]string, 256)
				for i := range keys {
					start := prefix + strconv.Itoa(i) + "/"
					keys[i] = start + strings.Repeat("k", 1024-len(start))
				}
				cursor, next = strings.Repeat("c", 4096), strings.Repeat("n", 4096)
			case "utf8-and-escaped-identities":
				keys = []string{prefix + "é", prefix + "e\u0301", prefix + "+%2B%2F"}
			case "surrogate-pair":
				keys = []string{prefix + "😀"}
			}
			body = listReply(keys, next)
			if mode == "empty-object" {
				body = `{}`
			}
			if mode == "surrogate-pair" {
				body = strings.Replace(body, "😀", `\ud83d\ude00`, 1)
			}
			if mode == "body-limit" {
				body += strings.Repeat(" ", contract.StoreListResponseBytes-len(body))
			}
			got := s.ListPage(context.Background(), cursor)
			if got.Status != contract.ListPageOK || got.Reason != contract.ReasonNone || len(got.Keys) != len(keys) || got.NextCursor != next || calls != 1 || creds.calls != 1 {
				t.Fatalf("page status=%d reason=%d keys=%d next=%d calls=%d credentials=%d", got.Status, got.Reason, len(got.Keys), len(got.NextCursor), calls, creds.calls)
			}
			for i, key := range keys {
				if got.Keys[i] != key {
					t.Fatalf("key %d changed", i)
				}
			}
		})
	}
}

type listCountedBody struct {
	io.ReadCloser
	bytes  int
	closed bool
}

func (b *listCountedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes += n
	return n, err
}
func (b *listCountedBody) Close() error { b.closed = true; return b.ReadCloser.Close() }

// full_only: false
func TestStoreListPageRejectsMalformedOrExcessResponse(t *testing.T) {
	prefix := "fixture/" + fmt.Sprintf("%x", contract.Hash([]byte("domain"))) + "/"
	valid := listReply([]string{prefix + "key"}, "")
	maximumPlusOne := make([]string, 257)
	for i := range maximumPlusOne {
		maximumPlusOne[i] = prefix + strconv.Itoa(i)
	}
	for _, tc := range []struct {
		name, body string
		limit      bool
	}{
		{"empty", "", false},
		{"truncated", strings.TrimSuffix(valid, "}"), false},
		{"trailing", valid + `{}`, false},
		{"trailing-text", valid + "garbage", false},
		{"duplicate-items", `{"items":[],"items":[]}`, false},
		{"duplicate-cursor", `{"nextPageToken":"one","nextPageToken":"two"}`, false},
		{"escaped-duplicate-field", `{"items":[],"\u0069tems":[]}`, false},
		{"null-cursor", `{"nextPageToken":null}`, false},
		{"number-cursor", `{"nextPageToken":12}`, false},
		{"null-items", `{"items":null}`, false},
		{"wrong-items-shape", `{"items":{}}`, false},
		{"unknown-field", `{"unexpected":[]}`, false},
		{"unknown-item-field", strings.Replace(valid, `"name":`, `"kind":"object","name":`, 1), false},
		{"duplicate-name", strings.Replace(valid, `"name":`, `"name":"other","name":`, 1), false},
		{"missing-name", `{"items":[{}]}`, false},
		{"null-name", `{"items":[{"name":null}]}`, false},
		{"duplicate-key", listReply([]string{prefix + "key", prefix + "key"}, ""), false},
		{"foreign-key", listReply([]string{"foreign/key"}, ""), false},
		{"invalid-utf8", strings.Replace(valid, "key", "\xff", 1), false},
		{"unpaired-high-surrogate", strings.Replace(valid, "key", `\ud800`, 1), false},
		{"unpaired-low-surrogate", strings.Replace(valid, "key", `\udc00`, 1), false},
		{"invalid-surrogate-pair", strings.Replace(valid, "key", `\ud800\u0061`, 1), false},
		{"long-key", listReply([]string{prefix + strings.Repeat("k", 1025-len(prefix))}, ""), true},
		{"long-cursor", listReply(nil, strings.Repeat("n", 4097)), true},
		{"entry-overflow", listReply(maximumPlusOne, ""), true},
		{"body-overflow", strings.Repeat(" ", contract.StoreListResponseBytes+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var observed *listCountedBody
			s, _ := newStore(t, func(*http.Request) (*http.Response, error) {
				calls++
				out := response(200, tc.body)
				observed = &listCountedBody{ReadCloser: out.Body}
				out.Body = observed
				return out, nil
			})
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
			calls := 0
			s, creds := newStore(t, func(*http.Request) (*http.Response, error) {
				calls++
				switch mode {
				case "denied":
					return response(403, `{"error":{"code":403}}`), nil
				case "redirect":
					out := response(302, "")
					out.Header.Set("Location", "https://foreign.invalid/bucket")
					return out, nil
				case "error-overflow":
					return response(500, strings.Repeat("e", maxJSON+1)), nil
				}
				return nil, errors.New("reply lost")
			})
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
			if got.Status == contract.ListPageOK || got.Keys != nil || got.NextCursor != "" || calls != wantCalls || creds.calls != wantCalls || mode == "denied" && got.Reason != contract.ReasonAccess {
				t.Fatalf("page=%+v calls=%d credentials=%d", got, calls, creds.calls)
			}
		})
	}
}
