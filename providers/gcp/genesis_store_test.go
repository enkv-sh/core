package gcp

import (
	"context"
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
)

// full_only: false
func TestFirstFlowCurrentAccessKeys(t *testing.T) {
	s := &Store{config: config(nil)}
	for _, kind := range []struct {
		name  string
		limit int
	}{{"access", contract.MaxAccessPageLength}, {"support", contract.MaxRequiredSupportPageLength}, {"admin-index", contract.MaxRequiredSupportPageLength}} {
		for _, index := range []int{0, 31, 32, 255, 256} {
			key := strings.Replace(childKey(s), "/member/0/", fmt.Sprintf("/%s/%d/", kind.name, index), 1)
			want := 0
			if index < 256 {
				want = kind.limit
			}
			if got := s.keyLimit(key); got != want {
				t.Fatalf("%s index %d limit=%d want=%d", kind.name, index, got, want)
			}
		}
	}
	for _, kind := range []string{"seed", "retained"} {
		key := strings.Replace(childKey(s), "/member/0/", "/"+kind+"/0/", 1)
		if s.keyLimit(key) != 0 {
			t.Fatal("future object kind admitted", kind)
		}
	}
}

// full_only: false
func TestStoreConfigurationKeyIsLimitedToSelectedDomain(t *testing.T) {
	s := &Store{config: config(nil)}
	key, err := contract.StoreConfigurationKey(storeConfiguration(s.config))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.keyLimit(key); got != contract.MaxStoreConfigurationLength {
		t.Fatalf("helper key limit=%d", got)
	}
	for _, bad := range []string{
		strings.Replace(key, "/configuration/", "/unknown/", 1),
		strings.Replace(key, "/configuration/", "/configuration/0/", 1),
		strings.ToUpper(key),
		strings.Replace(key, "/"+fmt.Sprintf("%x", s.config.Domain)+"/", "/"+strings.Repeat("1", 64)+"/", 1),
		key[:len(key)-64] + strings.Repeat("0", 64),
		key[:len(key)-1],
		key + "/extra",
	} {
		if got := s.keyLimit(bad); got != 0 {
			t.Fatalf("unselected helper key accepted: %q limit=%d", bad, got)
		}
	}
}

// full_only: false
func TestStoreConfigurationUsesBoundedImmutableIO(t *testing.T) {
	for _, size := range []int{1, contract.MaxStoreConfigurationLength} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := strings.Repeat("c", size)
			var key string
			calls := 0
			s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				switch r.Method {
				case http.MethodPost:
					if r.URL.Path != "/upload/storage/v1/b/fixture-bucket/o" || r.URL.Query().Get("ifGenerationMatch") != "0" || r.URL.Query().Get("uploadType") != "multipart" {
						t.Fatal("configuration create lost target or immutable condition")
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
					if err := json.NewDecoder(metadata).Decode(&fields); err != nil || fields["name"] != key || fields["cacheControl"] != "private, no-store, no-transform" {
						t.Fatal("configuration metadata differs", err)
					}
					media, err := reader.NextPart()
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(media)
					if err != nil || string(got) != body {
						t.Fatal("configuration media differs", err)
					}
					if _, err := reader.NextPart(); err != io.EOF {
						t.Fatal("extra configuration multipart data", err)
					}
					return response(http.StatusOK, fmt.Sprintf(`{"bucket":"fixture-bucket","name":%q,"generation":"24","size":%q,"crc32c":%q}`, key, strconv.Itoa(size), crcBase64([]byte(body)))), nil
				case http.MethodGet:
					if !strings.HasSuffix(r.URL.Path, "/o/"+key) {
						t.Fatal("configuration read target differs")
					}
					reply := response(http.StatusOK, body)
					reply.Header.Set("X-Goog-Generation", "24")
					return reply, nil
				default:
					t.Fatal("unexpected configuration method", r.Method)
					return nil, nil
				}
			})
			var err error
			key, err = contract.StoreConfigurationKey(s.StoreConfiguration())
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Create(context.Background(), key, []byte(body)); got.Status != contract.WriteAcknowledged {
				t.Fatal("configuration create", got)
			}
			if got := s.Read(context.Background(), key, uint32(size)); got.Status != contract.ReadOK || string(got.Body) != body || got.Token.Value != "24" {
				t.Fatal("configuration read", got.Status, got.Reason)
			}
			beforeCredentials := creds.calls
			if got := s.Read(context.Background(), key, contract.MaxStoreConfigurationLength+1); got.Status != contract.ReadInvalid {
				t.Fatal("oversized configuration read accepted", got)
			}
			if got := s.Create(context.Background(), key, make([]byte, contract.MaxStoreConfigurationLength+1)); got.Status != contract.WriteRefused {
				t.Fatal("oversized configuration create accepted", got)
			}
			if got := s.CompareAndSwap(context.Background(), key, contract.Token{Family: contract.GCP, Value: "24"}, []byte(body)); got.Status != contract.WriteRefused {
				t.Fatal("mutable configuration write accepted", got)
			}
			if calls != 2 || creds.calls != beforeCredentials {
				t.Fatal("refused configuration operation entered credentials or HTTP", calls, creds.calls, beforeCredentials)
			}
		})
	}
}
