package awsprovider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// full_only: false
func TestAdministrativeIndexStorePaths(t *testing.T) {
	for _, index := range []int{0, 255} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			key := testImmutableKey("admin-index", index)
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/fixture-bucket/"+key {
					t.Fatal("administrative index route differs", r.URL.Path)
				}
				switch r.Method {
				case http.MethodPut:
					return response(http.StatusOK, "", nil), nil
				case http.MethodGet:
					return response(http.StatusOK, "index", http.Header{"Etag": []string{`"index"`}}), nil
				case http.MethodDelete:
					if r.Header.Get("If-Match") != `"index"` {
						t.Fatal("administrative index delete lost observed ETag")
					}
					return response(http.StatusNoContent, "", nil), nil
				default:
					t.Fatal("unexpected administrative index method", r.Method)
					return nil, nil
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Create(context.Background(), key, []byte("index")); got.Status != contract.WriteAcknowledged {
				t.Fatal("administrative index create", got)
			}
			if got := s.Read(context.Background(), key, 5); got.Status != contract.ReadOK || string(got.Body) != "index" || got.Token.Value != `"index"` {
				t.Fatal("administrative index read", got)
			}
			if got := s.DeleteIfToken(context.Background(), key, contract.Token{Family: contract.AWS, Value: `"index"`}); got.Status != contract.WriteAcknowledged {
				t.Fatal("administrative index delete", got)
			}
			if got := s.Read(context.Background(), key, contract.MaxRequiredSupportPageLength+1); got.Status != contract.ReadInvalid {
				t.Fatal("oversize administrative index read accepted", got)
			}
			if got := s.Create(context.Background(), key, make([]byte, contract.MaxRequiredSupportPageLength+1)); got.Status != contract.WriteRefused {
				t.Fatal("oversize administrative index create accepted", got)
			}
			for _, badIndex := range []string{"256", "00", "-1"} {
				bad := strings.Replace(key, fmt.Sprintf("/admin-index/%d/", index), "/admin-index/"+badIndex+"/", 1)
				if got := s.Read(context.Background(), bad, 1); got.Status != contract.ReadInvalid {
					t.Fatal("malformed administrative index read accepted", bad, got)
				}
				if got := s.Create(context.Background(), bad, []byte("index")); got.Status != contract.WriteRefused {
					t.Fatal("malformed administrative index create accepted", bad, got)
				}
				if got := s.DeleteIfToken(context.Background(), bad, contract.Token{Family: contract.AWS, Value: `"index"`}); got.Status != contract.WriteRefused {
					t.Fatal("malformed administrative index delete accepted", bad, got)
				}
			}
			if calls != 3 {
				t.Fatal("refused administrative index path reached HTTP", calls)
			}
		})
	}
}

// full_only: false
func TestFirstFlowCurrentAccessKeys(t *testing.T) {
	c := testStoreConfig()
	for _, kind := range []string{"access", "support", "admin-index"} {
		for _, index := range []int{-1, 0, 31, 32, 255, 256} {
			want := 0
			if index >= 0 && index < contract.MaxChildPages {
				want = contract.MaxRequiredSupportPageLength
			}
			if got := keyLimit(c.Prefix, c.Domain, testImmutableKey(kind, index)); got != want {
				t.Fatalf("%s index %d limit=%d want=%d", kind, index, got, want)
			}
		}
	}
	for _, kind := range []string{"seed", "retained"} {
		if keyLimit(c.Prefix, c.Domain, testImmutableKey(kind, 0)) != 0 {
			t.Fatal("future object kind admitted", kind)
		}
	}
}

// full_only: false
func TestStoreConfigurationKeyIsLimitedToSelectedDomain(t *testing.T) {
	c := testStoreConfig()
	key, err := contract.StoreConfigurationKey(storeConfiguration(c))
	if err != nil {
		t.Fatal(err)
	}
	if got := keyLimit(c.Prefix, c.Domain, key); got != contract.MaxStoreConfigurationLength {
		t.Fatalf("helper key limit=%d", got)
	}
	for _, bad := range []string{
		strings.Replace(key, "/configuration/", "/unknown/", 1),
		strings.Replace(key, "/configuration/", "/configuration/0/", 1),
		strings.ToUpper(key),
		strings.Replace(key, "/"+fmt.Sprintf("%x", c.Domain)+"/", "/"+strings.Repeat("1", 64)+"/", 1),
		key[:len(key)-64] + strings.Repeat("0", 64),
		key[:len(key)-1],
		key + "/extra",
	} {
		if got := keyLimit(c.Prefix, c.Domain, bad); got != 0 {
			t.Fatalf("unselected helper key accepted: %q limit=%d", bad, got)
		}
	}
}

// full_only: false
func TestStoreConfigurationUsesBoundedImmutableIO(t *testing.T) {
	for _, size := range []int{1, contract.MaxStoreConfigurationLength} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			c := testStoreConfig()
			key, err := contract.StoreConfigurationKey(storeConfiguration(c))
			if err != nil {
				t.Fatal(err)
			}
			body := strings.Repeat("c", size)
			calls, credentialCalls := 0, 0
			credentials := c.Credentials
			c.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				credentialCalls++
				return credentials.Retrieve(ctx)
			})
			s, err := newStore(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/fixture-bucket/"+key || r.Header.Get("X-Amz-Expected-Bucket-Owner") != c.ExpectedBucketOwner {
					t.Fatal("configuration request lost target or owner guard")
				}
				switch r.Method {
				case http.MethodPut:
					got, err := io.ReadAll(r.Body)
					if err != nil || string(got) != body || r.ContentLength != int64(size) || r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "" {
						t.Fatal("configuration create lost immutable condition or body")
					}
					return response(http.StatusOK, "", nil), nil
				case http.MethodGet:
					return response(http.StatusOK, body, http.Header{"Etag": []string{`"configuration"`}}), nil
				default:
					t.Fatal("unexpected configuration method", r.Method)
					return nil, nil
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Create(context.Background(), key, []byte(body)); got.Status != contract.WriteAcknowledged {
				t.Fatal("configuration create", got)
			}
			if got := s.Read(context.Background(), key, uint32(size)); got.Status != contract.ReadOK || string(got.Body) != body || got.Token.Value != `"configuration"` {
				t.Fatal("configuration read", got.Status, got.Reason)
			}
			if got := s.Read(context.Background(), key, contract.MaxStoreConfigurationLength+1); got.Status != contract.ReadInvalid {
				t.Fatal("oversized configuration read accepted", got)
			}
			if got := s.Create(context.Background(), key, make([]byte, contract.MaxStoreConfigurationLength+1)); got.Status != contract.WriteRefused {
				t.Fatal("oversized configuration create accepted", got)
			}
			if got := s.CompareAndSwap(context.Background(), key, contract.Token{Family: contract.AWS, Value: `"configuration"`}, []byte(body)); got.Status != contract.WriteRefused {
				t.Fatal("mutable configuration write accepted", got)
			}
			if calls != 2 || credentialCalls != 2 {
				t.Fatal("refused configuration operation entered credentials or HTTP", calls, credentialCalls)
			}
		})
	}
}
