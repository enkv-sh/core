package core

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
)

// full_only: false
func TestAWSPublicCleanupListsOnlyTheBoundPrefix(t *testing.T) {
	settings, _ := awsLiveTestSettings(t)
	domain := contract.Hash([]byte("domain"))
	credentials := &awsLiveTestCredentials{}
	requests := 0
	transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.Host != "s3.us-east-1.amazonaws.com" || r.URL.Path != "/fixture-bucket" ||
			q.Get("list-type") != "2" || q.Get("prefix") != "run/" || q.Get("max-keys") != "128" ||
			r.Header.Get("X-Amz-Expected-Bucket-Owner") != settings.Account || r.Header.Get("X-Amz-Security-Token") != "test-session" {
			t.Error("LIST escaped its bound bucket, owner, prefix, or credential")
		}
		continuation := q.Get("continuation-token")
		if requests == 1 && continuation != "" || requests == 2 && continuation != "next" || requests > 2 {
			t.Error("LIST changed the exact continuation sequence")
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		if requests == 1 {
			_, _ = fmt.Fprint(w, `<ListBucketResult><Name>fixture-bucket</Name><Prefix>run/</Prefix><MaxKeys>128</MaxKeys><KeyCount>1</KeyCount><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>run/HEAD</Key><Size>1</Size></Contents></ListBucketResult>`)
		} else {
			_, _ = fmt.Fprintf(w, `<ListBucketResult><Name>fixture-bucket</Name><Prefix>run/</Prefix><MaxKeys>128</MaxKeys><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><ContinuationToken>next</ContinuationToken><Contents><Key>run/%s/support/0/%s</Key><Size>1</Size></Contents></ListBucketResult>`,
				hex.EncodeToString(domain[:]), strings.Repeat("2", 64))
		}
	}))
	s := newAWSSetup(settings, "run", domain, nil, credentials, transport)
	first, err := s.listPrefix(context.Background(), "run/", "")
	if err != nil || len(first.Keys) != 1 || first.Keys[0] != "run/HEAD" || first.Next != "next" {
		t.Fatalf("first LIST result: %+v %v", first, err)
	}
	second, err := s.listPrefix(context.Background(), "run/", first.Next)
	if err != nil || len(second.Keys) != 1 || second.Next != "" || requests != 2 || credentials.calls.Load() != 2 {
		t.Fatalf("second LIST result: %+v %v requests=%d credentials=%s", second, err, requests, strconv.Itoa(int(credentials.calls.Load())))
	}
	if _, err := s.listPrefix(context.Background(), "foreign/", ""); err == nil || requests != 2 {
		t.Fatal("foreign prefix reached the provider")
	}
}

// full_only: false
func TestAWSPublicCleanupRefusesUnprovedListReplies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"foreign_key", http.StatusOK, `<ListBucketResult><Name>fixture-bucket</Name><Prefix>run/</Prefix><MaxKeys>128</MaxKeys><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>run/foreign</Key><Size>1</Size></Contents></ListBucketResult>`},
		{"zero_size", http.StatusOK, `<ListBucketResult><Name>fixture-bucket</Name><Prefix>run/</Prefix><MaxKeys>128</MaxKeys><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>run/HEAD</Key><Size>0</Size></Contents></ListBucketResult>`},
		{"denied", http.StatusForbidden, `<Error><Code>AccessDenied</Code></Error>`},
		{"over_limit", http.StatusOK, strings.Repeat("x", operatorPrefixBodyLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings, _ := awsLiveTestSettings(t)
			credentials := &awsLiveTestCredentials{}
			requests := 0
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(tc.status)
				if _, err := io.WriteString(w, tc.body); err != nil {
					t.Error(err)
				}
			}))
			s := newAWSSetup(settings, "run", contract.Hash([]byte("domain")), nil, credentials, transport)
			if _, err := s.listPrefix(context.Background(), "run/", ""); err == nil || requests != 1 || credentials.calls.Load() != 1 {
				t.Fatalf("unproved LIST reply accepted or replayed: %v requests=%d credentials=%d", err, requests, credentials.calls.Load())
			}
		})
	}
}

// full_only: false
func TestAWSPublicCleanupAdmitsCurrentAdministrativeIndexKey(t *testing.T) {
	domain := contract.Hash([]byte("domain"))
	setup := &awsSetup{head: "run/HEAD", objects: "run/" + hex.EncodeToString(domain[:]) + "/"}
	key := setup.objects + "admin-index/0/" + strings.Repeat("2", 64)
	if !setup.validKey(key) {
		t.Fatal("current administrative index cannot enter conditional fixture cleanup")
	}
}

// full_only: false
func TestAWSPublicCapturedCleanupUsesObjectBounds(t *testing.T) {
	checkPublicCapturedCleanupProvider(t, func(t *testing.T, prefix string, domain contract.ID, key string, body []byte) *livePrefixCleaner {
		settings, _ := awsLiveTestSettings(t)
		credentials := &awsLiveTestCredentials{}
		deleted := false
		transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != "s3.us-east-1.amazonaws.com" || r.URL.Path != "/"+settings.Bucket+"/"+key || r.Header.Get("X-Amz-Expected-Bucket-Owner") != settings.Account {
				t.Error("cleanup changed exact bucket, key or owner")
			}
			switch r.Method {
			case http.MethodGet:
				if deleted {
					w.WriteHeader(http.StatusNotFound)
					_, _ = io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>")
					return
				}
				w.Header().Set("ETag", `"observed-etag"`)
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				_, _ = w.Write(body)
			case http.MethodDelete:
				if deleted || r.Header.Get("If-Match") != `"observed-etag"` {
					t.Error("conditional cleanup changed its observed token")
				}
				deleted = true
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Error("unexpected cleanup method")
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: settings.Region, Bucket: settings.Bucket, ExpectedBucketOwner: settings.Account, Prefix: prefix, Domain: domain, CredentialRoute: contract.Hash([]byte("test-route")), Credentials: credentials, Transport: transport, Timeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		setup := newAWSSetup(settings, prefix, domain, nil, credentials, transport)
		return &livePrefixCleaner{Store: store, ValidKey: setup.validKey, Delete: setup.delete}
	})
}
