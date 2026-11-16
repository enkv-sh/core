package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	awsprovider "enkv.sh/providers/aws"
)

// full_only: false
func TestAWSInboxDeleteKeepsObservedETagAndQualifiedFinalReply(t *testing.T) {
	domain := contract.Hash([]byte("inbox-domain"))
	inbox := contract.Hash([]byte("inbox-id"))
	key, err := format.GeneratedResultKey("fixture", domain, inbox)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantStatus contract.WriteStatus
	}{
		{"final", 204, "", contract.WriteAcknowledged},
		{"ok", 200, "", contract.WriteUnknown},
		{"accepted", 202, "", contract.WriteUnknown},
		{"partial", 206, "", contract.WriteUnknown},
		{"other-success", 299, "", contract.WriteUnknown},
		{"denied", 403, "<Error><Code>AccessDenied</Code></Error>", contract.WriteUnknown},
		{"changed", 412, "<Error><Code>PreconditionFailed</Code></Error>", contract.WritePrecondition},
		{"conflict", 409, "<Error><Code>ConditionalRequestConflict</Code></Error>", contract.WriteConflict},
		{"lost", 0, "", contract.WriteUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings, _ := awsLiveTestSettings(t)
			var reads, deletes atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "s3.us-east-1.amazonaws.com" || r.URL.Path != "/"+settings.Bucket+"/"+key || r.Header.Get("X-Amz-Expected-Bucket-Owner") != settings.Account {
					t.Error("request changed its bucket, key or owner")
				}
				switch r.Method {
				case http.MethodGet:
					reads.Add(1)
					w.Header().Set("ETag", `"observed-etag"`)
					w.Header().Set("Content-Length", "16")
					_, _ = io.WriteString(w, "selected handoff")
				case http.MethodDelete:
					deletes.Add(1)
					if r.Header.Get("If-Match") != `"observed-etag"` || !strings.Contains(r.URL.RawQuery, "x-id=DeleteObject") {
						t.Error("DELETE lost its observed token or operation")
					}
					if tc.status == 0 {
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = connection.Close()
						return
					}
					w.WriteHeader(tc.status)
					if _, err := io.WriteString(w, tc.body); err != nil {
						t.Error(err)
					}
				default:
					t.Error(errors.New("unexpected request method"))
				}
			}))
			credentials := &awsLiveTestCredentials{}
			store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: settings.Region, Bucket: settings.Bucket, ExpectedBucketOwner: settings.Account,
				Prefix: "fixture", Domain: domain, CredentialRoute: contract.Hash([]byte("test-route")), Credentials: credentials, Transport: transport, Timeout: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			read := store.Read(context.Background(), key, 64)
			if read.Status != contract.ReadOK || string(read.Body) != "selected handoff" || read.Token != (contract.Token{Family: contract.AWS, Value: `"observed-etag"`}) {
				t.Fatalf("observed handoff: %+v", read)
			}
			result := store.DeleteIfToken(context.Background(), key, read.Token)
			if result.Status != tc.wantStatus || reads.Load() != 1 || deletes.Load() != 1 || credentials.calls.Load() != 2 {
				t.Fatalf("delete result=%+v reads=%d deletes=%d credentials=%d", result, reads.Load(), deletes.Load(), credentials.calls.Load())
			}
		})
	}
}

// full_only: false
func TestAWSInboxDeleteFactControlsColdRelease(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		clean  bool
	}{{"qualified", 204, true}, {"nonfinal", 202, false}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGeneratedProviderRelease(t, t.Context(), contract.AWS, tc.clean, func(domain contract.ID, prefix, key string, body []byte) contract.Store {
				settings, _ := awsLiveTestSettings(t)
				var reads, deletes atomic.Int32
				transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Host != "s3.us-east-1.amazonaws.com" || r.URL.Path != "/"+settings.Bucket+"/"+key || r.Header.Get("X-Amz-Expected-Bucket-Owner") != settings.Account {
						t.Error("provider request changed its bucket, key or owner")
					}
					switch r.Method {
					case http.MethodGet:
						reads.Add(1)
						w.Header().Set("ETag", `"observed-etag"`)
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
						_, _ = w.Write(body)
					case http.MethodDelete:
						deletes.Add(1)
						if r.Header.Get("If-Match") != `"observed-etag"` || !strings.Contains(r.URL.RawQuery, "x-id=DeleteObject") {
							t.Error("provider DELETE lost its observed token")
						}
						w.WriteHeader(tc.status)
					default:
						t.Errorf("unexpected provider method: %s", r.Method)
					}
				}))
				credentials := &awsLiveTestCredentials{}
				adapter, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: settings.Region, Bucket: settings.Bucket,
					ExpectedBucketOwner: settings.Account, Prefix: prefix, Domain: domain, CredentialRoute: contract.Hash([]byte("test-route")),
					Credentials: credentials, Transport: transport, Timeout: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if reads.Load() != 1 || deletes.Load() != 1 || credentials.calls.Load() != 2 {
						t.Errorf("provider requests=%d/%d credentials=%d", reads.Load(), deletes.Load(), credentials.calls.Load())
					}
				})
				return adapter
			})
		})
	}
}
