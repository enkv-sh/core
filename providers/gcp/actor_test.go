package gcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

type actorCredentials struct {
	token string
	err   error
	calls int
}

func (c *actorCredentials) Token(ctx context.Context) (string, error) {
	c.calls++
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return c.token, c.err
}

// full_only: false
func TestActorCredentialsKeepSharedBindingsAndSeparateRequests(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		status     int
		wantStatus contract.ReadStatus
		wantReason contract.Reason
	}{
		{"success", 200, contract.ReadOK, contract.ReasonNone},
		{"unauthorized", 401, contract.ReadUnavailable, contract.ReasonAccess},
		{"forbidden", 403, contract.ReadUnavailable, contract.ReasonAccess},
		{"unavailable", 503, contract.ReadUnavailable, contract.ReasonTransport},
		{"truncated-refusal", 403, contract.ReadUnavailable, contract.ReasonTransport},
		{"invalid-success", 200, contract.ReadInvalid, contract.ReasonMalformed},
		{"token-failure", 200, contract.ReadUnavailable, contract.ReasonAccess},
		{"cancelled", 200, contract.ReadUnavailable, contract.ReasonAccess},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := &actorCredentials{token: "writer-token"}
			reader := &actorCredentials{token: "reader-token"}
			if test.name == "token-failure" {
				reader.err = errors.New("controlled token transport failure")
			}
			objects := make(map[string][]byte)
			writerSends, readerSends := 0, 0
			var trustSettings TrustConfig
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					readerSends++
					if request.Header.Get("Authorization") != "Bearer reader-token" || request.URL.Host != "storage.us-central1.rep.googleapis.com" || request.URL.Query().Get("alt") != "media" {
						t.Fatal("reader request used another actor or provider operation")
					}
					if test.status != 200 {
						// A body cannot turn a physical 503 into an access refusal.
						reply := response(test.status, `{"error":{"code":403}}`)
						if test.name == "truncated-refusal" {
							reply.ContentLength++
						}
						return reply, nil
					}
					name := strings.TrimPrefix(request.URL.Path, "/download/storage/v1/b/fixture-bucket/o/")
					body, ok := objects[name]
					if !ok {
						t.Fatal("reader requested an object the writer did not create")
					}
					reply := response(http.StatusOK, string(body))
					reply.Header.Set("X-Goog-Generation", "24")
					if test.name == "invalid-success" {
						reply.Header.Set("X-Goog-Generation", "024")
					}
					return reply, nil
				}
				writerSends++
				if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer writer-token" {
					t.Fatal("reader signed or wrote with a different credential route")
				}
				if request.URL.Host == "us-central1-cloudkms.googleapis.com" {
					if request.URL.Path != "/v1/"+trustSettings.KeyVersion+":asymmetricSign" {
						t.Fatal("writer signing target changed")
					}
					var input struct {
						Digest struct {
							SHA256 string `json:"sha256"`
						} `json:"digest"`
					}
					if json.NewDecoder(request.Body).Decode(&input) != nil {
						t.Fatal("writer signing request unavailable")
					}
					digest, err := base64.StdEncoding.DecodeString(input.Digest.SHA256)
					if err != nil {
						t.Fatal(err)
					}
					signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
					if err != nil {
						t.Fatal(err)
					}
					body, err := json.Marshal(map[string]any{"name": trustSettings.KeyVersion, "verifiedDigestCrc32c": true, "signature": base64.StdEncoding.EncodeToString(signature), "signatureCrc32c": strconv.FormatUint(uint64(crc(signature)), 10)})
					if err != nil {
						t.Fatal(err)
					}
					return response(200, string(body)), nil
				}
				if request.URL.Host != "storage.us-central1.rep.googleapis.com" || request.URL.Path != "/upload/storage/v1/b/fixture-bucket/o" {
					t.Fatal("writer used an unexpected resource")
				}
				kind, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
				if err != nil || kind != "multipart/related" {
					t.Fatal("writer did not send bounded multipart bytes")
				}
				parts := multipart.NewReader(request.Body, parameters["boundary"])
				metadata, err := parts.NextPart()
				if err != nil {
					t.Fatal(err)
				}
				var fields struct {
					Name string `json:"name"`
				}
				if json.NewDecoder(metadata).Decode(&fields) != nil {
					t.Fatal("writer object name unavailable")
				}
				media, err := parts.NextPart()
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(media)
				if err != nil {
					t.Fatal(err)
				}
				objects[fields.Name] = bytes.Clone(body)
				reply, err := json.Marshal(map[string]string{"bucket": "fixture-bucket", "name": fields.Name, "generation": "24", "size": strconv.Itoa(len(body)), "crc32c": crcBase64(body)})
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(reply)), nil
			})
			writerClient, readerClient := makeClient(transport, writer), makeClient(transport, reader)
			writerStore, err := NewStore(context.Background(), config(writerClient))
			if err != nil {
				t.Fatal(err)
			}
			readerStore, err := NewStore(context.Background(), config(readerClient))
			if err != nil {
				t.Fatal(err)
			}
			trustSettings = trustConfig(writerClient, public)
			writerTrust, err := NewTrust(context.Background(), trustSettings)
			if err != nil {
				t.Fatal(err)
			}
			readerTrust, err := NewTrust(context.Background(), trustConfig(readerClient, public))
			if err != nil {
				t.Fatal(err)
			}
			if writerStore.Descriptor() != readerStore.Descriptor() || writerTrust.Identity() != readerTrust.Identity() {
				t.Fatal("actor identity changed shared Store or Trust bindings")
			}
			child, head := childKey(writerStore), writerStore.Descriptor().HeadKey
			if result := writerStore.Create(context.Background(), child, []byte("complete child bytes")); result.Status != contract.WriteAcknowledged {
				t.Fatal(result)
			}
			if result := writerStore.CompareAndSwap(context.Background(), head, contract.Token{Family: contract.GCP, Value: "23"}, []byte("selected head bytes")); result.Status != contract.WriteAcknowledged {
				t.Fatal(result)
			}
			if result := writerTrust.Sign(context.Background(), signRequest(t)); result.Reason != contract.ReasonNone {
				t.Fatal(result)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.name == "cancelled" {
				cancel()
			}
			for _, name := range []string{head, child} {
				result := readerStore.Read(ctx, name, 1024)
				if result.Status != test.wantStatus || result.Reason != test.wantReason || result.Status == contract.ReadOK && !bytes.Equal(result.Body, objects[name]) {
					t.Fatal("reader response changed the selected actor's bounded evidence")
				}
			}
			wantReaderSends := 2
			if test.name == "token-failure" || test.name == "cancelled" {
				wantReaderSends = 0
			}
			wantReaderCalls := 2
			if test.name == "cancelled" {
				wantReaderCalls = 0
			}
			if writer.calls != 3 || writerSends != 3 || reader.calls != wantReaderCalls || readerSends != wantReaderSends {
				t.Fatalf("actor requests: writer credentials=%d sends=%d, want 3 each; reader credentials=%d sends=%d, want %d and %d", writer.calls, writerSends, reader.calls, readerSends, wantReaderCalls, wantReaderSends)
			}
		})
	}
}
