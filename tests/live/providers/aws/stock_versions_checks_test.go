package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestStockAWSHistoricalResultRequiresUniqueCompleteVersion(t *testing.T) {
	for _, mode := range []string{"exact", "absent", "duplicate-bytes", "foreign-key", "duplicate-id", "wrong-owner-echo", "cursor-cycle", "truncated-without-cursor", "null-version", "wrong-response-version", "changed-token", "extra-body", "bad-latest", "budget"} {
		t.Run(mode, func(t *testing.T) {
			settings, der := awsLiveTestSettings(t)
			domain := contract.Hash([]byte("domain"))
			const prefix = "enkv-test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/plugin-contracts"
			key := fmt.Sprintf("%s/%x/result/%x", prefix, domain, contract.Hash([]byte("inbox")))
			const body = "original"
			const etag = `"0123456789abcdef0123456789abcdef"`
			calls := 0
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				q := r.URL.Query()
				if r.Method != "GET" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != settings.Account {
					t.Error("historical lookup escaped the bound owner or read operation")
					return
				}
				if q.Has("versions") {
					if q.Get("prefix") != key || q.Get("max-keys") != "128" || r.URL.Path != "/"+settings.Bucket {
						t.Error("historical listing escaped requested scope")
						return
					}
					currentKey := key
					if mode == "foreign-key" {
						currentKey += "x"
					}
					bucket := settings.Bucket
					if mode == "wrong-owner-echo" {
						bucket = "another-bucket"
					}
					page := fmt.Sprintf("<ListVersionsResult><Name>%s</Name><Prefix>%s</Prefix><MaxKeys>128</MaxKeys>", bucket, key)
					marker := "<DeleteMarker><Key>" + currentKey + "</Key><VersionId>deleted</VersionId><IsLatest>true</IsLatest></DeleteMarker>"
					data := func(id string) string {
						return "<Version><Key>" + currentKey + "</Key><VersionId>" + id + "</VersionId><IsLatest>false</IsLatest><ETag>" + etag + "</ETag><Size>8</Size></Version>"
					}
					if q.Get("key-marker") == "" {
						if mode == "bad-latest" {
							marker = strings.Replace(marker, "true", "false", 1)
						}
						page += marker + "<IsTruncated>true</IsTruncated><NextKeyMarker>" + key + "</NextKeyMarker>"
						if mode != "truncated-without-cursor" {
							page += "<NextVersionIdMarker>deleted</NextVersionIdMarker>"
						}
					} else {
						if q.Get("key-marker") != key || q.Get("version-id-marker") != "deleted" {
							t.Error("loss of paired version cursor")
							return
						}
						page += "<KeyMarker>" + key + "</KeyMarker><VersionIdMarker>deleted</VersionIdMarker>"
						version := "original"
						if mode == "null-version" {
							version = "null"
						}
						page += data(version)
						if mode == "duplicate-bytes" {
							page += data("copy")
						}
						if mode == "duplicate-id" {
							page += data(version)
						}
						if mode == "cursor-cycle" {
							page += "<IsTruncated>true</IsTruncated><NextKeyMarker>" + key + "</NextKeyMarker><NextVersionIdMarker>deleted</NextVersionIdMarker>"
						} else {
							page += "<IsTruncated>false</IsTruncated>"
						}
					}
					io.WriteString(w, page+"</ListVersionsResult>")
					return
				}
				version := q.Get("versionId")
				if r.URL.Path != "/"+settings.Bucket+"/"+key || (version != "original" && version != "copy") {
					t.Error("version read selected wrong coordinate")
					return
				}
				if mode == "wrong-response-version" {
					version = "other"
				}
				w.Header().Set("x-amz-version-id", version)
				received := body
				if mode == "absent" {
					received = "replaced"
				}
				if mode == "extra-body" {
					received += "!"
				}
				token := etag
				if mode == "changed-token" {
					token = `"11111111111111111111111111111111"`
				}
				w.Header().Set("ETag", token)
				w.Header().Set("Content-Length", strconv.Itoa(len(received)))
				io.WriteString(w, received)
			}))
			setup := newAWSSetup(settings, prefix, domain, der, &awsLiveTestCredentials{}, transport)
			setup.client.Transport = stockAWSBudgetTransport{setup.transport}
			budget := &runBudget{limits: liveLimits{Requests: 12, BodyBytes: 32 << 20}}
			if mode == "budget" {
				budget.limits.Requests = 1
			}
			ctx := context.WithValue(t.Context(), stockAWSBudgetKey{}, budget)
			read, err := stockS3FindOriginal(ctx, setup, key, contract.Hash([]byte(body)), uint32(len(body)))
			if mode == "exact" {
				if err != nil || read.Status != contract.ReadOK || string(read.Body) != body || calls != 3 || read.Token.Value != etag {
					t.Fatal("exact historical result unavailable", err, calls)
				}
			} else if err == nil || len(read.Body) != 0 {
				t.Fatal("unqualified history accepted", mode, calls)
			}
			if mode == "budget" && (calls != 1 || !budget.exhausted) {
				t.Fatal("budget overrun reached S3", calls)
			}
		})
	}
}

// full_only: false
func TestStockAWSHistoryPreflightRejectsRetainedPrefix(t *testing.T) {
	for _, mode := range []string{"empty", "marker-only", "data", "suspended", "unversioned", "unknown-key", "ordinary-grant", "ordinary-versioned"} {
		t.Run(mode, func(t *testing.T) {
			settings, der := awsLiveTestSettings(t)
			const run = "0123456789abcdef0123456789abcdef"
			const prefix = "enkv-test/" + run + "/plugin-contracts"
			settings.Bucket = "enkv-" + settings.Account + "-pa-" + run
			fixture := records.StockPluginFixture{Schema: 1, Provider: "aws", Account: settings.Account, Region: settings.Region, Bucket: settings.Bucket, FixtureID: run, Purpose: records.StockRetirementProofPurpose}
			input := liveRunInput{Settings: settings, RecoveryMode: "enabled", RunID: run, Prefix: prefix, Scenarios: []string{records.StockPluginScenario}, PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Fixture: fixture}}}
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if r.Method != "GET" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != settings.Account {
					t.Error("preflight attempted a change or used a different owner")
					return
				}
				if q.Has("versions") {
					if q.Get("prefix") != prefix+"/" {
						t.Error("wrong history prefix")
						return
					}
					key := prefix + "/HEAD"
					content := ""
					switch mode {
					case "unknown-key":
						key = prefix + "/other"
						fallthrough
					case "marker-only":
						content = "<DeleteMarker><Key>" + key + "</Key><VersionId>marker</VersionId><IsLatest>true</IsLatest></DeleteMarker>"
					case "data":
						content = "<Version><Key>" + key + "</Key><VersionId>data</VersionId><IsLatest>true</IsLatest><Size>1</Size><ETag>&quot;1&quot;</ETag></Version>"
					}
					io.WriteString(w, "<ListVersionsResult><Name>"+settings.Bucket+"</Name><Prefix>"+prefix+"/</Prefix><MaxKeys>128</MaxKeys><IsTruncated>false</IsTruncated>"+content+"</ListVersionsResult>")
					return
				}
				expected := "versioning"
				if mode == "suspended" {
					expected = "suspended"
				}
				if mode == "unversioned" || mode == "ordinary-grant" && input.PublicConfiguration.Stock.Fixture.Purpose == "stock-plugin-acceptance" {
					expected = ""
				}
				if q.Has("list-type") {
					io.WriteString(w, "<ListBucketResult><Name>"+settings.Bucket+"</Name><Prefix>"+prefix+"/</Prefix><KeyCount>0</KeyCount><MaxKeys>128</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>")
					return
				}
				code, body := awsLiveConfigurationReply(t, settings, der, r, expected)
				w.WriteHeader(code)
				io.WriteString(w, body)
			}))
			setup := newAWSSetup(settings, prefix, contract.Hash([]byte("domain")), der, &awsLiveTestCredentials{}, transport)
			if mode == "ordinary-versioned" || mode == "ordinary-grant" {
				input.PublicConfiguration.Stock.Fixture.Purpose = "stock-plugin-acceptance"
			}
			store, err := stockAWSStorePrefix(input, setup, nil)
			if err != nil {
				t.Fatal(err)
			}
			budget := &runBudget{limits: liveLimits{Requests: 100, BodyBytes: 128 << 20}}
			got, err := store.Inspect(t.Context(), budget)
			switch mode {
			case "empty":
				if err != nil || !got.Empty || got.Identity == "" {
					t.Fatal("valid empty versioned prefix refused", err)
				}
			case "data", "marker-only":
				if err != nil || got.Empty {
					t.Fatal("retained prefix reported empty", err)
				}
			case "ordinary-grant":
				if err != nil || !got.Empty {
					t.Fatal("ordinary fixture refused", err)
				}
				input.PublicConfiguration.Stock.Fixture.Purpose = records.StockRetirementProofPurpose
				if _, err := stockAWSStorePrefix(input, setup, &got); err == nil {
					t.Fatal("ordinary grant activated historical fixture")
				}
			default:
				if err == nil || got.Empty {
					t.Fatal("unqualified preflight accepted")
				}
			}
		})
	}
}
