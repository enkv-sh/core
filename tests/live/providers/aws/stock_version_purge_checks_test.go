package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestStockAWSPurgeVersionsRequiresExactInventoryAndFinalAcknowledgements(t *testing.T) {
	for _, mode := range []string{
		"exact", "paginated", "explicit-data-marker-false", "missing", "extra", "changed-length", "changed-etag", "changed-version", "changed-latest", "changed-marker",
		"remaining-marker-changed", "remaining-extra", "remaining-missing", "concurrent-replacement", "head-changed", "final-nonempty",
		"wrong-version-ack", "missing-version-ack", "data-marker-ack", "missing-marker-ack", "false-marker-ack", "nonfinal-ack", "lost-data-response", "lost-marker-response", "lost-head-response",
		"initial-budget", "marker-budget", "head-budget", "final-budget",
	} {
		t.Run(mode, func(t *testing.T) {
			settings, der := awsLiveTestSettings(t)
			domain := contract.Hash([]byte("domain"))
			const prefix = "enkv-test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/plugin-contracts"
			root := fmt.Sprintf("%s/%x/root/0/%x", prefix, domain, contract.Hash([]byte("root")))
			result := fmt.Sprintf("%s/%x/result/%x", prefix, domain, contract.Hash([]byte("result")))
			data := func(key, version string, latest bool) stockS3Version {
				return stockS3Version{stockS3VersionID: stockS3VersionID{key, version}, token: contract.Token{Family: contract.AWS, Value: `"qualified-etag"`}, length: 8, latest: latest}
			}
			// Deliberately shuffled. The expected DELETE order below is independent
			// of both the candidate order and the service's returned array order.
			frozen := []stockS3Version{
				{stockS3VersionID: stockS3VersionID{result, "result-marker"}, marker: true, latest: true},
				data(root, "root-data", true), data(prefix+"/HEAD", "head-current", true),
				data(result, "result-data", false), data(prefix+"/HEAD", "head-old", false),
			}
			current := slices.Clone(frozen)
			wantDeletes := []string{"head-old", "result-data", "root-data", "result-marker", "head-current"}
			var deletes []string
			lists, calls := 0, 0
			var page []stockS3Version
			var mu sync.Mutex
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				q := r.URL.Query()
				if r.Header.Get("X-Amz-Expected-Bucket-Owner") != settings.Account {
					t.Error("purge changed its bound owner")
					return
				}
				if r.Method == http.MethodGet && q.Has("versions") {
					if q.Get("prefix") != prefix+"/" || q.Get("max-keys") != "128" || r.URL.Path != "/"+settings.Bucket {
						t.Error("purge listing escaped its run prefix")
						return
					}
					cursorKey, cursorVersion := q.Get("key-marker"), q.Get("version-id-marker")
					if cursorKey == "" {
						lists++
						page = slices.Clone(current)
						switch {
						case lists == 1:
							switch mode {
							case "missing":
								page = append(page[:1], page[2:]...)
							case "extra":
								page = append(page, data(root, "extra", false))
							case "changed-length":
								page[1].length++
							case "changed-etag":
								page[1].token.Value = `"changed-etag"`
							case "changed-version":
								page[1].version = "replacement"
							case "changed-latest":
								page[2].latest, page[4].latest = false, true
							case "changed-marker":
								page[0].version = "new-marker"
							}
						case lists == 2:
							switch mode {
							case "remaining-marker-changed":
								page[0].version = "new-marker"
							case "remaining-extra":
								page = append(page, data(root, "unexpected", true))
							case "remaining-missing":
								page = page[1:]
							}
						case lists == 3 && mode == "head-changed":
							page[0].length++
						case lists == 4 && mode == "final-nonempty":
							page = append(page, data(root, "unexpected", true))
						}
					}
					items := page
					truncated := mode == "paginated" && cursorKey == "" && len(items) > 1
					if truncated {
						items = items[:1]
					} else if cursorKey != "" {
						if len(page) < 2 || cursorKey != page[0].key || cursorVersion != page[0].version {
							t.Error("purge lost its paired version-list cursor")
							return
						}
						items = page[1:]
					}
					var body strings.Builder
					fmt.Fprintf(&body, "<ListVersionsResult><Name>%s</Name><Prefix>%s/</Prefix><MaxKeys>128</MaxKeys><IsTruncated>%t</IsTruncated>", settings.Bucket, prefix, truncated)
					if cursorKey != "" {
						fmt.Fprintf(&body, "<KeyMarker>%s</KeyMarker><VersionIdMarker>%s</VersionIdMarker>", cursorKey, cursorVersion)
					}
					if truncated {
						fmt.Fprintf(&body, "<NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>", items[0].key, items[0].version)
					}
					for _, item := range items {
						if item.marker {
							fmt.Fprintf(&body, "<DeleteMarker><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest></DeleteMarker>", item.key, item.version, item.latest)
						} else {
							fmt.Fprintf(&body, "<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><Size>%d</Size><ETag>%s</ETag></Version>", item.key, item.version, item.latest, item.length, item.token.Value)
						}
					}
					body.WriteString("</ListVersionsResult>")
					_, _ = io.WriteString(w, body.String())
					return
				}
				if r.Method != http.MethodDelete || !q.Has("versionId") || q.Get("versionId") == "" || q.Get("x-id") != "DeleteObject" {
					t.Error("purge sent an operation without an exact version")
					return
				}
				version := q.Get("versionId")
				if r.Header.Values("If-Match") != nil {
					http.Error(w, "conditional deletion of a specified version", http.StatusNotImplemented)
					return
				}
				if mode == "concurrent-replacement" && len(deletes) == 0 {
					for i := range current {
						if current[i].key == root {
							current[i].latest = false
						}
					}
					current = append(current, data(root, "replacement-version", true))
				}
				index := slices.IndexFunc(current, func(item stockS3Version) bool {
					return version == item.version && r.URL.Path == "/"+settings.Bucket+"/"+item.key
				})
				if index < 0 {
					t.Error("purge selected an unqualified exact coordinate")
					return
				}
				item := current[index]
				deletes = append(deletes, version)
				if len(deletes) > len(wantDeletes) || version != wantDeletes[len(deletes)-1] {
					t.Error("purge changed the deterministic data-marker-HEAD order")
				}
				current = slices.Delete(current, index, index+1)
				lost := mode == "lost-data-response" && len(deletes) == 1 || mode == "lost-marker-response" && item.marker || mode == "lost-head-response" && version == "head-current"
				if lost {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error("could not simulate a lost response")
						return
					}
					_ = connection.Close()
					return
				}
				ack := version
				if mode == "wrong-version-ack" {
					ack = "another-version"
				}
				if mode != "missing-version-ack" {
					w.Header().Set("x-amz-version-id", ack)
				}
				if item.marker && mode != "missing-marker-ack" {
					w.Header().Set("x-amz-delete-marker", strconv.FormatBool(mode != "false-marker-ack"))
				} else if mode == "data-marker-ack" {
					w.Header().Set("x-amz-delete-marker", "true")
				} else if mode == "explicit-data-marker-false" {
					w.Header().Set("x-amz-delete-marker", "false")
				}
				status := http.StatusNoContent
				if mode == "nonfinal-ack" {
					status = http.StatusAccepted
				}
				w.WriteHeader(status)
			}))
			setup := newAWSSetup(settings, prefix, domain, der, &awsLiveTestCredentials{}, transport)
			setup.client.Transport = stockAWSBudgetTransport{setup.transport}
			budget := &runBudget{limits: liveLimits{Requests: 64, BodyBytes: 32 << 20}}
			switch mode {
			case "initial-budget":
				budget.limits.Requests = 1
			case "marker-budget":
				budget.limits.Requests = 4
			case "head-budget":
				budget.limits.Requests = 6
			case "final-budget":
				budget.limits.Requests = 8
			}
			ctx := context.WithValue(t.Context(), stockAWSBudgetKey{}, budget)
			complete, err := stockS3PurgeVersions(ctx, setup, prefix, frozen)
			mu.Lock()
			defer mu.Unlock()
			wantComplete := mode == "exact" || mode == "paginated" || mode == "explicit-data-marker-false"
			if complete != wantComplete || (err == nil) != wantComplete {
				t.Fatalf("purge qualification differs: complete=%t error=%t lists=%d deletes=%d", complete, err != nil, lists, len(deletes))
			}
			wantCount, wantLists := 0, 1
			switch mode {
			case "exact", "explicit-data-marker-false", "paginated", "final-nonempty", "final-budget":
				wantCount, wantLists = 5, 4
			case "remaining-marker-changed", "remaining-extra", "remaining-missing", "concurrent-replacement":
				wantCount, wantLists = 3, 2
			case "head-changed", "missing-marker-ack", "false-marker-ack", "lost-marker-response", "head-budget":
				wantCount, wantLists = 4, 2
			case "wrong-version-ack", "missing-version-ack", "data-marker-ack", "nonfinal-ack", "lost-data-response":
				wantCount = 1
			case "lost-head-response":
				wantCount, wantLists = 5, 3
			case "marker-budget":
				wantCount = 3
			}
			if mode == "head-changed" {
				wantLists = 3
			}
			if mode == "final-budget" {
				wantLists = 3
			}
			if len(deletes) != wantCount || !slices.Equal(deletes, wantDeletes[:wantCount]) || lists != wantLists {
				t.Fatalf("purge continued after incomplete evidence: deletes=%d want=%d lists=%d want=%d", len(deletes), wantCount, lists, wantLists)
			}
			if mode == "concurrent-replacement" && !slices.Contains(current, data(root, "replacement-version", true)) {
				t.Fatal("purge removed the concurrent replacement")
			}
			if strings.HasSuffix(mode, "budget") && (!budget.exhausted || calls != int(budget.limits.Requests)) {
				t.Fatal("purge escaped its cumulative request budget")
			}
			if strings.Contains(mode, "ack") || strings.HasPrefix(mode, "lost-") {
				var failure *awsSetupFailure
				if !errors.As(err, &failure) || failure.Effect != "unknown" || failure.Attempt != 1 {
					t.Fatal("purge lost its uncertain delete effect")
				}
				for _, secret := range []string{"qualified-etag", "test-secret", "test-session", "test-access", root, result} {
					if strings.Contains(fmt.Sprintf("%v %+v", err, err), secret) {
						t.Fatal("purge exposed private request details")
					}
				}
			}
		})
	}
}
