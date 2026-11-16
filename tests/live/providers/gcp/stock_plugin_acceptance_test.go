package core

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/providers/gcp"
	"enkv.sh/telemetry"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

type stockGCPBudgetKey struct{}

type stockGCPBudgetTransport struct {
	base         http.RoundTripper
	quotaProject string
}

func (t stockGCPBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	budget, _ := r.Context().Value(stockGCPBudgetKey{}).(*runBudget)
	op, _ := r.Context().Value(gcpSetupContextKey{}).(*gcpSetupOperation)
	limit := int64(gcpSetupLimit)
	if op != nil && op.bodyLimit > 0 {
		limit = op.bodyLimit
	}
	if budget == nil || !budget.reserve(1, uint64(limit), "", 0) {
		return nil, errRunLimit
	}
	if t.quotaProject != "" {
		r.Header.Set("X-Goog-User-Project", t.quotaProject)
	}
	return t.base.RoundTrip(r)
}

func stockGCPFixture(input liveRunInput) (records.StockPluginFixture, error) {
	if input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil {
		return records.StockPluginFixture{}, errInventory
	}
	f, s := input.PublicConfiguration.Stock.Fixture, input.Settings
	if f.Validate() != nil || f.Provider != "gcp" || s.Provider != f.Provider || s.Bucket != f.Bucket || s.Project != f.Project ||
		s.ProjectNumber != f.ProjectNumber || s.Region != f.Region || input.RecoveryMode != "enabled" ||
		!records.ValidRunID(input.RunID) || !strings.HasPrefix(input.Prefix, "enkv-test/"+input.RunID+"/") ||
		!slices.Equal(input.Scenarios, []string{records.StockPluginScenario}) {
		return records.StockPluginFixture{}, errInventory
	}
	return f, nil
}

func stockGCPTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: gcpSetupLimit, DisableKeepAlives: true, DisableCompression: true}
}

func openStockStorePrefix(ctx context.Context, input liveRunInput, directory string, original *stockPrefixInspection) (*stockStorePrefix, error) {
	if ctx == nil {
		return nil, errInventory
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return nil, errInventory
	}
	if _, err := stockGCPFixture(input); err != nil {
		return nil, err
	}
	restore, err := publicSDKEnvironment(input, "cleanup", directory)
	if err != nil {
		return nil, err
	}
	defer restore()
	source, err := gcp.LoadDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}
	s := input.Settings
	transport := stockGCPBudgetTransport{base: stockGCPTransport(), quotaProject: input.PublicConfiguration.Actors["cleanup"].SDKQuotaProject}
	setup, err := newGCPSetup(ctx, source, transport, s.Bucket, input.Prefix, contract.Hash([]byte(input.Prefix)),
		"https://storage."+s.Region+".rep.googleapis.com/storage/v1/", "https://"+s.Region+"-cloudkms.googleapis.com/")
	if err != nil {
		return nil, err
	}
	return stockGCPStorePrefix(input, setup, original)
}

func stockGCPStorePrefix(input liveRunInput, setup *gcpSetup, original *stockPrefixInspection) (*stockStorePrefix, error) {
	f, err := stockGCPFixture(input)
	if err != nil || setup == nil || setup.bucket != f.Bucket || setup.head != input.Prefix+"/HEAD" {
		return nil, errInventory
	}
	// The generated SDK uses its configured base path for Download as well.
	// Regional media requests need the separate documented download endpoint.
	media, err := storage.NewService(context.Background(), option.WithHTTPClient(&http.Client{Transport: setup.transport, Timeout: time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}),
		option.WithEndpoint(strings.TrimSuffix(setup.storage.BasePath, "storage/v1/")+"download/storage/v1/"),
		option.WithUniverseDomain("googleapis.com"), option.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		return nil, errInventory
	}
	var admitted *stockPrefixInspection
	if original != nil {
		if !original.Empty || len(original.Identity) != 64 || original.Prefix != input.Prefix {
			return nil, errInventory
		}
		copy := *original
		admitted = &copy
	}
	setup.ownedKey = func(key string) bool { return publicObjectKeyLimit(input.Prefix, key) > 0 }
	inspect := func(ctx context.Context, budget *runBudget) (stockPrefixInspection, error) {
		ctx = context.WithValue(ctx, stockGCPBudgetKey{}, budget)
		_, identity, err := stockGCPBucketMetadata(ctx, setup, input.Settings, f)
		if err != nil {
			return stockPrefixInspection{}, err
		}
		if admitted != nil && identity != admitted.Identity {
			return stockPrefixInspection{}, errInventory
		}
		objects, err := stockGCPPrefixObjects(ctx, setup, input.Prefix)
		if err != nil {
			return stockPrefixInspection{}, err
		}
		return stockPrefixInspection{Empty: len(objects) == 0, Identity: identity, Prefix: input.Prefix}, nil
	}
	attempted := false
	return &stockStorePrefix{Inspect: inspect, Clean: func(ctx context.Context, budget *runBudget) (bool, error) {
		if attempted || admitted == nil {
			return false, errInventory
		}
		attempted = true
		ctx = context.WithValue(ctx, stockGCPBudgetKey{}, budget)
		_, identity, err := stockGCPBucketMetadata(ctx, setup, input.Settings, f)
		if err != nil {
			return false, err
		}
		if identity != admitted.Identity {
			return false, errInventory
		}
		objects, err := stockGCPPrefixObjects(ctx, setup, input.Prefix)
		if err != nil {
			return false, err
		}
		for _, object := range objects {
			if err := stockGCPReadOwnedObject(ctx, setup, media, object); err != nil {
				return false, err
			}
			token := contract.Token{Family: contract.GCP, Value: strconv.FormatInt(object.Generation, 10)}
			if err := setup.delete(ctx, object.Name, token); err != nil {
				return false, err
			}
		}
		remaining, err := stockGCPPrefixObjects(ctx, setup, input.Prefix)
		if err != nil {
			return false, err
		}
		if len(remaining) != 0 {
			return false, errInventory
		}
		return true, nil
	}}, nil
}

func stockGCPBucketMetadata(ctx context.Context, setup *gcpSetup, settings liveSettings, fixture records.StockPluginFixture) (*storage.Bucket, string, error) {
	requestCtx, op, err := setup.begin(ctx, setup.storageHost, telemetry.OpSetupRead)
	if err != nil {
		return nil, "", err
	}
	bucket, err := setup.storage.Buckets.Get(setup.bucket).Projection("noAcl").Context(requestCtx).Do()
	if err != nil || op.status != http.StatusOK || !gcpBucketAdmitted(bucket, settings) || bucket.Metageneration <= 0 {
		return nil, "", op.fail("configuration_check", "ownership_mismatch", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, bucket.TimeCreated); err != nil {
		return nil, "", op.fail("configuration_check", "malformed_envelope", nil)
	}
	// Preserve the original bucket creation and configuration observation;
	// object changes do not change bucket metageneration.
	id := contract.Hash([]byte("enkv/test/stock-gcs/v1\x00" + fixture.FixtureID + "\x00" + fixture.ProjectNumber + "\x00" + fixture.Region + "\x00" + fixture.Bucket + "\x00" + bucket.TimeCreated + "\x00" + strconv.FormatInt(bucket.Metageneration, 10)))
	return bucket, hex.EncodeToString(id[:]), nil
}

func stockGCPPrefixObjects(ctx context.Context, setup *gcpSetup, prefix string) ([]*storage.Object, error) {
	var objects []*storage.Object
	seen, tokens := map[string]bool{}, map[string]bool{}
	next := ""
	for page := 0; page < operatorPrefixPages; page++ {
		requestCtx, op, err := setup.begin(ctx, setup.storageHost, telemetry.OpSetupRead)
		if err != nil {
			return nil, err
		}
		op.bodyLimit = operatorPrefixBodyLimit
		request := setup.storage.Objects.List(setup.bucket).MaxResults(operatorPrefixPageKeys).Projection("noAcl").Versions(true).Prefix(prefix + "/")
		if next != "" {
			request = request.PageToken(next)
		}
		out, err := request.Context(requestCtx).Do()
		if err != nil || out == nil || op.status != http.StatusOK || out.Kind != "storage#objects" || len(out.Prefixes) != 0 || len(out.Items) > operatorPrefixPageKeys {
			return nil, op.fail("ownership_read", "malformed_envelope", err)
		}
		for _, object := range out.Items {
			if !stockGCPOwnedObject(setup, object) || seen[object.Name] || len(objects) >= operatorPrefixObjects {
				return nil, op.fail("ownership_check", "ownership_mismatch", nil)
			}
			seen[object.Name] = true
			objects = append(objects, object)
		}
		if out.NextPageToken == "" {
			return objects, nil
		}
		next = out.NextPageToken
		if len(next) > operatorPrefixTokenMax || tokens[next] {
			return nil, errInventory
		}
		tokens[next] = true
	}
	return nil, errRunLimit
}

func stockGCPOwnedObject(setup *gcpSetup, object *storage.Object) bool {
	return object != nil && object.Bucket == setup.bucket && setup.validKey(object.Name) && object.Generation > 0 &&
		object.Size > 0 && object.Size <= 2<<20 && !object.EventBasedHold && !object.TemporaryHold && object.Retention == nil && object.SoftDeleteTime == ""
}

func stockGCPReadOwnedObject(ctx context.Context, setup *gcpSetup, media *storage.Service, object *storage.Object) error {
	if !stockGCPOwnedObject(setup, object) {
		return errInventory
	}
	requestCtx, op, err := setup.begin(ctx, setup.storageHost, telemetry.OpSetupRead)
	if err != nil {
		return err
	}
	op.bodyLimit = 2 << 20
	response, err := media.Objects.Get(setup.bucket, object.Name).Generation(object.Generation).IfGenerationMatch(object.Generation).Context(requestCtx).Download()
	if err != nil || response == nil || response.Body == nil {
		return op.fail("ownership_read", "evidence_unavailable", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	closeErr := response.Body.Close()
	defer clear(body)
	if readErr != nil || closeErr != nil || op.status != http.StatusOK || uint64(len(body)) != object.Size || gcpChecksum(body) != object.Crc32c {
		return op.fail("ownership_read", "ownership_mismatch", errors.Join(readErr, closeErr))
	}
	return nil
}

func stockGCPOutputRequest(ctx context.Context, input liveRunInput, budget *runBudget, directory, role, target, suffix string) (int, []byte, error) {
	if ctx == nil {
		return 0, nil, errInventory
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return 0, nil, errInventory
	}
	prefix := "projects/" + input.Settings.ProjectNumber + "/secrets/"
	name, valid := strings.CutPrefix(target, prefix)
	if !valid || !slices.Contains(publicOutputNames(input.Prefix), name) || budget == nil {
		return 0, nil, errInventory
	}
	restore, err := publicSDKEnvironment(input, role, directory)
	if err != nil {
		return 0, nil, err
	}
	defer restore()
	source, err := gcp.LoadDefaultCredentials(ctx)
	if err != nil {
		return 0, nil, err
	}
	captured, err := gcp.CaptureCredentials(ctx, source)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	u := &url.URL{Scheme: "https", Host: "secretmanager.googleapis.com", Path: "/v1/" + target + suffix}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, errInventory
	}
	request.Header.Set("Authorization", "Bearer "+captured.Token)
	if captured.QuotaProject != "" {
		request.Header.Set("X-Goog-User-Project", captured.QuotaProject)
	}
	transport := &gcpOutputTransport{base: stockGCPTransport(), budget: budget}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return 0, nil, err
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		clear(body)
		return response.StatusCode, nil, errInventory
	}
	return response.StatusCode, body, nil
}

func readStockCloudOutput(ctx context.Context, input liveRunInput, budget *runBudget, directory, target string) (stockCloudOutputRead, error) {
	status, body, err := stockGCPOutputRequest(ctx, input, budget, directory, "consumer", target, "/versions/latest:access")
	defer clear(body)
	if err != nil {
		return stockCloudOutputRead{}, err
	}
	if status != http.StatusOK {
		return stockCloudOutputRead{}, gcpOutputResponseFailure(status, "provider_refused", "no_effect")
	}
	return stockGCPOutputValue(body, target)
}

func stockGCPOutputValue(body []byte, target string) (stockCloudOutputRead, error) {
	fields, valid := gcpOutputObject(body)
	payload, payloadValid := gcpOutputObject(fields["payload"])
	var name string
	var data, checksum *string
	if !valid || !payloadValid || json.Unmarshal(fields["name"], &name) != nil || !gcpOutputVersion(target, name) ||
		json.Unmarshal(payload["data"], &data) != nil || data == nil || json.Unmarshal(payload["dataCrc32c"], &checksum) != nil || checksum == nil {
		return stockCloudOutputRead{}, errInventory
	}
	value, err := base64.StdEncoding.Strict().DecodeString(*data)
	crc, crcErr := strconv.ParseUint(*checksum, 10, 32)
	if err != nil || len(value) == 0 || len(value) > 65536 || base64.StdEncoding.EncodeToString(value) != *data || crcErr != nil ||
		strconv.FormatUint(crc, 10) != *checksum || uint32(crc) != crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli)) {
		clear(value)
		return stockCloudOutputRead{}, errInventory
	}
	return stockCloudOutputRead{Bytes: value, Instance: name}, nil
}

func verifyStockCloudOutputDeleted(ctx context.Context, input liveRunInput, budget *runBudget, directory, target string) (stockCloudOutputDeletion, error) {
	status, body, err := stockGCPOutputRequest(ctx, input, budget, directory, "cleanup", target, "")
	defer clear(body)
	if err != nil {
		return stockCloudOutputDeletion{}, err
	}
	if !gcpOutputErrorEnvelope(status, body, http.StatusNotFound, "NOT_FOUND") {
		return stockCloudOutputDeletion{}, gcpOutputResponseFailure(status, "evidence_unavailable", "no_effect")
	}
	return stockCloudOutputDeletion{Disposition: "absent", Instance: target}, nil
}

// full_only: false
func TestStockGCPOutputReaderRequiresCompleteOwnedValue(t *testing.T) {
	const target = "projects/123456789012/secrets/ENKV_TEST_SECRET"
	// Root derived 1259731357 from these literal bytes with a separate Python
	// bitwise Castagnoli calculation (0x82f63b78, initial/final XOR 0xffffffff).
	const good = `{"name":"projects/123456789012/secrets/ENKV_TEST_SECRET/versions/7","payload":{"data":"Y29tcGxldGUgcHJpdmF0ZSB2YWx1ZQ==","dataCrc32c":"1259731357"}}`
	for _, tc := range []struct {
		name, body string
		good       bool
	}{
		{"complete", good, true},
		{"wrong-project", strings.Replace(good, "123456789012", "000000000000", 1), false},
		{"wrong-secret", strings.Replace(good, "ENKV_TEST_SECRET", "ENKV_OTHER_SECRET", 1), false},
		{"alias-not-version", strings.Replace(good, "/versions/7", "/versions/latest", 1), false},
		{"wrong-crc", strings.Replace(good, "1259731357", "0", 1), false},
		{"duplicate-data", strings.Replace(good, `"data":`, `"data":"eA==","data":`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read, err := stockGCPOutputValue([]byte(tc.body), target)
			defer clear(read.Bytes)
			if (err == nil) != tc.good || tc.good && (string(read.Bytes) != "complete private value" || read.Instance != target+"/versions/7") {
				t.Fatal("independent output value or exact ownership differs")
			}
		})
	}
}

// This checks the standard local ADC route without obtaining a bearer. The
// existing provider loader still owns credential resolution during execution.
func validateStockSDKContext(input liveRunInput, role string) error {
	if input.PublicConfiguration == nil {
		return errInventory
	}
	actor, ok := input.PublicConfiguration.Actors[role]
	if !ok || actor.SDKMode != "gcp-impersonated-adc" || !filepath.IsAbs(actor.SDKHome) {
		return errInventory
	}
	body, err := ReadLocalProtectedFile(context.Background(), filepath.Join(actor.SDKHome, ".config", "gcloud", "application_default_credentials.json"), 64<<10)
	if err != nil {
		return errInventory
	}
	defer clear(body)
	if !stockGCPContextUsesUserADC(body) {
		return errInventory
	}
	return nil
}

func stockGCPContextUsesUserADC(body []byte) bool {
	fields, valid := gcpOutputObject(body)
	if !valid {
		return false
	}
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	var kind, impersonation string
	if json.Unmarshal(fields["type"], &kind) != nil || kind != "impersonated_service_account" ||
		json.Unmarshal(fields["service_account_impersonation_url"], &impersonation) != nil {
		return false
	}
	u, err := url.Parse(impersonation)
	if err != nil || u.Scheme != "https" || u.Host != "iamcredentials.googleapis.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	account, found := strings.CutPrefix(u.Path, "/v1/projects/-/serviceAccounts/")
	account, end := strings.CutSuffix(account, ":generateAccessToken")
	if !found || !end || !gcpOutputEmail.MatchString(account) {
		return false
	}
	source, valid := gcpOutputObject(fields["source_credentials"])
	if !valid {
		return false
	}
	defer func() {
		for _, value := range source {
			clear(value)
		}
	}()
	return json.Unmarshal(source["type"], &kind) == nil && kind == "authorized_user"
}

// full_only: false
func TestStockGCPContextRequiresImpersonatedUserADC(t *testing.T) {
	const good = `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/apply@fixture-project.iam.gserviceaccount.com:generateAccessToken","source_credentials":{"type":"authorized_user","client_id":"synthetic","client_secret":"synthetic","refresh_token":"synthetic"}}`
	for _, tc := range []struct {
		name, body string
		good       bool
	}{
		{"normal", good, true},
		{"service-account-seed", strings.Replace(good, `"type":"authorized_user"`, `"type":"service_account"`, 1), false},
		{"external-source", strings.Replace(good, `"type":"authorized_user"`, `"type":"external_account"`, 1), false},
		{"other-endpoint", strings.Replace(good, "iamcredentials.googleapis.com", "other.invalid", 1), false},
		{"duplicate-type", strings.Replace(good, `"type":"authorized_user"`, `"type":"service_account","type":"authorized_user"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if stockGCPContextUsesUserADC([]byte(tc.body)) != tc.good {
				t.Fatal("ADC source route differs")
			}
		})
	}
}

// full_only: false
func TestStockGCPStorePrefixRequiresOriginalGrantAndConditionalCleanup(t *testing.T) {
	for _, condition := range []string{"empty", "owned-object", "multiple-pages", "later-page-foreign", "foreign-object", "damaged-object", "wrong-success-status", "lost-reply", "condition-failed", "late-object", "changed-generation", "wrong-original", "wrong-original-prefix", "soft-delete", "occupied-prefix", "bounded-read", "repeated-page"} {
		t.Run(condition, func(t *testing.T) {
			fixture := records.StockPluginFixture{Schema: 1, Purpose: "stock-plugin-acceptance", FixtureID: "0123456789abcdef0123456789abcdef", Provider: "gcp", Region: "us-central1", Project: "fixture-project", ProjectNumber: "123456789012", Bucket: "fixture-pa-0123456789abcdef0123456789abcdef"}
			settings := liveSettings{Provider: "gcp", Bucket: fixture.Bucket, Project: fixture.Project, ProjectNumber: fixture.ProjectNumber, Region: fixture.Region}
			input := liveRunInput{Settings: settings, RecoveryMode: "enabled", RunID: "abcdef0123456789abcdef0123456789", Prefix: "enkv-test/abcdef0123456789abcdef0123456789/plugin-contracts", Scenarios: []string{records.StockPluginScenario}, PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Fixture: fixture}}}
			metadata := gcpAdmittedTestBucket()
			metadata.Name, metadata.ProjectNumber, metadata.Metageneration, metadata.TimeCreated = fixture.Bucket, 123456789012, 1, "2026-10-31T00:00:00Z"
			if condition == "soft-delete" {
				metadata.SoftDeletePolicy.RetentionDurationSeconds = 604800
			}
			firstKey := input.Prefix + "/HEAD"
			secondKey := input.Prefix + "/" + strings.Repeat("1", 64) + "/root/0/" + strings.Repeat("2", 64)
			objects := map[string]bool{}
			if condition == "occupied-prefix" {
				objects[firstKey] = true
			}
			requests, reads, deletes, secondPages := 0, 0, 0, 0
			cleaning := false
			base := gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.URL.Host != "storage.us-central1.rep.googleapis.com" {
					t.Error("Store operation changed the exact regional route")
				}
				if strings.HasSuffix(r.URL.Path, "/o") {
					if r.URL.Query().Get("prefix") != input.Prefix+"/" || r.URL.Query().Get("versions") != "true" {
						t.Error("Store listing escaped the exact run prefix")
					}
					current := r.URL.Query().Get("pageToken")
					if current != "" {
						secondPages++
					}
					var listed []string
					for _, key := range []string{firstKey, secondKey} {
						if objects[key] {
							listed = append(listed, key)
						}
					}
					next := ""
					if condition == "repeated-page" {
						listed, next = nil, "repeat"
					} else if cleaning && len(listed) > 0 {
						switch condition {
						case "foreign-object":
							listed = []string{input.Prefix + "-sibling/HEAD"}
						case "multiple-pages", "later-page-foreign":
							if current == "" {
								listed, next = listed[:1], "second"
							} else if condition == "later-page-foreign" {
								listed = []string{input.Prefix + "-sibling/HEAD"}
							} else {
								listed = listed[1:]
							}
						}
					}
					var items []*storage.Object
					for _, key := range listed {
						// Published CRC32C check vector: "123456789" -> e3069283.
						items = append(items, &storage.Object{Bucket: fixture.Bucket, Name: key, Generation: 7, Size: 9, Crc32c: "4waSgw=="})
					}
					body, err := json.Marshal(&storage.Objects{Kind: "storage#objects", Items: items, NextPageToken: next})
					if err != nil {
						t.Fatal("controlled prefix listing encoding failed")
					}
					return gcpSetupReply(http.StatusOK, string(body)), nil
				}
				if _, key, found := strings.Cut(r.URL.Path, "/o/"); found && objects[key] {
					if r.URL.Query().Get("generation") != "7" || r.URL.Query().Get("ifGenerationMatch") != "7" {
						t.Error("Store cleanup lost the exact observed object generation")
					}
					switch r.Method {
					case http.MethodGet:
						reads++
						if !strings.HasPrefix(r.URL.Path, "/download/storage/v1/") || r.URL.Query().Get("alt") != "media" {
							t.Error("Store read changed the regional download route")
						}
						body := "123456789"
						if condition == "damaged-object" {
							body = "123456788"
						}
						return gcpSetupReply(http.StatusOK, body), nil
					case http.MethodDelete:
						deletes++
						if condition == "condition-failed" {
							return gcpSetupReply(http.StatusPreconditionFailed, `{"error":{"code":412}}`), nil
						}
						delete(objects, key)
						if condition == "lost-reply" {
							return nil, errors.New("controlled object reply loss")
						}
						if condition == "late-object" {
							objects[firstKey] = true
						}
						if condition == "wrong-success-status" {
							return gcpSetupReply(http.StatusOK, ""), nil
						}
						return gcpSetupReply(http.StatusNoContent, ""), nil
					}
				}
				if r.Method == http.MethodDelete {
					t.Error("Store cleanup attempted a bucket or foreign-object deletion")
					return gcpSetupReply(http.StatusForbidden, `{"error":{"code":403}}`), nil
				}
				body, err := json.Marshal(metadata)
				if err != nil {
					t.Fatal("controlled bucket metadata encoding failed")
				}
				return gcpSetupReply(http.StatusOK, string(body)), nil
			})
			setup, err := newGCPSetup(context.Background(), &gcpSetupCredential{}, stockGCPBudgetTransport{base: base}, fixture.Bucket, input.Prefix, contract.Hash([]byte("domain")), "https://storage.us-central1.rep.googleapis.com/storage/v1/", "https://us-central1-cloudkms.googleapis.com/")
			if err != nil {
				t.Fatal("controlled provider construction failed")
			}
			store, err := stockGCPStorePrefix(input, setup, nil)
			if err != nil {
				t.Fatal("fixture construction refused")
			}
			budget := &runBudget{limits: liveLimits{Requests: 1000, BodyBytes: 256 << 20}, keys: map[string]bool{}}
			if condition == "bounded-read" {
				budget.limits.Requests = 0
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			original, err := store.Inspect(ctx, budget)
			if condition == "occupied-prefix" {
				if err != nil || original.Empty || deletes != 0 {
					t.Fatal("occupied prefix did not refuse empty preflight")
				}
				return
			}
			if condition == "soft-delete" || condition == "bounded-read" || condition == "repeated-page" {
				if err == nil || deletes != 0 || condition == "bounded-read" && requests != 0 || condition == "repeated-page" && requests > 3 {
					t.Fatal("unqualified or incomplete prefix preflight acquired authority")
				}
				return
			}
			if err != nil || !original.Empty || original.Prefix != input.Prefix {
				t.Fatal("empty run prefix was not observed")
			}
			if empty, err := store.Clean(ctx, budget); empty || err == nil || deletes != 0 {
				t.Fatal("read-only inspection granted cleanup authority")
			}
			if condition == "wrong-original" {
				original.Identity = strings.Repeat("0", 64)
			} else if condition == "wrong-original-prefix" {
				original.Prefix += "-sibling"
			}
			cleanup, err := stockGCPStorePrefix(input, setup, &original)
			if condition == "wrong-original-prefix" {
				if err == nil || deletes != 0 {
					t.Fatal("another prefix's original grant was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("original prefix grant refused")
			}
			if condition == "changed-generation" {
				metadata.Metageneration = 2
			}
			cleaning = true
			if condition != "empty" {
				objects[firstKey] = true
			}
			if condition == "multiple-pages" || condition == "later-page-foreign" {
				objects[secondKey] = true
			}
			empty, err := cleanup.Clean(ctx, budget)
			wantEmpty := condition == "empty" || condition == "owned-object" || condition == "multiple-pages"
			if empty != wantEmpty || (err == nil) != wantEmpty {
				t.Fatal("cleanup result did not preserve the exact prefix observation", condition)
			}
			if (condition == "foreign-object" || condition == "later-page-foreign" || condition == "wrong-original" || condition == "changed-generation") && (reads != 0 || deletes != 0) {
				t.Fatal("unqualified listing or bucket reached object read or delete")
			}
			if condition == "damaged-object" && deletes != 0 {
				t.Fatal("damaged complete object read reached deletion")
			}
			if (condition == "multiple-pages" || condition == "later-page-foreign") && secondPages != 1 {
				t.Fatal("later prefix page was not checked")
			}
			before := deletes
			if empty, err := cleanup.Clean(ctx, budget); empty || err == nil || deletes != before {
				t.Fatal("completed or uncertain prefix cleanup was repeated")
			}
		})
	}
}

// full_only: false
func TestStockGCPStorePrefixKeepsBucketReusableAcrossRuns(t *testing.T) {
	fixture := records.StockPluginFixture{Schema: 1, Purpose: "stock-plugin-acceptance", FixtureID: "0123456789abcdef0123456789abcdef", Provider: "gcp", Region: "us-central1", Project: "fixture-project", ProjectNumber: "123456789012", Bucket: "fixture-pa-0123456789abcdef0123456789abcdef"}
	settings := liveSettings{Provider: "gcp", Bucket: fixture.Bucket, Project: fixture.Project, ProjectNumber: fixture.ProjectNumber, Region: fixture.Region}
	metadata := gcpAdmittedTestBucket()
	metadata.Name, metadata.ProjectNumber, metadata.Metageneration, metadata.TimeCreated = fixture.Bucket, 123456789012, 1, "2026-10-31T00:00:00Z"
	const firstRun = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const secondRun = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	firstPrefix := "enkv-test/" + firstRun + "/plugin-contracts"
	siblingKey := firstPrefix + "-sibling/HEAD"
	objects := map[string]bool{siblingKey: true}
	activePrefix := ""
	bucketDeletes := 0
	base := gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "storage.us-central1.rep.googleapis.com" {
			t.Error("Store operation changed the configured regional route")
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/storage/v1/b/"+fixture.Bucket {
			bucketDeletes++
			return gcpSetupReply(http.StatusForbidden, `{"error":{"code":403}}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/o") {
			prefix := r.URL.Query().Get("prefix")
			if prefix != activePrefix+"/" || r.URL.Query().Get("versions") != "true" {
				t.Error("Store listing escaped the exact run prefix")
			}
			var listed []*storage.Object
			for key := range objects {
				if strings.HasPrefix(key, prefix) {
					// Published CRC32C check vector: "123456789" -> e3069283.
					listed = append(listed, &storage.Object{Bucket: fixture.Bucket, Name: key, Generation: 7, Size: 9, Crc32c: "4waSgw=="})
				}
			}
			body, err := json.Marshal(&storage.Objects{Kind: "storage#objects", Items: listed})
			if err != nil {
				t.Fatal("controlled prefix listing encoding failed")
			}
			return gcpSetupReply(http.StatusOK, string(body)), nil
		}
		if _, key, found := strings.Cut(r.URL.Path, "/o/"); found && objects[key] {
			if key != activePrefix+"/HEAD" {
				t.Error("Store cleanup touched a different run or sibling prefix")
			}
			if r.URL.Query().Get("generation") != "7" || r.URL.Query().Get("ifGenerationMatch") != "7" {
				t.Error("Store cleanup lost the observed object generation")
			}
			switch r.Method {
			case http.MethodGet:
				return gcpSetupReply(http.StatusOK, "123456789"), nil
			case http.MethodDelete:
				delete(objects, key)
				return gcpSetupReply(http.StatusNoContent, ""), nil
			}
		}
		body, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal("controlled bucket metadata encoding failed")
		}
		return gcpSetupReply(http.StatusOK, string(body)), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, runID := range []string{firstRun, secondRun} {
		activePrefix = "enkv-test/" + runID + "/plugin-contracts"
		input := liveRunInput{Settings: settings, RecoveryMode: "enabled", RunID: runID, Prefix: activePrefix, Scenarios: []string{records.StockPluginScenario}, PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Fixture: fixture}}}
		setup, err := newGCPSetup(ctx, &gcpSetupCredential{}, stockGCPBudgetTransport{base: base}, fixture.Bucket, input.Prefix, contract.Hash([]byte("domain")), "https://storage.us-central1.rep.googleapis.com/storage/v1/", "https://us-central1-cloudkms.googleapis.com/")
		if err != nil {
			t.Fatal("controlled provider construction failed")
		}
		bucket, err := stockGCPStorePrefix(input, setup, nil)
		if err != nil {
			t.Fatal("reusable Store construction refused")
		}
		budget := &runBudget{limits: liveLimits{Requests: 1000, BodyBytes: 256 << 20}, keys: map[string]bool{}}
		original, err := bucket.Inspect(ctx, budget)
		if err != nil || !original.Empty || original.Identity == "" {
			t.Fatal("fresh run prefix was refused in a reusable bucket")
		}
		objects[activePrefix+"/HEAD"] = true
		cleanup, err := stockGCPStorePrefix(input, setup, &original)
		if err != nil {
			t.Fatal("original empty-prefix observation was refused")
		}
		if empty, err := cleanup.Clean(ctx, budget); err != nil || !empty || objects[activePrefix+"/HEAD"] {
			t.Fatal("run prefix cleanup did not observe exact absence")
		}
		if !objects[siblingKey] || bucketDeletes != 0 {
			t.Fatal("run prefix cleanup consumed shared infrastructure or another prefix")
		}
		objects[activePrefix+"/HEAD"] = true
	}
	if !objects[firstPrefix+"/HEAD"] || !objects[siblingKey] || bucketDeletes != 0 {
		t.Fatal("later run removed an old late arrival or deleted its bucket")
	}
}
