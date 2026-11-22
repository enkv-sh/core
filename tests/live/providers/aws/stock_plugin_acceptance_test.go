package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	awsprovider "enkv.sh/providers/aws"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"
)

type stockAWSBudgetKey struct{}

type stockAWSBudgetTransport struct{ base http.RoundTripper }

func (t stockAWSBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	budget, _ := r.Context().Value(stockAWSBudgetKey{}).(*runBudget)
	limit := int64(awsSetupLimit)
	if op := awsSetupOperationFrom(r.Context()); op != nil && op.bodyLimit > 0 {
		limit = op.bodyLimit
	}
	if budget == nil || !budget.reserve(1, uint64(limit), "", 0) {
		return nil, errRunLimit
	}
	return t.base.RoundTrip(r)
}

func stockAWSFixture(input liveRunInput) (records.StockPluginFixture, error) {
	if input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil {
		return records.StockPluginFixture{}, errInventory
	}
	f, s := input.PublicConfiguration.Stock.Fixture, input.Settings
	if f.Validate() != nil || f.Provider != "aws" || s.Provider != f.Provider || s.Bucket != f.Bucket ||
		s.Account != f.Account || s.Region != f.Region || input.RecoveryMode != "enabled" ||
		!records.ValidRunID(input.RunID) || !strings.HasPrefix(input.Prefix, "enkv-test/"+input.RunID+"/") ||
		!slices.Equal(input.Scenarios, []string{records.StockPluginScenario}) {
		return records.StockPluginFixture{}, errInventory
	}
	return f, nil
}

func openStockStorePrefix(ctx context.Context, input liveRunInput, directory string, original *stockPrefixInspection) (*stockStorePrefix, error) {
	if ctx == nil {
		return nil, errInventory
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return nil, errInventory
	}
	if fixture, err := stockAWSFixture(input); err != nil || fixture.Purpose == records.StockRetirementProofPurpose && input.StockRecovery != nil {
		return nil, errInventory
	}
	restore, err := publicSDKEnvironment(input, "cleanup", directory)
	if err != nil {
		return nil, err
	}
	defer restore()
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, input.Settings.Region)
	if err != nil {
		return nil, err
	}
	setup := newAWSSetup(input.Settings, input.Prefix, contract.Hash([]byte(input.Prefix)), nil, credentials,
		&http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second})
	return stockAWSStorePrefix(input, setup, original)
}

func stockAWSStorePrefix(input liveRunInput, setup *awsSetup, original *stockPrefixInspection) (*stockStorePrefix, error) {
	f, err := stockAWSFixture(input)
	if err != nil || setup == nil || setup.settings.Bucket != f.Bucket || setup.settings.Account != f.Account || setup.settings.Region != f.Region || setup.head != input.Prefix+"/HEAD" {
		return nil, errInventory
	}
	setup.client.Transport = stockAWSBudgetTransport{setup.transport}
	// S3 exposes no bucket-incarnation token here. The identity binds the
	// explicit fixture route; actual ownership/configuration is checked below.
	versioned := f.Purpose == records.StockRetirementProofPurpose
	fixtureType := "enkv/test/stock-s3/v1"
	var versioning s3types.BucketVersioningStatus
	if versioned {
		fixtureType = "enkv/test/stock-s3-history/v1"
		versioning = s3types.BucketVersioningStatusEnabled
	}
	id := contract.Hash([]byte(fixtureType + "\x00" + f.FixtureID + "\x00" + f.Account + "\x00" + f.Region + "\x00" + f.Bucket))
	identity := hex.EncodeToString(id[:])
	var admitted *stockPrefixInspection
	if original != nil {
		if !original.Empty || original.Identity != identity || original.Prefix != input.Prefix {
			return nil, errInventory
		}
		copy := *original
		admitted = &copy
	}
	setup.ownedKey = func(key string) bool { return publicObjectKeyLimit(input.Prefix, key) > 0 }
	inspect := func(ctx context.Context, budget *runBudget) (stockPrefixInspection, error) {
		ctx = context.WithValue(ctx, stockAWSBudgetKey{}, budget)
		if err := setup.checkBucketVersioning(ctx, versioning); err != nil {
			return stockPrefixInspection{}, err
		}
		if versioned {
			items, err := stockS3ListVersions(ctx, setup, input.Prefix+"/", false)
			if err != nil {
				return stockPrefixInspection{}, err
			}
			return stockPrefixInspection{Empty: len(items) == 0, Identity: identity, Prefix: input.Prefix}, nil
		}
		keys, err := stockAWSPrefixKeys(ctx, setup, input.Prefix)
		if err != nil {
			return stockPrefixInspection{}, err
		}
		return stockPrefixInspection{Empty: len(keys) == 0, Identity: identity, Prefix: input.Prefix}, nil
	}
	attempted := false
	store := &stockStorePrefix{Inspect: inspect, Clean: func(ctx context.Context, budget *runBudget) (bool, error) {
		if attempted || admitted == nil || versioned {
			return false, errInventory
		}
		attempted = true
		ctx = context.WithValue(ctx, stockAWSBudgetKey{}, budget)
		if err := setup.checkBucket(ctx); err != nil {
			return false, err
		}
		keys, err := stockAWSPrefixKeys(ctx, setup, input.Prefix)
		if err != nil {
			return false, err
		}
		for _, key := range keys {
			token, err := stockAWSObservedObject(ctx, setup, key)
			if err != nil {
				return false, err
			}
			if err := setup.delete(ctx, key, token); err != nil {
				return false, err
			}
		}
		remaining, err := stockAWSPrefixKeys(ctx, setup, input.Prefix)
		if err != nil {
			return false, err
		}
		if len(remaining) != 0 {
			return false, errInventory
		}
		return true, nil
	}}
	if versioned && admitted != nil && input.StockRecovery == nil {
		store.CleanHistory = func(ctx context.Context, budget *runBudget, basis PublicBasis, domain contract.ID, evidence records.StockPluginEvidence, directory string) (bool, error) {
			if attempted || budget == nil || domain.IsZero() || evidence.RunID != input.RunID || evidence.Prefix != input.Prefix || !stockProviderWorkClosed(evidence) || evidence.ValidateBeforeCleanup(*input.PublicConfiguration.Stock) != nil {
				return false, errInventory
			}
			attempted = true
			ctx = context.WithValue(ctx, stockAWSBudgetKey{}, budget)
			if err := setup.checkBucketVersioning(ctx, versioning); err != nil {
				return false, err
			}
			s := input.Settings
			reader, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: s.Region, Bucket: s.Bucket, ExpectedBucketOwner: s.Account, Prefix: input.Prefix, Domain: domain, CredentialRoute: contract.Hash([]byte("enkv/test/public-get-only/aws/v1")), Credentials: setup.credentials, Transport: setup.transport.base, Timeout: time.Minute})
			if err != nil {
				return false, errInventory
			}
			observed := recordedStore{Store: reader, budget: budget}
			admission, result := admitPublicNormal(ctx, domain, observed.Descriptor(), basis, observed, contract.Hash([]byte("enkv/composition/full/v1")), nil)
			if result.Outcome != ObservedCurrent {
				return false, errInventory
			}
			selected, result := Open(ctx, admission, observed)
			if result.Outcome != ObservedCurrent || selected == nil || selected.root.Domain != domain {
				return false, errInventory
			}
			items, err := stockS3ListVersions(ctx, setup, input.Prefix+"/", false)
			if err != nil {
				return false, err
			}
			err = stockS3RetainQualifiedHistory(ctx, selected, *input.PublicConfiguration.Stock, evidence, items, directory, func(ctx context.Context, item stockS3Version) (contract.ReadResult, error) {
				return stockS3ReadVersion(ctx, setup, item)
			})
			if err != nil {
				return false, err
			}
			return stockS3PurgeVersions(ctx, setup, input.Prefix, items)
		}
	}
	return store, nil
}

func stockAWSPrefixKeys(ctx context.Context, setup *awsSetup, prefix string) ([]string, error) {
	var keys []string
	seen, tokens := map[string]bool{}, map[string]bool{}
	next := ""
	for page := 0; page < operatorPrefixPages; page++ {
		requestCtx, cancel, credentials, err := setup.begin(ctx, "s3", telemetry.OpSetupRead)
		if err != nil {
			cancel()
			return nil, err
		}
		op := awsSetupOperationFrom(requestCtx)
		op.bodyLimit = operatorPrefixBodyLimit
		request := &s3.ListObjectsV2Input{Bucket: aws.String(setup.settings.Bucket), ExpectedBucketOwner: aws.String(setup.settings.Account), MaxKeys: aws.Int32(operatorPrefixPageKeys), Prefix: aws.String(prefix + "/")}
		if next != "" {
			request.ContinuationToken = aws.String(next)
		}
		out, err := setup.s3(credentials).ListObjectsV2(requestCtx, request)
		cancel()
		if err != nil || out == nil || op.status.Load() != http.StatusOK || aws.ToString(out.Name) != setup.settings.Bucket ||
			aws.ToString(out.Prefix) != prefix+"/" || out.KeyCount == nil || int(*out.KeyCount) != len(out.Contents) || out.IsTruncated == nil ||
			aws.ToInt32(out.MaxKeys) != operatorPrefixPageKeys || len(out.Contents) > operatorPrefixPageKeys || len(out.CommonPrefixes) != 0 ||
			out.Delimiter != nil || out.EncodingType != "" || aws.ToString(out.ContinuationToken) != next {
			return nil, awsSetupFailureFor(requestCtx, errAWSSetup, "ownership_read", "malformed_envelope", err)
		}
		for _, item := range out.Contents {
			key := aws.ToString(item.Key)
			if !setup.validKey(key) || seen[key] || item.Size == nil || *item.Size <= 0 || *item.Size > 2<<20 || len(keys) >= operatorPrefixObjects {
				return nil, awsSetupFailureFor(requestCtx, errAWSSetup, "ownership_check", "ownership_mismatch", nil)
			}
			seen[key] = true
			keys = append(keys, key)
		}
		if !*out.IsTruncated {
			if out.NextContinuationToken != nil {
				return nil, errInventory
			}
			return keys, nil
		}
		next = aws.ToString(out.NextContinuationToken)
		if next == "" || len(next) > operatorPrefixTokenMax || tokens[next] {
			return nil, errInventory
		}
		tokens[next] = true
	}
	return nil, errRunLimit
}

func stockAWSObservedObject(ctx context.Context, setup *awsSetup, key string) (contract.Token, error) {
	if !setup.validKey(key) {
		return contract.Token{}, errInventory
	}
	requestCtx, cancel, credentials, err := setup.begin(ctx, "s3", telemetry.OpSetupRead)
	defer cancel()
	if err != nil {
		return contract.Token{}, err
	}
	op := awsSetupOperationFrom(requestCtx)
	op.bodyLimit = 2 << 20
	out, err := setup.s3(credentials).GetObject(requestCtx, &s3.GetObjectInput{Bucket: aws.String(setup.settings.Bucket), ExpectedBucketOwner: aws.String(setup.settings.Account), Key: aws.String(key)})
	if err != nil || out == nil || out.Body == nil {
		return contract.Token{}, awsSetupFailureFor(requestCtx, errAWSSetup, "ownership_read", "evidence_unavailable", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(out.Body, (2<<20)+1))
	closeErr := out.Body.Close()
	defer clear(body)
	token := contract.Token{Family: contract.AWS, Value: aws.ToString(out.ETag)}
	if readErr != nil || closeErr != nil || len(body) == 0 || len(body) > 2<<20 || out.ContentLength == nil || *out.ContentLength != int64(len(body)) ||
		op.status.Load() != http.StatusOK || !token.Valid() ||
		aws.ToString(out.VersionId) != "" || aws.ToBool(out.DeleteMarker) {
		return contract.Token{}, awsSetupFailureFor(requestCtx, errAWSSetup, "ownership_read", "ownership_mismatch", errors.Join(readErr, closeErr))
	}
	return token, nil
}

func stockAWSOutputClient(ctx context.Context, input liveRunInput, budget *runBudget, directory, role, target string) (*awsLiveOutput, aws.Credentials, string, error) {
	if ctx == nil {
		return nil, aws.Credentials{}, "", errInventory
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return nil, aws.Credentials{}, "", errInventory
	}
	s := input.Settings
	prefix := "arn:aws:secretsmanager:" + s.Region + ":" + s.Account + ":secret:"
	name, found := strings.CutPrefix(target, prefix)
	if !found || !slices.Contains(publicOutputNames(input.Prefix), name) || budget == nil {
		return nil, aws.Credentials{}, "", errInventory
	}
	restore, err := publicSDKEnvironment(input, role, directory)
	if err != nil {
		return nil, aws.Credentials{}, "", err
	}
	defer restore()
	source, err := awsprovider.LoadDefaultCredentials(ctx, s.Region)
	if err != nil {
		return nil, aws.Credentials{}, "", err
	}
	credentials, err := source.Retrieve(ctx)
	if err != nil || !credentials.HasKeys() || credentials.CanExpire && !time.Now().Before(credentials.Expires) {
		return nil, aws.Credentials{}, "", errInventory
	}
	return &awsLiveOutput{location: liveOutputLocation{Provider: "aws", Region: s.Region, Account: s.Account, SecretNamePrefix: "ENKV_"}, budget: budget,
		transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableKeepAlives: true, DisableCompression: true}}, credentials, name, nil
}

func readStockCloudOutput(ctx context.Context, input liveRunInput, budget *runBudget, directory, target string) (stockCloudOutputRead, error) {
	client, credentials, name, err := stockAWSOutputClient(ctx, input, budget, directory, "consumer", target)
	if err != nil {
		return stockCloudOutputRead{}, err
	}
	response, op, err := client.secretRequest(ctx, credentials, "GetSecretValue", struct {
		SecretID string `json:"SecretId"`
		Stage    string `json:"VersionStage"`
	}{name, "AWSCURRENT"}, awsOutputReplyLimit, false, "configuration_check")
	if err != nil {
		return stockCloudOutputRead{}, err
	}
	defer clear(response.body)
	if response.status != http.StatusOK {
		return stockCloudOutputRead{}, op.failure("provider_refused", nil)
	}
	return stockAWSOutputValue(response.body, client, name)
}

func stockAWSOutputValue(body []byte, client *awsLiveOutput, name string) (stockCloudOutputRead, error) {
	if _, err := awsOutputObject(body); err != nil {
		return stockCloudOutputRead{}, errInventory
	}
	var out struct {
		ARN, Name, VersionId       string
		VersionStages              []string
		SecretBinary, SecretString *string
	}
	if json.Unmarshal(body, &out) != nil || out.Name != name || len(out.VersionId) < 32 || len(out.VersionId) > 64 ||
		!awsOutputCharacters(out.VersionId, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") ||
		!slices.Contains(out.VersionStages, "AWSCURRENT") || len(out.VersionStages) > 20 || (out.SecretBinary == nil) == (out.SecretString == nil) {
		return stockCloudOutputRead{}, errInventory
	}
	resolved, valid := client.qualifiedName(out.ARN)
	if !valid || resolved != name {
		return stockCloudOutputRead{}, errInventory
	}
	stages := map[string]bool{}
	for _, stage := range out.VersionStages {
		if stage == "" || len(stage) > 256 || stages[stage] {
			return stockCloudOutputRead{}, errInventory
		}
		stages[stage] = true
	}
	var value []byte
	var err error
	if out.SecretBinary != nil {
		value, err = base64.StdEncoding.Strict().DecodeString(*out.SecretBinary)
	} else {
		value = []byte(*out.SecretString)
	}
	if err != nil || len(value) == 0 || len(value) > awsOutputValueLimit {
		clear(value)
		return stockCloudOutputRead{}, errInventory
	}
	return stockCloudOutputRead{Bytes: value, Instance: out.ARN}, nil
}

func verifyStockCloudOutputDeleted(ctx context.Context, input liveRunInput, budget *runBudget, directory, target string) (stockCloudOutputDeletion, error) {
	client, credentials, name, err := stockAWSOutputClient(ctx, input, budget, directory, "cleanup", target)
	if err != nil {
		return stockCloudOutputDeletion{}, err
	}
	response, op, err := client.secretRequest(ctx, credentials, "DescribeSecret", struct {
		SecretID string `json:"SecretId"`
	}{name}, awsOutputRequestLimit, false, "ownership_read")
	if err != nil {
		return stockCloudOutputDeletion{}, err
	}
	defer clear(response.body)
	if response.status != http.StatusOK {
		return stockCloudOutputDeletion{}, op.failure("provider_refused", nil)
	}
	if _, err := awsOutputObject(response.body); err != nil {
		return stockCloudOutputDeletion{}, errInventory
	}
	var out struct {
		ARN, Name   string
		DeletedDate json.RawMessage
	}
	if json.Unmarshal(response.body, &out) != nil || out.Name != name || !awsOutputTimestamp(out.DeletedDate) {
		return stockCloudOutputDeletion{}, errInventory
	}
	if resolved, valid := client.qualifiedName(out.ARN); !valid || resolved != name {
		return stockCloudOutputDeletion{}, errInventory
	}
	return stockCloudOutputDeletion{Disposition: "scheduled", Instance: out.ARN}, nil
}

// full_only: false
func TestStockAWSOutputReaderRequiresCompleteOwnedValue(t *testing.T) {
	client := &awsLiveOutput{location: liveOutputLocation{Region: "us-east-1", Account: "123456789012", SecretNamePrefix: "ENKV_"}}
	const name = "ENKV_TEST_PLAIN"
	const good = `{"ARN":"arn:aws:secretsmanager:us-east-1:123456789012:secret:ENKV_TEST_PLAIN-aB1234","Name":"ENKV_TEST_PLAIN","VersionId":"01234567890123456789012345678901","VersionStages":["AWSCURRENT"],"SecretString":"complete private value"}`
	for _, tc := range []struct {
		name, body string
		good       bool
	}{
		{"complete", good, true},
		{"wrong-account", strings.Replace(good, "123456789012:secret", "000000000000:secret", 1), false},
		{"wrong-name", strings.Replace(good, `"Name":"ENKV_TEST_PLAIN"`, `"Name":"ENKV_OTHER_PLAIN"`, 1), false},
		{"wrong-stage", strings.Replace(good, "AWSCURRENT", "AWSPREVIOUS", 1), false},
		{"duplicate-value", strings.Replace(good, `"SecretString":`, `"SecretString":"wrong","SecretString":`, 1), false},
		{"two-representations", strings.Replace(good, `"SecretString":`, `"SecretBinary":"eA==","SecretString":`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read, err := stockAWSOutputValue([]byte(tc.body), client, name)
			defer clear(read.Bytes)
			if (err == nil) != tc.good || tc.good && (!bytes.Equal(read.Bytes, []byte("complete private value")) || read.Instance != "arn:aws:secretsmanager:us-east-1:123456789012:secret:ENKV_TEST_PLAIN-aB1234") {
				t.Fatal("independent output value or exact ownership differs")
			}
		})
	}
}

// validateStockSDKContext inspects the pinned SDK's selected shared config only.
// It never retrieves credentials or contacts SSO, STS or a provider service.
func validateStockSDKContext(input liveRunInput, role string) error {
	if input.PublicConfiguration == nil {
		return errInventory
	}
	actor, ok := input.PublicConfiguration.Actors[role]
	if !ok || actor.SDKMode != "aws-assume-role" || !filepath.IsAbs(actor.SDKHome) || actor.SDKProfile == "" {
		return errInventory
	}
	path := filepath.Join(actor.SDKHome, ".aws", "config")
	body, err := ReadLocalProtectedFile(context.Background(), path, 64<<10)
	if err != nil {
		return errInventory
	}
	clear(body)
	selected, err := config.LoadSharedConfigProfile(context.Background(), actor.SDKProfile, func(o *config.LoadSharedConfigOptions) {
		o.ConfigFiles, o.CredentialsFiles, o.Logger = []string{path}, []string{}, logging.Nop{}
	})
	if err != nil || !stockAWSConfigUsesSSO(selected, input.Settings.Account) {
		return errInventory
	}
	return nil
}

func stockAWSConfigUsesSSO(selected config.SharedConfig, account string) bool {
	clean := func(v config.SharedConfig) bool {
		return v.Credentials.AccessKeyID == "" && v.Credentials.SecretAccessKey == "" && v.Credentials.SessionToken == "" &&
			v.CredentialSource == "" && v.CredentialProcess == "" && v.WebIdentityTokenFile == ""
	}
	if !clean(selected) || !strings.HasPrefix(selected.RoleARN, "arn:aws:iam::"+account+":role/") ||
		selected.SourceProfileName == "" || selected.Source == nil || selected.SSOSession != nil || selected.SSOStartURL != "" {
		return false
	}
	source := selected.Source
	if !clean(*source) || source.Source != nil || source.SourceProfileName != "" || source.RoleARN != "" || !awsOutputAccount(source.SSOAccountID) || source.SSORoleName == "" {
		return false
	}
	if source.SSOSession != nil {
		return source.SSOSessionName != "" && source.SSOSession.Name == source.SSOSessionName && source.SSOSession.SSORegion != "" && strings.HasPrefix(source.SSOSession.SSOStartURL, "https://")
	}
	return source.SSORegion != "" && strings.HasPrefix(source.SSOStartURL, "https://")
}

// full_only: false
func TestStockAWSContextRequiresSSOSourceProfile(t *testing.T) {
	source := config.SharedConfig{Profile: "sso", SSOAccountID: "123456789012", SSORoleName: "PermissionSet", SSORegion: "us-east-1", SSOStartURL: "https://example.awsapps.com/start"}
	selected := config.SharedConfig{RoleARN: "arn:aws:iam::123456789012:role/acceptance-apply", SourceProfileName: "sso", Source: &source}
	if !stockAWSConfigUsesSSO(selected, "123456789012") {
		t.Fatal("normal SSO source profile was refused")
	}
	for _, field := range []string{"static", "process", "web-identity", "credential-source", "wrong-target-account", "invalid-source-account", "missing-source"} {
		copy, originalSource := selected, source
		copy.Source = &originalSource
		switch field {
		case "static":
			originalSource.Credentials = aws.Credentials{AccessKeyID: "static", SecretAccessKey: "static"}
		case "process":
			originalSource.CredentialProcess = "external-command"
		case "web-identity":
			originalSource.WebIdentityTokenFile = "/private/other-token"
		case "credential-source":
			originalSource.CredentialSource = "Environment"
		case "wrong-target-account":
			copy.RoleARN = "arn:aws:iam::000000000000:role/other"
		case "invalid-source-account":
			originalSource.SSOAccountID = "other"
		case "missing-source":
			copy.Source = nil
		}
		if stockAWSConfigUsesSSO(copy, "123456789012") {
			t.Fatal("a different credential route was accepted", field)
		}
	}
}

// full_only: false
func TestStockAWSStorePrefixRequiresOriginalGrantAndConditionalCleanup(t *testing.T) {
	for _, condition := range []string{"empty", "owned-object", "multiple-pages", "later-page-foreign", "foreign-object", "wrong-prefix-echo", "wrong-success-status", "lost-reply", "condition-failed", "late-object", "wrong-original", "wrong-original-prefix", "occupied-prefix", "bounded-read", "repeated-page"} {
		t.Run(condition, func(t *testing.T) {
			settings, der := awsLiveTestSettings(t)
			fixture := records.StockPluginFixture{Schema: 1, Purpose: "stock-plugin-acceptance", FixtureID: "0123456789abcdef0123456789abcdef", Provider: "aws", Region: settings.Region, Account: settings.Account, Bucket: "fixture-pa-0123456789abcdef0123456789abcdef"}
			settings.Bucket = fixture.Bucket
			input := liveRunInput{Settings: settings, RecoveryMode: "enabled", RunID: "abcdef0123456789abcdef0123456789", Prefix: "enkv-test/abcdef0123456789abcdef0123456789/plugin-contracts", Scenarios: []string{records.StockPluginScenario}, PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Fixture: fixture}}}
			firstKey := input.Prefix + "/HEAD"
			secondKey := input.Prefix + "/" + strings.Repeat("1", 64) + "/root/0/" + strings.Repeat("2", 64)
			objects := map[string]bool{}
			if condition == "occupied-prefix" {
				objects[firstKey] = true
			}
			requests, reads, deletes, secondPages := 0, 0, 0, 0
			cleaning := false
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Header.Get("X-Amz-Expected-Bucket-Owner") != fixture.Account {
					t.Error("Store call changed the exact expected owner")
				}
				if r.URL.Query().Get("list-type") == "2" {
					prefix := r.URL.Query().Get("prefix")
					if prefix != input.Prefix+"/" {
						t.Error("Store listing escaped the exact run prefix")
					}
					current := r.URL.Query().Get("continuation-token")
					echo, next, truncated := "", "", "false"
					if current != "" {
						echo = "<ContinuationToken>" + current + "</ContinuationToken>"
						secondPages++
					}
					var listed []string
					for _, key := range []string{firstKey, secondKey} {
						if objects[key] {
							listed = append(listed, key)
						}
					}
					if condition == "repeated-page" {
						listed, next, truncated = nil, "repeat", "true"
					} else if cleaning && len(listed) > 0 {
						switch condition {
						case "foreign-object":
							listed = []string{input.Prefix + "-sibling/HEAD"}
						case "multiple-pages", "later-page-foreign":
							if current == "" {
								listed, next, truncated = listed[:1], "second", "true"
							} else if condition == "later-page-foreign" {
								listed = []string{input.Prefix + "-sibling/HEAD"}
							} else {
								listed = listed[1:]
							}
						}
					}
					contents := ""
					for _, key := range listed {
						contents += "<Contents><Key>" + key + "</Key><Size>1</Size></Contents>"
					}
					if next != "" {
						next = "<NextContinuationToken>" + next + "</NextContinuationToken>"
					}
					if cleaning && condition == "wrong-prefix-echo" {
						prefix += "other/"
					}
					_, _ = io.WriteString(w, "<ListBucketResult><Name>"+fixture.Bucket+"</Name><Prefix>"+prefix+"</Prefix><KeyCount>"+strconv.Itoa(len(listed))+"</KeyCount><MaxKeys>128</MaxKeys><IsTruncated>"+truncated+"</IsTruncated>"+echo+next+contents+"</ListBucketResult>")
					return
				}
				key, object := strings.CutPrefix(r.URL.Path, "/"+fixture.Bucket+"/")
				if object && objects[key] {
					switch r.Method {
					case http.MethodGet:
						reads++
						w.Header().Set("ETag", `"observed"`)
						_, _ = io.WriteString(w, "x")
						return
					case http.MethodDelete:
						deletes++
						if r.Header.Get("If-Match") != `"observed"` {
							t.Error("Store cleanup lost the exact observed token")
						}
						if condition == "condition-failed" {
							w.WriteHeader(http.StatusPreconditionFailed)
							_, _ = io.WriteString(w, "<Error><Code>PreconditionFailed</Code></Error>")
							return
						}
						delete(objects, key)
						if condition == "lost-reply" {
							connection, _, err := w.(http.Hijacker).Hijack()
							if err != nil {
								t.Error("controlled reply close failed")
								return
							}
							_ = connection.Close()
							return
						}
						if condition == "late-object" {
							objects[firstKey] = true
						}
						if condition == "wrong-success-status" {
							w.WriteHeader(http.StatusOK)
						} else {
							w.WriteHeader(http.StatusNoContent)
						}
						return
					}
				}
				if r.Method == http.MethodDelete {
					t.Error("Store cleanup attempted a bucket or foreign-object deletion")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				status, body := awsLiveConfigurationReply(t, settings, der, r, "")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			}))
			setup := newAWSSetup(settings, input.Prefix, contract.Hash([]byte("domain")), der, &awsLiveTestCredentials{}, transport)
			store, err := stockAWSStorePrefix(input, setup, nil)
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
			if condition == "bounded-read" || condition == "repeated-page" {
				if err == nil || deletes != 0 || condition == "bounded-read" && requests != 0 || condition == "repeated-page" && requests > 10 {
					t.Fatal("unbounded or incomplete preflight acquired authority")
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
			cleanup, err := stockAWSStorePrefix(input, setup, &original)
			if strings.HasPrefix(condition, "wrong-original") {
				if err == nil || deletes != 0 {
					t.Fatal("another prefix's original grant was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("original prefix grant refused")
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
			if (condition == "foreign-object" || condition == "later-page-foreign" || condition == "wrong-prefix-echo") && (reads != 0 || deletes != 0) {
				t.Fatal("unqualified listing reached object read or delete")
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
func TestStockAWSStorePrefixKeepsBucketReusableAcrossRuns(t *testing.T) {
	settings, der := awsLiveTestSettings(t)
	fixture := records.StockPluginFixture{Schema: 1, Purpose: "stock-plugin-acceptance", FixtureID: "0123456789abcdef0123456789abcdef", Provider: "aws", Region: settings.Region, Account: settings.Account, Bucket: "fixture-pa-0123456789abcdef0123456789abcdef"}
	settings.Bucket = fixture.Bucket
	const firstRun = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const secondRun = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	firstPrefix := "enkv-test/" + firstRun + "/plugin-contracts"
	siblingKey := firstPrefix + "-sibling/HEAD"
	objects := map[string]bool{siblingKey: true}
	activePrefix := ""
	bucketDeletes := 0
	transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Expected-Bucket-Owner") != fixture.Account {
			t.Error("Store operation changed the expected owner")
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/"+fixture.Bucket {
			bucketDeletes++
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			prefix := r.URL.Query().Get("prefix")
			if prefix != activePrefix+"/" {
				t.Error("Store listing escaped the exact run prefix")
			}
			contents, count := "", 0
			for key := range objects {
				if strings.HasPrefix(key, prefix) {
					contents += "<Contents><Key>" + key + "</Key><Size>1</Size></Contents>"
					count++
				}
			}
			_, _ = io.WriteString(w, "<ListBucketResult><Name>"+fixture.Bucket+"</Name><Prefix>"+prefix+"</Prefix><KeyCount>"+strconv.Itoa(count)+"</KeyCount><MaxKeys>128</MaxKeys><IsTruncated>false</IsTruncated>"+contents+"</ListBucketResult>")
			return
		}
		key, object := strings.CutPrefix(r.URL.Path, "/"+fixture.Bucket+"/")
		if object && objects[key] {
			if key != activePrefix+"/HEAD" {
				t.Error("Store cleanup touched a different run or sibling prefix")
			}
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("ETag", `"observed"`)
				_, _ = io.WriteString(w, "x")
				return
			case http.MethodDelete:
				if r.Header.Get("If-Match") != `"observed"` {
					t.Error("Store cleanup lost the observed object token")
				}
				delete(objects, key)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		status, body := awsLiveConfigurationReply(t, settings, der, r, "")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, runID := range []string{firstRun, secondRun} {
		activePrefix = "enkv-test/" + runID + "/plugin-contracts"
		input := liveRunInput{Settings: settings, RecoveryMode: "enabled", RunID: runID, Prefix: activePrefix, Scenarios: []string{records.StockPluginScenario}, PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Fixture: fixture}}}
		setup := newAWSSetup(settings, input.Prefix, contract.Hash([]byte("domain")), der, &awsLiveTestCredentials{}, transport)
		bucket, err := stockAWSStorePrefix(input, setup, nil)
		if err != nil {
			t.Fatal("reusable Store construction refused")
		}
		budget := &runBudget{limits: liveLimits{Requests: 1000, BodyBytes: 256 << 20}, keys: map[string]bool{}}
		original, err := bucket.Inspect(ctx, budget)
		if err != nil || !original.Empty || original.Identity == "" {
			t.Fatal("fresh run prefix was refused in a reusable bucket")
		}
		objects[activePrefix+"/HEAD"] = true
		cleanup, err := stockAWSStorePrefix(input, setup, &original)
		if err != nil {
			t.Fatal("original empty-prefix observation was refused")
		}
		if empty, err := cleanup.Clean(ctx, budget); err != nil || !empty || objects[activePrefix+"/HEAD"] {
			t.Fatal("run prefix cleanup did not observe exact absence")
		}
		if !objects[siblingKey] || bucketDeletes != 0 {
			t.Fatal("run prefix cleanup consumed shared infrastructure or another prefix")
		}
		// A request may arrive after that run's final observation. It remains
		// in the old prefix while the next run uses a different prefix.
		objects[activePrefix+"/HEAD"] = true
	}
	if !objects[firstPrefix+"/HEAD"] || !objects[siblingKey] || bucketDeletes != 0 {
		t.Fatal("later run removed an old late arrival or deleted its bucket")
	}
}
