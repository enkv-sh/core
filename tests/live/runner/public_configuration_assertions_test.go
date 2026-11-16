package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

func publicExpected(value []byte) map[string]string {
	sum := sha256.Sum256(value)
	return map[string]string{"secret": hex.EncodeToString(sum[:])}
}
func publicAssertNoRecovery(t testing.TB, capture nativeprocess.Capture) {
	t.Helper()
	for _, e := range capture.Events {
		if e.Kind == "http-start" && (e.Role == "recovery-private" || e.Role == "recovery-signing") {
			t.Fatal("ordinary apply attempted Recovery private capability")
		}
	}
}
func publicAssertGETOnly(t testing.TB, capture nativeprocess.Capture) {
	t.Helper()
	if !publicGETOnly(capture) {
		t.Fatal("public Reader did not have only actual GET observations")
	}
}

func publicGETOnly(capture nativeprocess.Capture) bool {
	count := 0
	for _, e := range capture.Events {
		if e.Kind != "http-start" {
			continue
		}
		if e.Operation != "head-read" && e.Operation != "store-read" {
			return false
		}
		count++
	}
	return count != 0
}
func publicAssertPlain(t testing.TB, capture nativeprocess.Capture, recovery bool) {
	t.Helper()
	kind := "plaintext"
	if recovery {
		kind = "recovery-plaintext"
	}
	count := 0
	for _, e := range capture.Events {
		if e.Kind == kind {
			if !e.Matched || e.Count != 1 {
				t.Fatal("independent private byte observation differs")
			}
			count++
		}
	}
	if count != 1 {
		t.Fatal("independent private byte observation missing")
	}
}
func publicDenied(capture nativeprocess.Capture, role string) error {
	operation := map[string]string{"public": "kms-public", "normal": "kms-sign", "authority": "kms-decrypt", "recovery-signing": "kms-sign", "recovery-private": "kms-decrypt"}[role]
	if operation == "" {
		return errors.New("required IAM capability is unknown")
	}
	denied := 0
	for _, e := range capture.Events {
		if e.Kind == "http-start" && e.Operation == "head-write" {
			return errors.New("failed qualification attempted HEAD publication")
		}
		matches := e.Operation == operation && (role == "public" || e.Role == role)
		if e.Kind == "http-return" && matches && e.Sent && e.PermissionDenied {
			denied++
		}
	}
	if denied == 0 {
		return errors.New("required IAM denial was not independently observed")
	}
	return nil
}

func publicRecipientPrivateDenied(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget) {
	t.Helper()
	result := publicCLI(t, ctx, inv, input, budget, "authority", true, nativeprocess.Policy{RecipientKEK: input.Settings.ReaderKEKID}, nil, "--probe-recipient-private-denial", "--provider", input.Settings.Provider, "--selector", input.Settings.ReaderKEKID)
	defer clear(result.Body)
	var fact struct {
		Schema string `json:"schema"`
		Denied bool   `json:"denied"`
	}
	if result.Code != 0 || json.Unmarshal(result.Body, &fact) != nil || fact.Schema != "RecipientPrivateDenialProbe/v1" || !fact.Denied {
		t.Fatal("ordinary recipient private denial probe unavailable")
	}
	public, sent, denied := 0, 0, 0
	for _, event := range result.Capture.Events {
		if event.Kind == "http-start" && event.Sent {
			if event.Operation == "kms-public" {
				public++
			} else if event.Operation == "kms-decrypt" && event.Role == "recipient-private" {
				sent++
			} else {
				t.Fatal("ordinary recipient denial probe attempted another capability")
			}
		}
		if event.Kind == "http-return" && event.Sent && event.Operation == "kms-decrypt" && event.Role == "recipient-private" && event.PermissionDenied {
			denied++
		}
	}
	if public == 0 || sent != 1 || denied != 1 {
		t.Fatal("ordinary recipient private denial was not one authenticated provider refusal")
	}
}

func publicRecipientOracle(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, value []byte, excluded bool) {
	t.Helper()
	publicObservePair(t, ctx, inv, input, budget, source)
	binding, selector := publicRecipientBinding(t, input, source)
	role := "recipient-consumer"
	if excluded {
		role = "excluded-consumer"
	}
	result := publicCLI(t, ctx, inv, input, budget, role, true, nativeprocess.Policy{ExpectedSHA256: publicExpected(value), RecipientOracle: true, RecipientBinding: binding, RecipientKEK: selector}, nil, "--source", source, "--source-format", "json")
	defer clear(result.Body)
	if result.Code == 0 {
		t.Fatal("private Recipient oracle claimed Product reconstruction success")
	}
	count, opens := 0, 0
	for _, event := range result.Capture.Events {
		if event.Kind == "http-start" && event.Operation == "kms-decrypt" {
			opens++
			if event.Role != "recipient-private" {
				t.Fatal("Recipient oracle attempted another private route")
			}
		}
		if event.Kind == "recipient-plaintext" {
			count++
			if excluded && (!event.WrapAbsent || event.Count != 0 || event.Matched) || !excluded && (!event.Matched || event.Count != 1 || event.WrapAbsent) {
				t.Fatal("Recipient membership and private byte observation differs")
			}
		}
	}
	if count != 1 || excluded && opens != 0 || !excluded && opens != 1 {
		t.Fatal("Recipient oracle actual private call count differs")
	}
}

func publicIndependentHEAD(t testing.TB, ctx context.Context, input liveRunInput, budget *runBudget, source, directory string) format.Head {
	t.Helper()
	domain := publicReadDomain(t, source)
	cleaner, err := openPublicPrefixCleaner(ctx, input, domain, directory)
	if err != nil {
		t.Fatal("independent public observation unavailable")
	}
	read, _ := cleanupRead(ctx, recordedStore{Store: cleaner.Store, budget: budget}, input.Prefix+"/HEAD", contract.MaxHeadLength)
	if read.Status != contract.ReadOK {
		t.Fatal("independent ready HEAD observation unavailable")
	}
	head, err := format.DecodeHead(read.Body)
	if err != nil {
		t.Fatal("independent selected HEAD decoding refused")
	}
	return head
}

func publicObservePair(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) {
	t.Helper()
	publicObservePairVerdict(t, ctx, inv, input, budget, source, "match", nil)
}

func publicObservePairVerdict(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source, verdict string, observation *publicComparisonObservation) {
	t.Helper()
	image := publicSourceImage(t, source)
	result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "plan", "--trusted", source, "--trusted-format", "json", "--json")
	defer clear(result.Body)
	product := publicProduct(t, result, contract.ReaderCompareOperation)
	if !publicPairComparisonMatches(result, product, verdict, observation) {
		t.Fatal("pair-only public comparison differs from its exact expected verdict or observation")
	}
	publicImageUnchanged(t, image)
}

func publicPairComparisonMatches(result publicChildResult, product publicProductResult, verdict string, observation *publicComparisonObservation) bool {
	code := 0
	switch verdict {
	case "match":
	case "mismatch":
		code = 1
	default:
		return false
	}
	if result.Code != code || product.State != "success" || product.Payload.Verdict != verdict || !product.Payload.Complete || len(product.Payload.Scope) != 12 || !publicGETOnly(result.Capture) {
		return false
	}
	for _, scope := range product.Payload.Scope {
		if scope.Status != "complete" {
			return false
		}
	}
	return observation == nil || product.Observation != nil && *product.Observation == *observation
}

func publicObserveMismatch(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, trusted string) {
	t.Helper()
	candidate := publicPortablePair(t, trusted, filepath.Join(inv.StateDir, "portable-mismatch"))
	document := publicSourceDocument(t, candidate)
	entries, ok := document["entries"].(map[string]any)
	if !ok {
		t.Fatal("public mismatch candidate entries unavailable")
	}
	entries["public-mismatch"] = map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": "independent public candidate"}}
	publicRewritePortableSource(t, candidate, document)
	baseline, desired := publicSourceImage(t, trusted), publicSourceImage(t, candidate)
	result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "plan", "--trusted", trusted, "--trusted-format", "json", "--candidate", candidate, "--candidate-format", "json", "--json")
	defer clear(result.Body)
	product := publicProduct(t, result, contract.ReaderCompareOperation)
	if result.Code != 1 || product.State != "success" || product.Payload.Verdict != "mismatch" || !product.Payload.Complete || len(product.Payload.Scope) != 12 {
		t.Fatal("valid public candidate difference did not produce complete mismatch")
	}
	for _, scope := range product.Payload.Scope {
		if scope.Status != "complete" {
			t.Fatal("public mismatch comparison scope incomplete")
		}
	}
	publicAssertGETOnly(t, result.Capture)
	publicImageUnchanged(t, baseline)
	publicImageUnchanged(t, desired)
}

func publicRefuseDamagedPairs(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) {
	t.Helper()
	original := publicSourceImage(t, source)
	for _, condition := range []string{"missing-generated", "damaged-public-basis"} {
		copySource := publicPortablePair(t, source, filepath.Join(inv.StateDir, "portable-"+condition))
		document := publicSourceDocument(t, copySource)
		reference, ok := document["generated"].(string)
		if !ok {
			t.Fatal("negative pair reference unavailable")
		}
		generatedPath := filepath.Join(filepath.Dir(copySource), filepath.FromSlash(reference))
		if condition == "missing-generated" {
			if os.Remove(generatedPath) != nil {
				t.Fatal("missing dependency fixture unavailable")
			}
		} else {
			publicDamagePortableBasis(t, copySource)
		}
		result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "plan", "--trusted", copySource, "--trusted-format", "json", "--json")
		product := publicProduct(t, result, contract.ReaderCompareOperation)
		clear(result.Body)
		if result.Code == 0 || product.State == "success" || len(product.Payload.Scope) != 12 || len(result.Capture.Events) != 1 || result.Capture.Events[0].Kind != "footer" {
			t.Fatal("damaged portable pair reached credentials or advertised public success")
		}
		for _, scope := range product.Payload.Scope {
			if scope.Status != "unchecked" {
				t.Fatal("damaged portable pair fabricated checked scope")
			}
		}
	}
	publicImageUnchanged(t, original)
}

func publicDamagePortableBasis(t testing.TB, source string) {
	t.Helper()
	document := publicSourceDocument(t, source)
	reference, ok := document["generated"].(string)
	if !ok {
		t.Fatal("negative pair reference unavailable")
	}
	generatedPath := filepath.Join(filepath.Dir(source), filepath.FromSlash(reference))
	body, err := os.ReadFile(generatedPath)
	var generated map[string]any
	if err != nil || json.Unmarshal(body, &generated) != nil {
		t.Fatal("negative public basis fixture unavailable")
	}
	basis, ok := generated["public_basis"].(map[string]any)
	if !ok || basis["kind"] != "genesis" && basis["kind"] != "successor" {
		t.Fatal("portable public basis kind unavailable")
	}
	basis["kind"] = "damaged"
	changed, err := json.Marshal(generated)
	if err != nil {
		t.Fatal("negative public basis encoding unavailable")
	}
	if os.Chmod(generatedPath, 0600) != nil {
		t.Fatal("negative public basis rewrite permission unavailable")
	}
	defer func() {
		if os.Chmod(generatedPath, 0400) != nil {
			t.Fatal("negative public basis read-only permission restore failed")
		}
	}()
	if os.WriteFile(generatedPath, changed, 0400) != nil {
		t.Fatal("negative public basis delivery unavailable")
	}
}
