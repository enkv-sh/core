package core

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicOutputCoordinate = records.PublicOutputCoordinate
type publicOutputPreviewRow = records.PublicOutputPreviewRow
type publicOutputPreview = records.PublicOutputPreview

func publicOutputNames(prefix string) []string {
	return records.PublicOutputFixtureNames(prefix)
}

func rowOutputCommand(input liveRunInput, args []string) bool {
	if len(input.Scenarios) != 1 || len(args) == 0 {
		return false
	}
	row, ok := catalog.PublicConfiguration(input.Scenarios[0])
	return ok && row.Output && (args[0] == "publish" || args[0] == "apply" && slices.Contains(args, "--publish"))
}

func publicOutputEnvironment(environment []string, effect bool, scopes []string) []string {
	out := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, "GITHUB_TOKEN=") && !strings.HasPrefix(item, "GH_TOKEN=") {
			out = append(out, item)
		}
	}
	if effect && slices.ContainsFunc(scopes, func(scope string) bool {
		return scope == "github-repository" || scope == "github-organization" || scope == "github-environment"
	}) {
		out = append(out, "GITHUB_TOKEN="+os.Getenv("GITHUB_TOKEN"))
	}
	return out
}

func publicOutputScopes(input liveRunInput) []string {
	if len(input.Scenarios) != 1 {
		return nil
	}
	row, ok := catalog.PublicConfiguration(input.Scenarios[0])
	if !ok {
		return nil
	}
	return row.OutputScopes(input.Settings.Provider)
}

func publicOutputDeclaration(input liveRunInput) map[string]any {
	return publicOutputDeclarationForScopes(input, publicOutputScopes(input))
}

func publicOutputDeclarationForScopes(input liveRunInput, scopes []string) map[string]any {
	names := publicOutputNames(input.Prefix)
	outputs := input.PublicConfiguration.Outputs
	destinations := map[string]any{}
	cloud := "aws-secrets-manager"
	cloudSpec := map[string]any{"account": input.Settings.Account, "region": input.Settings.Region}
	if input.Settings.Provider == "gcp" {
		cloud, cloudSpec = "gcp-secret-manager", map[string]any{"project_number": input.Settings.ProjectNumber}
	}
	if slices.Contains(scopes, cloud) {
		destinations[cloud] = map[string]any{"plugin": cloud, "settings": cloudSpec, "encodings": map[string]any{names[1]: "base64"}}
	}
	for _, row := range []struct {
		name string
		spec records.PublicOutputScope
	}{{"github-repository", outputs.Repository}, {"github-organization", outputs.Organization}, {"github-environment", outputs.Environment}} {
		if slices.Contains(scopes, row.name) {
			destinations[row.name] = map[string]any{"plugin": strings.Replace(row.name, "github-", "github-actions-", 1), "settings": row.spec, "encodings": map[string]any{names[1]: "base64"}}
		}
	}
	return map[string]any{"destinations": destinations, "routing": map[string]any{"default": slices.Clone(scopes)}, "groups": [][]string{names}}
}

func publicExpectedOutputCoordinates(input liveRunInput) []publicOutputCoordinate {
	return publicExpectedOutputCoordinatesForScopes(input, publicOutputScopes(input))
}

func publicExpectedOutputCoordinatesForScopes(input liveRunInput, scopes []string) []publicOutputCoordinate {
	return records.PublicOutputFixtureCoordinates(input.Settings.Provider, input.Settings.Region, input.Settings.Account, input.Settings.ProjectNumber, input.Prefix, input.PublicConfiguration.Outputs, scopes)
}

func publicObserveOutputs(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) (publicOutputPreview, string, uint16) {
	t.Helper()
	image := publicSourceImage(t, source)
	result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "plan", "--trusted", source, "--trusted-format", "json", "--publish", "--json")
	defer clear(result.Body)
	product := publicProduct(t, result, contract.ReaderCompareOperation)
	var body struct {
		Payload struct {
			Publication publicOutputPreview `json:"publication"`
		} `json:"payload"`
	}
	if result.Code != 0 && result.Code != 1 || product.State != "success" || !product.Payload.Complete || len(product.Payload.Scope) != 12 || json.Unmarshal(result.Body, &body) != nil {
		t.Fatal("complete public output observation unavailable")
	}
	for _, scope := range product.Payload.Scope {
		if scope.Status != "complete" {
			t.Fatal("public output observation scope incomplete")
		}
	}
	publicAssertGETOnly(t, result.Capture)
	publicImageUnchanged(t, image)
	return body.Payload.Publication, product.Payload.Verdict, publicOutputCaptureOrdinal(t, inv, result.CapturePath)
}

func publicOutputPreviewMatches(preview publicOutputPreview, expected []publicOutputCoordinate, settled bool) bool {
	return records.PublicOutputPreviewMatches(preview, expected, settled)
}

func publicOutputPublication(t testing.TB, result publicChildResult, expected []publicOutputCoordinate, combined, noOp, deletion bool) []records.PublicOutputActionResult {
	t.Helper()
	body := result.Body
	if combined {
		var stages struct {
			Schema      string          `json:"schema"`
			Apply       json.RawMessage `json:"apply"`
			Publication struct {
				Stage  string          `json:"stage"`
				Reason *string         `json:"reason"`
				Result json.RawMessage `json:"result"`
			} `json:"publication"`
		}
		if json.Unmarshal(body, &stages) != nil || stages.Schema != "ApplyPublicationResult/v1" || stages.Publication.Stage != "evaluated" || stages.Publication.Reason != nil {
			t.Fatal("public combined stage facts unavailable")
		}
		apply := publicChildResult{Body: stages.Apply, Code: result.Code}
		product := publicProduct(t, apply, "apply-declaration")
		if !publicApplyMatches(apply, product, "success") && !publicApplyMatches(apply, product, "no-op") {
			t.Fatal("public combined apply did not complete")
		}
		if noOp && product.State != "no-op" {
			t.Fatal("repeated combined apply changed the selected state")
		}
		body = stages.Publication.Result
	}
	var output struct {
		Schema    string `json:"schema"`
		Operation string `json:"operation_kind"`
		State     string `json:"state_result"`
		Summary   string `json:"output_summary"`
		Evidence  string `json:"evidence_ceiling"`
		Payload   struct {
			Schema  string `json:"schema"`
			Warning *bool  `json:"domain_wide_warning"`
			Entries []struct {
				records.PublicOutputActionResult
				Target *struct {
					Origin      string  `json:"origin"`
					Entry       *string `json:"entry_name"`
					Destination *string `json:"destination_id"`
					Service     string  `json:"service_contract_id"`
					Canonical   string  `json:"canonical_target"`
				} `json:"target"`
			} `json:"entries"`
		} `json:"payload"`
	}
	state, summary, disposition := "success", "output-complete", "acknowledged"
	if noOp {
		state, summary, disposition = "no-op", "output-no-change", "no-op"
	}
	if result.Code != 0 || json.Unmarshal(body, &output) != nil || output.Schema != "ProductResult/v1" || output.Operation != "publish" || output.State != state || output.Summary != summary || output.Evidence != "canonical" || output.Payload.Schema != "OutputPayload/v3" || output.Payload.Warning == nil || *output.Payload.Warning || len(output.Payload.Entries) != len(expected) {
		t.Fatal("public publication complete result unavailable")
	}
	want := make([]string, len(expected))
	targets := make(map[string]publicOutputCoordinate, len(expected))
	for i, row := range expected {
		want[i] = row.CoordinateID
		targets[row.CoordinateID] = row
	}
	slices.Sort(want)
	for i, entry := range output.Payload.Entries {
		if entry.Coordinate != want[i] || len(entry.Actions) == 0 || noOp && len(entry.Actions) != 1 {
			t.Fatal("public publication coordinate vector differs")
		}
		target := targets[entry.Coordinate]
		if entry.Target == nil || entry.Target.Service != target.ServiceContractID || entry.Target.Canonical != target.PhysicalTarget {
			t.Fatal("public publication target description differs from its exact selection")
		}
		if deletion {
			if entry.Target.Origin != "retained-deletion" || entry.Target.Entry != nil {
				t.Fatal("retained publication target acquired a current name")
			}
		} else if entry.Target.Origin != "current" || entry.Target.Entry == nil || entry.Target.Destination == nil || *entry.Target.Destination == "" {
			t.Fatal("current publication target lost its entry or destination")
		}
		for _, action := range entry.Actions {
			if noOp && (action.Action != nil || action.Projection != nil || action.Attempt != nil || action.Evidence != nil) {
				t.Fatal("publication no-op acquired action identity or effect evidence")
			}
			if action.Disposition != disposition || action.Reason == nil || *action.Reason != 0 || action.Remote == nil || *action.Remote != !noOp || action.Late == nil || *action.Late || action.Blockers == nil || len(action.Blockers) != 0 || deletion && (action.Action == nil || *action.Action != "delete-owned" && *action.Action != "delete-reserved-slot") {
				t.Fatal("public publication action result differs")
			}
		}
	}
	if noOp {
		for _, event := range result.Capture.Events {
			// Combined apply must still compare supplied secrets. The native
			// capture covers both stages; publication custody is checked separately.
			if event.Kind == "http-start" && (!combined && event.Operation == "kms-decrypt" || event.Operation == "head-write" || event.Operation == "store-write") {
				t.Fatal("acknowledged publication equality acquired private or mutation work")
			}
		}
	}
	entries := make([]records.PublicOutputActionResult, len(output.Payload.Entries))
	for i, row := range output.Payload.Entries {
		entries[i] = row.PublicOutputActionResult
	}
	return entries
}

func runPublicOutput(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, row catalog.PublicConfigurationCase, source string) []publicOutputCoordinate {
	t.Helper()
	names := publicOutputNames(input.Prefix)
	set := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, []byte("public output secret\x00\xff"), "set", "--source", source, "--source-format", "json", "--name", names[1], "--json")
	publicAssertSet(t, set, source, names[1])
	clear(set.Body)
	document := publicSourceDocument(t, source)
	document["entries"].(map[string]any)[names[0]] = map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": "public output plain"}}
	document["outputs"] = publicOutputDeclaration(input)
	publicWriteSource(t, source, document)
	image := publicSourceImage(t, source)
	applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	if !publicApplyMatches(applied, publicProduct(t, applied, "apply-declaration"), "success") {
		t.Fatal("public output declaration apply did not complete")
	}
	clear(applied.Body)
	publicImageUnchanged(t, image)
	expected := publicExpectedOutputCoordinates(input)
	preview, verdict, _ := publicObserveOutputs(t, ctx, inv, input, budget, source)
	if verdict != "match" || !publicOutputPreviewMatches(preview, expected, false) {
		t.Fatal("public output apply lost exact unpublished targets")
	}
	for i, row := range preview.Entries {
		if len(row.Actions) == 0 {
			t.Fatal("apply without publication advertised completed output")
		}
		expected[i].CoordinateID, expected[i].BindingID = *row.Coordinate, *row.Binding
	}
	args := []string{"publish", "--source", source, "--source-format", "json", "--name", names[0], "--name", names[1], "--json"}
	combined := row.Condition == "output-combined"
	if combined {
		args = []string{"apply", "--source", source, "--source-format", "json", "--publish", "--json"}
	}
	result := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, args...)
	publicOutputPublication(t, result, expected, combined, false, false)
	clear(result.Body)
	publicImageUnchanged(t, image)
	// A separate default evaluation must use selected acknowledgement equality.
	repeated := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, args...)
	publicOutputPublication(t, repeated, expected, combined, true, false)
	clear(repeated.Body)
	publicImageUnchanged(t, image)
	return expected
}

func publicCleanupOutputs(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, ledger publicOwnership) {
	t.Helper()
	if !publicProcessAdmitted(inv, input) {
		t.Fatal("public process admission refused")
	}
	expected := publicExpectedOutputCoordinates(input)
	var facts publicProcessFacts
	if records.ReadJSON(filepath.Join(inv.StateDir, "after.json"), &facts) != nil || facts.RunID != input.RunID || facts.Prefix != input.Prefix || facts.Domain != ledger.Domain || len(expected) == 0 || len(facts.Outputs) != len(expected) {
		t.Fatal("public output original selected facts unavailable; domain retained")
	}
	for i := range expected {
		id := facts.Outputs[i].CoordinateID
		expected[i].CoordinateID, expected[i].BindingID = id, facts.Outputs[i].BindingID
		if !validInventoryDigest(id) || expected[i] != facts.Outputs[i] {
			t.Fatal("public output selected target changed; domain retained")
		}
	}
	for _, capture := range ledger.Captures {
		if capture.ParentRole == "cleanup" && capture.Actor == input.Participants["apply"] {
			t.Fatal("public output cleanup already entered; original invocation is not replayable")
		}
	}
	document := publicSourceDocument(t, source)
	got, err := json.Marshal(document["outputs"])
	declaration := publicOutputDeclaration(input)
	row, _ := catalog.PublicConfiguration(input.Scenarios[0])
	if row.Condition == "manifest" {
		declaration = publicManifestDeclaration(input)
	}
	want, wantErr := json.Marshal(declaration)
	if err != nil || wantErr != nil || !publicOutputDeclarationMatches(got, want) {
		t.Fatal("public output cleanup declaration differs from the exact run targets")
	}
	var passive []records.PublicOutputPassiveCoordinate
	if row.Condition == "manifest" {
		if facts.Manifest == nil || !facts.Manifest.Verified {
			t.Fatal("manifest cleanup original facts unavailable")
		}
		passive = publicManifestPassiveSupport(t, ctx, inv, input, budget, source, *facts.Manifest, expected, nil)
	}
	document["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	if row.Condition == "manifest" {
		document["outputs"] = publicManifestDeclarationForScopes(input, []string{"github-repository", "github-organization", "github-environment"})
	}
	publicWriteSource(t, source, document)
	appliedImage := publicSourceImage(t, source)
	applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	if !publicApplyMatches(applied, publicProduct(t, applied, "apply-declaration"), "success") {
		clear(applied.Body)
		t.Fatal("output bindings did not leave the selected cleanup declaration")
	}
	clear(applied.Body)
	publicImageUnchanged(t, appliedImage)
	if passive != nil {
		passive = publicManifestPassiveSupport(t, ctx, inv, input, budget, source, *facts.Manifest, expected, passive)
	}
	preview, _, _ := publicObserveOutputs(t, ctx, inv, input, budget, source)
	eligible := publicOutputPreviewMatches(preview, expected, false)
	if passive != nil {
		eligible = records.PublicManifestOutputPreviewMatches(preview, expected, passive, false)
	}
	if !eligible {
		t.Fatal("public output cleanup eligibility incomplete; domain retained")
	}
	for _, row := range preview.Entries[:len(expected)] {
		if row.Origin != "observed" || row.Basis != "retained-deletion" || *row.Conditional || len(row.Actions) != 1 || row.Actions[0] != "delete-owned" && row.Actions[0] != "delete-reserved-slot" {
			t.Fatal("public output cleanup has other work; domain retained")
		}
	}
	image := publicSourceImage(t, source)
	args := []string{"publish", "--source", source, "--source-format", "json", "--json"}
	for _, coordinate := range expected {
		args = append(args, "--delete-coordinate", coordinate.CoordinateID+"="+publicOutputDeletionPlugin(t, coordinate))
	}
	result := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, args...)
	deletes := publicOutputPublication(t, result, expected, false, false, true)
	cleanupOrdinal := publicOutputCaptureOrdinal(t, inv, result.CapturePath)
	clear(result.Body)
	publicImageUnchanged(t, image)
	preview, verdict, observationOrdinal := publicObserveOutputs(t, ctx, inv, input, budget, source)
	settled := publicOutputPreviewMatches(preview, expected, true)
	if passive != nil {
		passive = publicManifestPassiveSupport(t, ctx, inv, input, budget, source, *facts.Manifest, expected, passive)
		settled = records.PublicManifestOutputPreviewMatches(preview, expected, passive, true)
	}
	if verdict != "match" || !settled {
		t.Fatal("public output deletion acknowledgement evidence incomplete; domain retained")
	}
	var generatedDigest string
	for path, body := range image.Files {
		if path != source {
			generatedDigest = bodyDigest(body)
		}
	}
	evidence := &records.PublicOutputEvidence{Verdict: verdict, Version: 2, EditableSHA256: bodyDigest(image.Files[source]), GeneratedSHA256: generatedDigest, Coordinates: expected, CleanupCaptureOrdinal: cleanupOrdinal, ObservationCaptureOrdinal: observationOrdinal, Deletes: deletes, Preview: preview}
	if passive != nil {
		evidence.Version, evidence.PassiveCoordinates = 3, passive
	}
	if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil || evidence.Validate(len(ledger.Captures), publicOutputScopes(input)) != nil {
		t.Fatal("public output acknowledgement evidence unavailable; domain retained")
	}
	ledger.Outputs = evidence
	if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
		t.Fatal("public output acknowledgement retention failed; domain retained")
	}

}

func publicOutputDeclarationMatches(actual, expected []byte) bool {
	if !json.Valid(actual) || !json.Valid(expected) {
		return false
	}
	var values [2]any
	for i, body := range [][]byte{actual, expected} {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if decoder.Decode(&values[i]) != nil {
			return false
		}
	}
	return reflect.DeepEqual(values[0], values[1])
}

func publicOutputDeletionPlugin(t testing.TB, row publicOutputCoordinate) string {
	t.Helper()
	switch row.ServiceContractID {
	case "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1":
		return "aws-secrets-manager"
	case "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1":
		return "gcp-secret-manager"
	case "github-actions/service/v1":
		parts := strings.Split(row.PhysicalTarget, "/")
		switch {
		case len(parts) == 5 && parts[0] == "orgs" && parts[2] == "actions" && parts[3] == "secrets":
			return "github-actions-organization"
		case len(parts) == 6 && parts[0] == "repos" && parts[3] == "actions" && parts[4] == "secrets":
			return "github-actions-repository"
		case len(parts) == 7 && parts[0] == "repos" && parts[3] == "environments" && parts[5] == "secrets":
			return "github-actions-environment"
		}
	}
	t.Fatal("public output cleanup exact plugin unavailable")
	return ""
}

func publicOutputCaptureOrdinal(t testing.TB, inv records.Invocation, path string) uint16 {
	t.Helper()
	var ledger publicOwnership
	if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil {
		t.Fatal("public output joined capture owner unavailable")
	}
	for _, row := range ledger.Captures {
		if row.Path == path && row.Complete {
			return row.Ordinal
		}
	}
	t.Fatal("public output original capture is incomplete")
	return 0
}
