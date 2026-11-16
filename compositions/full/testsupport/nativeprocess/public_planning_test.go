package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

type nativePlanningObservation struct {
	Domain   string `json:"domain_id"`
	Revision string `json:"head_revision_id"`
	Snapshot string `json:"snapshot_id"`
}

type nativePlanningChange struct {
	Subject struct {
		Kind, Name  string
		Destination string `json:"destination_id"`
		Entry       struct{ Kind, Name string }
	}
	Path          []struct{ Field string }
	Action        string
	Before, After struct {
		State, Type string
		Value       json.RawMessage
	}
}

type nativePlanningOutput struct {
	Observation nativePlanningObservation `json:"observation"`
	Schema      string
	Kind        string `json:"operation_kind"`
	State       string `json:"state_result"`
	Effect      string `json:"effect_summary"`
	Output      string `json:"output_summary"`
	Payload     struct {
		Schema, Verdict  string
		EvidenceLimit    string                 `json:"evidence_limit"`
		Complete         bool                   `json:"diagnostics_complete"`
		PrivateComplete  bool                   `json:"private_complete"`
		DisplayDelivery  string                 `json:"display_delivery"`
		SelectedRecords  uint32                 `json:"selected_records"`
		CompletedRecords uint32                 `json:"completed_records"`
		Changes          []nativePlanningChange `json:"changes"`
		PrivateEntries   []struct {
			Name, Relation, Reason string
			Form                   string `json:"input_form"`
		} `json:"private_entries"`
	}
}

// full_only: false
func TestPublicNativePlanningChecksAndDisplaysCapturedProposals(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			const expectedChildren = 16
			s := newWorkflowServer(t, family, true)
			s.childLimit, s.requestLimit = expectedChildren, expectedChildren*workflowChildRequestLimit
			f := nativeSequenceSetupOnServer(t, cli, s, true)
			_, originalHead := workflowHead(t, s)
			objects := s.objectCount()
			restore := workflowReadOnlyPair(t, f.source, f.pair)
			defer restore()
			candidate := nativeMergePair(t, f.pair)
			pair := workflowPrepare(t, s, cli, candidate, "set", workflowReadPair(t, candidate), f.value)
			if bytes.Equal(pair.sealed, f.pair.sealed) {
				t.Fatal("equal proposal did not have an independent seal")
			}
			args := []string{"plan", "--trusted", f.source, "--trusted-format", "json", "--candidate", candidate, "--candidate-format", "json"}
			run := func(extra ...string) workflowChild {
				return workflowRun(t, s, cli, "noop", observer.Policy{}, nil, append(append([]string{}, args...), extra...)...)
			}
			equal := run("--check-secrets", "--json")
			nativePlanningFact(t, equal, 0, "match", "sealed", "equal", "not-requested")
			nativePlanningReads(t, equal, 2)
			nativePlanningNoSecret(t, equal, f.value)
			pending := []byte{'p', 'e', 'n', 'd', 'i', 'n', 'g', 0, 255, '\n', 128}
			defer clear(pending)
			pair = workflowPrepare(t, s, cli, candidate, "set-change", pair, pending)
			public := run("--json")
			if workflowResult(t, public, "success").Payload.Verdict != "match" {
				t.Fatal("public planning compared private content")
			}
			workflowGETOnly(t, public)
			nativePlanningNoSecret(t, public, pending)
			publicCandidate := nativeMergePair(t, pair)
			var editable map[string]any
			if json.Unmarshal(pair.editable, &editable) != nil {
				t.Fatal("public proposal unavailable")
			}
			editable["entries"].(map[string]any)["plain"] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "different public entry"}}
			body, err := json.Marshal(editable)
			if err != nil || os.WriteFile(publicCandidate, body, 0600) != nil {
				t.Fatal("public difference proposal unavailable")
			}
			publicPair := workflowReadPair(t, publicCandidate)
			publicDifference := workflowRun(t, s, cli, "noop", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", f.source, "--trusted-format", "json", "--candidate", publicCandidate, "--candidate-format", "json", "--json")
			var compared workflowOutput
			if publicDifference.code != 1 || len(publicDifference.diagnostic) != 0 || json.Unmarshal(publicDifference.out, &compared) != nil || compared.Schema != "ProductResult/v1" || compared.State != "success" || compared.Payload.Verdict != "mismatch" || !compared.Payload.DiagnosticsComplete || compared.Payload.EvidenceLimit != contract.ComparisonEvidenceLimit {
				t.Fatal("complete public difference did not retain successful command completion")
			}
			var publicFacts nativePlanningOutput
			if json.Unmarshal(publicDifference.out, &publicFacts) != nil || publicFacts.Observation.Domain == "" || publicFacts.Observation.Revision == "" || publicFacts.Observation.Snapshot == "" {
				t.Fatal("public proposal has no fixed observation")
			}
			var captured struct {
				Domain struct{ Authority struct{ ID string } }
			}
			if json.Unmarshal(pair.generated, &captured) != nil || len(captured.Domain.Authority.ID) != 64 {
				t.Fatal("captured Authority identity unavailable")
			}
			nativePlanningAddedPlainFacts(t, publicFacts.Payload.Changes, captured.Domain.Authority.ID)
			nativePlanningReads(t, publicDifference, 0)
			workflowUnchanged(t, publicCandidate, publicPair)
			changed := run("--check-secrets", "--json")
			privateFacts := nativePlanningFact(t, changed, 1, "mismatch", "sealed", "changed", "not-requested")
			if privateFacts.Observation != publicFacts.Observation || len(privateFacts.Payload.Changes) != 0 {
				t.Fatal("private check changed observation or claimed secret public values")
			}
			nativePlanningReads(t, changed, 2)
			nativePlanningNoSecret(t, changed, pending)
			displayed := run("--check-secrets", "--show-secret", "binary", "--json")
			displayFacts := nativePlanningDisplay(t, displayed, 1, pending, "sealed", "mismatch", "changed")
			if displayFacts.Observation != publicFacts.Observation || len(displayFacts.Payload.Changes) != 0 {
				t.Fatal("display result changed observation or public secret facts")
			}
			nativePlanningReads(t, displayed, 3)
			retained := nativePlanningRetainedPair(t, s, f.pair)
			retainedChild := workflowRun(t, s, cli, "noop", observer.Policy{}, nil, "plan", "--trusted", retained, "--trusted-format", "json", "--check-secrets", "--show-secret", "binary", "--json")
			nativePlanningDisplay(t, retainedChild, 0, f.value, "retained", "match", "equal")
			nativePlanningReads(t, retainedChild, 2)
			human := run("--check-secrets", "--show-secret", "binary")
			if human.code != 1 || !bytes.Contains(human.out, []byte(`pending\x00\xff\x0a\x80`)) || bytes.Contains(human.diagnostic, pending) {
				t.Fatal("human display lost reversible binary bytes or failed outcome")
			}
			nativePlanningReads(t, human, 3)
			duplicate := run("--check-secrets", "--show-secret", "binary", "--show-secret", "binary", "--json")
			if duplicate.code != 2 || bytes.Contains(duplicate.out, []byte(`"kind":"secret-display"`)) {
				t.Fatal("duplicate selected name reached display")
			}
			nativePlanningNoSecret(t, duplicate, pending)
			workflowUnchanged(t, candidate, pair)
			nativePlanningInvalidLastSource(t, s, cli, candidate, pair)
			invalidPair := workflowReadPair(t, candidate)
			invalidFact := run("--check-secrets", "--json")
			var refused nativePlanningOutput
			decoded := json.Unmarshal(invalidFact.out, &refused) == nil
			rowsExact := false
			if len(refused.Payload.PrivateEntries) == 2 {
				first, last := refused.Payload.PrivateEntries[0], refused.Payload.PrivateEntries[1]
				rowsExact = first.Name == "binary" && first.Form == "sealed" && first.Relation == "changed" && first.Reason == "none" &&
					last.Name == "z-invalid" && last.Form == "sealed" && last.Relation == "failed" && last.Reason == "invalid-input"
			}
			factExact := decoded && refused.Schema == "ProductResult/v1" && refused.Kind == "plan-supplied-values" && refused.State == "refused" &&
				refused.Payload.Schema == "PlanningPayload/v1" && refused.Payload.Verdict == "unable to verify" && !refused.Payload.PrivateComplete &&
				refused.Payload.DisplayDelivery == "not-requested" && refused.Payload.SelectedRecords == 0 && refused.Payload.CompletedRecords == 0 && rowsExact
			nativePlanningReads(t, invalidFact, 3)
			for _, value := range [][]byte{f.value, pending, []byte("unselected private sentinel")} {
				nativePlanningNoSecret(t, invalidFact, value)
			}
			if invalidFact.code != 2 || len(invalidFact.diagnostic) == 0 || !factExact {
				t.Logf("later planning refusal: exit=%d diagnostic_bytes=%d decoded=%t fact_exact=%t rows_exact=%t read_scope_exact=true", invalidFact.code, len(invalidFact.diagnostic), decoded, factExact, rowsExact)
				t.Fatal("later planning refusal differs from the exact safe nondisplay result")
			}
			invalid := run("--check-secrets", "--show-secret", "binary", "--json")
			if invalid.code != 2 || bytes.Contains(invalid.out, []byte(`"kind":"secret-display"`)) {
				t.Fatal("invalid later required source disclosed an earlier selected value")
			}
			nativePlanningNoSecret(t, invalid, pending)
			nativePlanningReads(t, invalid, 3)
			workflowUnchanged(t, candidate, invalidPair)
			workflowUnchanged(t, f.source, f.pair)
			_, afterHead := workflowHead(t, s)
			if !reflect.DeepEqual(originalHead, afterHead) || objects != s.objectCount() || s.children != expectedChildren {
				t.Fatalf("planning changed selected state or child inventory: actual=%d expected=%d", s.children, expectedChildren)
			}
		})
	}
}

func nativePlanningFact(t *testing.T, child workflowChild, exit int, verdict, form, relation, delivery string) nativePlanningOutput {
	t.Helper()
	var result nativePlanningOutput
	if len(child.diagnostic) != 0 {
		t.Fatalf("complete planning wrote unexpected diagnostics: bytes=%d", len(child.diagnostic))
	}
	if json.Unmarshal(child.out, &result) != nil || !nativePlanningInstallationRequirementsMatch(child.out) || child.code != exit || result.Schema != "ProductResult/v1" || result.Kind != "plan-supplied-values" || result.State != "success" || result.Payload.Schema != "PlanningPayload/v1" || result.Payload.Verdict != verdict || !result.Payload.PrivateComplete || result.Payload.DisplayDelivery != delivery || len(result.Payload.PrivateEntries) != 1 {
		t.Fatalf("private planning result differs: exit=%d schema=%s state=%s verdict=%s complete=%t rows=%d", child.code, result.Schema, result.State, result.Payload.Verdict, result.Payload.PrivateComplete, len(result.Payload.PrivateEntries))
	}
	if result.Effect != "not-applicable" || result.Output != "not-applicable" || !result.Payload.Complete || result.Payload.EvidenceLimit != contract.PlanningEvidenceLimit || delivery == "not-requested" && (result.Payload.SelectedRecords != 0 || result.Payload.CompletedRecords != 0) {
		t.Fatal("complete planning result lost its evidence limit, scope, or disclosure counts")
	}
	row := result.Payload.PrivateEntries[0]
	if row.Name != "binary" || row.Form != form || row.Relation != relation || row.Reason != "none" {
		t.Fatal("private planning did not return the exact safe relation")
	}
	return result
}

func nativePlanningDisplay(t *testing.T, child workflowChild, exit int, value []byte, form, verdict, relation string) nativePlanningOutput {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(child.out, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal("selected display did not have one record and one final result")
	}
	var display struct {
		Kind, Name string
		Form       string `json:"input_form"`
		Length     uint32 `json:"byte_length"`
		Value      string `json:"value_base64"`
	}
	var terminal struct {
		Kind   string
		Result json.RawMessage
	}
	if json.Unmarshal(lines[0], &display) != nil || json.Unmarshal(lines[1], &terminal) != nil || display.Kind != "secret-display" || display.Name != "binary" || display.Form != form || int(display.Length) != len(value) || display.Value != base64.StdEncoding.EncodeToString(value) || terminal.Kind != "plan-result" {
		t.Fatal("selected display failed exact binary round trip or terminal framing")
	}
	child.out = terminal.Result
	result := nativePlanningFact(t, child, exit, verdict, form, relation, "complete")
	if result.Payload.SelectedRecords != 1 || result.Payload.CompletedRecords != 1 {
		t.Fatal("selected display counts differ")
	}
	nativePlanningNoSecret(t, child, value)
	return result
}

func nativePlanningReads(t *testing.T, child workflowChild, decrypts int) {
	t.Helper()
	actual, reads := 0, 0
	for _, event := range child.capture.Events {
		if event.Kind != "http-start" {
			continue
		}
		switch event.Operation {
		case "head-read", "store-read":
			reads++
		case "kms-decrypt":
			actual++
			if event.Role != "authority" {
				t.Fatal("private planning used another private route")
			}
		default:
			t.Fatal("private planning attempted a non-read capability")
		}
	}
	if actual != decrypts || reads == 0 {
		t.Fatalf("private read scope differs: decrypts=%d expected=%d reads=%d", actual, decrypts, reads)
	}
}

func nativePlanningNoSecret(t *testing.T, child workflowChild, value []byte) {
	t.Helper()
	if len(value) == 0 {
		return
	}
	sum := sha256.Sum256(value)
	private := [][]byte{value, []byte(base64.StdEncoding.EncodeToString(value)), []byte(hex.EncodeToString(value)), sum[:], []byte(hex.EncodeToString(sum[:])), []byte(base64.StdEncoding.EncodeToString(sum[:]))}
	defer func() {
		for _, encoding := range private[1:] {
			clear(encoding)
		}
	}()
	for _, body := range [][]byte{child.out, child.diagnostic} {
		for _, encoding := range private {
			if bytes.Contains(body, encoding) {
				t.Fatal("private value or unkeyed digest escaped ordinary result or diagnostics")
			}
		}
	}
}

func nativePlanningRetainedPair(t *testing.T, s *workflowServer, source workflowPair) string {
	t.Helper()
	path := nativeMergePair(t, source)
	head, _ := workflowHead(t, s)
	entry := workflowEntry(t, s, workflowRoot(t, s, head))
	var generated map[string]any
	if json.Unmarshal(source.generated, &generated) != nil {
		t.Fatal("generated source unavailable")
	}
	generated["secrets"].(map[string]any)["binary"] = map[string]any{"retained": map[string]any{"incarnation": hex.EncodeToString(entry.Incarnation[:]), "material": hex.EncodeToString(entry.ValueState[:])}}
	body, err := json.Marshal(generated)
	if err != nil || os.WriteFile(filepath.Join(filepath.Dir(path), source.reference), body, 0600) != nil {
		t.Fatal("retained source preparation failed")
	}
	return path
}

func nativePlanningInvalidLastSource(t *testing.T, s *workflowServer, cli, path string, pair workflowPair) {
	t.Helper()
	var editable map[string]any
	if json.Unmarshal(pair.editable, &editable) != nil {
		t.Fatal("editable source unavailable")
	}
	editable["entries"].(map[string]any)["z-invalid"] = map[string]any{"confidentiality": "secret", "recipients": []string{"reader"}, "source": map[string]any{"kind": "supplied"}}
	body, err := json.Marshal(editable)
	if err != nil || os.WriteFile(path, body, 0600) != nil {
		t.Fatal("later source declaration failed")
	}
	child := workflowRun(t, s, cli, "set", observer.Policy{NoKMS: true}, []byte("unselected private sentinel"), "set", "--source", path, "--source-format", "json", "--name", "z-invalid", "--json")
	workflowResult(t, child, "success")
	generatedPath := filepath.Join(filepath.Dir(path), pair.reference)
	body, err = os.ReadFile(generatedPath)
	var generated map[string]any
	if err != nil || json.Unmarshal(body, &generated) != nil {
		t.Fatal("later generated source unavailable")
	}
	row := generated["secrets"].(map[string]any)["z-invalid"].(map[string]any)
	encoded, err := base64.StdEncoding.DecodeString(row["sealed"].(string))
	if err != nil {
		t.Fatal("later seal encoding invalid")
	}
	envelope, err := contract.DecodeSealedInputEnvelope(encoded)
	if err != nil || len(envelope.Ciphertext) == 0 {
		t.Fatal("later seal unavailable")
	}
	envelope.Ciphertext[0] ^= 1
	encoded, err = contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		t.Fatal("damaged source encoding failed")
	}
	row["sealed"] = encoded
	body, err = json.Marshal(generated)
	if err != nil || os.WriteFile(generatedPath, body, 0600) != nil {
		t.Fatal("damaged source preparation failed")
	}
}

func nativePlanningAddedPlainFacts(t *testing.T, changes []nativePlanningChange, authority string) {
	t.Helper()
	// Fixed ASCII bytes independently encode to this Base64 literal. The
	// Authority ID is captured source input, never taken from the plan result.
	expected := `[
` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"class"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"uint","value":"1"}},` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"input_encoding"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"uint","value":"1"}},` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"memberships"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"id-set","value":[{"id":"` + authority + `","change":"added"}]}},` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"name"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"text","value":"plain"}},` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"output_encoding"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"uint","value":"1"}},` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"plain_value"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"bytes","value":{"base64":"ZGlmZmVyZW50IHB1YmxpYyBlbnRyeQ==","byte_length":22}}},` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"presence"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"boolean","value":true}},` +
		`{"subject":{"kind":"entry","name":"plain"},"path":[{"field":"source"}],"action":"added","before":{"state":"absent"},"after":{"state":"present","type":"uint","value":"1"}}]`
	var want []nativePlanningChange
	if json.Unmarshal([]byte(expected), &want) != nil || len(changes) != len(want) {
		t.Fatal("native plan omitted or altered complete added public fields")
	}
	for at := range want {
		got, expected := changes[at], want[at]
		for _, values := range [][2]json.RawMessage{{got.Before.Value, expected.Before.Value}, {got.After.Value, expected.After.Value}} {
			if len(values[0]) == 0 && len(values[1]) == 0 {
				continue
			}
			var actualValue, expectedValue interface{}
			if json.Unmarshal(values[0], &actualValue) != nil || json.Unmarshal(values[1], &expectedValue) != nil || !reflect.DeepEqual(actualValue, expectedValue) {
				t.Fatal("native plan changed complete public value", at)
			}
		}
		got.Before.Value, got.After.Value, expected.Before.Value, expected.After.Value = nil, nil, nil, nil
		if !reflect.DeepEqual(got, expected) {
			t.Fatal("native plan changed public field metadata", at)
		}
	}
}
