package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicPlanningRow struct {
	Name, Relation, Reason string
	Form                   string `json:"input_form"`
}

type publicPlanningResult struct {
	Schema    string
	Operation string `json:"operation_kind"`
	State     string `json:"state_result"`
	Effect    string `json:"effect_summary"`
	Output    string `json:"output_summary"`
	Observed  struct {
		Domain   string `json:"domain_id"`
		Revision string `json:"head_revision_id"`
		Snapshot string `json:"snapshot_id"`
	} `json:"observation"`
	Payload struct {
		Schema, Verdict string
		EvidenceLimit   string              `json:"evidence_limit"`
		Complete        bool                `json:"diagnostics_complete"`
		PrivateComplete bool                `json:"private_complete"`
		Delivery        string              `json:"display_delivery"`
		Selected        uint32              `json:"selected_records"`
		Completed       uint32              `json:"completed_records"`
		Entries         []publicPlanningRow `json:"private_entries"`
	}
}

func publicPlanningFactMatches(body []byte, code int, verdict, delivery string, rows []publicPlanningRow, count uint32, observation [3]string) bool {
	var result publicPlanningResult
	if json.Unmarshal(body, &result) != nil {
		return false
	}
	wantCode := 0
	if verdict == "mismatch" {
		wantCode = 1
	}
	return code == wantCode && result.Schema == "ProductResult/v1" && result.Operation == "plan-supplied-values" && result.State == "success" &&
		result.Effect == "not-applicable" && result.Output == "not-applicable" && result.Payload.Schema == "PlanningPayload/v1" &&
		result.Payload.EvidenceLimit == contract.PlanningEvidenceLimit &&
		result.Payload.Verdict == verdict && result.Payload.Complete && result.Payload.PrivateComplete && result.Payload.Delivery == delivery &&
		result.Payload.Selected == count && result.Payload.Completed == count && reflect.DeepEqual(result.Payload.Entries, rows) &&
		[3]string{result.Observed.Domain, result.Observed.Revision, result.Observed.Snapshot} == observation
}

func publicPlanningDisplayResult(body []byte, name, form string, value []byte) ([]byte, bool) {
	lines := bytes.Split(bytes.TrimSuffix(body, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 {
		return nil, false
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
	if json.Unmarshal(lines[0], &display) != nil || json.Unmarshal(lines[1], &terminal) != nil || display.Kind != "secret-display" ||
		display.Name != name || display.Form != form || int(display.Length) != len(value) || display.Value != base64.StdEncoding.EncodeToString(value) || terminal.Kind != "plan-result" || !json.Valid(terminal.Result) {
		return nil, false
	}
	return terminal.Result, true
}

func publicPlanningReadCapture(capture nativeprocess.Capture, decrypts int, requireReads bool) bool {
	actual, reads := 0, 0
	for _, event := range capture.Events {
		if event.Kind == "construction" && (event.Operation != "key-access" || event.Role != "authority" || decrypts == 0) {
			return false
		}
		if event.Kind != "http-start" {
			continue
		}
		switch event.Operation {
		case "head-read", "store-read":
			reads++
		case "kms-decrypt":
			actual++
			if event.Role != "authority" || !event.Sent {
				return false
			}
		default:
			return false
		}
	}
	return actual == decrypts && (!requireReads || reads > 0)
}

func publicPlanningComparisonMatches(child publicChildResult, product publicProductResult) bool {
	if child.Code != 0 || child.DiagnosticBytes != 0 || product.State != "success" || product.Payload.Verdict != "match" || !product.Payload.Complete || len(product.Payload.Scope) != 12 || !publicPlanningReadCapture(child.Capture, 0, true) || product.Payload.EvidenceLimit != contract.ComparisonEvidenceLimit {
		return false
	}
	for _, scope := range product.Payload.Scope {
		if scope.Status != "complete" {
			return false
		}
	}
	return true
}

func publicPlanningSafe(t testing.TB, child publicChildResult, ordinary []byte, values ...[]byte) {
	t.Helper()
	capture, err := os.ReadFile(child.CapturePath)
	if err != nil || len(capture) > nativeprocess.MaxCaptureBytes {
		t.Fatal("planning safe capture unavailable")
	}
	defer clear(capture)
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		sum := sha256.Sum256(value)
		for _, body := range [][]byte{ordinary, capture} {
			for _, private := range [][]byte{value, []byte(base64.StdEncoding.EncodeToString(value)), []byte(hex.EncodeToString(value)), sum[:], []byte(hex.EncodeToString(sum[:])), []byte(base64.StdEncoding.EncodeToString(sum[:]))} {
				if bytes.Contains(body, private) {
					t.Fatal("planning private bytes or unkeyed digest escaped the selected display")
				}
			}
		}
	}
}

// The selected two-entry fixture is reused; every proposal remains unselected.
func runPublicPlanning(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, current *StateSession, value []byte) {
	t.Helper()
	sourceImage := publicSourceImage(t, source)
	candidate := publicPortablePair(t, source, filepath.Join(inv.StateDir, "planning-proposal-pair"))
	retained := publicPortablePair(t, source, filepath.Join(inv.StateDir, "planning-retained-pair"))
	observation := [3]string{hex.EncodeToString(current.root.Domain[:]), hex.EncodeToString(current.head.Core.Revision[:]), hex.EncodeToString(current.root.Snapshot[:])}
	pending := []byte{'p', 'e', 'n', 'd', 'i', 'n', 'g', 0, 255, '\n', 128}
	defer clear(pending)
	set := func(name string, plain []byte) {
		child := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true, MaxRequests: 1, MaxBytes: 1}, plain,
			"set", "--source", candidate, "--source-format", "json", "--name", name, "--json")
		defer clear(child.Body)
		publicAssertSet(t, child, candidate, name)
		publicPlanningSafe(t, child, child.Body, value, pending)
	}
	run := func(proposed string, private bool, extra ...string) publicChildResult {
		args := []string{"plan", "--trusted", source, "--trusted-format", "json", "--candidate", proposed, "--candidate-format", "json"}
		role := "reader"
		if private {
			role = "apply"
			args = append(args, "--check-secrets")
		}
		return publicLifecycleReadOnly(t, source, func() publicChildResult {
			return publicLifecycleReadOnly(t, proposed, func() publicChildResult {
				return publicCLI(t, ctx, inv, input, budget, role, false, nativeprocess.Policy{NoKMS: !private, MaxRequests: 128, MaxBytes: 8 << 20}, nil, append(args, extra...)...)
			})
		})
	}
	assertFact := func(child publicChildResult, verdict, delivery string, rows []publicPlanningRow, count uint32, decrypts int) {
		t.Helper()
		if child.DiagnosticBytes != 0 || !publicPlanningFactMatches(child.Body, child.Code, verdict, delivery, rows, count, observation) || !publicPlanningReadCapture(child.Capture, decrypts, true) {
			t.Fatal("planning differs from the exact safe relation, observation or read scope")
		}
		publicPlanningSafe(t, child, child.Body, value, pending)
	}
	assertDisplay := func(child publicChildResult, name, form string, plain []byte, verdict string, rows []publicPlanningRow, decrypts int) {
		t.Helper()
		defer clear(child.Body)
		terminal, ok := publicPlanningDisplayResult(child.Body, name, form, plain)
		if !ok {
			t.Fatal("planning selected display lost exact bytes, source form or terminal framing")
		}
		defer clear(terminal)
		child.Body = terminal
		assertFact(child, verdict, "complete", rows, 1, decrypts)
	}
	equalRows := []publicPlanningRow{{Name: "secret", Form: "sealed", Relation: "equal", Reason: "none"}}
	changedRows := []publicPlanningRow{{Name: "secret", Form: "sealed", Relation: "changed", Reason: "none"}}
	generatedPath := filepath.Join(filepath.Dir(candidate), filepath.FromSlash(publicSourceDocument(t, candidate)["generated"].(string)))
	originalSeal := publicSourceDocument(t, generatedPath)["secrets"].(map[string]any)["secret"].(map[string]any)["sealed"].(string)
	set("secret", value)
	if publicSourceDocument(t, generatedPath)["secrets"].(map[string]any)["secret"].(map[string]any)["sealed"].(string) == originalSeal {
		t.Fatal("planning equal proposal did not have an independent seal")
	}
	equal := run(candidate, true, "--json")
	assertFact(equal, "match", "not-requested", equalRows, 0, 2)
	clear(equal.Body)
	set("secret", pending)
	public := run(candidate, false, "--json")
	product := publicProduct(t, public, contract.ReaderCompareOperation)
	if !publicPlanningComparisonMatches(public, product) {
		t.Fatal("public planning treated secret content as checked or constructed a private route")
	}
	publicPlanningSafe(t, public, public.Body, value, pending)
	clear(public.Body)
	changed := run(candidate, true, "--json")
	assertFact(changed, "mismatch", "not-requested", changedRows, 0, 2)
	clear(changed.Body)
	assertDisplay(run(candidate, true, "--show-secret", "secret", "--json"), "secret", "sealed", pending, "mismatch", changedRows, 3)
	human := run(candidate, true, "--show-secret", "secret")
	prefix := []byte("secret-display name=\"secret\" input_form=sealed byte_length=11 value=\"pending\\x00\\xff\\x0a\\x80\"\n")
	if human.Code != 1 || human.DiagnosticBytes != 0 || !bytes.HasPrefix(human.Body, prefix) || !bytes.Contains(human.Body[len(prefix):], []byte("verdict: mismatch\n")) || !bytes.Contains(human.Body[len(prefix):], []byte("display_delivery: complete\nselected_records: 1\ncompleted_records: 1\n")) || !publicPlanningReadCapture(human.Capture, 3, true) {
		t.Fatal("planning human display lost reversible binary bytes or complete result")
	}
	publicPlanningSafe(t, human, human.Body[len(prefix):], value, pending)
	clear(human.Body)
	for _, selection := range [][]string{{"--show-secret", "secret", "--show-secret", "secret", "--json"}, {"--show-secret", "plain", "--json"}} {
		child := run(candidate, true, selection...)
		if child.Code != 2 || bytes.Contains(child.Body, []byte(`"kind":"secret-display"`)) || !publicPlanningReadCapture(child.Capture, 0, false) {
			t.Fatal("planning invalid selector reached disclosure or private work")
		}
		publicPlanningSafe(t, child, child.Body, value, pending)
		clear(child.Body)
	}
	retainedDocument := publicSourceDocument(t, retained)
	retainedPath := filepath.Join(filepath.Dir(retained), filepath.FromSlash(retainedDocument["generated"].(string)))
	generated := publicSourceDocument(t, retainedPath)
	entry := publicLifecycleEntries(t, current)["secret"]
	generated["secrets"].(map[string]any)["secret"] = map[string]any{"retained": map[string]any{"incarnation": hex.EncodeToString(entry.Incarnation[:]), "material": hex.EncodeToString(entry.ValueState[:])}}
	publicRewritePortableSource(t, retainedPath, generated)
	retainedRows := []publicPlanningRow{{Name: "secret", Form: "retained", Relation: "equal", Reason: "none"}}
	assertDisplay(run(retained, true, "--show-secret", "secret", "--json"), "secret", "retained", value, "match", retainedRows, 2)
	document := publicSourceDocument(t, candidate)
	document["entries"].(map[string]any)["z-empty"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "supplied"}}
	publicRewritePortableSource(t, candidate, document)
	set("z-empty", nil)
	newRows := append(append([]publicPlanningRow{}, changedRows...), publicPlanningRow{Name: "z-empty", Form: "sealed", Relation: "new", Reason: "none"})
	assertDisplay(run(candidate, true, "--show-secret", "z-empty", "--json"), "z-empty", "sealed", nil, "mismatch", newRows, 4)
	generated = publicSourceDocument(t, generatedPath)
	row := generated["secrets"].(map[string]any)["z-empty"].(map[string]any)
	sealed, err := base64.StdEncoding.Strict().DecodeString(row["sealed"].(string))
	if err != nil {
		t.Fatal("planning later proposal encoding unavailable")
	}
	envelope, err := contract.DecodeSealedInputEnvelope(sealed)
	clear(sealed)
	if err != nil || len(envelope.Ciphertext) == 0 {
		t.Fatal("planning later proposal ciphertext unavailable")
	}
	envelope.Ciphertext[0] ^= 1
	sealed, err = contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		t.Fatal("planning later damaged proposal encoding unavailable")
	}
	row["sealed"] = sealed
	publicRewritePortableSource(t, generatedPath, generated)
	clear(sealed)
	invalid := run(candidate, true, "--json")
	defer clear(invalid.Body)
	var failed publicPlanningResult
	if invalid.Code != 2 || invalid.DiagnosticBytes == 0 || json.Unmarshal(invalid.Body, &failed) != nil || failed.Schema != "ProductResult/v1" || failed.Operation != "plan-supplied-values" || failed.State != "refused" || failed.Payload.Schema != "PlanningPayload/v1" || failed.Payload.Verdict != "unable to verify" || failed.Payload.PrivateComplete || failed.Payload.Delivery != "not-requested" || failed.Payload.Selected != 0 || failed.Payload.Completed != 0 || !reflect.DeepEqual(failed.Payload.Entries, []publicPlanningRow{changedRows[0], {Name: "z-empty", Form: "sealed", Relation: "failed", Reason: "invalid-input"}}) || !publicPlanningReadCapture(invalid.Capture, 3, true) {
		t.Fatal("planning failed later required input hid the exact failed check")
	}
	publicPlanningSafe(t, invalid, invalid.Body, value, pending)
	failedDisplay := run(candidate, true, "--show-secret", "secret", "--json")
	defer clear(failedDisplay.Body)
	if failedDisplay.Code != 2 || len(failedDisplay.Body) != 0 || failedDisplay.DiagnosticBytes == 0 || !publicPlanningReadCapture(failedDisplay.Capture, 3, true) {
		t.Fatal("planning failed later required input disclosed an earlier selected value")
	}
	publicPlanningSafe(t, failedDisplay, failedDisplay.Body, value, pending)
	if after := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir); !reflect.DeepEqual(current.head, after) {
		t.Fatal("read-only planning changed the selected state")
	}
	publicImageUnchanged(t, sourceImage)
}

// full_only: false
func TestPublicPlanningOracleRequiresExactRelationsObservationAndReadScope(t *testing.T) {
	t.Run("public-comparison", func(t *testing.T) {
		body := []byte(`{"state_result":"success","payload":{"verdict":"match","diagnostics_complete":true,"evidence_limit":"Fixed authenticated public settings and requested generated intent only; future generated content is unavailable and secret-value equality is unchecked. Excludes apply admission or no-op, performed effects or credential validity, remote output contents or IAM, historical application, and continued currentness.","checked_scope":[{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"}]}}`)
		var product publicProductResult
		if err := json.Unmarshal(body, &product); err != nil {
			t.Fatal(err)
		}
		child := publicChildResult{Body: body, Capture: nativeprocess.Capture{Events: []nativeprocess.Event{{Kind: "http-start", Operation: "head-read", Sent: true}}}}
		if !publicPlanningComparisonMatches(child, product) {
			t.Fatal("independent complete public planning fixture refused")
		}
		for _, limit := range []string{"", "secret-value equality is unchecked", "excludes secret-value equality"} {
			changed := product
			changed.Payload.EvidenceLimit = limit
			if publicPlanningComparisonMatches(child, changed) {
				t.Fatal("public planning oracle accepted an absent, partial or obsolete evidence limit")
			}
		}
	})
	body := []byte(`{"schema":"ProductResult/v1","operation_kind":"plan-supplied-values","state_result":"success","effect_summary":"not-applicable","output_summary":"not-applicable","observation":{"domain_id":"domain","head_revision_id":"revision","snapshot_id":"snapshot"},"payload":{"schema":"PlanningPayload/v1","verdict":"match","diagnostics_complete":true,"evidence_limit":"Fixed authenticated public settings, requested generated intent and supported supplied-secret relations only; future generated content is unavailable and public secret content is unchecked. Excludes apply admission or no-op, performed effects, output actions, remote state, and continued currentness.","private_complete":true,"display_delivery":"not-requested","selected_records":0,"completed_records":0,"private_entries":[{"name":"secret","input_form":"sealed","relation":"equal","reason":"none"}]}}`)
	rows := []publicPlanningRow{{Name: "secret", Form: "sealed", Relation: "equal", Reason: "none"}}
	observation := [3]string{"domain", "revision", "snapshot"}
	if !publicPlanningFactMatches(body, 0, "match", "not-requested", rows, 0, observation) {
		t.Fatal("independent complete safe planning fixture refused")
	}
	for _, substitution := range []struct{ name, before, after string }{
		{"wrong-operation", `"plan-supplied-values"`, `"apply-declaration"`},
		{"wrong-observation", `"head_revision_id":"revision"`, `"head_revision_id":"later"`},
		{"wrong-verdict", `"verdict":"match"`, `"verdict":"mismatch"`},
		{"incomplete-public", `"diagnostics_complete":true`, `"diagnostics_complete":false`},
		{"incomplete-private", `"private_complete":true`, `"private_complete":false`},
		{"wrong-delivery", `"display_delivery":"not-requested"`, `"display_delivery":"complete"`},
		{"unexpected-disclosure", `"completed_records":0`, `"completed_records":1`},
		{"wrong-name", `"name":"secret"`, `"name":"another"`},
		{"wrong-source", `"input_form":"sealed"`, `"input_form":"retained"`},
		{"unchecked-relation", `"relation":"equal"`, `"relation":"unchecked"`},
		{"failed-reason", `"reason":"none"`, `"reason":"invalid-input"`},
		{"missing-row", `[{"name":"secret","input_form":"sealed","relation":"equal","reason":"none"}]`, `[]`},
		{"extra-row", `"private_entries":[`, `"private_entries":[{"name":"unselected","input_form":"sealed","relation":"equal","reason":"none"},`},
		{"lost-evidence-limit", `Excludes apply admission or no-op`, `proves apply admission`},
	} {
		t.Run(substitution.name, func(t *testing.T) {
			changed := bytes.Replace(body, []byte(substitution.before), []byte(substitution.after), 1)
			if bytes.Equal(changed, body) || publicPlanningFactMatches(changed, 0, "match", "not-requested", rows, 0, observation) {
				t.Fatal("planning oracle accepted a substituted relation, source, scope or observation")
			}
		})
	}
	if publicPlanningFactMatches(body, 1, "match", "not-requested", rows, 0, observation) {
		t.Fatal("planning oracle accepted a failed matching command")
	}
	read := nativeprocess.Event{Kind: "http-start", Operation: "head-read", Sent: true}
	decrypt := nativeprocess.Event{Kind: "http-start", Operation: "kms-decrypt", Role: "authority", Sent: true}
	if !publicPlanningReadCapture(nativeprocess.Capture{Events: []nativeprocess.Event{read, decrypt}}, 1, true) || !publicPlanningReadCapture(nativeprocess.Capture{Events: []nativeprocess.Event{read}}, 0, true) {
		t.Fatal("planning oracle refused exact public/private read observations")
	}
	for _, operation := range []string{"kms-public", "kms-sign", "store-write", "head-write", "generator-create"} {
		t.Run(operation, func(t *testing.T) {
			capture := nativeprocess.Capture{Events: []nativeprocess.Event{read, decrypt, {Kind: "http-start", Operation: operation}}}
			if publicPlanningReadCapture(capture, 1, true) {
				t.Fatal("planning oracle accepted a non-read capability")
			}
		})
	}
	for _, role := range []string{"recipient-private", "recovery-private", "ordinary"} {
		wrong := decrypt
		wrong.Role = role
		if publicPlanningReadCapture(nativeprocess.Capture{Events: []nativeprocess.Event{read, wrong}}, 1, true) {
			t.Fatal("planning oracle accepted another private route")
		}
	}
	for _, capture := range []nativeprocess.Capture{
		{Events: []nativeprocess.Event{decrypt}},
		{Events: []nativeprocess.Event{read, decrypt, decrypt}},
		{Events: []nativeprocess.Event{read, decrypt, {Kind: "construction", Operation: "signer", Role: "normal"}}},
	} {
		if publicPlanningReadCapture(capture, 1, true) {
			t.Fatal("planning oracle accepted missing reads, repeated opens or signer construction")
		}
	}
	if publicPlanningReadCapture(nativeprocess.Capture{Events: []nativeprocess.Event{read, {Kind: "construction", Operation: "key-access", Role: "authority"}}}, 0, true) {
		t.Fatal("public planning oracle accepted private construction")
	}
}

// full_only: false
func TestPublicPlanningDisplayOracleRequiresExactSelectedRecordAndTerminal(t *testing.T) {
	value := []byte{0, 255, 10, 128}
	body := []byte("{\"kind\":\"secret-display\",\"name\":\"secret\",\"input_form\":\"sealed\",\"byte_length\":4,\"value_base64\":\"AP8KgA==\"}\n{\"kind\":\"plan-result\",\"result\":{\"safe\":true}}\n")
	terminal, ok := publicPlanningDisplayResult(body, "secret", "sealed", value)
	if !ok || !bytes.Equal(terminal, []byte(`{"safe":true}`)) {
		t.Fatal("independent binary display representation or safe terminal refused")
	}
	for _, substitution := range []struct{ name, before, after string }{
		{"wrong-name", `"name":"secret"`, `"name":"unselected"`},
		{"wrong-form", `"input_form":"sealed"`, `"input_form":"retained"`},
		{"wrong-length", `"byte_length":4`, `"byte_length":3`},
		{"wrong-byte", `AP8KgA==`, `AP8KgQ==`},
		{"missing-padding", `AP8KgA==`, `AP8KgA`},
		{"wrong-record-kind", `"kind":"secret-display"`, `"kind":"value"`},
		{"wrong-terminal-kind", `"kind":"plan-result"`, `"kind":"result"`},
	} {
		t.Run(substitution.name, func(t *testing.T) {
			changed := bytes.Replace(body, []byte(substitution.before), []byte(substitution.after), 1)
			if _, ok := publicPlanningDisplayResult(changed, "secret", "sealed", value); ok || bytes.Equal(changed, body) {
				t.Fatal("planning display oracle accepted substituted content or framing")
			}
		})
	}
	for _, incomplete := range [][]byte{bytes.Split(body, []byte{'\n'})[0], append(bytes.Clone(body), body...), []byte("{}\n")} {
		if _, ok := publicPlanningDisplayResult(incomplete, "secret", "sealed", value); ok {
			t.Fatal("planning display oracle accepted missing terminal or extra disclosure")
		}
	}
	empty := bytes.Replace(bytes.Replace(body, []byte(`"byte_length":4`), []byte(`"byte_length":0`), 1), []byte("AP8KgA=="), nil, 1)
	if _, ok := publicPlanningDisplayResult(empty, "secret", "sealed", nil); !ok {
		t.Fatal("planning display oracle refused explicit empty content")
	}
}
