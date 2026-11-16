package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicPrepareResult struct {
	Schema, Operation, Branch, Outcome string
	RequestID                          string `json:"request_id"`
	MissingInputs                      []struct {
		Name       string `json:"name"`
		Reason     string `json:"reason"`
		NextAction string `json:"next_action"`
	} `json:"missing_inputs"`
	Recovery struct{ Status, Domain, Head string }
	Delivery struct {
		Outcome        string
		EditablePath   string `json:"editable_path"`
		GeneratedPath  string `json:"generated_path"`
		RecoverySource string `json:"recovery_source"`
		CleanupFailed  bool   `json:"cleanup_failed"`
		Readback       *struct {
			EditableDigest  string `json:"editable_digest"`
			GeneratedDigest string `json:"generated_digest"`
		}
	} `json:"local_delivery"`
	Dependencies struct {
		Assessment                 string
		MinimumAdministrativeReady bool `json:"minimum_administrative_ready"`
		AllDeclaredReady           bool `json:"all_declared_ready"`
		SettingsFailure            *struct {
			Stage, Object, Reason, Action string
			Path                          *string
			Location                      *struct {
				Byte, Line, Column uint64
				Precision          string
			}
		} `json:"settings_failure"`
		// These branches declare no dependencies; every nonempty row is refused.
		Requirements  []json.RawMessage
		Installations []json.RawMessage
	}
	Diagnostics []struct{ Reason, Subject string }
}

func publicPreparedResult(t testing.TB, child publicChildResult, branch string) publicPrepareResult {
	t.Helper()
	result, ok := publicPreparedResultMatches(child, branch)
	if !ok {
		t.Fatal("public prepare did not complete the exact dependency-free branch")
	}
	return result
}

func publicPreparedResultMatches(child publicChildResult, branch string) (publicPrepareResult, bool) {
	var result publicPrepareResult
	var fields map[string]json.RawMessage
	if child.Code != 0 || operatorStrictJSON(child.Body, &result) != nil || json.Unmarshal(child.Body, &fields) != nil || len(fields) != 10 ||
		result.Schema != "enkv/prepare-result/v2" || result.Operation != "prepare" || result.Branch != branch || result.Outcome != "complete" ||
		!publicIdentityHex(result.RequestID) || len(result.Diagnostics) != 0 || result.Dependencies.Assessment != "complete" ||
		!result.Dependencies.MinimumAdministrativeReady || !result.Dependencies.AllDeclaredReady || result.Dependencies.Requirements == nil || len(result.Dependencies.Requirements) != 0 ||
		result.Dependencies.Installations == nil || len(result.Dependencies.Installations) != 0 || result.Dependencies.SettingsFailure != nil || result.MissingInputs == nil || len(result.MissingInputs) != 0 {
		return result, false
	}
	for _, name := range []string{"schema", "operation", "request_id", "branch", "recovery", "local_delivery", "dependencies", "missing_inputs", "diagnostics", "outcome"} {
		if fields[name] == nil {
			return result, false
		}
	}
	var dependencies map[string]json.RawMessage
	if json.Unmarshal(fields["dependencies"], &dependencies) != nil || len(dependencies) != 6 {
		return result, false
	}
	for _, name := range []string{"assessment", "minimum_administrative_ready", "all_declared_ready", "requirements", "installations", "settings_failure"} {
		if dependencies[name] == nil {
			return result, false
		}
	}
	return result, true
}

// full_only: false
func TestPublicPrepareRequiresCurrentDependencyFreeResult(t *testing.T) {
	body := []byte(`{"schema":"enkv/prepare-result/v2","operation":"prepare","request_id":"1111111111111111111111111111111111111111111111111111111111111111","branch":"reconstruction","recovery":{},"local_delivery":{},"dependencies":{"assessment":"complete","minimum_administrative_ready":true,"all_declared_ready":true,"requirements":[],"installations":[],"settings_failure":null},"missing_inputs":[],"diagnostics":[],"outcome":"complete"}`)
	if _, ok := publicPreparedResultMatches(publicChildResult{Body: body}, "reconstruction"); !ok {
		t.Fatal("current complete dependency-free prepare result was refused")
	}
	for _, change := range []struct{ name, before, after string }{
		{"obsolete-schema", "prepare-result/v2", "prepare-result/v1"},
		{"missing-requirements", `"requirements":[],`, ``},
		{"null-requirements", `"requirements":[]`, `"requirements":null`},
		{"missing-installations", `,"installations":[]`, ``},
		{"null-installations", `"installations":[]`, `"installations":null`},
		{"missing-settings-failure", `,"settings_failure":null`, ``},
		{"present-settings-failure", `"settings_failure":null`, `"settings_failure":{"stage":"settings","object":"plugins.json","path":null,"reason":"settings-invalid","location":null,"action":"correct-settings"}`},
		{"missing-missing-inputs", `,"missing_inputs":[]`, ``},
		{"null-missing-inputs", `"missing_inputs":[]`, `"missing_inputs":null`},
		{"unfilled-input", `"missing_inputs":[]`, `"missing_inputs":[{"name":"","reason":"supplied-input-missing","next_action":"set"}]`},
		{"undeclared-requirement", `"requirements":[]`, `"requirements":[{"role":"generator","plugin":null,"contract":"not-declared","protocol_version":1,"artifact":null,"status":"verified","reason":"none"}]`},
		{"undeclared-installation", `"installations":[]`, `"installations":[{"name":"not-declared","role":"generator","version":"1","artifact":null,"platform":"darwin/arm64","source":"local","status":"verified","reason":"none","previous":null,"changed":false}]`},
		{"unknown-member", `"installations":[]`, `"installations":[],"unknown":[]`},
		{"case-alias", `"installations":[]`, `"Installations":[]`},
		{"wrong-branch", `"reconstruction"`, `"existing-pair"`},
		{"not-ready", `"all_declared_ready":true`, `"all_declared_ready":false`},
		{"not-assessed", `"assessment":"complete"`, `"assessment":"incomplete"`},
		{"not-complete", `"outcome":"complete"`, `"outcome":"incomplete"`},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := bytes.Replace(body, []byte(change.before), []byte(change.after), 1)
			if _, ok := publicPreparedResultMatches(publicChildResult{Body: changed}, "reconstruction"); bytes.Equal(body, changed) || ok {
				t.Fatal("prepare oracle accepted a different schema, branch or dependency contract")
			}
		})
	}
	if _, ok := publicPreparedResultMatches(publicChildResult{Code: 2, Body: body}, "reconstruction"); ok {
		t.Fatal("prepare oracle accepted failed command completion")
	}
}

func publicPrepareReadOnly(t testing.TB, capture nativeprocess.Capture) {
	t.Helper()
	for _, event := range capture.Events {
		if event.Kind != "http-start" {
			continue
		}
		if !event.Sent || event.Operation != "head-read" && event.Operation != "store-read" && event.Operation != "kms-public" &&
			(event.Operation != "kms-decrypt" || event.Role != "authority") {
			t.Fatal("public prepare or unchanged apply entered a forbidden remote operation")
		}
	}
	publicAssertNoRecovery(t, capture)
}

func runPublicPrepareCompleteLoss(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) string {
	t.Helper()
	value := []byte("complete-loss public secret\x00\xff")
	defer clear(value)
	document := publicSourceDocument(t, source)
	document["entries"] = map[string]any{"secret": map[string]any{"confidentiality": "secret", "recipients": []string{"consumer"}, "source": map[string]any{"kind": "supplied"}}}
	publicWriteSource(t, source, document)
	set := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, value, "set", "--source", source, "--source-format", "json", "--name", "secret", "--json")
	publicAssertSet(t, set, source, "secret")
	clear(set.Body)
	applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	if !publicApplyMatches(applied, publicProduct(t, applied, "apply-declaration"), "success") {
		clear(applied.Body)
		t.Fatal("complete-loss supplied fixture did not select its exact declaration")
	}
	clear(applied.Body)
	basis, genesis := publicOperatorGenesis(t, source)
	store, err := openPublicReaderStore(ctx, input, genesis.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("complete-loss independent GET-only Store unavailable")
	}
	current := publicOperatorOpen(t, ctx, genesis.DomainID, basis, recordedStore{Store: store, budget: budget})
	if current.head.Core.Form == format.GenesisHead || len(current.root.Names) != 1 || current.root.SecretCount != 1 {
		t.Fatal("complete-loss fixture lacks one ordinary selected secret")
	}
	entry := current.valueEntry(current.root.Names[0].Slot)
	if entry == nil || entry.Name != "secret" || len(entry.Recipients) != 2 {
		t.Fatal("complete-loss fixture lacks exact shared supplied membership")
	}
	selected := *entry
	oldGenerated := publicSourceDocument(t, filepath.Join(filepath.Dir(source), publicSourceDocument(t, source)["generated"].(string)))
	var ledger publicOwnership
	if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil {
		t.Fatal("complete-loss cleanup facts unavailable")
	}
	ledger.Domain = hex.EncodeToString(current.root.Domain[:])
	if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
		t.Fatal("complete-loss cleanup Domain could not be retained before removal")
	}
	if os.RemoveAll(filepath.Dir(source)) != nil {
		t.Fatal("complete-loss source removal failed")
	}
	if _, err := os.Lstat(filepath.Dir(source)); !os.IsNotExist(err) {
		t.Fatal("complete-loss barrier retained the setup directory")
	}
	directory := filepath.Join(inv.StateDir, "recovered-source")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("complete-loss fresh destination unavailable")
	}
	source = filepath.Join(directory, "recovered.json")
	prepared := publicCLI(t, ctx, inv, input, budget, "authority", false, nativeprocess.Policy{ExpectedSHA256: publicExpected(value)}, nil,
		"prepare", "--source", source, "--source-format", "json", "--name", "restored", "--provider", input.Settings.Provider,
		"--bucket", input.Settings.Bucket, "--region", input.Settings.Region, "--prefix", input.Prefix, "--normal-signing-key", input.Settings.KeyID, "--json")
	result := publicPreparedResult(t, prepared, "reconstruction")
	image := publicSourceImage(t, source)
	generatedPath := filepath.Join(directory, ".enkv", "restored.generated.json")
	if result.Recovery.Status != "complete" || result.Recovery.Domain != ledger.Domain || result.Recovery.Head != bodyDigest(current.body) ||
		result.Delivery.Outcome != "recorded" || result.Delivery.EditablePath != source || result.Delivery.GeneratedPath != generatedPath || result.Delivery.CleanupFailed ||
		result.Delivery.RecoverySource != "" || result.Delivery.Readback == nil || result.Delivery.Readback.EditableDigest != bodyDigest(image.Files[source]) ||
		result.Delivery.Readback.GeneratedDigest != bodyDigest(image.Files[generatedPath]) {
		t.Fatal("complete-loss prepare changed selected identity or exact delivery facts")
	}
	publicPrepareMeaning(t, source, generatedPath, oldGenerated, selected, current)
	publicAssertPlain(t, prepared.Capture, false)
	publicPrepareReadOnly(t, prepared.Capture)
	publicPlanningSafe(t, prepared, prepared.Body, value)
	clear(prepared.Body)
	publicObservePair(t, ctx, inv, input, budget, source)
	private := publicLifecycleReadOnly(t, source, func() publicChildResult {
		return publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "plan", "--trusted", source, "--trusted-format", "json", "--check-secrets", "--json")
	})
	observation := [3]string{ledger.Domain, hex.EncodeToString(current.head.Core.Revision[:]), hex.EncodeToString(current.root.Snapshot[:])}
	rows := []publicPlanningRow{{Name: "secret", Form: "retained", Relation: "equal", Reason: "none"}}
	if private.DiagnosticBytes != 0 || !publicPlanningFactMatches(private.Body, private.Code, "match", "not-requested", rows, 0, observation) || !publicPlanningReadCapture(private.Capture, 1, true) {
		t.Fatal("fresh recovered private comparison did not prove the exact retained equality")
	}
	publicPlanningSafe(t, private, private.Body, value)
	clear(private.Body)
	consumed := publicLifecycleReadOnly(t, source, func() publicChildResult {
		return publicCLI(t, ctx, inv, input, budget, "consumer", true, nativeprocess.Policy{ExpectedSHA256: publicExpected(value)}, nil, "--source", source, "--source-format", "json")
	})
	if consumed.Code != 0 {
		t.Fatal("fresh recovered independent private byte observation failed")
	}
	publicAssertPlain(t, consumed.Capture, false)
	publicPrepareReadOnly(t, consumed.Capture)
	publicPlanningSafe(t, consumed, consumed.Body, value)
	clear(consumed.Body)
	idle := publicLifecycleReadOnly(t, source, func() publicChildResult {
		return publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	})
	if !publicApplyMatches(idle, publicProduct(t, idle, "apply-declaration"), "no-op") {
		t.Fatal("fresh recovered idle apply did not remain unchanged")
	}
	publicPrepareReadOnly(t, idle.Capture)
	clear(idle.Body)
	listed := publicLifecycleReadOnly(t, source, func() publicChildResult {
		return publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "abandon", "list", "--source", source, "--source-format", "json", "--json")
	})
	list, err := operatorAbandonmentResult(listed.Body)
	if listed.Code != 0 || err != nil || list.State != "success" {
		t.Fatal("fresh recovered minimum administrative query failed")
	}
	publicAssertGETOnly(t, listed.Capture)
	clear(listed.Body)
	existing := publicLifecycleReadOnly(t, source, func() publicChildResult {
		return publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "prepare", "--source", source, "--source-format", "json", "--json")
	})
	repeated := publicPreparedResult(t, existing, "existing")
	if repeated.RequestID == result.RequestID || repeated.Recovery.Status != "not-attempted" || repeated.Recovery.Domain != "" || repeated.Recovery.Head != "" ||
		repeated.Delivery.Outcome != "not-recorded" || repeated.Delivery.EditablePath != "" || repeated.Delivery.GeneratedPath != "" || repeated.Delivery.Readback != nil ||
		repeated.Delivery.CleanupFailed || repeated.Delivery.RecoverySource != "" || len(existing.Capture.Events) != 1 || existing.Capture.Events[0].Kind != "footer" {
		t.Fatal("existing recovered pair preparation repeated recovery or provider work")
	}
	clear(existing.Body)
	publicImageUnchanged(t, image)
	if after := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir); !reflect.DeepEqual(current.head, after) {
		t.Fatal("fresh recovered consumers changed the exact selected HEAD")
	}
	return source
}

func publicPrepareMeaning(t testing.TB, source, generatedPath string, previous map[string]any, selected contract.ValueEntry, current *StateSession) {
	t.Helper()
	document := publicSourceDocument(t, source)
	generated := publicSourceDocument(t, generatedPath)
	domain, ok := document["domain"].(map[string]any)
	if !ok || domain["name"] != "restored" || document["generated"] != ".enkv/restored.generated.json" || generated["file_id"] == previous["file_id"] ||
		!reflect.DeepEqual(generated["domain"], previous["domain"]) {
		t.Fatal("recovered pair changed public domain control or failed to create new local identity")
	}
	entries, ok := document["entries"].(map[string]any)
	if !ok || len(entries) != 1 {
		t.Fatal("recovered pair changed the complete supplied entry set")
	}
	entry, ok := entries["secret"].(map[string]any)
	if !ok || entry["confidentiality"] != "secret" || !reflect.DeepEqual(entry["source"], map[string]any{"kind": "supplied"}) {
		t.Fatal("recovered pair changed supplied entry meaning")
	}
	secrets, ok := generated["secrets"].(map[string]any)
	want := map[string]any{"retained": map[string]any{"incarnation": hex.EncodeToString(selected.Incarnation[:]), "material": hex.EncodeToString(selected.ValueState[:])}}
	if !ok || len(secrets) != 1 || !reflect.DeepEqual(secrets["secret"], want) {
		t.Fatal("recovered pair lost the selected supplied material identity")
	}
	recipients, ok := generated["recipients"].(map[string]any)
	editableRecipients, editableOK := document["recipients"].(map[string]any)
	if !ok || !editableOK || len(recipients) != 1 || len(editableRecipients) != 1 {
		t.Fatal("recovered pair changed the complete ordinary Recipient set")
	}
	members := []contract.ID{current.root.CurrentAccess.Core.CurrentControl.AuthorityRecipientID}
	for reference, value := range recipients {
		row, ok := value.(map[string]any)
		editable, editableOK := editableRecipients[reference].(map[string]any)
		if !ok || !editableOK {
			t.Fatal("recovered Recipient reference has no complete declaration")
		}
		var original *contract.RecipientRecord
		for _, candidate := range current.registry() {
			if row["id"] == hex.EncodeToString(candidate.RecipientID[:]) {
				copy := candidate
				original = &copy
			}
		}
		if original == nil || original.CurrentBinding == nil || original.Status != contract.CurrentRecipient || editable["display_name"] != original.DisplayName || editable["encryption_key"] != original.CurrentBinding.KeySelector {
			t.Fatal("recovered Recipient changed its selected identity, name or selector")
		}
		key, ok := row["encryption"].(map[string]any)
		if !ok {
			t.Fatal("recovered Recipient encryption binding unavailable")
		}
		prior := previous["recipients"].(map[string]any)["consumer"].(map[string]any)
		if prior["id"] != row["id"] || !reflect.DeepEqual(key, prior["encryption"]) {
			t.Fatal("recovered Recipient changed its exact public encryption binding")
		}
		if !reflect.DeepEqual(entry["recipients"], []any{reference}) {
			t.Fatal("recovered secret changed its exact Recipient reference")
		}
		members = append(members, original.RecipientID)
	}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	wantMembers := slices.Clone(selected.Recipients)
	slices.SortFunc(wantMembers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if !slices.Equal(members, wantMembers) {
		t.Fatal("recovered secret changed exact selected membership")
	}
	var witness struct {
		Kind   string
		Anchor []byte `json:"anchor"`
		HEAD   []byte `json:"head"`
		Root   []byte `json:"root"`
	}
	encoded, err := json.Marshal(generated["public_basis"])
	if err != nil || json.Unmarshal(encoded, &witness) != nil || witness.Kind != "observation" || !bytes.Equal(witness.HEAD, current.body) {
		t.Fatal("recovered pair did not retain its exact independently anchored observation")
	}
	anchor, err := contract.DecodePublicSigningBinding(witness.Anchor)
	if err != nil || !reflect.DeepEqual(anchor, current.root.CurrentAccess.Core.CurrentControl.NormalSigning) {
		t.Fatal("recovered pair changed the independently selected normal signing anchor")
	}
	root, err := format.DecodeRoot(witness.Root)
	if err != nil || !reflect.DeepEqual(root, current.root) {
		t.Fatal("recovered pair changed its exact selected root")
	}
	outputs, ok := document["outputs"].(map[string]any)
	if !ok || !reflect.DeepEqual(outputs, map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}, "groups": []any{}}) {
		t.Fatal("recovered pair changed its empty output declaration")
	}
}
