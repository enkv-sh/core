package nativeprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeRecoveredRoutingKeepsOverridesAfterDefaultChange(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	output := newNativePublicationServer(t)
	binaries := buildNativeOutputExecutables(t, output.server.URL)
	binaries.nativePluginFixture = newNativePluginFixture(t, append(slices.Clone(binaries.builds), nativeManifestProductionBuild(t))...)
	s := newWorkflowServer(t, "aws", false)
	s.childLimit, s.childRequestLimit, s.objectLimit = 14, 2048, 512
	const account, project, owner = "000000000001", "900000000001", "routing"
	source := filepath.Join(t.TempDir(), "configuration.json")
	if err := os.WriteFile(source, workflowSetup(t, s, false), 0600); err != nil {
		t.Fatal(err)
	}
	children := []workflowChild{workflowRun(t, s, binaries.cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json")}
	workflowResult(t, children[0], "success")
	names := []string{"EMPTY", "INHERITED", "PINNED"}
	values := map[string]string{"EMPTY": "unpublished empty override", "INHERITED": "inherited route", "PINNED": "explicit equal default"}
	for _, name := range names {
		nativePublicationSource(t, source, func(value map[string]any) {
			value["entries"].(map[string]any)[name] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "supplied"}}
		})
		child := workflowRun(t, s, binaries.cli, "set", observer.Policy{NoKMS: true}, []byte(values[name]), "set", "--source", source, "--source-format", "json", "--name", name, "--json")
		workflowResult(t, child, "success")
		children = append(children, child)
	}
	nativePublicationSource(t, source, func(value map[string]any) {
		declaration := nativePublicationDeclaration(account, project, owner)
		destinations := declaration["destinations"].(map[string]any)
		for id := range destinations {
			if id != "gcp" && id != "repository" {
				delete(destinations, id)
				continue
			}
		}
		declaration["routing"] = map[string]any{"default": []string{"gcp"}, "entries": map[string]any{"EMPTY": []string{}, "PINNED": []string{"gcp"}}}
		value["outputs"] = declaration
	})
	beforeEffects := nativePublicationCounters(t, binaries)
	applied := workflowRunEnvironment(t, s, binaries.cli, "apply", observer.Policy{}, nil, binaries.Environment(t, source), "apply", "--source", source, "--source-format", "json", "--json")
	workflowResult(t, applied, "success")
	children = append(children, applied)
	original := workflowReadPair(t, source)
	_, selected := workflowHead(t, s)
	objects := s.objectCount()
	if err := os.RemoveAll(filepath.Dir(source)); err != nil {
		t.Fatal("complete-loss barrier failed", err)
	}
	if _, err := os.Lstat(filepath.Dir(source)); !os.IsNotExist(err) {
		t.Fatal("complete-loss barrier retained source files")
	}
	recovered := filepath.Join(t.TempDir(), "recovered.json")
	expectedValues := make(map[string]string, len(values))
	for name, value := range values {
		digest := sha256.Sum256([]byte(value))
		expectedValues[name] = hex.EncodeToString(digest[:])
	}
	environment := binaries.Environment(t, recovered)
	prepared := workflowRunEnvironment(t, s, binaries.cli, "authority", observer.Policy{ExpectedSHA256: expectedValues}, nil, environment, nativePrepareArgs(s, recovered, "restored", "--normal-signing-key", s.selector(1))...)
	preparation := nativeRecoveredRoutingPrepareResult(t, prepared, "reconstruction")
	children = append(children, prepared)
	pair := workflowReadNamedPair(t, recovered, "restored")
	if preparation.Recovery.Status != "complete" || preparation.Recovery.Head != workflowDigest(selected.body) || preparation.Delivery.Outcome != "recorded" || preparation.Delivery.CleanupFailed || preparation.Delivery.Readback == nil || preparation.Delivery.Readback.EditableDigest != workflowDigest(pair.editable) || preparation.Delivery.Readback.GeneratedDigest != workflowDigest(pair.generated) || pair.fileID == original.fileID {
		t.Fatal("reconstruction lost selected provenance or exact fresh pair delivery")
	}
	nativePrepareReadOnly(t, prepared)
	var editable map[string]any
	if err := json.Unmarshal(pair.editable, &editable); err != nil {
		t.Fatal(err)
	}
	outputs := editable["outputs"].(map[string]any)
	wantRouting := `{"default":["gcp"],"entries":{"EMPTY":[],"PINNED":["gcp"]}}`
	assertRouting := func(value any, expected string) {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil || string(body) != expected {
			t.Fatal("recovered routing lost inheritance or explicit override presence")
		}
	}
	assertRouting(outputs["routing"], wantRouting)
	for _, raw := range outputs["destinations"].(map[string]any) {
		destination := raw.(map[string]any)
		if destination["plugin"] != nil || destination["canonical"] == nil || destination["settings"] != nil {
			t.Fatal("reconstruction did not preserve canonical output settings without plugin selection")
		}
	}
	unselected := workflowRunEnvironment(t, s, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "plan", "--trusted", recovered, "--trusted-format", "json", "--json")
	var unavailable workflowOutput
	if err := json.Unmarshal(unselected.out, &unavailable); err != nil || unselected.code != 3 || unavailable.State != "unavailable" || unavailable.Payload.Verdict != string(contract.ComparisonUnable) || !unavailable.Payload.DiagnosticsComplete || unavailable.Observation.Revision != "" {
		t.Fatal("recovered local route without a selected plugin received the wrong admission result", unselected.code, unavailable.State)
	}
	for _, event := range unselected.capture.Events {
		if event.Kind == "http-start" || event.Kind == "plaintext" || event.Kind == "recovery-plaintext" {
			t.Fatal("local route refusal reached a domain or private operation", event.Kind)
		}
	}
	workflowUnchanged(t, recovered, pair)
	children = append(children, unselected)
	nativePublicationSource(t, recovered, func(value map[string]any) {
		for id, raw := range value["outputs"].(map[string]any)["destinations"].(map[string]any) {
			plugin := "gcp-secret-manager"
			if id == "repository" {
				plugin = "github-actions-repository"
			}
			raw.(map[string]any)["plugin"] = plugin
		}
	})
	selectedPlugins := workflowReadNamedPair(t, recovered, "restored")
	setup := workflowRunEnvironment(t, s, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "prepare", "--source", recovered, "--source-format", "json", "--json")
	ready := nativeRecoveredRoutingPrepareResult(t, setup, "existing")
	if ready.RequestID == preparation.RequestID {
		t.Fatal("plugin setup reused the reconstruction invocation identity")
	}
	workflowUnchanged(t, recovered, selectedPlugins)
	children = append(children, setup)
	plan := func(verdict, inherited string) {
		t.Helper()
		child := workflowRunEnvironment(t, s, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "plan", "--trusted", recovered, "--trusted-format", "json", "--publish", "--json")
		wantExit := 0
		if verdict == "mismatch" {
			wantExit = 1
		}
		var result workflowOutput
		if child.code != wantExit || json.Unmarshal(child.out, &result) != nil || result.Schema != "ProductResult/v1" || result.State != "success" || result.Payload.Schema != "ComparisonPayload/v1" || result.Payload.Verdict != verdict || !result.Payload.DiagnosticsComplete || result.Payload.EvidenceLimit != contract.ComparisonEvidenceLimit {
			t.Fatal("recovered routing plan lost its complete comparison or exact verdict exit", child.code, wantExit)
		}
		nativeRecoveredRoutingPreview(t, child, project, owner, inherited, verdict)
		workflowGETOnly(t, child)
		children = append(children, child)
	}
	plan("match", "gcp")
	nativePublicationSource(t, recovered, func(value map[string]any) {
		outputs := value["outputs"].(map[string]any)
		outputs["routing"].(map[string]any)["default"] = []string{"repository"}
	})
	pending := workflowReadNamedPair(t, recovered, "restored")
	if err := json.Unmarshal(pending.editable, &editable); err != nil {
		t.Fatal(err)
	}
	assertRouting(editable["outputs"].(map[string]any)["routing"], `{"default":["repository"],"entries":{"EMPTY":[],"PINNED":["gcp"]}}`)
	plan("mismatch", "repository")
	manifest := func(inherited string) {
		t.Helper()
		f := nativeMaterializationObservation(t, s, recovered, "", pending)
		bindings := nativeManifestBindings(t, s, f)
		if len(bindings) != 2 || len(f.entries) != 3 {
			t.Fatal("routing fixture lost an exact selected entry or destination")
		}
		routes := map[string][]string{"EMPTY": {}, "INHERITED": {inherited}, "PINNED": {"gcp"}}
		destination := filepath.Join(t.TempDir(), "manifest.json")
		child := nativeManifestRun(t, s, binaries.cli, binaries.nativePluginFixture, recovered, "json", destination, observer.Policy{})
		want := nativeManifestExpected(t, f, bindings, account, project, owner, hex.EncodeToString(original.descriptor.AuthorityRecipientID[:]), "current-authority", "all-authorized", "", names, routes, nil)
		nativeManifestInstalled(t, child, destination, want)
		children = append(children, child)
	}
	manifest("gcp")
	_, beforeApply := workflowHead(t, s)
	if !reflect.DeepEqual(beforeApply, selected) || objects != s.objectCount() {
		t.Fatal("recovery, pending plan or manifest changed selected state")
	}
	workflowUnchanged(t, recovered, pending)
	changed := workflowRunEnvironment(t, s, binaries.cli, "apply", observer.Policy{}, nil, environment, "apply", "--source", recovered, "--source-format", "json", "--json")
	workflowResult(t, changed, "success")
	children = append(children, changed)
	_, afterApply := workflowHead(t, s)
	if reflect.DeepEqual(afterApply, selected) {
		t.Fatal("changed routing default was not selected")
	}
	objectsAfterApply := s.objectCount()
	plan("match", "repository")
	manifest("repository")
	workflowUnchanged(t, recovered, pending)
	_, afterConsumers := workflowHead(t, s)
	if !reflect.DeepEqual(afterConsumers, afterApply) || s.objectCount() != objectsAfterApply || output.effectCount() != 0 || s.children != 14 {
		t.Fatal("routing consumers changed selected state, reached an output service or lost a child")
	}
	for _, child := range children {
		for _, value := range values {
			nativePlanningNoSecret(t, child, []byte(value))
		}
	}
	nativePublicationNoEffects(t, binaries, beforeEffects)
	nativeMaterializationJoined(t, children, 14)
	s.clean(t)
}

func nativeRecoveredRoutingPreview(t *testing.T, child workflowChild, project, owner, inherited, verdict string) {
	t.Helper()
	var result struct {
		Payload struct {
			Publication struct {
				Schema            string
				Complete          bool
				Reason            uint8 `json:"reason_code"`
				DomainWideWarning bool  `json:"domain_wide_warning"`
				Entries           []struct {
					Name        *string  `json:"entry_name"`
					Destination *string  `json:"destination_id"`
					Target      string   `json:"physical_target"`
					Actions     []string `json:"actions"`
					Conditional bool
					Basis       string
					Origin      string
					Reason      uint8    `json:"reason_code"`
					Blockers    []string `json:"blocker_ids"`
					Remote      bool     `json:"remote_value_may_remain"`
					Late        bool     `json:"late_write_risk"`
				}
			}
		}
	}
	if err := json.Unmarshal(child.out, &result); err != nil {
		t.Fatal(err)
	}
	preview := result.Payload.Publication
	logPreview := func() {
		t.Helper()
		t.Logf("routing preview facts: schema_valid=%t complete=%t reason=%d warning=%t rows=%d expected_inherited_repository=%t expected_pinned_gcp=true expected_empty_absent=true", preview.Schema == "PublicationPreview/v2", preview.Complete, preview.Reason, preview.DomainWideWarning, len(preview.Entries), inherited == "repository")
		for i, row := range preview.Entries[:min(4, len(preview.Entries))] {
			name, destination := "other", "other"
			if row.Name != nil {
				switch *row.Name {
				case "EMPTY", "INHERITED", "PINNED":
					name = *row.Name
				}
			}
			if row.Destination != nil {
				switch *row.Destination {
				case "gcp", "repository":
					destination = *row.Destination
				}
			}
			t.Logf("routing preview row[%d]: name=%s destination=%s destination_null=%t conditional=%t unchecked=%t retained_deletion=%t acknowledged_equal=%t origin_proposed=%t origin_observed=%t origin_both=%t reason=%d action_count=%d create_empty=%t write_value=%t create_with_value=%t", i, name, destination, row.Destination == nil, row.Conditional, row.Basis == "secret-unchecked", row.Basis == "retained-deletion", row.Basis == "acknowledged-equal", row.Origin == "proposed", row.Origin == "observed", row.Origin == "both", row.Reason, len(row.Actions), slices.Contains(row.Actions, "create-empty"), slices.Contains(row.Actions, "write-value"), slices.Contains(row.Actions, "create-with-value"))
		}
	}
	type expectedRow struct {
		name, destination, origin, basis string
		conditional                      bool
		actions                          []string
	}
	gcpInherited := "projects/" + project + "/secrets/INHERITED"
	gcpPinned := "projects/" + project + "/secrets/PINNED"
	repositoryInherited := "repos/" + owner + "/repo/actions/secrets/INHERITED"
	want := map[string]expectedRow{
		gcpInherited: {"INHERITED", "gcp", "both", "secret-unchecked", true, []string{"create-empty", "write-value"}},
		gcpPinned:    {"PINNED", "gcp", "both", "secret-unchecked", true, []string{"create-empty", "write-value"}},
	}
	if inherited == "repository" {
		// The old coordinate remains in the observed/proposed union. It has
		// never had a send, so it has no deletion action or risk to report.
		destination, origin := "gcp", "proposed"
		if verdict == "match" {
			destination, origin = "", "both"
		}
		want[gcpInherited] = expectedRow{"INHERITED", destination, "observed", "acknowledged-equal", false, nil}
		want[repositoryInherited] = expectedRow{"INHERITED", "repository", origin, "secret-unchecked", true, []string{"create-with-value"}}
	}
	if preview.Schema != "PublicationPreview/v2" || !preview.Complete || preview.Reason != 0 || preview.DomainWideWarning || len(preview.Entries) != len(want) {
		logPreview()
		t.Fatal("routing plan did not retain its exact complete publication selection")
	}
	for _, row := range preview.Entries {
		expected, present := want[row.Target]
		if !present || row.Name == nil || *row.Name != expected.name || row.Reason != 0 || len(row.Blockers) != 0 || row.Remote || row.Late {
			logPreview()
			t.Fatal("routing plan added, omitted or changed a coordinate or its safety facts")
		}
		destinationMatches := row.Destination == nil
		if expected.destination != "" {
			destinationMatches = row.Destination != nil && *row.Destination == expected.destination
		}
		if !destinationMatches || row.Origin != expected.origin || row.Basis != expected.basis || row.Conditional != expected.conditional || !slices.Equal(row.Actions, expected.actions) {
			logPreview()
			t.Fatal("routing plan changed an observed or proposed route's exact action facts")
		}
		delete(want, row.Target)
	}
	if len(want) != 0 {
		logPreview()
		t.Fatal("routing plan omitted an observed or proposed coordinate")
	}
}

func nativeRecoveredRoutingPrepareResult(t *testing.T, child workflowChild, branch string) nativePrepareOutput {
	t.Helper()
	output := nativePrepareDecode(t, child, branch, branch == "existing")
	dependencies := output.Dependencies
	if dependencies.Assessment != "complete" || !dependencies.MinimumAdministrativeReady || dependencies.SettingsFailure != nil || len(dependencies.Requirements) != 2 || dependencies.Installations == nil {
		t.Fatal("routing preparation lost independent administrative or dependency facts")
	}
	wanted := map[string]struct {
		plugin  string
		subject uint16
	}{"ENKV/OUTPUT/GCP-SECRET-MANAGER/CONFIG/v1": {"gcp-secret-manager", 0}, "github-actions/repository-config/v1": {"github-actions-repository", 1}}
	for _, row := range dependencies.Requirements {
		want, present := wanted[row.Contract]
		if !present || row.Role != "output" || row.ProtocolVersion != 6 || len(row.Subjects) != 1 || row.Subjects[0] != want.subject {
			t.Fatal("routing preparation changed an exact output requirement")
		}
		switch branch {
		case "reconstruction":
			if row.Plugin != nil || row.Artifact != nil || row.Status != "missing" || row.Reason != "selection-required" {
				t.Fatal("plugin-free reconstruction invented a selected output implementation")
			}
		case "existing":
			if row.Plugin == nil || *row.Plugin != want.plugin || row.Artifact == nil || row.Status != "verified" || row.Reason != "none" {
				t.Fatal("explicit output setup did not verify the selected compatible implementation")
			}
		default:
			t.Fatal("unexpected routing preparation branch")
		}
		delete(wanted, row.Contract)
	}
	if len(wanted) != 0 {
		t.Fatal("routing preparation omitted an output requirement")
	}
	if branch == "reconstruction" {
		if child.code != 2 || output.Outcome != "incomplete" || dependencies.AllDeclaredReady || len(dependencies.Installations) != 0 || len(output.Diagnostics) != 1 || output.Diagnostics[0].Reason != "dependency-missing" || output.Diagnostics[0].Subject != "dependencies" {
			t.Fatal("plugin-free recovery did not preserve known setup incomplete after delivery")
		}
	} else {
		if child.code != 0 || output.Outcome != "complete" || !dependencies.AllDeclaredReady || len(dependencies.Installations) != 2 || len(output.Diagnostics) != 0 || output.Recovery.Status != "not-attempted" || output.Delivery.Outcome != "not-recorded" {
			t.Fatal("explicit output setup did not complete on the existing pair")
		}
		installed := map[string]bool{"gcp-secret-manager": true, "github-actions-repository": true}
		for _, row := range dependencies.Installations {
			if !installed[row.Name] || row.Role != "output" || row.Source != "local" || row.Status != "verified" || row.Reason != "none" || row.Artifact == nil {
				t.Fatal("explicit output setup lost an exact trusted installation")
			}
			delete(installed, row.Name)
		}
		if len(installed) != 0 {
			t.Fatal("explicit output setup omitted a selected installation")
		}
	}
	return output
}
