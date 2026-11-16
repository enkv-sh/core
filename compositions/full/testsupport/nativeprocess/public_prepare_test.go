package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

type nativePrepareOutput struct {
	Schema, Operation, Branch, Outcome string
	RequestID                          string                                      `json:"request_id"`
	SourceFailure                      *compositionfull.ConfigurationSourceFailure `json:"source_failure,omitempty"`
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
		MinimumAdministrativeReady bool                                `json:"minimum_administrative_ready"`
		AllDeclaredReady           bool                                `json:"all_declared_ready"`
		SettingsFailure            *plugininstallation.SettingsFailure `json:"settings_failure"`
		Requirements               []struct {
			Role, Contract, Status, Reason string
			Plugin                         *string
			ProtocolVersion                uint32 `json:"protocol_version"`
			Artifact                       *string
			Subjects                       []uint16 `json:"subjects"`
		}
		Installations []struct {
			Name, Role, Version, Platform, Source, Status, Reason string
			Artifact                                              *string
			Previous                                              *struct {
				Version, Artifact, Platform, Source string
			}
			Changed bool
		}
	}
	Diagnostics []struct{ Reason, Subject string }
}

func nativePrepareResult(t *testing.T, child workflowChild, branch string) nativePrepareOutput {
	t.Helper()
	output := nativePrepareDecode(t, child, branch, true)
	if len(output.Dependencies.Requirements) != 0 || len(output.Dependencies.Installations) != 0 {
		t.Fatal("preparation added an undeclared dependency or installation")
	}
	return output
}

func nativePrepareDependencyShape(body []byte) bool {
	var result struct {
		Dependencies map[string]json.RawMessage
	}
	if json.Unmarshal(body, &result) != nil || len(result.Dependencies) != 6 {
		return false
	}
	settings, present := result.Dependencies["settings_failure"]
	var failure *plugininstallation.SettingsFailure
	if !present || json.Unmarshal(settings, &failure) != nil || failure != nil && !failure.Valid() {
		return false
	}
	for member, fields := range map[string]int{"requirements": 8, "installations": 10} {
		var rows []map[string]json.RawMessage
		if json.Unmarshal(result.Dependencies[member], &rows) != nil || rows == nil {
			return false
		}
		seenSubjects := make(map[string]map[uint16]bool)
		for _, row := range rows {
			if len(row) != fields {
				return false
			}
			if member == "requirements" {
				var role string
				var subjects []uint16
				if json.Unmarshal(row["role"], &role) != nil || json.Unmarshal(row["subjects"], &subjects) != nil || len(subjects) == 0 {
					return false
				}
				limit := uint16(0)
				switch role {
				case "generator":
					limit = 512
				case "output":
					limit = 64
				case "manifest-generator":
					limit = 1
				default:
					return false
				}
				for i, subject := range subjects {
					if subject >= limit || i > 0 && subjects[i-1] >= subject || seenSubjects[role][subject] {
						return false
					}
					if seenSubjects[role] == nil {
						seenSubjects[role] = make(map[uint16]bool)
					}
					seenSubjects[role][subject] = true
				}
			}
		}
	}
	return true
}

func nativePrepareDecode(t *testing.T, child workflowChild, branch string, allReady bool) nativePrepareOutput {
	t.Helper()
	var output nativePrepareOutput
	decoder := json.NewDecoder(bytes.NewReader(child.out))
	decoder.DisallowUnknownFields()
	var members map[string]json.RawMessage
	decodeErr := decoder.Decode(&output)
	endErr := decoder.Decode(new(any))
	membersErr := json.Unmarshal(child.out, &members)
	wantOutcome, wantCode := "complete", 0
	diagnosticsMatch := len(output.Diagnostics) == 0
	if !allReady {
		wantOutcome, wantCode = "incomplete", 2
		diagnosticsMatch = len(output.Diagnostics) == 1 && output.Diagnostics[0].Reason == "dependency-missing" && output.Diagnostics[0].Subject == "dependencies"
	}
	if child.code != wantCode || decodeErr != nil || endErr != io.EOF || membersErr != nil || len(members) != 10 || !nativePrepareDependencyShape(child.out) || output.Schema != "enkv/prepare-result/v2" || output.Operation != "prepare" || output.Branch != branch || output.SourceFailure != nil || output.Dependencies.SettingsFailure != nil || output.MissingInputs == nil || len(output.MissingInputs) != 0 || output.Outcome != wantOutcome || !diagnosticsMatch || output.Dependencies.Assessment != "complete" || !output.Dependencies.MinimumAdministrativeReady || output.Dependencies.AllDeclaredReady != allReady || output.Dependencies.Requirements == nil || output.Dependencies.Installations == nil {
		t.Logf("prepare failure facts: decoded=%t reconstruction=%t recovery_complete=%t delivered=%t cleanup_failed=%t dependencies_complete=%t minimum_ready=%t all_ready=%t requirements=%d diagnostics=%d", decodeErr == nil, output.Branch == "reconstruction", output.Recovery.Status == "complete", output.Delivery.Outcome == "recorded", output.Delivery.CleanupFailed, output.Dependencies.Assessment == "complete", output.Dependencies.MinimumAdministrativeReady, output.Dependencies.AllDeclaredReady, len(output.Dependencies.Requirements), len(output.Diagnostics))
		for i, row := range output.Diagnostics[:min(4, len(output.Diagnostics))] {
			reason, subject := "other", "other"
			switch row.Reason {
			case "invalid-request", "source-invalid", "source-unavailable", "pending-edit", "target-occupied", "unsafe-path", "trust-invalid", "state-unavailable", "state-invalid", "secret-unverifiable", "contention", "cancelled", "delivery-failed", "delivery-unknown", "cleanup-failed", "dependency-missing", "dependency-invalid", "dependency-unavailable", "source-changed", "presentation-failed":
				reason = row.Reason
			}
			switch row.Subject {
			case "request", "source", "generated", "recovery", "delivery", "dependencies", "presentation":
				subject = row.Subject
			}
			t.Logf("prepare diagnostic[%d]: reason=%s subject=%s", i, reason, subject)
		}
		for i, row := range output.Dependencies.Requirements[:min(4, len(output.Dependencies.Requirements))] {
			t.Logf("dependency[%d]: generator=%t verified=%t missing=%t incompatible=%t tampered=%t unavailable=%t unsupported_protocol=%t identity_mismatch=%t platform_mismatch=%t not_installed=%t artifact_bound=%t version=%d", i, row.Role == "generator", row.Status == "verified", row.Status == "missing", row.Status == "incompatible", row.Status == "tampered", row.Status == "unavailable", row.Reason == "unsupported-protocol", row.Reason == "identity-mismatch", row.Reason == "platform-mismatch", row.Reason == "not-installed", row.Artifact != nil, row.ProtocolVersion)
		}
		t.Fatalf("public prepare did not complete its exact branch: branch=%s exit=%d %s", branch, child.code, child.summary)
	}
	id, err := hex.DecodeString(output.RequestID)
	if err != nil || len(id) != 32 || bytes.Equal(id, make([]byte, 32)) {
		t.Fatal("public prepare lost its fresh invocation identity")
	}
	return output
}

func nativePrepareReadFacts(t *testing.T, child workflowChild) map[string]any {
	t.Helper()
	var result struct {
		Schema  string
		State   string `json:"state_result"`
		Payload map[string]any
	}
	if child.code != 0 || json.Unmarshal(child.out, &result) != nil || result.Schema != "ProductResult/v1" || result.State != "success" || result.Payload == nil {
		t.Fatal("retained inspection or receipt query did not complete")
	}
	workflowGETOnly(t, child)
	return result.Payload
}

// full_only: false
func TestPublicNativePrepareCompleteLossAndFreshConsumers(t *testing.T) {
	cli, _ := workflowExecutables(t)
	manifest := nativeManifestProductionBuild(t)
	plugins := newNativePluginFixture(t, manifest)
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery-%t", family, recovery), func(t *testing.T) {
				s := newWorkflowServer(t, family, recovery)
				s.childLimit = 9
				f := nativeSequenceSetupOnServer(t, cli, s, recovery)
				head, selected := workflowHead(t, s)
				root := workflowRoot(t, s, head)
				entry := nativeLifecycleEntries(t, s, root)["binary"]
				if head.Core.Form == stateformat.GenesisHead || entry.Name != "binary" {
					t.Fatal("complete-loss fixture lacks an ordinary selected secret")
				}
				objects := s.objectCount()
				before := s.snapshot("authority")
				if err := os.RemoveAll(filepath.Dir(f.source)); err != nil {
					t.Fatal("complete-loss source removal failed", err)
				}
				if _, err := os.Lstat(filepath.Dir(f.source)); !os.IsNotExist(err) {
					t.Fatal("complete-loss barrier did not remove the setup directory")
				}
				const name = "restored"
				path := filepath.Join(t.TempDir(), "recovered.json")
				region := "us-east-1"
				if family == "gcp" {
					region = "us-central1"
				}
				args := []string{"prepare", "--source", path, "--source-format", "json", "--name", name, "--provider", family, "--bucket", "fixture-bucket", "--region", region, "--prefix", s.prefix, "--normal-signing-key", s.selector(1), "--json"}
				sum := sha256.Sum256(f.value)
				environment := plugins.Environment(t, path)
				prepared := workflowRunEnvironment(t, s, cli, "authority", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}}, nil, environment, args...)
				result := nativePrepareResult(t, prepared, "reconstruction")
				pair := workflowReadNamedPair(t, path, name)
				if result.Recovery.Status != "complete" || result.Recovery.Domain != hex.EncodeToString(root.Domain[:]) || result.Recovery.Head != workflowDigest(selected.body) || result.Delivery.Outcome != "recorded" || result.Delivery.CleanupFailed || result.Delivery.RecoverySource != "" || result.Delivery.EditablePath != path || result.Delivery.GeneratedPath != filepath.Join(filepath.Dir(path), pair.reference) || result.Delivery.Readback == nil || result.Delivery.Readback.EditableDigest != workflowDigest(pair.editable) || result.Delivery.Readback.GeneratedDigest != workflowDigest(pair.generated) || pair.fileID == f.pair.fileID {
					t.Fatal("complete-loss prepare changed domain identity or lost exact native delivery")
				}
				workflowPlaintext(t, prepared, "plaintext")
				nativePlanningNoSecret(t, prepared, f.value)
				workflowNoRecovery(t, prepared)
				nativePrepareReadOnly(t, prepared)
				nativePreparedMeaning(t, s, path, name, pair, f.pair.control, root, entry)
				after := s.snapshot("authority")
				if after.reads <= before.reads || after.creates != before.creates || after.headCreates != before.headCreates || after.headUpdates != before.headUpdates || after.deletes != before.deletes || after.lists != before.lists {
					t.Fatal("complete-loss preparation did not remain read-only")
				}
				restore := workflowReadOnlyPair(t, path, pair)
				defer restore()
				public := workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "plan", "--trusted", path, "--trusted-format", "json", "--json")
				publicResult := workflowResult(t, public, "success")
				if !nativePlanningInstallationRequirementsMatch(public.out) {
					t.Fatal("fresh public plan changed self installation requirements")
				}
				if publicResult.Payload.Verdict != "match" || !publicResult.Payload.DiagnosticsComplete || len(publicResult.Payload.Scope) != 12 {
					t.Fatal("fresh public plan did not match the recovered pair")
				}
				for _, scope := range publicResult.Payload.Scope {
					if scope.Status != "complete" {
						t.Fatal("fresh public plan omitted a configuration family")
					}
				}
				workflowGETOnly(t, public)
				private := workflowRunEnvironment(t, s, cli, "noop", observer.Policy{}, nil, environment, "plan", "--trusted", path, "--trusted-format", "json", "--check-secrets", "--json")
				nativePlanningFact(t, private, 0, "match", "retained", "equal", "not-requested")
				nativePlanningReads(t, private, 1)
				nativePlanningNoSecret(t, private, f.value)
				idle := workflowRunEnvironment(t, s, cli, "noop", observer.Policy{}, nil, environment, "apply", "--source", path, "--source-format", "json", "--json")
				if workflowResult(t, idle, "no-op").Receipt != "" {
					t.Fatal("unchanged recovered apply fabricated a receipt")
				}
				nativePrepareReadOnly(t, idle)
				admin := workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "abandon", "list", "--source", path, "--source-format", "json", "--json")
				workflowResult(t, admin, "success")
				workflowGETOnly(t, admin)
				existing := workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "prepare", "--source", path, "--source-format", "json", "--json")
				repeated := nativePrepareResult(t, existing, "existing")
				if repeated.RequestID == result.RequestID || repeated.Recovery.Status != "not-attempted" || repeated.Recovery.Domain != "" || repeated.Recovery.Head != "" || repeated.Delivery.Outcome != "not-recorded" || repeated.Delivery.Readback != nil || len(existing.capture.Events) != 1 || existing.capture.Events[0].Kind != "footer" {
					t.Fatal("existing-pair preparation repeated recovery or provider work")
				}
				current := workflowReadNamedPair(t, path, name)
				_, final := workflowHead(t, s)
				if !bytes.Equal(current.editable, pair.editable) || !bytes.Equal(current.generated, pair.generated) || !reflect.DeepEqual(final, selected) || s.objectCount() != objects || s.children != 9 {
					t.Fatal("fresh recovered consumers changed the pair, selected state or child inventory")
				}
			})
		}
	}
}

func nativePrepareReadOnly(t *testing.T, child workflowChild) {
	t.Helper()
	for _, event := range child.capture.Events {
		if event.Kind != "http-start" {
			continue
		}
		if !event.Sent || event.Operation != "head-read" && event.Operation != "store-read" && event.Operation != "kms-public" && (event.Operation != "kms-decrypt" || event.Role != "authority") {
			t.Fatal("preparation or idle apply entered a forbidden remote operation", event.Operation)
		}
	}
}

func nativePrepareArgs(s *workflowServer, path, name, flag, signer string) []string {
	region := "us-east-1"
	if s.family == "gcp" {
		region = "us-central1"
	}
	return []string{"prepare", "--source", path, "--source-format", "json", "--name", name, "--provider", s.family, "--bucket", "fixture-bucket", "--region", region, "--prefix", s.prefix, flag, signer, "--json"}
}

// full_only: false
func TestPublicNativePrepareSelectedProofFamilies(t *testing.T) {
	cli, _ := workflowExecutables(t)
	manifest := nativeManifestProductionBuild(t)
	plugins := newNativePluginFixture(t, manifest)
	for _, cell := range []struct {
		family   string
		recovery bool
	}{{"aws", false}, {"gcp", true}} {
		t.Run(cell.family+"/genesis", func(t *testing.T) {
			s := newWorkflowServer(t, cell.family, cell.recovery)
			s.childLimit = 4
			original := filepath.Join(t.TempDir(), "configuration.json")
			if err := os.WriteFile(original, workflowSetup(t, s, cell.recovery), 0600); err != nil {
				t.Fatal(err)
			}
			workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", original, "--source-format", "json", "--json"), "success")
			before := workflowReadPair(t, original)
			head, selected := workflowHead(t, s)
			if head.Genesis == nil {
				t.Fatal("genesis recovery fixture has no genesis proof")
			}
			if err := os.RemoveAll(filepath.Dir(original)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "genesis.json")
			environment := plugins.Environment(t, path)
			child := workflowRunEnvironment(t, s, cli, "authority", observer.Policy{}, nil, environment, nativePrepareArgs(s, path, "genesis-restored", "--normal-signing-key", s.selector(1))...)
			result := nativePrepareResult(t, child, "reconstruction")
			pair := workflowReadNamedPair(t, path, "genesis-restored")
			if result.Recovery.Head != workflowDigest(selected.body) || result.Recovery.Domain != hex.EncodeToString(head.Core.Domain[:]) || !reflect.DeepEqual(pair.control, before.control) {
				t.Fatal("complete-loss genesis pair changed authenticated identity or control")
			}
			nativePrepareReadOnly(t, child)
			for _, event := range child.capture.Events {
				if event.Kind == "plaintext" || event.Kind == "http-start" && event.Operation == "kms-decrypt" {
					t.Fatal("empty genesis recovery constructed a private value route")
				}
			}
			public := workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "plan", "--trusted", path, "--trusted-format", "json", "--json")
			if workflowResult(t, public, "success").Payload.Verdict != "match" {
				t.Fatal("fresh genesis reader did not match recovered configuration")
			}
			workflowGETOnly(t, public)
			idle := workflowRunEnvironment(t, s, cli, "noop", observer.Policy{}, nil, environment, "apply", "--source", path, "--source-format", "json", "--json")
			workflowResult(t, idle, "no-op")
			nativePrepareReadOnly(t, idle)
			workflowUnchanged(t, path, pair)
			_, final := workflowHead(t, s)
			if !reflect.DeepEqual(selected, final) || s.children != 4 {
				t.Fatal("genesis recovery changed selection or child inventory")
			}
		})
	}
	t.Run("gcp/recovery-authorized-normal-replacement", func(t *testing.T) {
		s := newWorkflowServer(t, "gcp", true)
		s.childLimit = 12
		f := nativeSequenceSetupOnServer(t, cli, s, true)
		successor := filepath.Join(administrativeReplacementDirectory(t), "successor.json")
		replaced := workflowRun(t, s, cli, "successor", observer.Policy{}, nil, "keys", "replace", "--source", f.source, "--source-format", "json", "--target", "authority", "--authorizer", "recovery", "--signing", s.selector(6), "--out", successor, "--json")
		if result := nativeReplacementDecode(t, replaced, "keys-replace-authority", "TransitionPayload/v1"); result.Delivery.Status != "delivered" {
			t.Fatal("replacement fixture did not deliver selected succession")
		}
		head, selected := workflowHead(t, s)
		root := workflowRoot(t, s, head)
		if head.Succession == nil {
			t.Fatal("replacement recovery fixture has no succession proof")
		}
		entry := nativeLifecycleEntries(t, s, root)["binary"]
		for _, source := range []string{f.source, successor} {
			if err := os.RemoveAll(filepath.Dir(source)); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Dir(source)); !os.IsNotExist(err) {
				t.Fatal("replacement loss barrier retained a source directory")
			}
		}
		sum := sha256.Sum256(f.value)
		for _, anchor := range []struct{ name, flag, signer string }{
			{"normal-restored", "--normal-signing-key", s.selector(6)},
			{"recovery-restored", "--recovery-signing-key", s.selector(3)},
		} {
			t.Run(anchor.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "recovered.json")
				environment := plugins.Environment(t, path)
				child := workflowRunEnvironment(t, s, cli, "authority", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}}, nil, environment, nativePrepareArgs(s, path, anchor.name, anchor.flag, anchor.signer)...)
				result := nativePrepareResult(t, child, "reconstruction")
				if result.Recovery.Head != workflowDigest(selected.body) {
					t.Fatal("replacement recovery selected another HEAD")
				}
				workflowPlaintext(t, child, "plaintext")
				nativePrepareReadOnly(t, child)
				pair := workflowReadNamedPair(t, path, anchor.name)
				nativePreparedMeaning(t, s, path, anchor.name, pair, f.pair.control, root, entry)
				public := workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "plan", "--trusted", path, "--trusted-format", "json", "--json")
				if workflowResult(t, public, "success").Payload.Verdict != "match" {
					t.Fatal("fresh replacement reader did not match recovered configuration")
				}
				workflowGETOnly(t, public)
				private := workflowRunEnvironment(t, s, cli, "noop", observer.Policy{}, nil, environment, "plan", "--trusted", path, "--trusted-format", "json", "--check-secrets", "--json")
				nativePlanningFact(t, private, 0, "match", "retained", "equal", "not-requested")
				nativePlanningReads(t, private, 1)
				idle := workflowRunEnvironment(t, s, cli, "noop", observer.Policy{}, nil, environment, "apply", "--source", path, "--source-format", "json", "--json")
				workflowResult(t, idle, "no-op")
				nativePrepareReadOnly(t, idle)
				workflowUnchanged(t, path, pair)
			})
		}
		_, final := workflowHead(t, s)
		if !reflect.DeepEqual(selected, final) || s.children != 12 {
			t.Fatal("replacement recovery changed selection or child inventory")
		}
	})
}

// full_only: false
func TestPublicNativePrepareSelectedFailureInstallsNoPair(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, cell := range []struct {
		condition, family, phase, reason string
		code, maxHeads                   int
	}{
		{"missing-selected-value-page", "aws", "authority", "state-unavailable", 3, 3},
		{"invalid-selection-signature", "gcp", "authority", "state-invalid", 2, 1},
		{"invalid-current-private-packet", "aws", "invalid-private", "state-invalid", 2, 3},
	} {
		t.Run(cell.condition, func(t *testing.T) {
			s := newWorkflowServer(t, cell.family, false)
			s.childLimit = 4
			f := nativeSequenceSetupOnServer(t, cli, s, false)
			head, object := workflowHead(t, s)
			root := workflowRoot(t, s, head)
			switch cell.condition {
			case "missing-selected-value-page":
				key, err := stateformat.Key(s.prefix, *root.ValueEntryPages[0])
				if err != nil {
					t.Fatal(err)
				}
				s.mu.Lock()
				delete(s.objects, key)
				s.mu.Unlock()
			case "invalid-selection-signature":
				head.K1 = bytes.Clone(head.AuthorizationSignature)
				body, err := stateformat.EncodeHead(head)
				if err != nil {
					t.Fatal(err)
				}
				object.body = body
				s.mu.Lock()
				s.objects[s.prefix+"/HEAD"] = object
				s.mu.Unlock()
			}
			objects := s.objectCount()
			if err := os.RemoveAll(filepath.Dir(f.source)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "recovered.json")
			child := workflowRun(t, s, cli, cell.phase, observer.Policy{}, nil, nativePrepareArgs(s, path, "failure-restored", "--normal-signing-key", s.selector(1))...)
			var result nativePrepareOutput
			decoder := json.NewDecoder(bytes.NewReader(child.out))
			decoder.DisallowUnknownFields()
			if child.code != cell.code || !nativePrepareDependencyShape(child.out) || decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Schema != "enkv/prepare-result/v2" || result.Operation != "prepare" || result.Branch != "reconstruction" || result.Outcome != "incomplete" || result.SourceFailure != nil || result.Dependencies.SettingsFailure != nil || result.MissingInputs == nil || len(result.MissingInputs) != 0 || result.Recovery.Status != "failed" || result.Recovery.Domain != "" || result.Recovery.Head != "" || result.Delivery.Outcome != "not-recorded" || result.Delivery.Readback != nil || result.Delivery.RecoverySource != "" || result.Dependencies.Assessment != "not-attempted" || result.Dependencies.MinimumAdministrativeReady || result.Dependencies.AllDeclaredReady || len(result.Dependencies.Requirements) != 0 || len(result.Dependencies.Installations) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Reason != cell.reason || result.Diagnostics[0].Subject != "recovery" {
				t.Fatalf("failed selected state changed preparation facts: condition=%s exit=%d %s", cell.condition, child.code, child.summary)
			}
			heads := 0
			for _, event := range child.capture.Events {
				if event.Kind == "http-start" && event.Operation == "head-read" {
					heads++
				}
			}
			if heads == 0 || heads > cell.maxHeads {
				t.Fatal("failed selected state repeated its complete attempt", heads)
			}
			nativePrepareReadOnly(t, child)
			for _, target := range []string{path, filepath.Join(filepath.Dir(path), ".enkv", "failure-restored.generated.json")} {
				if _, err := os.Lstat(target); !os.IsNotExist(err) {
					t.Fatal("failed reconstruction installed a partial pair", err)
				}
			}
			_, final := workflowHead(t, s)
			if !reflect.DeepEqual(object, final) || s.objectCount() != objects || s.children != 4 {
				t.Fatal("failed reconstruction changed selected state or child inventory")
			}
		})
	}
}

func nativePreparedMeaning(t *testing.T, s *workflowServer, path, name string, pair workflowPair, before contract.ControlCore, root stateformat.Root, selected contract.ValueEntry) {
	t.Helper()
	before.CurrentControl = root.CurrentAccess.Core.CurrentControl
	if !reflect.DeepEqual(pair.control, before) {
		t.Fatal("complete-loss pair changed selected public control or keys")
	}
	captured, err := configuration.Capture(t.Context(), path, configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := captured.Close(); err != nil {
			t.Error("recovered pair capture did not close", err)
		}
	}()
	model, err := configuration.Parse(t.Context(), captured)
	if err != nil || !model.Resolved || model.DomainName != name || len(model.Plugins) != 0 || model.DomainID != root.Domain || model.RecoveryEnabled != (before.Recovery != nil) || model.Generated != ".enkv/"+name+".generated.json" || len(model.Entries) != 1 || len(model.Recipients) != 1 || len(model.Public.OutputBindings.Value) != 0 {
		t.Fatal("recovered pair changed complete current configuration")
	}
	if len(model.Routes) != 1 || !model.Routes[0].Default || model.Routes[0].EntryName != "" || len(model.Routes[0].Destinations) != 0 || model.Public.Routing.State != contract.PublicPresent || len(model.Public.Routing.Value) != 1 {
		t.Fatal("recovered pair did not retain exactly one empty shared routing default")
	}
	route := model.Public.Routing.Value[0]
	if route.Key != (contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}) || route.Destinations.State != contract.PublicPresent || len(route.Destinations.Value) != 0 {
		t.Fatal("recovered public routing changed the empty shared default")
	}
	entry := model.Entries[0]
	if entry.Name != "binary" || !entry.Secret || entry.Generated != nil || entry.Retained == nil || entry.Retained.Incarnation != selected.Incarnation || entry.Retained.Material != selected.ValueState || len(entry.Sealed) != 0 || len(entry.Recipients) != 1 {
		t.Fatal("recovered supplied value lost its exact retained identity")
	}
	recipient := model.Recipients[0]
	var original *contract.RecipientRecord
	for _, ref := range root.Recipients {
		if ref == nil {
			continue
		}
		key, err := stateformat.Key(s.prefix, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.DecodeRecipientPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Slots {
			if row != nil && row.RecipientID == recipient.ID {
				original = row
			}
		}
	}
	if original == nil || original.CurrentBinding == nil {
		t.Fatal("recovered recipient was not in the independent selected registry")
	}
	binding := original.CurrentBinding
	if recipient.Reference != entry.Recipients[0] || recipient.DisplayName != original.DisplayName || recipient.Selector != binding.KeySelector || recipient.Encryption.Selector != binding.KeySelector || !bytes.Equal(recipient.Encryption.PublicKey, binding.SPKI) || recipient.Encryption.Binding.ID != binding.BindingID || recipient.Encryption.Binding.Incarnation != binding.BindingIncarnationID || recipient.Encryption.Binding.Serial != binding.BindingSerial || recipient.Encryption.Binding.Protection != binding.ProtectionClass {
		t.Fatal("recovered current recipient lost its exact reference, name or public binding")
	}
	members := []contract.ID{model.Authority.ID, model.Recipients[0].ID}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	want := slices.Clone(selected.Recipients)
	slices.SortFunc(want, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if !slices.Equal(members, want) {
		t.Fatal("recovered value changed exact recipient membership")
	}
}
