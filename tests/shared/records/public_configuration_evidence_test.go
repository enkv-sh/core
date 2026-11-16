package records

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func publicEvidenceFixture() (PublicConfigurationEvidenceSnapshot, PublicConfigurationEvidenceBinding) {
	run := strings.Repeat("a", 32)
	prefix := "enkv-test/" + run + "/0000-" + strings.Repeat("b", 64)
	digest := strings.Repeat("c", 64)
	worker := PublicConfigurationWorkerJoin{Worker: "0000-case-writer", Nonce: strings.Repeat("d", 32), Role: "writer", Actor: "selected-authority", InvocationSHA256: digest, ResultSHA256: digest, Started: true, Joined: true, Process: "passed"}
	fresh := worker
	fresh.Worker = "0000-case-fresh"
	fresh.Nonce = strings.Repeat("f", 32)
	fresh.Role = "fresh_after"
	fresh.Actor = "selected-reader"
	cleanup := worker
	cleanup.Worker = "0000-case-cleanup"
	cleanup.Nonce = strings.Repeat("c", 32)
	cleanup.Role = "cleanup"
	cleanup.Actor = "selected-cleanup"
	binding := PublicConfigurationEvidenceBinding{RunID: run, Scenario: "public-configuration.keys-replace-authority-signing-by-authority/keys_replace_authority_signing_by_authority", Provider: "aws", RecoveryMode: "disabled", Prefix: prefix, Binding: digest, Workers: []PublicConfigurationWorkerJoin{worker, fresh, cleanup}, Source: Source{Revision: strings.Repeat("e", 40)}, CaseIdentitySHA256: digest, BuildClosureSHA256: digest, OverlaySHA256: digest}
	token := PublicConfigurationToken{Family: contract.AWS, Value: []byte{'"', 0x80, '"'}}
	domain := contract.Hash([]byte("fixed public evidence domain"))
	intent := PublicConfigurationObjectIntent{Key: prefix + "/HEAD", Digest: digest, Bytes: 1, Kind: "compare_and_swap", ConditionToken: &token, State: "acknowledged"}
	attempt := PublicConfigurationCleanupAttempt{TargetIntent: 0, Ordinal: 1, Key: intent.Key, Digest: digest, Bytes: 1, Token: token, Cutoff: 0, State: "settled"}
	original := &PublicConfigurationTokenSource{Version: 1, RunID: run, Prefix: prefix, Binding: digest, Domain: domain, Observations: []PublicConfigurationTokenObservation{
		{Kind: "intent-condition", Index: 0, TargetIntent: 0, Key: intent.Key, Digest: digest, Bytes: 1, Token: token},
		{Kind: "cleanup-condition", Index: 0, TargetIntent: 0, AttemptOrdinal: 1, Key: intent.Key, Digest: digest, Bytes: 1, Token: token},
	}}
	inventory := PublicConfigurationInventoryEvidence{RunID: run, Prefix: prefix, Binding: digest, Domain: domain, Intents: []PublicConfigurationObjectIntent{intent}, Deleted: []PublicConfigurationDeleted{{Key: intent.Key, Cutoff: 1}}, CleanupAttempts: []PublicConfigurationCleanupAttempt{attempt}, TokenSource: original, OriginalTokenSourceSHA256: digest}
	snapshot := PublicConfigurationEvidenceSnapshot{Version: 1, RunID: run, Scenario: binding.Scenario, Provider: "aws", RecoveryMode: "disabled", Prefix: prefix, Binding: digest, PreflightEmpty: true, Domains: []contract.ID{domain}, Captures: []PublicConfigurationCaptureReceipt{{Ordinal: 0, ParentWorker: worker.Worker, ParentNonce: worker.Nonce, ParentRole: worker.Role, Actor: "selected-reader", NativeKind: "cli", SourceRelative: "public-command-4294967295/capture.jsonl", Complete: true, ExitCode: 0, SHA256: digest, Bytes: 1}}, Cleanup: inventory, OriginalOwnershipSHA256: digest, OriginalCleanupSHA256: digest}
	return snapshot, binding
}
func publicEvidenceClone(t *testing.T, value PublicConfigurationEvidenceSnapshot) PublicConfigurationEvidenceSnapshot {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result PublicConfigurationEvidenceSnapshot
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func publicEvidenceManifest(binding PublicConfigurationEvidenceBinding) PublicConfigurationEvidenceManifest {
	return PublicConfigurationEvidenceManifest{Version: 1, RunID: binding.RunID, Scenario: binding.Scenario, Provider: binding.Provider, RecoveryMode: binding.RecoveryMode, Source: binding.Source, CaseIdentitySHA256: binding.CaseIdentitySHA256, BuildClosureSHA256: binding.BuildClosureSHA256, OverlaySHA256: binding.OverlaySHA256, Workers: binding.Workers, Snapshot: PublicConfigurationEvidenceFile{Kind: "snapshot", Path: "ownership.json", SHA256: binding.Binding, Bytes: 1}, Captures: []PublicConfigurationEvidenceFile{{Kind: "native-capture", Ordinal: 0, Path: "captures/0000.jsonl", SHA256: binding.Binding, Bytes: 1}}}
}

// full_only: false
func TestPublicConfigurationEvidencePreservesOriginalConditionBytes(t *testing.T) {
	cases := []struct {
		name   string
		family contract.Family
		token  []byte
	}{
		{"aws-invalid-utf8", contract.AWS, []byte{'"', 0x80, '"'}},
		{"aws-valid-utf8", contract.AWS, []byte("\"é\"")},
		{"aws-literal-replacement", contract.AWS, []byte("\"�\"")},
		{"aws-limit", contract.AWS, append(append([]byte{'"'}, bytes.Repeat([]byte{0x80}, 254)...), '"')},
		{"gcp-int64-limit", contract.GCP, []byte("9223372036854775807")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			snapshot, binding := publicEvidenceFixture()
			if test.family == contract.GCP {
				snapshot.Provider, binding.Provider = "gcp", "gcp"
			}
			token := PublicConfigurationToken{Family: test.family, Value: bytes.Clone(test.token)}
			snapshot.Cleanup.Intents[0].ConditionToken = &token
			snapshot.Cleanup.CleanupAttempts[0].Token = token
			for i := range snapshot.Cleanup.TokenSource.Observations {
				snapshot.Cleanup.TokenSource.Observations[i].Token = token
			}
			body, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadPublicConfigurationEvidenceSnapshotBytes(body, binding)
			if err != nil {
				t.Fatal("valid exact source refused", err)
			}
			clear(body)
			if !bytes.Equal(got.Cleanup.Intents[0].ConditionToken.Value, test.token) || !bytes.Equal(got.Cleanup.CleanupAttempts[0].Token.Value, test.token) || !bytes.Equal(got.Cleanup.TokenSource.Observations[0].Token.Value, test.token) {
				t.Fatal("original condition bytes changed or borrowed input")
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationEvidenceRequiresCompleteOriginalTokenSource(t *testing.T) {
	original, binding := publicEvidenceFixture()
	if original.Validate(binding) != nil {
		t.Fatal("baseline original condition rejected")
	}
	cases := []struct {
		name   string
		damage func(*PublicConfigurationEvidenceSnapshot)
	}{
		{"missing-source", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.TokenSource = nil }},
		{"missing-source-hash", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.OriginalTokenSourceSHA256 = "" }},
		{"missing-observation", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Cleanup.TokenSource.Observations = v.Cleanup.TokenSource.Observations[:1]
		}},
		{"duplicate-observation", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Cleanup.TokenSource.Observations[1] = v.Cleanup.TokenSource.Observations[0]
		}},
		{"foreign-source-run", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.TokenSource.RunID = strings.Repeat("b", 32) }},
		{"foreign-source-domain", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Cleanup.TokenSource.Domain = contract.Hash([]byte("other domain"))
		}},
		{"wrong-original-index", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.TokenSource.Observations[0].Index = 1 }},
		{"wrong-original-target", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.TokenSource.Observations[1].TargetIntent = 1 }},
		{"wrong-original-ordinal", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.TokenSource.Observations[1].AttemptOrdinal = 2 }},
		{"wrong-original-key", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.TokenSource.Observations[0].Key += "-foreign" }},
		{"wrong-original-digest", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Cleanup.TokenSource.Observations[0].Digest = strings.Repeat("f", 64)
		}},
		{"wrong-original-size", func(v *PublicConfigurationEvidenceSnapshot) { v.Cleanup.TokenSource.Observations[0].Bytes = 2 }},
		{"normalized-legacy-is-not-original", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Cleanup.Intents[0].ConditionToken.Value = []byte("\"�\"")
		}},
		{"wrong-family", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Cleanup.TokenSource.Observations[0].Token.Family = contract.GCP
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := publicEvidenceClone(t, original)
			test.damage(&value)
			if value.Validate(binding) == nil {
				t.Fatal("damaged original source accepted")
			}
		})
	}
	empty := publicEvidenceClone(t, original)
	empty.Cleanup.Intents = nil
	empty.Cleanup.Deleted = nil
	empty.Cleanup.CleanupAttempts = nil
	empty.Cleanup.TokenSource.Observations = nil
	if empty.Validate(binding) != nil {
		t.Fatal("explicit complete zero-token source refused")
	}
	empty.Cleanup.TokenSource = nil
	if empty.Validate(binding) == nil {
		t.Fatal("absent source became complete zero-token source")
	}
}

// full_only: false
func TestPublicConfigurationEvidenceBindsRegisteredParentsAndFiniteCaptures(t *testing.T) {
	original, binding := publicEvidenceFixture()
	// The selected command actor can differ from its writer actor.
	if original.Captures[0].Actor == binding.Workers[0].Actor || original.Validate(binding) != nil {
		t.Fatal("distinct selected actor lost original parent binding")
	}
	cases := []struct {
		name   string
		damage func(*PublicConfigurationEvidenceSnapshot)
	}{
		{"no-preflight", func(v *PublicConfigurationEvidenceSnapshot) { v.PreflightEmpty = false }},
		{"incomplete-capture", func(v *PublicConfigurationEvidenceSnapshot) { v.Captures[0].Complete = false }},
		{"missing-cleanup", func(v *PublicConfigurationEvidenceSnapshot) {
			v.OriginalCleanupSHA256 = ""
			v.Cleanup = PublicConfigurationInventoryEvidence{}
		}},
		{"foreign-parent", func(v *PublicConfigurationEvidenceSnapshot) { v.Captures[0].ParentWorker = "foreign-writer" }},
		{"foreign-nonce", func(v *PublicConfigurationEvidenceSnapshot) { v.Captures[0].ParentNonce = strings.Repeat("f", 32) }},
		{"wrong-parent-role", func(v *PublicConfigurationEvidenceSnapshot) { v.Captures[0].ParentRole = "fresh_after" }},
		{"absolute-source", func(v *PublicConfigurationEvidenceSnapshot) { v.Captures[0].SourceRelative = "/private/capture.jsonl" }},
		{"traversal-source", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Captures[0].SourceRelative = "public-command-1/../capture.jsonl"
		}},
		{"wrong-kind", func(v *PublicConfigurationEvidenceSnapshot) { v.Captures[0].NativeKind = "policy" }},
		{"missing-complete-hash", func(v *PublicConfigurationEvidenceSnapshot) { v.Captures[0].SHA256 = "" }},
		{"capture-overflow", func(v *PublicConfigurationEvidenceSnapshot) {
			v.Captures[0].Bytes = MaximumPublicConfigurationCaptureBytes + 1
		}},
		{"duplicate-source", func(v *PublicConfigurationEvidenceSnapshot) {
			row := v.Captures[0]
			row.Ordinal = 1
			v.Captures = append(v.Captures, row)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := publicEvidenceClone(t, original)
			test.damage(&value)
			if value.Validate(binding) == nil {
				t.Fatal("unbound capture accepted")
			}
		})
	}
	value := publicEvidenceClone(t, original)
	value.Captures = nil
	for i := 0; i < MaximumPublicConfigurationCaptures; i++ {
		row := original.Captures[0]
		row.Ordinal = uint16(i)
		row.SourceRelative = "public-command-" + strconv.Itoa(i+1) + "/capture.jsonl"
		value.Captures = append(value.Captures, row)
	}
	if value.Validate(binding) != nil {
		t.Fatal("exact capture ceiling refused")
	}
	row := value.Captures[0]
	row.Ordinal = 64
	row.SourceRelative = "public-command-99/capture.jsonl"
	value.Captures = append(value.Captures, row)
	if value.Validate(binding) == nil {
		t.Fatal("capture count overflow accepted")
	}
}

// full_only: false
func TestPublicConfigurationEvidenceStrictIntakeAndExclusiveSnapshot(t *testing.T) {
	value, binding := publicEvidenceFixture()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	invalid := [][]byte{
		append(append([]byte{}, body...), []byte(" {}")...),
		append([]byte(`{"unknown":"private-policy",`), body[1:]...),
		append([]byte(`{"version":1,`), body[1:]...),
		append([]byte(`{"VERSION":1,`), body[1:]...),
		bytes.Repeat([]byte{' '}, MaximumPublicConfigurationSnapshotBytes+1),
	}
	for i, raw := range invalid {
		if _, err := ReadPublicConfigurationEvidenceSnapshotBytes(raw, binding); err == nil {
			t.Fatalf("invalid strict image %d accepted", i)
		}
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "public-configuration-evidence.json")
	if err := WritePublicConfigurationEvidenceSnapshot(path, value); err != nil {
		t.Fatal("exclusive snapshot failed", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePublicConfigurationEvidenceSnapshot(path, value); err == nil {
		t.Fatal("snapshot was replaced")
	}
	got, err := ReadPublicConfigurationEvidenceSnapshot(path, binding)
	if err != nil || !reflect.DeepEqual(got, value) {
		t.Fatal("exact snapshot read failed", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("exclusive failure changed original snapshot")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("snapshot mode changed")
	}
}

// full_only: false
func TestPublicConfigurationEvidenceManifestBindsSourceFilesAndOriginalWorkers(t *testing.T) {
	_, binding := publicEvidenceFixture()
	original := publicEvidenceManifest(binding)
	if original.Validate(binding) != nil {
		t.Fatal("valid original manifest refused")
	}
	cases := []struct {
		name   string
		damage func(*PublicConfigurationEvidenceManifest)
	}{
		{"foreign-run", func(v *PublicConfigurationEvidenceManifest) { v.RunID = strings.Repeat("f", 32) }},
		{"foreign-source", func(v *PublicConfigurationEvidenceManifest) { v.Source.Revision = strings.Repeat("f", 40) }},
		{"wrong-case", func(v *PublicConfigurationEvidenceManifest) { v.CaseIdentitySHA256 = strings.Repeat("f", 64) }},
		{"wrong-build", func(v *PublicConfigurationEvidenceManifest) { v.BuildClosureSHA256 = strings.Repeat("f", 64) }},
		{"wrong-overlay", func(v *PublicConfigurationEvidenceManifest) { v.OverlaySHA256 = strings.Repeat("f", 64) }},
		{"wrong-worker-result", func(v *PublicConfigurationEvidenceManifest) { v.Workers[0].ResultSHA256 = strings.Repeat("f", 64) }},
		{"missing-join", func(v *PublicConfigurationEvidenceManifest) { v.Workers[0].Joined = false }},
		{"absolute-alias", func(v *PublicConfigurationEvidenceManifest) { v.Captures[0].Path = "/private/capture.jsonl" }},
		{"parent-alias", func(v *PublicConfigurationEvidenceManifest) { v.Captures[0].Path = "../capture.jsonl" }},
		{"snapshot-overflow", func(v *PublicConfigurationEvidenceManifest) {
			v.Snapshot.Bytes = MaximumPublicConfigurationSnapshotBytes + 1
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var value PublicConfigurationEvidenceManifest
			if json.Unmarshal(raw, &value) != nil {
				t.Fatal("fixture clone failed")
			}
			test.damage(&value)
			if value.Validate(binding) == nil {
				t.Fatal("unbound manifest accepted")
			}
		})
	}
	later := binding
	later.Workers = nil
	if original.Validate(later) != nil {
		t.Fatal("sealed later reader required discarded original invocation files")
	}
	impossible := publicEvidenceManifest(binding)
	impossible.Workers = append([]PublicConfigurationWorkerJoin(nil), binding.Workers...)
	impossible.Workers[0].Started = false
	if impossible.Validate(later) == nil {
		t.Fatal("passed worker without positive start accepted")
	}
	for _, state := range []string{"start_failed", "group_stop_failed"} {
		impossible.Workers[0].Started = true
		impossible.Workers[0].Process = state
		if impossible.Validate(later) == nil {
			t.Fatal("unsupported complete-handoff process state accepted")
		}
	}
	absent := publicEvidenceManifest(binding)
	absent.Workers = binding.Workers[1:]
	if absent.Validate(later) == nil {
		t.Fatal("complete manifest without writer accepted")
	}
	body, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublicConfigurationEvidenceManifestBytes(body, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublicConfigurationEvidenceManifestBytes(append([]byte(`{"version":1,`), body[1:]...), binding); err == nil {
		t.Fatal("duplicate manifest key accepted")
	}
	if _, err := ReadPublicConfigurationEvidenceManifestBytes(append([]byte(`{"VERSION":1,`), body[1:]...), binding); err == nil {
		t.Fatal("case-alias manifest key accepted")
	}
}

// full_only: false
func TestPublicConfigurationEvidenceReferenceUsesExactCaseNamespace(t *testing.T) {
	ref := PublicConfigurationEvidenceRef{SchemaVersion: 1, Path: "evidence/public-configuration/0007/manifest.json", SHA256: strings.Repeat("a", 64), Bytes: 1}
	if ref.Validate(7) != nil {
		t.Fatal("exact reference refused")
	}
	if ref.Validate(8) == nil || ref.Validate(-1) == nil {
		t.Fatal("foreign case sequence accepted")
	}
	for _, path := range []string{"evidence/public-configuration/7/manifest.json", "evidence/public-configuration/0007/../manifest.json", "/private/manifest.json", "evidence/telemetry/0007/manifest.json"} {
		value := ref
		value.Path = path
		if value.Validate(7) == nil {
			t.Fatal("nonfixed reference route accepted")
		}
	}
	ref.Bytes = MaximumPublicConfigurationManifestBytes + 1
	if ref.Validate(7) == nil {
		t.Fatal("manifest byte overflow accepted")
	}
}
