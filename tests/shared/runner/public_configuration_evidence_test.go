package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicEvidenceDisposalFixture struct {
	run                                              *runState
	result                                           scenarioResult
	identity, state, prefix                          string
	capture                                          []byte
	ownershipDigest, controlledDigest, cleanupDigest string
	participants                                     *scenarioParticipants
	snapshotPath                                     string
	key                                              string
	expectedSnapshot                                 records.PublicConfigurationEvidenceSnapshot
	expectedWorkers                                  []records.PublicConfigurationWorkerJoin
}

func publicEvidenceFixtureDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// As in the existing private cleanup fixtures, terminal scalar claims exercise
// the real filesystem owner. No cloud, native command or Product effect is
// invented by this test. The fixed native/ownership/inventory bytes below are
// local inputs to the evidence handoff, not a claim that a provider ran here.
func publicEvidenceDisposalFixtureFor(t *testing.T, repetitions int) publicEvidenceDisposalFixture {
	t.Helper()
	return publicEvidenceDisposalFixtureForScenario(t, repetitions, "public-configuration.keys-replace-authority-signing-by-authority/keys_replace_authority_signing_by_authority")
}

func publicEvidenceDisposalFixtureForScenario(t *testing.T, repetitions int, scenario string) publicEvidenceDisposalFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{scenario}, RecoveryMode: "disabled",
		SmokePolicy: catalog.SmokePublicConfiguration, Repetitions: repetitions})
	if err != nil || len(schedule.Entries) != repetitions {
		t.Fatal("public evidence disposal schedule unavailable", err)
	}
	off, empty := "off", []string{}
	settings, err := observability.Resolve(observability.Config{SchemaVersion: 1,
		Logs:    observability.LogConfig{Level: &off, Exporters: &empty},
		Metrics: observability.SignalConfig{Exporters: &empty},
		Traces:  observability.TraceConfig{Exporters: &empty}}, observability.Options{})
	if err != nil {
		t.Fatal("public evidence telemetry-off fixture unavailable", err)
	}
	source := records.Source{Revision: strings.Repeat("a", 40)}
	s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", Profile: "full",
		Schedule: schedule, telemetrySettings: &settings}, source, "controlled")
	if err != nil {
		t.Fatal("public evidence disposal owner unavailable", err)
	}
	s.record.CoverageScope = "live_scenarios"
	s.record.Resolved = &resolvedRequest{Profile: "full", Race: true, Mode: "live", Provider: "gcp", RecoveryMode: "disabled"}
	s.record.BuildClosure = &assemblyClosure{Race: true, PublicConfiguration: &publicConfigurationClosure{
		CLISHA256: strings.Repeat("c", 64), ConsumerSHA256: strings.Repeat("d", 64),
		OverlaySHA256: strings.Repeat("e", 64), SourceSHA256: strings.Repeat("f", 64)}}
	assertions := &records.AssertionEvidence{Marker: "no_failure_marker", Checkpoint: "no_checkpoint",
		Completed: records.CompletedCheckpoint{Code: "none"}}
	worker := func(name, role string) workerEvidence {
		return workerEvidence{Worker: name, Role: role, Outcome: "passed", Process: "passed", Started: true, Joined: true,
			Assertions: assertions, Phases: []records.PhaseResult{{Sequence: 1, Name: "verification", Outcome: "passed"}}}
	}
	writer, fresh, cleanup := worker("proof-writer", "writer"), worker("proof-fresh", "fresh_after"), worker("proof-cleanup", "cleanup")
	shape, err := recordedFixture(scenario, 0)
	if err != nil {
		t.Fatal("public evidence fixture shape unavailable", err)
	}
	result := scenarioResult{Entry: schedule.Entries[0], Fixture: shape, Outcome: "passed", CorrectnessPassed: true,
		Writer: &writer, PostExit: []workerEvidence{fresh}, CleanupWorker: &cleanup,
		Cleanup: records.Cleanup{Outcome: "passed", RemainingOwnedObjects: new(int64), UnknownEffects: new(int64)}}
	name, err := currentCaseDirectory(result.Entry)
	if err != nil {
		t.Fatal("public evidence case route unavailable", err)
	}
	state := filepath.Join(s.private, name)
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	prefix := "enkv-test/" + s.record.RunID + "/" + name
	key := prefix + "/HEAD"
	keyDigest := publicEvidenceFixtureDigest([]byte(key))
	command := filepath.Join(state, "public-command-1")
	if err := os.Mkdir(command, 0700); err != nil {
		t.Fatal(err)
	}
	// These are complete corrected native fixture records, including the
	// independent logical/wire create0 and CAS7 observations. The actual native
	// observer has its own direct regression; no old-capture fallback is used.
	events := []nativeprocess.Event{
		{Kind: "http-start", Operation: "head-write", ObjectKeySHA256: keyDigest, Sequence: 1, Sent: true,
			LogicalConditionKind: "absent", WireConditionKind: "gcp-generation-match", WireConditionValue: []byte("0")},
		{Kind: "http-return", Operation: "head-write", ObjectKeySHA256: keyDigest, Sequence: 1, Sent: true, Status: 200},
		{Kind: "store-result", Operation: "head-write", ObjectKeySHA256: keyDigest, Sequence: 1, Sent: true, WriteStatus: 1,
			LogicalConditionKind: "absent", WireConditionKind: "gcp-generation-match", WireConditionValue: []byte("0")},
		{Kind: "http-start", Operation: "head-write", ObjectKeySHA256: keyDigest, Sequence: 2, Sent: true,
			LogicalConditionKind: "match", LogicalConditionValue: []byte("7"), WireConditionKind: "gcp-generation-match", WireConditionValue: []byte("7")},
		{Kind: "http-return", Operation: "head-write", ObjectKeySHA256: keyDigest, Sequence: 2, Sent: true, Status: 200},
		{Kind: "store-result", Operation: "head-write", ObjectKeySHA256: keyDigest, Sequence: 2, Sent: true, WriteStatus: 1,
			LogicalConditionKind: "match", LogicalConditionValue: []byte("7"), WireConditionKind: "gcp-generation-match", WireConditionValue: []byte("7")},
		{Kind: "footer"},
	}
	var captureBuffer bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&captureBuffer).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	capture := captureBuffer.Bytes()
	capturePath := filepath.Join(command, "capture.jsonl")
	if err := os.WriteFile(capturePath, capture, 0600); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(state, "input.json")
	input := workerInput{RunID: s.record.RunID, Scenarios: []string{scenario}, Prefix: prefix, RecoveryMode: "disabled",
		Participants:        map[string]string{"authority": "authority", "reader": "reader", "cleanup": "cleanup"},
		PublicConfiguration: &publicConfigurationInput{Artifact: publicConfigurationArtifactFromClosure(filepath.Join(state, "build"), s.record.BuildClosure.PublicConfiguration, s.record.BuildClosure.Race)}}
	if err := records.WriteJSON(inputPath, input, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "facts.json"), []byte("{}\n"), 0400); err != nil {
		t.Fatal(err)
	}
	workers := []*workerEvidence{result.Writer, &result.PostExit[0], result.CleanupWorker}
	routes := []string{"workers/writer", "workers/fresh-0000-after", "workers/cleanup"}
	actors := []string{"authority", "reader", "cleanup"}
	var original records.Invocation
	var expectedWorkers []records.PublicConfigurationWorkerJoin
	var cleanupOutput string
	for i, worker := range workers {
		worker.Actor = actors[i]
		output := filepath.Join(state, filepath.FromSlash(routes[i]))
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		inv := records.Invocation{SchemaVersion: records.SchemaVersion, RunID: s.record.RunID, Worker: worker.Worker,
			Nonce: strings.Repeat(fmt.Sprint(i+1), 32), Role: worker.Role, Scenario: result.Scenario, Input: inputPath,
			StateDir: state, OutputDir: output}
		if worker.Role != "cleanup" {
			inv.RecoveryMode = "disabled"
		}
		if worker.Role == "fresh_after" {
			inv.Facts = "facts.json"
		}
		if err := inv.Validate(); err != nil {
			t.Fatal("original joined invocation fixture refused", err)
		}
		if err := records.WriteJSON(filepath.Join(output, "invocation.json"), inv, 0400); err != nil {
			t.Fatal(err)
		}
		raw := records.WorkerResult{SchemaVersion: records.SchemaVersion, RunID: inv.RunID, Worker: inv.Worker,
			Role: inv.Role, Actor: worker.Actor, Scenario: inv.Scenario, Outcome: "passed", Phases: worker.Phases}
		if err := records.WriteJSON(filepath.Join(output, "worker.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		invBody, invErr := json.Marshal(inv)
		resultBody, resultErr := json.Marshal(raw)
		if invErr != nil || resultErr != nil {
			t.Fatal("fixed original worker bytes unavailable", invErr, resultErr)
		}
		expectedWorkers = append(expectedWorkers, records.PublicConfigurationWorkerJoin{Worker: inv.Worker, Nonce: inv.Nonce,
			Role: worker.Role, Actor: worker.Actor, Started: true, Joined: true, Process: "passed",
			InvocationSHA256: publicEvidenceFixtureDigest(append(invBody, '\n')),
			ResultSHA256:     publicEvidenceFixtureDigest(append(resultBody, '\n'))})
		checked := records.InspectAssertions(inv, true)
		worker.Assertions = &checked
		if i == 0 {
			original = inv
		}
		if i == 2 {
			cleanupOutput = output
		}
	}
	binding, domain := strings.Repeat("b", 64), strings.Repeat("d", 64)
	var domainBytes [32]byte
	for i := range domainBytes {
		domainBytes[i] = 0xdd
	}
	bodyOne, bodyTwo := strings.Repeat("1", 64), strings.Repeat("2", 64)
	controlledPath := filepath.Join(state, "public-controlled-inventory.json")
	write := func(path string, value any) []byte {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil || !json.Valid(body) {
			t.Fatal("public evidence fixed JSON unavailable", err)
		}
		body = append(body, '\n')
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return body
	}
	intents := []any{
		map[string]any{"key": key, "digest": bodyOne, "bytes": 3, "kind": "create_head", "state": "acknowledged"},
		map[string]any{"key": key, "digest": bodyTwo, "bytes": 5, "kind": "compare_and_swap", "condition_token": map[string]any{"Family": 2, "Value": "7"}, "state": "acknowledged"},
	}
	controlled := write(controlledPath, map[string]any{"version": 1, "run_id": s.record.RunID, "binding": binding,
		"prefix": prefix, "domain": domainBytes, "intents": intents, "deleted": map[string]int{}})
	cleanupImage := write(filepath.Join(state, "public-cleanup-inventory.json"), map[string]any{"version": 1,
		"run_id": s.record.RunID, "binding": binding, "prefix": prefix, "domain": domainBytes,
		"intents": []any{map[string]any{"key": key, "digest": bodyTwo, "bytes": 5, "kind": "fixture_create", "state": "acknowledged"}},
		"deleted": map[string]int{key: 1}, "cleanup_attempts": []any{map[string]any{"target_intent": 0, "ordinal": 1,
			"key": key, "digest": bodyTwo, "bytes": 5, "token": map[string]any{"Family": 2, "Value": "9"}, "cutoff": 0, "state": "acknowledged"}}})
	ownership := write(filepath.Join(state, "public-ownership.json"), map[string]any{"version": 1, "RunID": s.record.RunID,
		"Prefix": prefix, "Binding": binding, "Source": filepath.Join(state, "public-source", "configuration.json"),
		"Domain": domain, "PreflightEmpty": true, "controlled_inventory": controlledPath,
		"Captures": []any{map[string]any{"Path": capturePath, "SHA256": publicEvidenceFixtureDigest(capture), "Complete": true,
			"Ordinal": 0, "ParentWorker": original.Worker, "ParentNonce": original.Nonce, "ParentRole": "writer",
			"Actor": "authority", "NativeKind": "cli", "ExitCode": 0, "Bytes": len(capture)}},
		"Deleted": []string{key}})
	if err := os.WriteFile(filepath.Join(state, "source-body-must-not-be-exported.txt"), []byte("excluded-private-input-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	domainID := contract.ID(domainBytes)
	token7, token9 := records.PublicConfigurationToken{Family: contract.GCP, Value: []byte("7")}, records.PublicConfigurationToken{Family: contract.GCP, Value: []byte("9")}
	controlledTokens := records.PublicConfigurationTokenSource{Version: 1, RunID: s.record.RunID, Prefix: prefix, Binding: binding, Domain: domainID,
		Observations: []records.PublicConfigurationTokenObservation{{Kind: "intent-condition", Index: 1, TargetIntent: 1,
			Key: key, Digest: bodyTwo, Bytes: 5, Token: token7}}}
	cleanupTokens := records.PublicConfigurationTokenSource{Version: 1, RunID: s.record.RunID, Prefix: prefix, Binding: binding, Domain: domainID,
		Observations: []records.PublicConfigurationTokenObservation{{Kind: "cleanup-condition", Index: 0, TargetIntent: 0, AttemptOrdinal: 1,
			Key: key, Digest: bodyTwo, Bytes: 5, Token: token9}}}
	controlledTokenBody := write(controlledPath+".token-evidence.json", controlledTokens)
	cleanupTokenBody := write(filepath.Join(state, "public-cleanup-inventory.json.token-evidence.json"), cleanupTokens)
	controlledProof := records.PublicConfigurationInventoryEvidence{RunID: s.record.RunID, Prefix: prefix, Binding: binding, Domain: domainID,
		Intents: []records.PublicConfigurationObjectIntent{
			{Key: key, Digest: bodyOne, Bytes: 3, Kind: "create_head", State: "acknowledged"},
			{Key: key, Digest: bodyTwo, Bytes: 5, Kind: "compare_and_swap", ConditionToken: &token7, State: "acknowledged"}},
		TokenSource: &controlledTokens, OriginalTokenSourceSHA256: publicEvidenceFixtureDigest(controlledTokenBody)}
	cleanupProof := records.PublicConfigurationInventoryEvidence{RunID: s.record.RunID, Prefix: prefix, Binding: binding, Domain: domainID,
		Intents: []records.PublicConfigurationObjectIntent{{Key: key, Digest: bodyTwo, Bytes: 5, Kind: "fixture_create", State: "acknowledged"}},
		Deleted: []records.PublicConfigurationDeleted{{Key: key, Cutoff: 1}},
		CleanupAttempts: []records.PublicConfigurationCleanupAttempt{{TargetIntent: 0, Ordinal: 1, Key: key,
			Digest: bodyTwo, Bytes: 5, Token: token9, Cutoff: 0, State: "acknowledged"}},
		TokenSource: &cleanupTokens, OriginalTokenSourceSHA256: publicEvidenceFixtureDigest(cleanupTokenBody)}
	snapshot := records.PublicConfigurationEvidenceSnapshot{Version: 1, RunID: s.record.RunID, Scenario: result.Scenario,
		Provider: "gcp", RecoveryMode: "disabled", Prefix: prefix, Binding: binding, PreflightEmpty: true,
		Domains: []contract.ID{domainID}, Controlled: &controlledProof, Cleanup: cleanupProof,
		OriginalOwnershipSHA256: publicEvidenceFixtureDigest(ownership), OriginalControlledSHA256: publicEvidenceFixtureDigest(controlled),
		OriginalCleanupSHA256: publicEvidenceFixtureDigest(cleanupImage),
		Captures: []records.PublicConfigurationCaptureReceipt{{Ordinal: 0, ParentWorker: original.Worker, ParentNonce: original.Nonce,
			ParentRole: "writer", Actor: "authority", NativeKind: "cli", SourceRelative: "public-command-1/capture.jsonl",
			Complete: true, ExitCode: 0, SHA256: publicEvidenceFixtureDigest(capture), Bytes: uint64(len(capture))}}}
	if selected, ok := catalog.PublicConfiguration(scenario); ok && selected.Output {
		ownership = attachPublicOutputDisposalEvidence(t, state, &snapshot, ownership, expectedWorkers[2])
	}
	snapshotPath := filepath.Join(cleanupOutput, "public-configuration-evidence.json")
	if err := records.WritePublicConfigurationEvidenceSnapshot(snapshotPath, snapshot); err != nil {
		t.Fatal("valid original evidence snapshot refused", err)
	}
	identity, err := caseIdentitySHA256(s.record)
	if err != nil {
		t.Fatal(err)
	}
	if s.record.Telemetry.Enabled || s.record.Diagnostics.Enabled {
		t.Fatal("mandatory proof regression unexpectedly depends on telemetry")
	}
	return publicEvidenceDisposalFixture{run: s, result: result, identity: identity, state: state, prefix: prefix, capture: capture,
		ownershipDigest: publicEvidenceFixtureDigest(ownership), controlledDigest: publicEvidenceFixtureDigest(controlled),
		cleanupDigest: publicEvidenceFixtureDigest(cleanupImage), snapshotPath: snapshotPath, key: key, expectedSnapshot: snapshot, expectedWorkers: expectedWorkers,
		participants: &scenarioParticipants{state: state, input: input,
			writer: original, writerProcess: processResult{Status: "passed", Started: true, Joined: true}}}
}

func sealPublicEvidenceFixture(t *testing.T, fixture *publicEvidenceDisposalFixture) {
	t.Helper()
	s := fixture.run
	s.record.Scenarios = []scenarioResult{fixture.result}
	if err := s.writeCaseReceipt(fixture.result, fixture.identity); err != nil {
		t.Fatal("original immutable proof receipt refused", err)
	}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
}

func requirePublicEvidenceAfterPrivateDisposal(t *testing.T, fixture publicEvidenceDisposalFixture) {
	t.Helper()
	directory := filepath.Join(fixture.run.directory, "evidence", "public-configuration", "0000")
	manifest, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil || !json.Valid(manifest) {
		t.Fatal("successful private disposal lost required public configuration evidence")
	}
	for _, path := range []string{directory, filepath.Join(directory, "captures")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("required proof directory lost its restricted owner")
		}
	}
	capture, err := os.ReadFile(filepath.Join(directory, "captures", "0000.jsonl"))
	if err != nil || !bytes.Equal(capture, fixture.capture) {
		t.Fatal("required proof changed original native sequence or typed write results")
	}
	var snapshot records.PublicConfigurationEvidenceSnapshot
	body, err := os.ReadFile(filepath.Join(directory, "ownership.json"))
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&snapshot) != nil || decoder.Decode(new(any)) != io.EOF ||
		!reflect.DeepEqual(snapshot, fixture.expectedSnapshot) {
		t.Fatal("required proof lost complete original owned rows, tokens, capture parent or inventory commitments")
	}
	// The expected snapshot above is the fixed original input, including both
	// controlled intent rows, exact CAS7, cleanup target/cutoff/ordinal/token9,
	// domain, complete capture registration and both original token companions.
	var got records.PublicConfigurationEvidenceManifest
	decoder = json.NewDecoder(bytes.NewReader(manifest))
	decoder.DisallowUnknownFields()
	buildBody, buildErr := json.Marshal(fixture.run.record.BuildClosure)
	if buildErr != nil || decoder.Decode(&got) != nil || decoder.Decode(new(any)) != io.EOF ||
		got.Version != 1 || got.RunID != fixture.run.record.RunID || got.Scenario != fixture.result.Scenario ||
		got.Provider != "gcp" || got.RecoveryMode != "disabled" || !reflect.DeepEqual(got.Source, fixture.run.record.Source) ||
		got.CaseIdentitySHA256 != fixture.identity || got.BuildClosureSHA256 != publicEvidenceFixtureDigest(buildBody) ||
		got.OverlaySHA256 != strings.Repeat("e", 64) || !reflect.DeepEqual(got.Workers, fixture.expectedWorkers) ||
		got.Snapshot != (records.PublicConfigurationEvidenceFile{Kind: "snapshot", Ordinal: 0, Path: "ownership.json",
			SHA256: publicEvidenceFixtureDigest(body), Bytes: uint64(len(body))}) ||
		len(got.Captures) != 1 || got.Captures[0] != (records.PublicConfigurationEvidenceFile{Kind: "native-capture", Ordinal: 0,
		Path: "captures/0000.jsonl", SHA256: publicEvidenceFixtureDigest(fixture.capture), Bytes: uint64(len(fixture.capture))}) {
		t.Fatal("retained manifest lost exact source, build, original worker joins or fixed proof aliases")
	}
	ref := fixture.result.PublicConfigurationEvidence
	if ref == nil || ref.SchemaVersion != 1 || ref.Path != "evidence/public-configuration/0000/manifest.json" ||
		ref.SHA256 != publicEvidenceFixtureDigest(manifest) || ref.Bytes != uint64(len(manifest)) {
		t.Fatal("public result does not bind the actual retained manifest")
	}
	var persisted runRecord
	if records.ReadJSON(filepath.Join(fixture.run.directory, "run.json"), &persisted) != nil ||
		len(persisted.Scenarios) != 1 || !reflect.DeepEqual(persisted.Scenarios[0].PublicConfigurationEvidence, ref) ||
		validateCaseReceiptSet(fixture.run.directory, persisted) != nil ||
		readPublicConfigurationEvidence(fixture.run.directory, persisted, persisted.Scenarios[0]) != nil {
		t.Fatal("saved run and immutable case proof cannot reopen after private disposal")
	}
	publicPaths := []string{filepath.Join(fixture.run.directory, "run.json"), filepath.Join(fixture.run.directory, "cases", "0000.json")}
	for _, path := range publicPaths {
		publicBody, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, excluded := range []string{fixture.prefix, fixture.state, "excluded-private-input-sentinel", "condition_token", "token_source"} {
			if bytes.Contains(publicBody, []byte(excluded)) {
				t.Fatal("private proof facts escaped into public run or case projection")
			}
		}
	}
	allowed := map[string]bool{"manifest.json": true, "ownership.json": true, "captures/0000.jsonl": true}
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil || !allowed[filepath.ToSlash(relative)] {
			return errors.New("unexpected retained private input")
		}
		body, err := os.ReadFile(path)
		if err != nil || bytes.Contains(body, []byte("excluded-private-input-sentinel")) {
			return errors.New("excluded input escaped into retained proof")
		}
		return nil
	}); err != nil {
		t.Fatal("retained proof is not the fixed no-input-body evidence set", err)
	}
	for _, name := range []string{"manifest.json", "ownership.json", "captures/0000.jsonl"} {
		info, err := os.Lstat(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("required proof file is not restricted regular evidence")
		}
	}
}

// full_only: false
func TestPublicConfigurationRecoveryPacketStaysAvailableToPendingWorkflow(t *testing.T) {
	fixture := publicEvidenceDisposalFixtureFor(t, 2)
	s := fixture.run
	s.record.ContinuationRootRunID = strings.Repeat("d", 32)
	if err := s.retainPublicConfigurationEvidence(&fixture.result, fixture.participants); err != nil {
		t.Fatal(err)
	}
	sealPublicEvidenceFixture(t, &fixture)
	if err := s.verifyPublicConfigurationEvidence(); err != nil {
		t.Fatal(err)
	}
	requirePublicEvidenceOriginalsPresent(t, fixture)
	if err := readPublicConfigurationEvidence(s.directory, s.record, fixture.result); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestPublicConfigurationEvidenceFailureRetainsOriginalPrivateFiles(t *testing.T) {
	for _, boundary := range []string{"final-report", "repeated-case"} {
		t.Run(boundary, func(t *testing.T) {
			for _, damage := range []string{"missing", "bytes", "source", "directory-owner", "symlink", "file-identity"} {
				t.Run(damage, func(t *testing.T) {
					repetitions := 1
					if boundary == "repeated-case" {
						repetitions = 2
					}
					fixture := publicEvidenceDisposalFixtureFor(t, repetitions)
					s := fixture.run
					if err := s.retainPublicConfigurationEvidence(&fixture.result, fixture.participants); err != nil {
						t.Fatal("valid proof must qualify before the damage control", err)
					}
					sealPublicEvidenceFixture(t, &fixture)
					if err := readPublicConfigurationEvidence(s.directory, s.record, fixture.result); err != nil {
						t.Fatal("undamaged retained proof failed its positive control", err)
					}
					path := filepath.Join(s.directory, "evidence", "public-configuration", "0000", "captures", "0000.jsonl")
					before, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					switch damage {
					case "missing":
						err = os.Remove(path)
					case "bytes":
						err = os.WriteFile(path, append(append([]byte(nil), fixture.capture...), '\n'), 0600)
					case "source":
						s.record.Source.Revision = strings.Repeat("f", 40)
					case "directory-owner":
						directory := filepath.Dir(path)
						err = os.Rename(directory, directory+".original")
						if err == nil {
							err = os.Mkdir(directory, 0700)
						}
						if err == nil {
							err = os.Rename(filepath.Join(directory+".original", "0000.jsonl"), path)
						}
					case "symlink":
						err = os.Rename(path, path+".original")
						if err == nil {
							err = os.Symlink(path+".original", path)
						}
					case "file-identity":
						err = os.Rename(path, path+".original")
						if err == nil {
							err = os.WriteFile(path, fixture.capture, 0600)
						}
					}
					if err != nil {
						t.Fatal("retained proof damage fixture failed", err)
					}
					if damage == "file-identity" || damage == "directory-owner" {
						body, readErr := os.ReadFile(path)
						after, statErr := os.Lstat(path)
						if readErr != nil || statErr != nil || !bytes.Equal(body, fixture.capture) ||
							(damage == "file-identity" && records.SameLocalFile(before, after)) ||
							(damage == "directory-owner" && !records.SameLocalFile(before, after)) {
							t.Fatal("equal-byte identity control did not isolate its intended owner")
						}
					}
					if err := s.verifyPublicConfigurationEvidence(); err == nil {
						t.Fatal("damaged or foreign retained proof still grants source disposal")
					}
					if boundary == "final-report" {
						s.finish()
						err = s.finishCurrentRun(io.Discard, nil)
					} else {
						err = s.verifyPublicConfigurationEvidence()
					}
					if err == nil {
						t.Fatal("proof failure was hidden at the real disposal boundary")
					}
					requirePublicEvidenceOriginalsPresent(t, fixture)
					if len(s.record.Scenarios) != 1 || s.record.Scenarios[0].Outcome != "passed" ||
						!s.record.Scenarios[0].CorrectnessPassed || s.record.Scenarios[0].Cleanup.Outcome != "passed" {
						t.Fatal("evidence failure rewrote the original correctness or cleanup claim")
					}
				})
			}
		})
	}
	t.Run("recovery-journal-save", func(t *testing.T) {
		fixture := publicEvidenceDisposalFixtureFor(t, 1)
		s := fixture.run
		if err := s.retainPublicConfigurationEvidence(&fixture.result, fixture.participants); err != nil {
			t.Fatal(err)
		}
		sealPublicEvidenceFixture(t, &fixture)
		path := filepath.Join(s.directory, "run.json")
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := s.finishCurrentRun(io.Discard, nil); err == nil {
			t.Fatal("failed recovery journal save was hidden")
		}
		requirePublicEvidenceOriginalsPresent(t, fixture)
	})
}

func requirePublicEvidenceOriginalsPresent(t *testing.T, fixture publicEvidenceDisposalFixture) {
	t.Helper()
	for _, path := range []string{fixture.run.private, fixture.state} {
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			t.Fatal("failed evidence handoff removed original private owner", err)
		}
	}
	body, err := os.ReadFile(filepath.Join(fixture.state, "public-command-1", "capture.jsonl"))
	if err != nil || !bytes.Equal(body, fixture.capture) {
		t.Fatal("failed evidence handoff changed the original capture", err)
	}
	body, err = os.ReadFile(filepath.Join(fixture.state, "source-body-must-not-be-exported.txt"))
	if err != nil || string(body) != "excluded-private-input-sentinel" {
		t.Fatal("failed evidence handoff removed excluded private input", err)
	}
}

// full_only: false
func TestPublicConfigurationEvidenceHandoffRejectsChangedOriginals(t *testing.T) {
	for _, damage := range []string{"missing-snapshot", "inventory-image", "token-source", "writer-invocation", "input-image"} {
		t.Run(damage, func(t *testing.T) {
			fixture := publicEvidenceDisposalFixtureFor(t, 1)
			s := fixture.run
			var err error
			switch damage {
			case "missing-snapshot":
				err = os.Remove(fixture.snapshotPath)
			case "inventory-image", "token-source":
				path := filepath.Join(fixture.state, "public-controlled-inventory.json")
				if damage == "token-source" {
					path += ".token-evidence.json"
				}
				var body []byte
				body, err = os.ReadFile(path)
				if err == nil {
					err = os.WriteFile(path, append(body, '\n'), 0600)
				}
			case "writer-invocation":
				fixture.participants.writer.Nonce = strings.Repeat("4", 32)
			case "input-image":
				fixture.participants.input.Participants["authority"] = "foreign-authority"
			}
			if err != nil {
				t.Fatal("original proof damage fixture failed", err)
			}
			if err := s.retainPublicConfigurationEvidence(&fixture.result, fixture.participants); err == nil || fixture.result.PublicConfigurationEvidence != nil {
				t.Fatal("changed original source image published a complete public proof reference")
			}
			s.record.Scenarios = []scenarioResult{fixture.result}
			if s.writeCaseReceipt(fixture.result, fixture.identity) == nil {
				t.Fatal("missing required proof sealed a successful immutable case")
			}
			s.finish()
			if s.finishCurrentRun(io.Discard, nil) == nil {
				t.Fatal("failed original handoff allowed source disposal")
			}
			requirePublicEvidenceOriginalsPresent(t, fixture)
			if s.record.Scenarios[0].Outcome != "passed" || !s.record.Scenarios[0].CorrectnessPassed || s.record.Scenarios[0].Cleanup.Outcome != "passed" {
				t.Fatal("local evidence failure was substituted for original Product assertions")
			}
		})
	}
}

// full_only: false
func TestPublicGeneratedOriginalEvidenceBindsLedgerAndPositiveJoinImages(t *testing.T) {
	for _, condition := range []string{"exact", "ledger-hash", "join-hash", "changed-account", "changed-attempt", "pending-create", "missing-join", "false-join", "fixture-exact", "fixture-missing", "fixture-hash", "fixture-changed", "fixture-unprojected"} {
		t.Run(condition, func(t *testing.T) {
			// Reuse the existing local handoff fixture. Its scalar ownership inputs
			// test file provenance only; they do not claim a provider effect occurred.
			fixture := publicEvidenceDisposalFixtureFor(t, 1)
			snapshot := fixture.expectedSnapshot
			snapshot.Scenario = "public-configuration.generated-manual-lifecycle/generated_manual_lifecycle"
			account, target := strings.Repeat("a", 32), strings.Repeat("b", 32)
			create, retire := strings.Repeat("c", 64), strings.Repeat("d", 64)
			path := filepath.Join(fixture.state, "generator-cleanup.json")
			if records.NewGeneratorFixtureLedger(path, snapshot.RunID, account) != nil {
				t.Fatal("generator source fixture unavailable")
			}
			if err := records.UpdateGeneratorFixtureLedger(path, snapshot.RunID, account, func(l *records.GeneratorFixtureLedger) error {
				if err := l.BeginCreate(create); err != nil {
					return err
				}
				if err := l.RecordCreate(create, target); err != nil {
					return err
				}
				if err := l.BeginDelete(retire, target); err != nil {
					return err
				}
				return l.RecordDelete(retire, target)
			}); err != nil {
				t.Fatal(err)
			}
			joinedPath := filepath.Join(fixture.state, "generator-writer-joined.json")
			if records.WriteGeneratorFixtureJoined(joinedPath, snapshot.RunID, snapshot.Scenario) != nil {
				t.Fatal("positive join fixture unavailable")
			}
			body, err := records.ReadJSONBytes(path, records.MaximumJSONBytes)
			if err != nil {
				t.Fatal(err)
			}
			joinedBody, err := records.ReadJSONBytes(joinedPath, 4096)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := records.ReadGeneratorFixtureLedger(path, snapshot.RunID, account)
			if err != nil {
				t.Fatal(err)
			}
			joined := records.GeneratorFixtureJoined{SchemaVersion: 1, RunID: snapshot.RunID, Scenario: snapshot.Scenario, Joined: true}
			snapshot.Generator = &records.PublicConfigurationGeneratorEvidence{Account: account, Resources: slices.Clone(ledger.Resources), WriterJoined: joined, OriginalLedgerSHA256: digestBytes(body), OriginalJoinedSHA256: digestBytes(joinedBody)}
			fixturePath := filepath.Join(fixture.state, records.PublicGeneratorFixtureCleanupName)
			if strings.HasPrefix(condition, "fixture-") {
				if records.RecordPublicGeneratorFixtureCleanup(fixturePath, snapshot.RunID, snapshot.Scenario, account, retire, target) != nil {
					t.Fatal("fixture cleanup source unavailable")
				}
				body, err := records.ReadJSONBytes(fixturePath, records.MaximumPublicGeneratorFixtureCleanupBytes)
				if err != nil {
					t.Fatal(err)
				}
				original, err := records.ReadPublicGeneratorFixtureCleanupBytes(body, snapshot.RunID, snapshot.Scenario, account)
				if err != nil {
					t.Fatal(err)
				}
				if condition != "fixture-unprojected" {
					snapshot.Generator.FixtureCleanup, snapshot.Generator.OriginalFixtureCleanupSHA256 = &original, digestBytes(body)
				}
			}
			switch condition {
			case "ledger-hash":
				snapshot.Generator.OriginalLedgerSHA256 = strings.Repeat("e", 64)
			case "join-hash":
				snapshot.Generator.OriginalJoinedSHA256 = strings.Repeat("e", 64)
			case "changed-account":
				ledger.Account = strings.Repeat("f", 32)
			case "changed-attempt":
				ledger.Resources[0].CreateAttempt = strings.Repeat("f", 64)
			case "pending-create":
				ledger.PendingCreates = []string{strings.Repeat("f", 64)}
			case "missing-join":
				if os.Remove(joinedPath) != nil {
					t.Fatal("join loss fixture failed")
				}
			case "false-join":
				joined.Joined = false
				if records.WriteJSON(joinedPath, joined, 0400) != nil {
					t.Fatal("join mutation fixture failed")
				}
				changed, err := records.ReadJSONBytes(joinedPath, 4096)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.Generator.OriginalJoinedSHA256 = digestBytes(changed)
				snapshot.Generator.WriterJoined = joined
			case "fixture-missing":
				if os.Remove(fixturePath) != nil {
					t.Fatal("fixture source removal failed")
				}
			case "fixture-hash":
				snapshot.Generator.OriginalFixtureCleanupSHA256 = strings.Repeat("e", 64)
			case "fixture-changed":
				original := *snapshot.Generator.FixtureCleanup
				original.AcknowledgedDeletes = slices.Clone(original.AcknowledgedDeletes)
				original.AcknowledgedDeletes[0].Target = strings.Repeat("f", 32)
				if records.WriteJSON(fixturePath, original, 0600) != nil {
					t.Fatal("fixture source mutation failed")
				}
				changed, err := records.ReadJSONBytes(fixturePath, records.MaximumPublicGeneratorFixtureCleanupBytes)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.Generator.OriginalFixtureCleanupSHA256 = digestBytes(changed)
			}
			if condition == "changed-account" || condition == "changed-attempt" || condition == "pending-create" {
				if records.WriteJSON(path, ledger, 0600) != nil {
					t.Fatal("ledger mutation fixture failed")
				}
				changed, err := records.ReadJSONBytes(path, records.MaximumJSONBytes)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.Generator.OriginalLedgerSHA256 = digestBytes(changed)
			}
			if err := verifyOriginalPublicConfigurationEvidence(fixture.state, snapshot); (err == nil) != (condition == "exact" || condition == "fixture-exact") {
				t.Fatal("generator source projection lost exact image or positive join", condition, err)
			}
		})
	}
}
