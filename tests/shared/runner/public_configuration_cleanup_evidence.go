package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// This private manifest records fixture closure after failed Product work. It
// has two worker namespaces and cannot stand in for a successful lifecycle.
type publicCleanupEvidenceManifest struct {
	Schema              uint16                                    `json:"schema"`
	Kind                string                                    `json:"kind"`
	RunID               string                                    `json:"run_id"`
	OriginalRunID       string                                    `json:"original_run_id"`
	OriginalState       string                                    `json:"original_state"`
	OriginalEntry       catalog.Entry                             `json:"original_entry"`
	Entry               catalog.Entry                             `json:"entry"`
	OriginalCaseSHA256  string                                    `json:"original_case_sha256"`
	CaseSHA256          string                                    `json:"case_sha256"`
	OriginalBuildSHA256 string                                    `json:"original_build_sha256"`
	BuildSHA256         string                                    `json:"build_sha256"`
	OriginalSource      records.Source                            `json:"original_source"`
	Source              records.Source                            `json:"source"`
	SourceImages        []publicCleanupSourceImage                `json:"source_images"`
	OriginalWorkers     []records.PublicConfigurationWorkerJoin   `json:"original_workers"`
	CleanupWorker       records.PublicConfigurationWorkerJoin     `json:"cleanup_worker"`
	Files               []records.PublicConfigurationEvidenceFile `json:"files"`
}

type publicCleanupSourceImage struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  uint64 `json:"bytes"`
}

type publicCleanupEvidenceBasis struct {
	manifest publicCleanupEvidenceManifest
	base     string
	pins     map[string]retainedPublicConfigurationFile
}

func ordinaryPublicCleanupCase(scenario string) bool {
	row, known := catalog.PublicConfiguration(scenario)
	return known && scenario != records.StockPluginScenario && !row.Output && !recordedHasFixture(scenario, catalog.FixtureGeneratedProcess)
}

func publicCleanupOriginalInput(role, route string) (string, error) {
	switch role {
	case "writer", "fresh_after", "fresh_before":
		return "input.json", nil
	case "rerun":
		return "rerun-input.json", nil
	case "cleanup":
		if route == filepath.Join("workers", "cleanup") {
			return "cleanup-input.json", nil
		}
		if strings.HasPrefix(filepath.ToSlash(route), "workers/cleanup-retry-") {
			ordinal := strings.TrimPrefix(filepath.Base(route), "cleanup-retry-")
			if ordinal == "2" || ordinal == "3" {
				return "cleanup-retry-input-" + ordinal + ".json", nil
			}
		}
	}
	return "", errPublicConfigurationEvidence
}

func publicCleanupRecord(path string) ([]byte, os.FileInfo, error) {
	return publicCleanupRecordLimit(path, records.MaximumJSONBytes)
}

func publicCleanupRecordLimit(path string, limit uint64) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 {
		return nil, nil, errPublicConfigurationEvidence
	}
	return readPublicConfigurationFile(path, limit, info.Mode().Perm())
}

func publicCleanupBuildDigest(value *assemblyClosure) string {
	if value == nil {
		return ""
	}
	body, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return digestBytes(body)
}

func publicCleanupCaseIdentity(parent runRecord) (string, error) {
	if parent.Suite != "live" || parent.CoverageScope != "cleanup_recovery" || !records.ValidRunID(parent.RunID) || !records.ValidRunID(parent.RecoveryRunID) || parent.RunID == parent.RecoveryRunID ||
		parent.SchemaVersion != records.SchemaVersion || parent.BuildClosure == nil || parent.Limits == nil || parent.CleanupRecoveryBasis != nil || parent.ContinuationRootRunID != "" || len(parent.Schedule.Entries) == 0 || parent.Native.GOOS == "" || parent.Native.GOARCH == "" {
		return "", errPublicConfigurationEvidence
	}
	body, err := json.Marshal(caseStaticIdentityFor(parent))
	if err != nil || len(body) > records.MaximumJSONBytes {
		return "", errPublicConfigurationEvidence
	}
	return digestBytes(append([]byte("enkv/public-cleanup-case/v1\x00"), body...)), nil
}

// Physical files can be retained copies. Expected carries the unchanged
// original path metadata; only assertion interpretation uses the copied paths.
func publicCleanupJoinedWorker(output string, expected records.Invocation, evidence workerEvidence, sourceMap string) (records.PublicConfigurationWorkerJoin, error) {
	refused := errPublicConfigurationEvidence
	switch evidence.Process {
	case "passed", "process_failed", "timed_out", "interrupted", "resource_limit", "output_limit_exceeded":
	default:
		return records.PublicConfigurationWorkerJoin{}, refused
	}
	invBody, _, err := publicCleanupRecord(filepath.Join(output, "invocation.json"))
	var inv records.Invocation
	if err != nil || decodeCleanupRecord(invBody, &inv) != nil || inv.ValidateEvidence() != nil || inv.RunID != expected.RunID || inv.Scenario != expected.Scenario ||
		inv.StateDir != expected.StateDir || inv.OutputDir != expected.OutputDir || inv.Input != expected.Input || inv.Role != evidence.Role || inv.Worker != evidence.Worker ||
		!evidence.Started || !evidence.Joined || evidence.Assertions == nil || inv.FailureSources == nil {
		return records.PublicConfigurationWorkerJoin{}, refused
	}
	mapBody, _, err := publicCleanupRecord(sourceMap)
	if err != nil || digestBytes(mapBody) != inv.FailureSources.SHA256 {
		return records.PublicConfigurationWorkerJoin{}, refused
	}
	var sources records.FailureSources
	if decodeCleanupRecord(mapBody, &sources) != nil || sources.Validate() != nil {
		return records.PublicConfigurationWorkerJoin{}, refused
	}
	resultBody, _, err := publicCleanupRecord(filepath.Join(output, "worker.json"))
	var raw records.WorkerResult
	if err != nil || decodeCleanupRecord(resultBody, &raw) != nil || raw.SchemaVersion != records.SchemaVersion || raw.RunID != inv.RunID || raw.Scenario != inv.Scenario ||
		raw.Worker != inv.Worker || raw.Role != inv.Role || raw.Actor != evidence.Actor || raw.Outcome != evidence.Outcome && !(evidence.Outcome == "failed" && raw.Outcome == "incomplete") {
		return records.PublicConfigurationWorkerJoin{}, refused
	}
	interpreted := inv
	interpreted.OutputDir = output
	interpreted.FailureSources = &records.FailureSourceBinding{Path: sourceMap, SHA256: inv.FailureSources.SHA256}
	assertions := records.InspectAssertions(interpreted, evidence.Process == "passed" || raw.Outcome == "passed")
	if !reflect.DeepEqual(*evidence.Assertions, assertions) {
		return records.PublicConfigurationWorkerJoin{}, refused
	}
	return records.PublicConfigurationWorkerJoin{Worker: inv.Worker, Nonce: inv.Nonce, Role: inv.Role, Actor: raw.Actor, InvocationSHA256: digestBytes(invBody), ResultSHA256: digestBytes(resultBody), Started: evidence.Started, Joined: evidence.Joined, Process: evidence.Process}, nil
}

func (s *runState) preparePublicCleanupEvidence(entry recoveryEntry, result scenarioResult) (*publicCleanupEvidenceBasis, error) {
	refused := errPublicConfigurationEvidence
	if !ordinaryPublicCleanupCase(result.Scenario) || s.record.Suite != "live" || !records.ValidRunID(s.record.RecoveryRunID) || s.record.RecoveryRunID == s.record.RunID ||
		s.record.CleanupRecoveryBasis != nil || result.Writer != nil || result.Rerun != nil || len(result.Children)+len(result.PostExit) != 0 || result.CorrectnessPassed || s.record.BuildClosure == nil {
		return nil, refused
	}
	originalDirectory := filepath.Dir(filepath.Dir(entry.State))
	originalBody, _, err := publicCleanupRecord(filepath.Join(originalDirectory, "run.json"))
	var original runRecord
	if err != nil || decodeCleanupRecord(originalBody, &original) != nil || original.RunID != s.record.RecoveryRunID || original.BuildClosure == nil {
		return nil, refused
	}
	var selected *scenarioResult
	for i := range original.Scenarios {
		candidate := &original.Scenarios[i]
		name, err := recordedCaseDirectory(candidate.Entry)
		if err == nil && candidate.Scenario == result.Scenario && filepath.Join(originalDirectory, "private", name) == entry.State {
			if selected != nil {
				return nil, refused
			}
			selected = candidate
		}
	}
	if selected == nil {
		return nil, refused
	}
	for _, name := range []string{"public-cleanup-inventory.json", "public-cleanup-inventory.json.token-evidence.json"} {
		if _, err := os.Lstat(filepath.Join(entry.State, name)); !os.IsNotExist(err) {
			return nil, refused
		}
	}
	originalCase, err := caseIdentitySHA256(original)
	currentCase, currentErr := publicCleanupCaseIdentity(s.record)
	if err != nil || currentErr != nil {
		return nil, refused
	}
	basis := &publicCleanupEvidenceBasis{base: filepath.ToSlash(filepath.Join("evidence", "public-configuration", fmt.Sprintf("%04d", result.Sequence))), pins: map[string]retainedPublicConfigurationFile{},
		manifest: publicCleanupEvidenceManifest{Schema: 1, Kind: "public-cleanup-only", RunID: s.record.RunID, OriginalRunID: original.RunID, OriginalState: entry.State, OriginalEntry: selected.Entry, Entry: result.Entry,
			OriginalCaseSHA256: originalCase, CaseSHA256: currentCase, OriginalBuildSHA256: publicCleanupBuildDigest(original.BuildClosure), BuildSHA256: publicCleanupBuildDigest(s.record.BuildClosure), OriginalSource: original.Source, Source: s.record.Source}}
	add := func(path, relative string) error { return s.retainPublicCleanupSource(basis, path, relative, true) }
	for _, file := range []struct{ path, relative string }{
		{filepath.Join(originalDirectory, "run.json"), "origin/run.json"},
		{filepath.Join(originalDirectory, caseReceiptPath(selected.Sequence)), filepath.ToSlash(filepath.Join("origin", caseReceiptPath(selected.Sequence)))},
		{entry.InputPath, "origin/input.json"},
		{filepath.Join(originalDirectory, "private", "build", "failure-sources.json"), "origin/failure-sources.json"},
		{filepath.Join(entry.State, "public-ownership.json"), "origin/state/public-ownership.json"},
	} {
		if add(file.path, file.relative) != nil {
			return nil, refused
		}
	}
	workers, routes, err := publicConfigurationWorkerRoutes(*selected)
	if err != nil {
		return nil, refused
	}
	inputs := map[string]bool{"input.json": true}
	for i, route := range routes {
		input, err := publicCleanupOriginalInput(workers[i].Role, route)
		if err != nil {
			return nil, refused
		}
		if !inputs[input] {
			if add(filepath.Join(entry.State, input), filepath.ToSlash(filepath.Join("origin", "state", input))) != nil {
				return nil, refused
			}
			inputs[input] = true
		}
		output := filepath.Join(entry.State, route)
		for _, name := range []string{"invocation.json", "worker.json", "failure.json", "checkpoint.json"} {
			path := filepath.Join(output, name)
			if _, err := os.Lstat(path); os.IsNotExist(err) && (name == "failure.json" || name == "checkpoint.json") {
				continue
			}
			if add(path, filepath.ToSlash(filepath.Join("origin", "state", route, name))) != nil {
				return nil, refused
			}
		}
	}
	var ownership records.PublicConfigurationOwnership
	ownershipBody, _, err := publicCleanupRecord(filepath.Join(entry.State, "public-ownership.json"))
	if err != nil || decodeCleanupRecord(ownershipBody, &ownership) != nil || ownership.RunID != original.RunID || ownership.Prefix != entry.Input.Prefix || !ownership.PreflightEmpty || ownership.Outputs != nil || ownership.Source != filepath.Join(entry.State, "public-source", "configuration.json") {
		return nil, refused
	}
	for i, capture := range ownership.Captures {
		relative, err := filepath.Rel(entry.State, capture.Path)
		parsed, sum, parseErr := nativeprocess.ReadCaptureWithDigest(capture.Path)
		if err != nil || parseErr != nil || fmt.Sprintf("%x", sum) != capture.SHA256 || len(parsed.Events) == 0 || parsed.Events[len(parsed.Events)-1].Code != capture.ExitCode ||
			!capture.Complete || capture.Ordinal != uint16(i) || !strings.HasPrefix(filepath.ToSlash(relative), "public-command-") || filepath.Base(relative) != "capture.jsonl" || add(capture.Path, filepath.ToSlash(filepath.Join("origin", "state", relative))) != nil {
			return nil, refused
		}
	}
	if ownership.ControlledInventory != "" {
		if ownership.ControlledInventory != filepath.Join(entry.State, "public-controlled-inventory.json") {
			return nil, refused
		}
		for _, name := range []string{"public-controlled-inventory.json", "public-controlled-inventory.json.token-evidence.json"} {
			if add(filepath.Join(entry.State, name), "origin/state/"+name) != nil {
				return nil, refused
			}
		}
	}
	if s.pinPublicCleanupSourceImages(basis, ownership.Source) != nil {
		return nil, refused
	}
	root := filepath.Join(s.directory, basis.base, "origin")
	_, _, recordedInput, joins, err := readPublicCleanupOrigin(root, filepath.Join(root, "state"), filepath.Join(root, "input.json"), filepath.Join(root, "failure-sources.json"), basis.manifest, s.record.Provider)
	if err != nil || !reflect.DeepEqual(recordedInput, entry.Input) || !publicCleanupPinsUnchanged(basis) {
		return nil, refused
	}
	basis.manifest.OriginalWorkers = joins
	return basis, nil
}

func publicCleanupPinsUnchanged(basis *publicCleanupEvidenceBasis) bool {
	for path, original := range basis.pins {
		body, identity, err := publicCleanupRecordLimit(path, original.bytes)
		if err != nil || !samePublicConfigurationFile(original.identity, identity) || uint64(len(body)) != original.bytes || digestBytes(body) != original.sha256 {
			return false
		}
	}
	return true
}

func (s *runState) retainPublicCleanupSource(basis *publicCleanupEvidenceBasis, path, relative string, pin bool) error {
	limit := uint64(records.MaximumJSONBytes)
	if strings.HasSuffix(relative, "/capture.jsonl") {
		limit = nativeprocess.MaxCaptureBytes
	} else if relative == "snapshot.json" {
		limit = records.MaximumPublicConfigurationSnapshotBytes
	}
	body, identity, err := publicCleanupRecordLimit(path, limit)
	if err != nil {
		return err
	}
	if pin {
		basis.pins[path] = retainedPublicConfigurationFile{sha256: digestBytes(body), bytes: uint64(len(body)), identity: identity}
	}
	if s.retainPublicConfigurationFile(filepath.ToSlash(filepath.Join(basis.base, relative)), body) != nil {
		return errPublicConfigurationEvidence
	}
	basis.manifest.Files = append(basis.manifest.Files, records.PublicConfigurationEvidenceFile{Kind: "cleanup-support", Path: relative, SHA256: digestBytes(body), Bytes: uint64(len(body))})
	return nil
}

func (s *runState) pinPublicCleanupSourceImages(basis *publicCleanupEvidenceBasis, source string) error {
	body, identity, err := publicCleanupRecord(source)
	if err != nil {
		return err
	}
	images := []string{source}
	var document struct {
		Generated string `json:"generated"`
	}
	if json.Unmarshal(body, &document) != nil {
		return errPublicConfigurationEvidence
	}
	if document.Generated != "" {
		if filepath.IsAbs(document.Generated) || filepath.Clean(document.Generated) != document.Generated {
			return errPublicConfigurationEvidence
		}
		generated, err := records.SafePath(filepath.Dir(source), document.Generated)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(generated); err == nil {
			images = append(images, generated)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, path := range images {
		if path != source {
			body, identity, err = publicCleanupRecord(path)
		}
		if err != nil {
			return err
		}
		basis.pins[path] = retainedPublicConfigurationFile{sha256: digestBytes(body), bytes: uint64(len(body)), identity: identity}
		basis.manifest.SourceImages = append(basis.manifest.SourceImages, publicCleanupSourceImage{Path: path, SHA256: digestBytes(body), Bytes: uint64(len(body))})
	}
	return nil
}

func (s *runState) retainPublicCleanupEvidence(basis *publicCleanupEvidenceBasis, inv records.Invocation, result *scenarioResult) error {
	if basis == nil || s.failureSources == nil || result.CleanupWorker == nil || !scenarioCleanupPassed(*result) || result.CleanupWorker.Process != "passed" || result.CleanupWorker.Outcome != "passed" {
		return errPublicConfigurationEvidence
	}
	if !publicCleanupPinsUnchanged(basis) {
		return errPublicConfigurationEvidence
	}
	mapBody, _, err := publicCleanupRecord(s.failureSources.Path)
	if err != nil || digestBytes(mapBody) != s.record.BuildClosure.FailureSourcesSHA256 {
		return errPublicConfigurationEvidence
	}
	join, err := publicCleanupJoinedWorker(inv.OutputDir, inv, *result.CleanupWorker, s.failureSources.Path)
	if err != nil {
		return err
	}
	basis.manifest.CleanupWorker = join
	for _, file := range []struct{ path, relative string }{
		{inv.Input, "recovery/input.json"}, {s.failureSources.Path, "recovery/failure-sources.json"},
		{filepath.Join(inv.OutputDir, "invocation.json"), "recovery/invocation.json"}, {filepath.Join(inv.OutputDir, "worker.json"), "recovery/worker.json"},
		{filepath.Join(inv.OutputDir, "public-configuration-evidence.json"), "snapshot.json"},
		{filepath.Join(inv.StateDir, "public-cleanup-inventory.json"), "origin/state/public-cleanup-inventory.json"},
		{filepath.Join(inv.StateDir, "public-cleanup-inventory.json.token-evidence.json"), "origin/state/public-cleanup-inventory.json.token-evidence.json"},
	} {
		if s.retainPublicCleanupSource(basis, file.path, file.relative, false) != nil {
			return errPublicConfigurationEvidence
		}
	}
	for _, name := range []string{"failure.json", "checkpoint.json"} {
		path := filepath.Join(inv.OutputDir, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		if s.retainPublicCleanupSource(basis, path, "recovery/"+name, false) != nil {
			return errPublicConfigurationEvidence
		}
	}
	body, err := json.Marshal(basis.manifest)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	path := basis.base + "/manifest.json"
	if s.retainPublicConfigurationFile(path, body) != nil {
		return errPublicConfigurationEvidence
	}
	result.PublicConfigurationEvidence = &records.PublicConfigurationEvidenceRef{SchemaVersion: records.PublicConfigurationEvidenceVersion, Path: path, SHA256: digestBytes(body), Bytes: uint64(len(body))}
	if readPublicConfigurationCleanupEvidence(s.directory, s.record, *result) != nil {
		result.PublicConfigurationEvidence = nil
		return errPublicConfigurationEvidence
	}
	return nil
}

// The same original-owner checks apply before dispatch and after private files
// have been copied. Only these physical read locations differ between callers.
func readPublicCleanupOrigin(directory, state, inputPath, mapPath string, manifest publicCleanupEvidenceManifest, provider string) (runRecord, scenarioResult, workerInput, []records.PublicConfigurationWorkerJoin, error) {
	refused := func() (runRecord, scenarioResult, workerInput, []records.PublicConfigurationWorkerJoin, error) {
		return runRecord{}, scenarioResult{}, workerInput{}, nil, errPublicConfigurationEvidence
	}
	body, _, err := publicCleanupRecord(filepath.Join(directory, "run.json"))
	var original runRecord
	if err != nil || decodeCleanupRecord(body, &original) != nil || original.SchemaVersion != records.SchemaVersion || original.RunID != manifest.OriginalRunID || original.Suite != "live" || original.Provider != provider ||
		original.RecoveryRunID != "" || original.CleanupRecoveryBasis != nil || original.Outcome != "failed" || original.Failure == nil || original.Failure.Stage != "execution" ||
		original.FinishedAt == nil || original.FinishedAt.Before(original.StartedAt) || !runProcessesJoined(original) || original.BuildClosure == nil || original.BuildClosure.PublicConfiguration == nil || !validSource(original.Source) ||
		publicCleanupBuildDigest(original.BuildClosure) != manifest.OriginalBuildSHA256 || !sameSource(original.Source, manifest.OriginalSource) {
		return refused()
	}
	identity, err := caseIdentitySHA256(original)
	if err != nil || identity != manifest.OriginalCaseSHA256 || manifest.OriginalEntry.Scenario != manifest.Entry.Scenario || !ordinaryPublicCleanupCase(manifest.OriginalEntry.Scenario) {
		return refused()
	}
	var selected *scenarioResult
	for i := range original.Scenarios {
		if original.Scenarios[i].Entry == manifest.OriginalEntry {
			if selected != nil {
				return refused()
			}
			selected = &original.Scenarios[i]
		}
	}
	name, err := recordedCaseDirectory(manifest.OriginalEntry)
	if err != nil || selected == nil || filepath.Base(manifest.OriginalState) != name || !filepath.IsAbs(manifest.OriginalState) || filepath.Clean(manifest.OriginalState) != manifest.OriginalState ||
		selected.Writer == nil || !selected.Writer.Started || !selected.Writer.Joined || selected.CorrectnessPassed || selected.Outcome != "failed" || selected.Failure == nil || selected.Failure.Stage != "writer" || selected.PublicConfigurationEvidence != nil {
		return refused()
	}
	// This failed-writer branch has no fresh-reader or rerun facts to export.
	// Such completed lifecycle shapes keep their separate evidence owner.
	if selected.Rerun != nil || len(selected.Children)+len(selected.PostExit) != 0 {
		return refused()
	}
	matched := false
	for _, ref := range original.CaseReceipts {
		if ref.Sequence == selected.Sequence {
			leaf, err := validateCaseReceipt(directory, original, ref, selected.Entry)
			if matched || err != nil || !reflect.DeepEqual(leaf, *selected) {
				return refused()
			}
			matched = true
		}
	}
	if !matched {
		return refused()
	}
	inputBody, _, err := publicCleanupRecord(inputPath)
	var input workerInput
	if err != nil || decodeCleanupRecord(inputBody, &input) != nil || input.RunID != original.RunID || len(input.Scenarios) != 1 || input.Scenarios[0] != selected.Scenario || input.Prefix != "enkv-test/"+original.RunID+"/"+name ||
		!publicCleanupInputValid(input, provider) || input.CleanupGrant != nil || input.CleanupRetry != nil || input.StockRecovery != nil || input.Generator != nil || input.PublicConfiguration == nil ||
		!reflect.DeepEqual(input.PublicConfiguration.Artifact.closure(), original.BuildClosure.PublicConfiguration) || !reflect.DeepEqual(safeRunContext(input.Settings), original.Context) {
		return refused()
	}
	mapBody, _, err := publicCleanupRecord(mapPath)
	var sourceMap records.FailureSources
	if err != nil || digestBytes(mapBody) != original.BuildClosure.FailureSourcesSHA256 || decodeCleanupRecord(mapBody, &sourceMap) != nil || sourceMap.Validate() != nil || sourceMap.BinarySHA256 != original.BuildClosure.BinarySHA256 || sourceMap.OverlaySHA256 != original.BuildClosure.OverlaySHA256 {
		return refused()
	}
	workers, routes, err := publicConfigurationWorkerRoutes(*selected)
	if err != nil {
		return refused()
	}
	var joins []records.PublicConfigurationWorkerJoin
	for i, worker := range workers {
		role := worker.Role
		if role == "writer" || role == "rerun" {
			role = "authority"
		} else if role == "fresh_after" || role == "fresh_before" {
			role = "reader"
		}
		relativeInput, err := publicCleanupOriginalInput(worker.Role, routes[i])
		if err != nil {
			return refused()
		}
		physicalInput := inputPath
		if relativeInput != "input.json" {
			physicalInput = filepath.Join(state, relativeInput)
		}
		workerInputBody, _, err := publicCleanupRecord(physicalInput)
		var observed workerInput
		if err != nil || decodeCleanupRecord(workerInputBody, &observed) != nil || observed.Limits == nil {
			return refused()
		}
		expected := input
		expected.Limits, expected.CleanupRetry = observed.Limits, observed.CleanupRetry
		if !reflect.DeepEqual(observed, expected) || worker.Role != "cleanup" && observed.CleanupRetry != nil {
			return refused()
		}
		join, err := publicCleanupJoinedWorker(filepath.Join(state, routes[i]), records.Invocation{RunID: original.RunID, Scenario: selected.Scenario, StateDir: manifest.OriginalState,
			OutputDir: filepath.Join(manifest.OriginalState, routes[i]), Input: filepath.Join(manifest.OriginalState, relativeInput)}, worker, mapPath)
		if err != nil || join.Actor != input.Participants[role] {
			return refused()
		}
		joins = append(joins, join)
	}
	ownerBody, _, err := publicCleanupRecord(filepath.Join(state, "public-ownership.json"))
	var owner records.PublicConfigurationOwnership
	if err != nil || decodeCleanupRecord(ownerBody, &owner) != nil || owner.Version != 1 || owner.RunID != original.RunID || owner.Prefix != input.Prefix || !owner.PreflightEmpty ||
		owner.Source != filepath.Join(manifest.OriginalState, "public-source", "configuration.json") || owner.Outputs != nil || len(owner.Captures) == 0 || len(owner.Captures) > records.MaximumPublicConfigurationCaptures {
		return refused()
	}
	parents, actors := map[string]bool{}, map[string]bool{}
	for _, join := range joins {
		parents[join.Worker+"/"+join.Nonce+"/"+join.Role] = true
	}
	for role, actor := range input.Participants {
		if input.PublicConfiguration.Actors[role] != nil {
			actors[actor] = true
		}
	}
	for i, capture := range owner.Captures {
		relative, err := filepath.Rel(manifest.OriginalState, capture.Path)
		path, pathErr := records.SafePath(state, relative)
		if err != nil || pathErr != nil || !strings.HasPrefix(filepath.ToSlash(relative), "public-command-") || filepath.Base(relative) != "capture.jsonl" || capture.Ordinal != uint16(i) ||
			!capture.Complete || !parents[capture.ParentWorker+"/"+capture.ParentNonce+"/"+capture.ParentRole] || !actors[capture.Actor] {
			return refused()
		}
		data, _, err := publicCleanupRecordLimit(path, nativeprocess.MaxCaptureBytes)
		parsed, parseErr := nativeprocess.InspectCapture(data)
		if err != nil || parseErr != nil || uint64(len(data)) != capture.Bytes || digestBytes(data) != capture.SHA256 || len(parsed.Events) == 0 || parsed.Events[len(parsed.Events)-1].Code != capture.ExitCode {
			return refused()
		}
	}
	return original, *selected, input, joins, nil
}

func readPublicConfigurationCleanupEvidence(directory string, parent runRecord, result scenarioResult) error {
	refused := errPublicConfigurationEvidence
	if parent.Suite != "live" || !records.ValidRunID(parent.RecoveryRunID) || parent.RecoveryRunID == parent.RunID || parent.CleanupRecoveryBasis != nil || parent.BuildClosure == nil || parent.Limits == nil || parent.CoverageScope != "cleanup_recovery" ||
		parent.Correctness.Passed || parent.Correctness.EvidenceComplete || parent.FullCoverage || result.Sequence < 0 || result.Sequence >= len(parent.Schedule.Entries) || result.Entry != parent.Schedule.Entries[result.Sequence] ||
		!ordinaryPublicCleanupCase(result.Scenario) || result.Writer != nil || result.Rerun != nil || len(result.Children)+len(result.PostExit) != 0 || result.CorrectnessPassed || result.Outcome != "passed" ||
		result.CleanupWorker == nil || !result.CleanupWorker.Started || !result.CleanupWorker.Joined || result.CleanupWorker.Process != "passed" || result.CleanupWorker.Outcome != "passed" ||
		!cleanupPassed(result.Cleanup) || result.PublicConfigurationEvidence == nil || result.PublicConfigurationEvidence.Validate(result.Sequence) != nil {
		return refused
	}
	ref := result.PublicConfigurationEvidence
	body, _, err := readRetainedEvidenceBytes(directory, ref.Path, records.MaximumPublicConfigurationManifestBytes)
	var manifest publicCleanupEvidenceManifest
	identity, identityErr := publicCleanupCaseIdentity(parent)
	if err != nil || uint64(len(body)) != ref.Bytes || digestBytes(body) != ref.SHA256 || decodeCleanupRecord(body, &manifest) != nil || identityErr != nil ||
		manifest.Schema != 1 || manifest.Kind != "public-cleanup-only" || manifest.RunID != parent.RunID || manifest.OriginalRunID != parent.RecoveryRunID || manifest.Entry != result.Entry ||
		manifest.CaseSHA256 != identity || manifest.BuildSHA256 != publicCleanupBuildDigest(parent.BuildClosure) || !sameSource(manifest.Source, parent.Source) || len(manifest.Files) == 0 || len(manifest.Files) > records.MaximumPublicConfigurationCaptures+256 {
		return refused
	}
	base := filepath.Dir(ref.Path)
	files := map[string]records.PublicConfigurationEvidenceFile{}
	for _, file := range manifest.Files {
		if file.Kind != "cleanup-support" || file.Path == "" || filepath.ToSlash(filepath.Clean(file.Path)) != file.Path || filepath.IsAbs(file.Path) || strings.HasPrefix(file.Path, "../") || files[file.Path].Path != "" || !hexString(file.SHA256, 64) || file.Bytes == 0 {
			return refused
		}
		limit := uint64(records.MaximumJSONBytes)
		if strings.HasSuffix(file.Path, "/capture.jsonl") {
			limit = nativeprocess.MaxCaptureBytes
		} else if file.Path == "snapshot.json" {
			limit = records.MaximumPublicConfigurationSnapshotBytes
		}
		value, _, err := readRetainedEvidenceBytes(directory, filepath.ToSlash(filepath.Join(base, file.Path)), limit)
		if err != nil || uint64(len(value)) != file.Bytes || digestBytes(value) != file.SHA256 {
			return refused
		}
		files[file.Path] = file
	}
	root := filepath.Join(directory, base)
	original, selected, input, joins, err := readPublicCleanupOrigin(filepath.Join(root, "origin"), filepath.Join(root, "origin", "state"), filepath.Join(root, "origin", "input.json"), filepath.Join(root, "origin", "failure-sources.json"), manifest, parent.Provider)
	if err != nil || !reflect.DeepEqual(joins, manifest.OriginalWorkers) || !sameSource(original.Source, manifest.OriginalSource) {
		return refused
	}
	var currentInput workerInput
	currentInputBody, _, err := publicCleanupRecord(filepath.Join(root, "recovery", "input.json"))
	if err != nil || decodeCleanupRecord(currentInputBody, &currentInput) != nil || currentInput.Limits == nil || currentInput.RunID != input.RunID || currentInput.CleanupGrant != nil || currentInput.CleanupRetry != nil || currentInput.StockRecovery != nil {
		return refused
	}
	allowance := *parent.Limits
	for _, earlier := range parent.Scenarios {
		if earlier.Sequence >= result.Sequence {
			break
		}
		if debitBudget(&allowance, &records.BudgetReservation{}, earlier.Cleanup.BudgetReserved, 0, earlier.CleanupElapsed) != nil {
			return refused
		}
	}
	if *currentInput.Limits != allowance {
		return refused
	}
	expectedInput := input
	expectedInput.Limits = currentInput.Limits
	expectedInputBody, err := json.Marshal(expectedInput)
	if err != nil || !bytes.Equal(currentInputBody, append(expectedInputBody, '\n')) {
		return refused
	}
	name, err := recordedCaseDirectory(result.Entry)
	if err != nil {
		return refused
	}
	output := filepath.Join(directory, "private", name, "cleanup")
	inv := records.Invocation{RunID: parent.RunID, Scenario: result.Scenario, Input: filepath.Join(directory, "private", name, "input.json"), StateDir: manifest.OriginalState, OutputDir: output}
	currentJoin, err := publicCleanupJoinedWorker(filepath.Join(root, "recovery"), inv, *result.CleanupWorker, filepath.Join(root, "recovery", "failure-sources.json"))
	if err != nil || currentJoin != manifest.CleanupWorker || currentJoin.Actor != input.Participants["cleanup"] {
		return refused
	}
	mapBody, _, err := publicCleanupRecord(filepath.Join(root, "recovery", "failure-sources.json"))
	var sourceMap records.FailureSources
	if err != nil || digestBytes(mapBody) != parent.BuildClosure.FailureSourcesSHA256 || decodeCleanupRecord(mapBody, &sourceMap) != nil || sourceMap.BinarySHA256 != parent.BuildClosure.BinarySHA256 || sourceMap.OverlaySHA256 != parent.BuildClosure.OverlaySHA256 {
		return refused
	}
	var worker records.WorkerResult
	workerBody, _, err := publicCleanupRecord(filepath.Join(root, "recovery", "worker.json"))
	if err != nil || decodeCleanupRecord(workerBody, &worker) != nil || worker.Failure != nil || worker.HarnessFailure != nil || worker.Cleanup == nil || !reflect.DeepEqual(worker.Cleanup, &result.Cleanup) ||
		worker.BudgetReserved == nil || !reflect.DeepEqual(worker.BudgetReserved, result.Cleanup.BudgetReserved) || result.CleanupElapsed <= 0 || result.CleanupElapsed > time.Duration(allowance.CleanupSeconds)*time.Second ||
		debitBudget(&allowance, &records.BudgetReservation{}, result.Cleanup.BudgetReserved, 0, result.CleanupElapsed) != nil {
		return refused
	}
	expected := records.PublicConfigurationEvidenceBinding{RunID: original.RunID, Scenario: selected.Scenario, Provider: original.Provider, RecoveryMode: input.RecoveryMode, Prefix: input.Prefix}
	snapshotBody, _, err := publicCleanupRecordLimit(filepath.Join(root, "snapshot.json"), records.MaximumPublicConfigurationSnapshotBytes)
	snapshot, snapshotErr := records.ReadPublicConfigurationEvidenceSnapshotBytes(snapshotBody, expected)
	if err != nil || snapshotErr != nil || snapshot.Generator != nil || snapshot.Outputs != nil || verifyOriginalPublicConfigurationEvidenceAt(filepath.Join(root, "origin", "state"), manifest.OriginalState, snapshot) != nil {
		return refused
	}
	allowed := map[string]bool{}
	for _, capture := range snapshot.Captures {
		data, _, err := publicCleanupRecordLimit(filepath.Join(root, "origin", "state", filepath.FromSlash(capture.SourceRelative)), nativeprocess.MaxCaptureBytes)
		parsed, parseErr := nativeprocess.InspectCapture(data)
		if err != nil || parseErr != nil || digestBytes(data) != capture.SHA256 || uint64(len(data)) != capture.Bytes || len(parsed.Events) == 0 || parsed.Events[len(parsed.Events)-1].Code != capture.ExitCode {
			return refused
		}
		writes, terminals := map[uint64]nativeprocess.Event{}, map[uint64]nativeprocess.Event{}
		for _, event := range parsed.Events {
			if strings.HasPrefix(event.Kind, "generator-") {
				return refused
			}
			if event.Kind == "http-start" && event.Sent && (event.Operation == "store-write" || event.Operation == "head-write") {
				writes[event.Sequence] = event
				allowed[event.ObjectKeySHA256] = true
			}
			if event.Kind == "store-result" && event.Sent {
				terminals[event.Sequence] = event
			}
		}
		for sequence, write := range writes {
			terminal, present := terminals[sequence]
			if !present || terminal.Operation != write.Operation || terminal.ObjectKeySHA256 != write.ObjectKeySHA256 || contract.WriteStatus(terminal.WriteStatus) == contract.WriteUnknown {
				return refused
			}
		}
	}
	if snapshot.Controlled != nil {
		for _, intent := range snapshot.Controlled.Intents {
			allowed[fmt.Sprintf("%x", contract.Hash([]byte(intent.Key)))] = true
		}
	}
	for _, intent := range snapshot.Cleanup.Intents {
		if !allowed[fmt.Sprintf("%x", contract.Hash([]byte(intent.Key)))] {
			return refused
		}
	}
	required := map[string]bool{}
	for _, path := range []string{"origin/run.json", filepath.ToSlash(filepath.Join("origin", caseReceiptPath(selected.Sequence))), "origin/input.json", "origin/failure-sources.json", "origin/state/public-ownership.json", "snapshot.json", "origin/state/public-cleanup-inventory.json", "origin/state/public-cleanup-inventory.json.token-evidence.json", "recovery/input.json", "recovery/invocation.json", "recovery/worker.json", "recovery/failure-sources.json"} {
		required[path] = true
	}
	workers, routes, err := publicConfigurationWorkerRoutes(selected)
	if err != nil {
		return refused
	}
	for i, evidence := range append(workers, *result.CleanupWorker) {
		route := "recovery"
		if i < len(routes) {
			route = filepath.ToSlash(filepath.Join("origin", "state", routes[i]))
			input, err := publicCleanupOriginalInput(evidence.Role, routes[i])
			if err != nil {
				return refused
			}
			if input != "input.json" {
				required[filepath.ToSlash(filepath.Join("origin", "state", input))] = true
			}
		}
		for _, name := range []string{"invocation.json", "worker.json"} {
			required[route+"/"+name] = true
		}
		if evidence.Assertions == nil {
			return refused
		}
		if evidence.Assertions.Marker != "no_failure_marker" {
			required[route+"/failure.json"] = true
		}
		if evidence.Assertions.Checkpoint != "no_checkpoint" {
			required[route+"/checkpoint.json"] = true
		}
	}
	for _, capture := range snapshot.Captures {
		required["origin/state/"+capture.SourceRelative] = true
	}
	if snapshot.Controlled != nil {
		required["origin/state/public-controlled-inventory.json"], required["origin/state/public-controlled-inventory.json.token-evidence.json"] = true, true
	}
	if len(required) != len(files) {
		return refused
	}
	for path := range required {
		if files[path].Path == "" {
			return refused
		}
	}
	if len(manifest.SourceImages) == 0 || len(manifest.SourceImages) > 2 || manifest.SourceImages[0].Path != filepath.Join(manifest.OriginalState, "public-source", "configuration.json") {
		return refused
	}
	for _, image := range manifest.SourceImages {
		if !strings.HasPrefix(image.Path, filepath.Join(manifest.OriginalState, "public-source")+string(os.PathSeparator)) || filepath.Clean(image.Path) != image.Path || !hexString(image.SHA256, 64) || image.Bytes == 0 || image.Bytes > records.MaximumJSONBytes {
			return refused
		}
	}
	return nil
}
