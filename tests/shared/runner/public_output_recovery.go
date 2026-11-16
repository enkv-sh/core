package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

func publicOutputRecoveryCase(scenario string) bool {
	row, known := catalog.PublicConfiguration(scenario)
	return known && row.Output && scenario != records.StockPluginScenario
}

func (s *runState) preparePublicOutputRecovery(entry recoveryEntry, state string, allowance limits) (*records.PublicOutputRecoveryInput, error) {
	refused := errPublicConfigurationEvidence
	if !publicOutputRecoveryCase(entry.Input.Scenarios[0]) || entry.Input.OutputRecovery != nil || entry.Input.Generator != nil ||
		entry.Input.CleanupGrant != nil || entry.Input.StockRecovery != nil || s.record.RecoveryRunID != entry.Input.RunID {
		return nil, refused
	}
	if !publicOutputRecoveryStoreAbsent(entry.State) {
		return nil, refused
	}
	if _, err := os.Lstat(filepath.Join(entry.State, "public-output-recovery.json")); !os.IsNotExist(err) {
		return nil, refused
	}
	directory := filepath.Dir(filepath.Dir(entry.State))
	body, _, err := publicCleanupRecord(filepath.Join(directory, "run.json"))
	var original runRecord
	if err != nil || decodeCleanupRecord(body, &original) != nil || original.RunID != entry.Input.RunID || original.Provider != s.record.Provider ||
		original.RecoveryRunID != "" || original.FinishedAt == nil || !runProcessesJoined(original) || original.BuildClosure == nil ||
		original.BuildClosure.PublicConfiguration == nil || !validSource(original.Source) {
		return nil, refused
	}
	var selected *scenarioResult
	for i := range original.Scenarios {
		candidate := &original.Scenarios[i]
		name, err := recordedCaseDirectory(candidate.Entry)
		if err == nil && filepath.Join(directory, "private", name) == entry.State {
			if selected != nil || candidate.Scenario != entry.Input.Scenarios[0] {
				return nil, refused
			}
			selected = candidate
		}
	}
	if selected == nil || selected.Outcome == "passed" || !reflect.DeepEqual(entry.Input.PublicConfiguration.Artifact.closure(), original.BuildClosure.PublicConfiguration) ||
		!reflect.DeepEqual(safeRunContext(entry.Input.Settings), original.Context) {
		return nil, refused
	}
	var receipt *caseReceiptRef
	for i := range original.CaseReceipts {
		ref := &original.CaseReceipts[i]
		if ref.Sequence != selected.Sequence {
			continue
		}
		leaf, err := validateCaseReceipt(directory, original, *ref, selected.Entry)
		if receipt != nil || err != nil || !reflect.DeepEqual(leaf, *selected) {
			return nil, refused
		}
		receipt = ref
	}
	if receipt == nil {
		return nil, refused
	}
	limitBody, err := json.Marshal(allowance)
	if err != nil {
		return nil, refused
	}
	r := &records.PublicOutputRecoveryInput{Version: 1, OriginalRunID: original.RunID, RecoveryRunID: s.record.RunID,
		OriginalEntry: selected.Entry, OriginalState: entry.State, StateDir: state, Source: filepath.Join(entry.State, "public-source", "configuration.json"),
		Provider: original.Provider, RecoveryMode: entry.Input.RecoveryMode, Prefix: entry.Input.Prefix,
		OriginalRunSHA256: digestBytes(body), OriginalCaseSHA256: receipt.SHA256, OriginalBuildSHA256: publicCleanupBuildDigest(original.BuildClosure), LimitsSHA256: digestBytes(limitBody)}
	r.Region, r.Account, r.ProjectNumber, r.Outputs = entry.Input.Settings["region"], entry.Input.Settings["account"], entry.Input.Settings["project_number"], entry.Input.PublicConfiguration.Outputs
	r.CleanupObjectsRemaining, r.CleanupObjectBytesRemaining = entry.Input.Limits.Objects, entry.Input.Limits.ObjectBytes
	files := map[string]bool{}
	add := func(path string, limit uint64) error {
		if files[path] {
			return nil
		}
		data, info, err := publicCleanupRecordLimit(path, limit)
		if err != nil {
			return refused
		}
		files[path] = true
		r.Files = append(r.Files, records.PublicOutputRecoveryFile{Path: path, SHA256: digestBytes(data), Bytes: uint64(len(data)), Mode: uint32(info.Mode().Perm())})
		return nil
	}
	for _, path := range []string{filepath.Join(directory, "run.json"), filepath.Join(directory, receipt.Path), entry.InputPath, filepath.Join(entry.State, "public-ownership.json"), r.Source} {
		if add(path, records.MaximumJSONBytes) != nil {
			return nil, refused
		}
	}
	inputBody, _, err := publicCleanupRecord(entry.InputPath)
	if err != nil {
		return nil, refused
	}
	r.OriginalInputSHA256 = digestBytes(inputBody)
	sourceBody, _, err := publicCleanupRecord(r.Source)
	var source struct {
		Generated string `json:"generated"`
	}
	if err != nil || json.Unmarshal(sourceBody, &source) != nil || source.Generated == "" || filepath.IsAbs(source.Generated) || filepath.Clean(source.Generated) != source.Generated {
		return nil, refused
	}
	r.Generated, err = records.SafePath(filepath.Dir(r.Source), source.Generated)
	if err != nil || add(r.Generated, records.MaximumJSONBytes) != nil {
		return nil, refused
	}
	if _, err := os.Lstat(filepath.Join(entry.State, "after.json")); err == nil {
		if add(filepath.Join(entry.State, "after.json"), records.MaximumJSONBytes) != nil {
			return nil, refused
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, refused
	}
	var ownership records.PublicConfigurationOwnership
	ownerBody, _, err := publicCleanupRecord(filepath.Join(entry.State, "public-ownership.json"))
	if err != nil || decodeCleanupRecord(ownerBody, &ownership) != nil || ownership.Version != 1 || ownership.RunID != original.RunID ||
		ownership.Prefix != entry.Input.Prefix || ownership.Source != r.Source || !ownership.PreflightEmpty || ownership.ControlledInventory != "" ||
		len(ownership.Captures) == 0 || len(ownership.Captures) > records.MaximumPublicConfigurationCaptures {
		return nil, refused
	}
	r.Binding = ownership.Binding
	workers, routes, err := publicConfigurationWorkerRoutes(*selected)
	if err != nil {
		return nil, refused
	}
	parentStates := map[string]string{}
	joinWorker := func(parent runRecord, evidence workerEvidence, output, input, workerState string) error {
		// The retained build owns the original source map after scratch disposal.
		parentDirectory, pathErr := runPath(s.root, "live", "runs", parent.RunID)
		if pathErr != nil {
			return refused
		}
		mapPath := filepath.Join(parentDirectory, "private", "build", "failure-sources.json")
		join, err := publicCleanupJoinedWorker(output, records.Invocation{RunID: parent.RunID, Scenario: selected.Scenario, StateDir: workerState, OutputDir: output, Input: input}, evidence, mapPath)
		if err != nil {
			return refused
		}
		role := evidence.Role
		switch role {
		case "writer", "rerun":
			role = "authority"
		case "fresh_before", "fresh_after":
			role = "reader"
		}
		if join.Actor != entry.Input.Participants[role] {
			return refused
		}
		if evidence.Role == "cleanup" {
			body, _, err := publicCleanupRecord(filepath.Join(output, "worker.json"))
			var raw records.WorkerResult
			var budget struct {
				Reserved json.RawMessage `json:"budget_reserved"`
			}
			if err != nil || decodeCleanupRecord(body, &raw) != nil || json.Unmarshal(body, &budget) != nil || raw.Cleanup == nil ||
				raw.BudgetReserved == nil || raw.Cleanup.BudgetReserved == nil || !reflect.DeepEqual(raw.BudgetReserved, raw.Cleanup.BudgetReserved) {
				return refused
			}
			reserved, err := decodeReservation(budget.Reserved, false)
			if err != nil || !reflect.DeepEqual(reserved, raw.BudgetReserved) || reserved.GeneratorCreates != 0 || reserved.GeneratorRetires != 0 ||
				reserved.Objects > r.CleanupObjectsRemaining || reserved.ObjectBytes > r.CleanupObjectBytesRemaining {
				return refused
			}
			r.CleanupObjectsRemaining -= reserved.Objects
			r.CleanupObjectBytesRemaining -= reserved.ObjectBytes
			r.CleanupDebits = append(r.CleanupDebits, records.PublicOutputRecoveryDebit{RunID: parent.RunID, Worker: join.Worker, Nonce: join.Nonce, Reserved: *reserved})
		}
		for _, path := range []string{input, mapPath, filepath.Join(output, "invocation.json"), filepath.Join(output, "worker.json")} {
			if add(path, records.MaximumJSONBytes) != nil {
				return refused
			}
		}
		for _, name := range []string{"failure.json", "checkpoint.json"} {
			path := filepath.Join(output, name)
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				continue
			}
			if add(path, records.MaximumJSONBytes) != nil {
				return refused
			}
		}
		parentStates[join.Worker+"/"+join.Nonce+"/"+join.Role] = workerState
		r.Workers = append(r.Workers, records.PublicOutputRecoveryWorker{PublicConfigurationWorkerJoin: join, RunID: parent.RunID,
			StateDir: workerState, OutputDir: output, Input: input, SourceMap: mapPath})
		return nil
	}
	for i, worker := range workers {
		input, err := publicCleanupOriginalInput(worker.Role, routes[i])
		if err != nil || joinWorker(original, worker, filepath.Join(entry.State, routes[i]), filepath.Join(entry.State, input), entry.State) != nil {
			return nil, refused
		}
	}
	captures := append([]records.PublicConfigurationCaptureRegistration(nil), ownership.Captures...)
	_, runs, _, err := records.PrivateOwner(entry.State)
	if err != nil {
		return nil, refused
	}
	// Only cleanup runs that name this original run enter the exact intake.
	// Unrelated private state and evidence trees are never traversed.
	err = filepath.WalkDir(runs, func(path string, file fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return refused
		}
		relative, err := filepath.Rel(runs, path)
		if err != nil {
			return refused
		}
		depth := strings.Count(relative, string(filepath.Separator))
		if file.IsDir() {
			if file.Name() == "private" || file.Name() == "evidence" || depth > 1 {
				return filepath.SkipDir
			}
			return nil
		}
		if file.Name() != "run.json" {
			return nil
		}
		body, _, err := publicCleanupRecord(path)
		var relation struct {
			RunID    string `json:"run_id"`
			Original string `json:"recovery_run_id"`
		}
		if err != nil || json.Unmarshal(body, &relation) != nil || relation.Original != original.RunID || relation.RunID == s.record.RunID {
			return nil
		}
		var later runRecord
		if decodeCleanupRecord(body, &later) != nil || later.FinishedAt == nil || !runProcessesJoined(later) || later.Provider != original.Provider || later.BuildClosure == nil ||
			later.CleanupRecoveryBasis != nil || add(path, records.MaximumJSONBytes) != nil {
			return refused
		}
		for _, result := range later.Scenarios {
			if result.Scenario != selected.Scenario {
				continue
			}
			name, err := recordedCaseDirectory(result.Entry)
			if err != nil {
				return refused
			}
			caseState := filepath.Join(filepath.Dir(path), "private", name)
			var laterInput workerInput
			inputPath := filepath.Join(caseState, "input.json")
			data, _, err := publicCleanupRecord(inputPath)
			if err != nil || decodeCleanupRecord(data, &laterInput) != nil || laterInput.RunID != original.RunID {
				return refused
			}
			if laterInput.Prefix != entry.Input.Prefix {
				continue
			}
			workerState := entry.State
			var priorProof *records.PublicOutputRecoveryProof
			var priorOwner *records.PublicOutputRecoveryCaptureOwner
			if laterInput.OutputRecovery != nil {
				prior := laterInput.OutputRecovery
				if prior.Validate() != nil || prior.OriginalState != entry.State || prior.RecoveryRunID != later.RunID || prior.VerifyFiles() != nil {
					return refused
				}
				workerState = prior.StateDir
				if !publicOutputRecoveryStoreAbsent(workerState) {
					return refused
				}
				proofPath := filepath.Join(workerState, "public-output-recovery.json")
				var proof records.PublicOutputRecoveryProof
				proofBody, _, proofErr := publicCleanupRecord(proofPath)
				if proofErr != nil || decodeCleanupRecord(proofBody, &proof) != nil || !proof.BeforeStore(*prior) || add(proofPath, records.MaximumJSONBytes) != nil {
					return refused
				}
				priorBody, _ := json.Marshal(prior)
				var owner records.PublicOutputRecoveryCaptureOwner
				ownerPath := filepath.Join(workerState, "public-output-recovery-captures.json")
				data, _, err := publicCleanupRecord(ownerPath)
				if err != nil || decodeCleanupRecord(data, &owner) != nil || owner.Version != 1 || owner.RunID != later.RunID || owner.OriginalRunID != original.RunID || owner.InputSHA256 != digestBytes(priorBody) || add(ownerPath, records.MaximumJSONBytes) != nil {
					return refused
				}
				captures = append(captures, owner.Captures...)
				priorProof, priorOwner = &proof, &owner
			}
			if result.CleanupWorker == nil || joinWorker(later, *result.CleanupWorker, filepath.Join(caseState, "cleanup"), inputPath, workerState) != nil {
				return refused
			}
			if priorProof != nil {
				var prepared *records.PublicOutputRecoveryPreparedPair
				preparedPath := filepath.Join(workerState, "public-output-recovery-prepared-pair.json")
				if _, err := os.Lstat(preparedPath); err == nil {
					var image records.PublicOutputRecoveryPreparedPair
					data, _, err := publicCleanupRecord(preparedPath)
					if err != nil || decodeCleanupRecord(data, &image) != nil || add(preparedPath, records.MaximumJSONBytes) != nil {
						return refused
					}
					prepared = &image
				} else if !os.IsNotExist(err) {
					return refused
				}
				for _, capture := range priorOwner.Captures {
					for _, name := range []string{"command.json", "policy.json"} {
						if add(filepath.Join(filepath.Dir(capture.Path), name), records.MaximumJSONBytes) != nil {
							return refused
						}
					}
				}
				data, _, err := publicCleanupRecord(filepath.Join(caseState, "cleanup/worker.json"))
				var raw records.WorkerResult
				if err != nil || decodeCleanupRecord(data, &raw) != nil || raw.BudgetReserved == nil {
					return refused
				}
				readCommand := func(path string) ([]byte, error) { data, _, err := publicCleanupRecord(path); return data, err }
				if publicOutputRecoveryCommands(*laterInput.OutputRecovery, *priorProof, *priorOwner, entry.Input, *raw.BudgetReserved, prepared, readCommand) != nil {
					return refused
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, refused
	}
	parents := map[string]bool{}
	for _, join := range r.Workers {
		parents[join.Worker+"/"+join.Nonce+"/"+join.Role] = true
	}
	actors := map[string]bool{}
	for _, actor := range entry.Input.Participants {
		actors[actor] = true
	}
	for _, capture := range captures {
		parentState := parentStates[capture.ParentWorker+"/"+capture.ParentNonce+"/"+capture.ParentRole]
		relative, relativeErr := filepath.Rel(parentState, capture.Path)
		parsed, sum, err := nativeprocess.ReadCaptureWithDigest(capture.Path)
		if err != nil || !capture.Complete || fmt.Sprintf("%x", sum) != capture.SHA256 || len(parsed.Events) == 0 || parsed.Events[len(parsed.Events)-1].Code != capture.ExitCode ||
			!parents[capture.ParentWorker+"/"+capture.ParentNonce+"/"+capture.ParentRole] || relativeErr != nil || filepath.Dir(filepath.Dir(relative)) != "." ||
			filepath.Base(relative) != "capture.jsonl" || !strings.HasPrefix(filepath.Base(filepath.Dir(relative)), "public-command-") ||
			!actors[capture.Actor] || add(capture.Path, nativeprocess.MaxCaptureBytes) != nil {
			return nil, refused
		}
		for _, event := range parsed.Events {
			if strings.HasPrefix(event.Kind, "generator-") {
				return nil, refused
			}
		}
		r.Captures = append(r.Captures, capture)
	}
	slices.SortFunc(r.Files, func(a, b records.PublicOutputRecoveryFile) int { return strings.Compare(a.Path, b.Path) })
	if r.VerifyFiles() != nil || !r.MutationAllowance(entry.Input.Limits.Objects, entry.Input.Limits.ObjectBytes) {
		return nil, refused
	}
	return r, nil
}

func publicOutputRecoveryStoreAbsent(state string) bool {
	for _, name := range []string{"public-cleanup-inventory.json", "public-cleanup-inventory.json.token-evidence.json"} {
		if _, err := os.Lstat(filepath.Join(state, name)); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Validate the same closed command images for the current handoff and every
// retained predecessor. Reading a predecessor never grants another dispatch.
func publicOutputRecoveryCommands(input records.PublicOutputRecoveryInput, proof records.PublicOutputRecoveryProof, owner records.PublicOutputRecoveryCaptureOwner, original workerInput, budget records.BudgetReservation, prepared *records.PublicOutputRecoveryPreparedPair, read func(string) ([]byte, error)) error {
	refused := errPublicConfigurationEvidence
	requiresPair := false
	outcomes := map[string]string{}
	for _, stage := range proof.Stages {
		outcomes[stage.Name] = stage.Outcome
		requiresPair = requiresPair || stage.Name == "prepare-pair" && stage.Outcome == "complete"
	}
	if prepared != nil && (prepared.Version != 1 || prepared.InputSHA256 != proof.InputSHA256 || prepared.StageSHA256 != records.PublicOutputRecoveryStageBinding(proof.InputSHA256, "prepare-pair") || !strings.HasPrefix(prepared.CommandDirectory, "public-command-") || filepath.Base(prepared.CommandDirectory) != prepared.CommandDirectory || prepared.Pair.Validate(input) != nil) {
		return refused
	}
	prepareFound, lastStage := false, 0
	for ordinal, capture := range owner.Captures {
		relative, err := filepath.Rel(input.StateDir, capture.Path)
		if err != nil || filepath.Dir(filepath.Dir(relative)) != "." || filepath.Base(relative) != "capture.jsonl" || !strings.HasPrefix(filepath.Dir(relative), "public-command-") || !capture.Complete || capture.Ordinal != uint16(ordinal) || capture.NativeKind != "cli" {
			return refused
		}
		body, err := read(filepath.Join(filepath.Dir(capture.Path), "command.json"))
		var command records.PublicOutputRecoveryCommand
		if err != nil || decodeCleanupRecord(body, &command) != nil || command.Validate(input, proof) != nil || capture.Actor != original.Participants[command.Role] {
			return refused
		}
		policy, policyErr := read(filepath.Join(filepath.Dir(capture.Path), "policy.json"))
		var header struct {
			Version uint16 `json:"version"`
		}
		if policyErr != nil || json.Unmarshal(policy, &header) != nil || header.Version != 1 {
			return refused
		}
		stage := map[string]int{"prepare-pair": 1, "retire-bindings": 2, "remaining-deletions": 3}[command.Stage]
		if stage <= lastStage || command.Reservation.Requests > budget.Requests || command.Reservation.BodyBytes > budget.BodyBytes || command.Reservation.Objects > budget.Objects || command.Reservation.ObjectBytes > budget.ObjectBytes {
			return refused
		}
		lastStage = stage
		budget.Requests -= command.Reservation.Requests
		budget.BodyBytes -= command.Reservation.BodyBytes
		budget.Objects -= command.Reservation.Objects
		budget.ObjectBytes -= command.Reservation.ObjectBytes
		if command.Stage == "prepare-pair" {
			if prepareFound || command.Args[10] != original.Settings["bucket"] || command.Args[16] != original.Settings["key_id"] || prepared != nil && filepath.Dir(relative) != prepared.CommandDirectory {
				return refused
			}
			if prepared != nil {
				contracts, err := prepared.Pair.OutputContracts()
				if err != nil || prepared.ValidateResult(capture.ExitCode, proof.Domain, contracts) != nil {
					return refused
				}
			}
			prepareFound = true
		} else {
			requiresPair = true
			if capture.ExitCode != 0 && outcomes[command.Stage] == "complete" || !prepareFound || prepared == nil || command.Pair == nil || !command.Pair.OutputsRemovedFrom(prepared.Pair) {
				return refused
			}
		}
	}
	if requiresPair && (prepared == nil || !prepareFound) || prepared != nil && !prepareFound {
		return refused
	}
	return nil
}

type publicOutputRecoveryEvidenceManifest struct {
	Schema                             uint16
	Kind                               string
	RunID, OriginalRunID, OriginalRuns string
	Entry, OriginalEntry               catalog.Entry
	CaseSHA256, BuildSHA256            string
	Worker                             records.PublicConfigurationWorkerJoin
	Files                              []records.PublicConfigurationEvidenceFile
}

func outputRecoveryOriginPath(runs, path string) (string, error) {
	relative, err := filepath.Rel(runs, path)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errPublicConfigurationEvidence
	}
	return filepath.ToSlash(filepath.Join("origin", relative)), nil
}

func (s *runState) retainPublicOutputRecoveryEvidence(input records.PublicOutputRecoveryInput, inv records.Invocation, result *scenarioResult) error {
	refused := errPublicConfigurationEvidence
	if input.VerifyFiles() != nil || result.CleanupWorker == nil || !scenarioCleanupPassed(*result) || s.failureSources == nil {
		return refused
	}
	_, runs, _, err := records.PrivateOwner(input.OriginalState)
	identity, identityErr := publicCleanupCaseIdentity(s.record)
	join, joinErr := publicCleanupJoinedWorker(inv.OutputDir, inv, *result.CleanupWorker, s.failureSources.Path)
	if err != nil || identityErr != nil || joinErr != nil {
		return refused
	}
	manifest := publicOutputRecoveryEvidenceManifest{Schema: 1, Kind: "public-output-cleanup-current-proof", RunID: s.record.RunID,
		OriginalRunID: input.OriginalRunID, OriginalRuns: runs, Entry: result.Entry, OriginalEntry: input.OriginalEntry,
		CaseSHA256: identity, BuildSHA256: publicCleanupBuildDigest(s.record.BuildClosure), Worker: join}
	base := filepath.ToSlash(filepath.Join("evidence", "public-configuration", fmt.Sprintf("%04d", result.Sequence)))
	seen := map[string]bool{}
	add := func(path, relative, kind string, limit uint64) error {
		if seen[relative] {
			return refused
		}
		body, _, err := publicCleanupRecordLimit(path, limit)
		if err != nil || s.retainPublicConfigurationFile(base+"/"+relative, body) != nil {
			return refused
		}
		seen[relative] = true
		manifest.Files = append(manifest.Files, records.PublicConfigurationEvidenceFile{Kind: kind, Path: relative, SHA256: digestBytes(body), Bytes: uint64(len(body))})
		return nil
	}
	for _, pin := range input.Files {
		relative, err := outputRecoveryOriginPath(runs, pin.Path)
		if err != nil || add(pin.Path, relative, "original", pin.Bytes) != nil {
			return refused
		}
	}
	for _, file := range []struct{ path, relative string }{
		{inv.Input, "recovery/input.json"}, {s.failureSources.Path, "recovery/failure-sources.json"},
		{filepath.Join(inv.OutputDir, "invocation.json"), "recovery/invocation.json"}, {filepath.Join(inv.OutputDir, "worker.json"), "recovery/worker.json"},
		{filepath.Join(inv.StateDir, "public-output-recovery-input.json"), "recovery/output-recovery-input.json"},
		{filepath.Join(inv.StateDir, "public-output-recovery-captures.json"), "recovery/output-recovery-captures.json"},
		{filepath.Join(inv.StateDir, "public-output-recovery.json"), "recovery/output-recovery.json"},
		{filepath.Join(inv.StateDir, "public-output-recovery-prepared-pair.json"), "recovery/prepared-pair.json"},
		{filepath.Join(inv.StateDir, "public-cleanup-inventory.json"), "recovery/public-cleanup-inventory.json"},
		{filepath.Join(inv.StateDir, "public-cleanup-inventory.json.token-evidence.json"), "recovery/public-cleanup-inventory.json.token-evidence.json"},
	} {
		if add(file.path, file.relative, "recovery", records.MaximumJSONBytes) != nil {
			return refused
		}
	}
	for _, name := range []string{"failure.json", "checkpoint.json"} {
		path := filepath.Join(inv.OutputDir, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		if add(path, "recovery/"+name, "recovery", records.MaximumJSONBytes) != nil {
			return refused
		}
	}
	var captures records.PublicOutputRecoveryCaptureOwner
	if records.ReadJSON(filepath.Join(inv.StateDir, "public-output-recovery-captures.json"), &captures) != nil {
		return refused
	}
	for _, capture := range captures.Captures {
		relative, err := filepath.Rel(inv.StateDir, capture.Path)
		if err != nil || filepath.Dir(filepath.Dir(relative)) != "." || filepath.Base(relative) != "capture.jsonl" {
			return refused
		}
		for _, name := range []string{"capture.jsonl", "command.json", "policy.json"} {
			limit := uint64(records.MaximumJSONBytes)
			if name == "capture.jsonl" {
				limit = nativeprocess.MaxCaptureBytes
			}
			path := filepath.Join(filepath.Dir(capture.Path), name)
			if add(path, filepath.ToSlash(filepath.Join("recovery", "state", filepath.Dir(relative), name)), "recovery", limit) != nil {
				return refused
			}
		}
	}
	if input.VerifyFiles() != nil {
		return refused
	}
	body, err := json.Marshal(manifest)
	if err != nil || len(body)+1 > records.MaximumPublicConfigurationManifestBytes {
		return refused
	}
	body = append(body, '\n')
	path := base + "/manifest.json"
	if s.retainPublicConfigurationFile(path, body) != nil {
		return refused
	}
	result.PublicConfigurationEvidence = &records.PublicConfigurationEvidenceRef{SchemaVersion: records.PublicConfigurationEvidenceVersion,
		Path: path, SHA256: digestBytes(body), Bytes: uint64(len(body))}
	if readPublicOutputRecoveryEvidence(s.directory, s.record, *result) != nil {
		result.PublicConfigurationEvidence = nil
		return refused
	}
	return nil
}

func readPublicOutputRecoveryEvidence(directory string, parent runRecord, result scenarioResult) error {
	refused := errPublicConfigurationEvidence
	if parent.Suite != "live" || parent.CoverageScope != "cleanup_recovery" || !records.ValidRunID(parent.RecoveryRunID) || parent.RunID == parent.RecoveryRunID ||
		parent.CleanupRecoveryBasis != nil || parent.BuildClosure == nil || parent.Limits == nil || parent.Correctness.Passed || parent.FullCoverage ||
		!publicOutputRecoveryCase(result.Scenario) || result.Sequence < 0 || result.Sequence >= len(parent.Schedule.Entries) || result.Entry != parent.Schedule.Entries[result.Sequence] ||
		result.Writer != nil || result.Rerun != nil || len(result.Children)+len(result.PostExit) != 0 || result.CorrectnessPassed || result.Outcome != "passed" ||
		!scenarioCleanupPassed(result) || result.CleanupWorker == nil || result.PublicConfigurationEvidence == nil || result.PublicConfigurationEvidence.Validate(result.Sequence) != nil {
		return refused
	}
	ref := result.PublicConfigurationEvidence
	body, _, err := readRetainedEvidenceBytes(directory, ref.Path, records.MaximumPublicConfigurationManifestBytes)
	var manifest publicOutputRecoveryEvidenceManifest
	identity, identityErr := publicCleanupCaseIdentity(parent)
	if err != nil || uint64(len(body)) != ref.Bytes || digestBytes(body) != ref.SHA256 || decodeCleanupRecord(body, &manifest) != nil || identityErr != nil ||
		manifest.Schema != 1 || manifest.Kind != "public-output-cleanup-current-proof" || manifest.RunID != parent.RunID || manifest.OriginalRunID != parent.RecoveryRunID || manifest.Entry != result.Entry ||
		manifest.CaseSHA256 != identity || manifest.BuildSHA256 != publicCleanupBuildDigest(parent.BuildClosure) || len(manifest.Files) == 0 || len(manifest.Files) > 768 ||
		!filepath.IsAbs(manifest.OriginalRuns) || filepath.Clean(manifest.OriginalRuns) != manifest.OriginalRuns {
		return refused
	}
	base := filepath.Dir(ref.Path)
	files := map[string]records.PublicConfigurationEvidenceFile{}
	read := func(relative string) ([]byte, error) {
		file, found := files[relative]
		if !found {
			return nil, refused
		}
		body, _, err := readRetainedEvidenceBytes(directory, filepath.ToSlash(filepath.Join(base, relative)), file.Bytes)
		if err != nil || uint64(len(body)) != file.Bytes || digestBytes(body) != file.SHA256 {
			return nil, refused
		}
		return body, nil
	}
	for _, file := range manifest.Files {
		if file.Kind != "original" && file.Kind != "recovery" || file.Path == "" || filepath.ToSlash(filepath.Clean(file.Path)) != file.Path || filepath.IsAbs(file.Path) ||
			strings.HasPrefix(file.Path, "../") || files[file.Path].Path != "" || file.Bytes == 0 || file.Bytes > records.MaximumJSONBytes || !hexString(file.SHA256, 64) {
			return refused
		}
		files[file.Path] = file
		if _, err := read(file.Path); err != nil {
			return refused
		}
	}
	var input records.PublicOutputRecoveryInput
	body, err = read("recovery/output-recovery-input.json")
	if err != nil || decodeCleanupRecord(body, &input) != nil || input.Validate() != nil || input.OriginalRunID != parent.RecoveryRunID || input.RecoveryRunID != parent.RunID ||
		input.OriginalEntry != manifest.OriginalEntry || input.Provider != parent.Provider || input.OriginalEntry.Scenario != result.Scenario {
		return refused
	}
	required := map[string]bool{}
	for _, pin := range input.Files {
		relative, err := outputRecoveryOriginPath(manifest.OriginalRuns, pin.Path)
		if err != nil || files[relative].SHA256 != pin.SHA256 || files[relative].Bytes != pin.Bytes {
			return refused
		}
		required[relative] = true
	}
	originRead := func(path string) ([]byte, error) {
		relative, err := outputRecoveryOriginPath(manifest.OriginalRuns, path)
		if err != nil {
			return nil, refused
		}
		return read(relative)
	}
	var original workerInput
	body, err = originRead(filepath.Join(input.OriginalState, "input.json"))
	if err != nil || digestBytes(body) != input.OriginalInputSHA256 || decodeCleanupRecord(body, &original) != nil || !publicCleanupInputValid(original, parent.Provider) ||
		original.OutputRecovery != nil || !input.MutationAllowance(original.Limits.Objects, original.Limits.ObjectBytes) {
		return refused
	}
	var current workerInput
	body, err = read("recovery/input.json")
	if err != nil || decodeCleanupRecord(body, &current) != nil || current.Limits == nil || !reflect.DeepEqual(current.OutputRecovery, &input) {
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
	limitBody, limitErr := json.Marshal(allowance)
	if limitErr != nil || digestBytes(limitBody) != input.LimitsSHA256 {
		return refused
	}
	expected := original
	expected.Limits, expected.OutputRecovery = current.Limits, &input
	if *current.Limits != allowance || !reflect.DeepEqual(current, expected) {
		return refused
	}
	name, err := recordedCaseDirectory(result.Entry)
	if err != nil {
		return refused
	}
	inv := records.Invocation{RunID: parent.RunID, Scenario: result.Scenario, StateDir: filepath.Join(directory, "private", name, "state"),
		OutputDir: filepath.Join(directory, "private", name, "cleanup"), Input: filepath.Join(directory, "private", name, "input.json")}
	if input.StateDir != inv.StateDir {
		return refused
	}
	root := filepath.Join(directory, base)
	join, err := publicCleanupJoinedWorker(filepath.Join(root, "recovery"), inv, *result.CleanupWorker, filepath.Join(root, "recovery", "failure-sources.json"))
	if err != nil || join != manifest.Worker || join.Actor != original.Participants["cleanup"] {
		return refused
	}
	var proof records.PublicOutputRecoveryProof
	body, err = read("recovery/output-recovery.json")
	if err != nil || decodeCleanupRecord(body, &proof) != nil || proof.Validate(input) != nil {
		return refused
	}
	var prepared records.PublicOutputRecoveryPreparedPair
	body, err = read("recovery/prepared-pair.json")
	if err != nil || decodeCleanupRecord(body, &prepared) != nil {
		return refused
	}
	allowed, originErr := verifyPublicOutputRecoveryOrigin(input, manifest.OriginalRuns, root, originRead)
	if originErr != nil || verifyOriginalPublicConfigurationInventory(filepath.Join(root, "recovery", "public-cleanup-inventory.json"), files["recovery/public-cleanup-inventory.json"].SHA256, *proof.Store) != nil {
		return refused
	}
	var raw records.WorkerResult
	body, err = read("recovery/worker.json")
	if err != nil || decodeCleanupRecord(body, &raw) != nil || raw.BudgetReserved == nil || raw.Cleanup == nil || raw.Cleanup.BudgetReserved == nil ||
		!reflect.DeepEqual(raw.BudgetReserved, raw.Cleanup.BudgetReserved) || raw.BudgetReserved.Objects > input.CleanupObjectsRemaining ||
		raw.BudgetReserved.ObjectBytes > input.CleanupObjectBytesRemaining || raw.BudgetReserved.GeneratorCreates != 0 || raw.BudgetReserved.GeneratorRetires != 0 {
		return refused
	}
	normalized := *raw.Cleanup
	normalizedBudget := *raw.Cleanup.BudgetReserved
	normalizedBudget.Objects, normalizedBudget.ObjectBytes = 0, 0
	normalized.BudgetReserved = &normalizedBudget
	if !reflect.DeepEqual(normalized, result.Cleanup) || result.CleanupElapsed <= 0 ||
		debitBudget(&allowance, &records.BudgetReservation{}, result.Cleanup.BudgetReserved, 0, result.CleanupElapsed) != nil {
		return refused
	}
	var owner records.PublicOutputRecoveryCaptureOwner
	body, err = read("recovery/output-recovery-captures.json")
	if err != nil || decodeCleanupRecord(body, &owner) != nil || owner.Version != 1 || owner.RunID != parent.RunID || owner.OriginalRunID != parent.RecoveryRunID || owner.InputSHA256 != proof.InputSHA256 || len(owner.Captures) == 0 {
		return refused
	}
	readCommand := func(path string) ([]byte, error) {
		relative, err := filepath.Rel(input.StateDir, path)
		if err != nil {
			return nil, refused
		}
		return read(filepath.ToSlash(filepath.Join("recovery/state", relative)))
	}
	if publicOutputRecoveryCommands(input, proof, owner, original, *raw.BudgetReserved, &prepared, readCommand) != nil {
		return refused
	}
	for ordinal, capture := range owner.Captures {
		relative, err := filepath.Rel(input.StateDir, capture.Path)
		if err != nil || filepath.Dir(filepath.Dir(relative)) != "." || filepath.Base(relative) != "capture.jsonl" || !strings.HasPrefix(filepath.Base(filepath.Dir(relative)), "public-command-") ||
			!capture.Complete || capture.Ordinal != uint16(ordinal) || capture.ParentWorker != join.Worker || capture.ParentNonce != join.Nonce || capture.ParentRole != "cleanup" {
			return refused
		}
		for _, name := range []string{"capture.jsonl", "command.json", "policy.json"} {
			rel := filepath.ToSlash(filepath.Join("recovery", "state", filepath.Dir(relative), name))
			required[rel] = true
			data, err := read(rel)
			if err != nil {
				return refused
			}
			if name == "capture.jsonl" {
				parsed, err := nativeprocess.InspectCapture(data)
				if err != nil || digestBytes(data) != capture.SHA256 || uint64(len(data)) != capture.Bytes || len(parsed.Events) == 0 || parsed.Events[len(parsed.Events)-1].Code != capture.ExitCode {
					return refused
				}
				if recordPublicOutputRecoveryStoreKeys(parsed, allowed) != nil {
					return refused
				}
			}
		}
	}
	for _, intent := range proof.Store.Intents {
		if !allowed[fmt.Sprintf("%x", contract.Hash([]byte(intent.Key)))] {
			return refused
		}
	}
	for _, name := range []string{"input.json", "failure-sources.json", "invocation.json", "worker.json", "output-recovery-input.json", "output-recovery-captures.json", "output-recovery.json", "prepared-pair.json", "public-cleanup-inventory.json", "public-cleanup-inventory.json.token-evidence.json"} {
		required["recovery/"+name] = true
	}
	for _, name := range []string{"failure.json", "checkpoint.json"} {
		path := "recovery/" + name
		if files[path].Path != "" {
			required[path] = true
		}
	}
	if len(required) != len(files) {
		return refused
	}
	for path := range required {
		if files[path].Path == "" {
			return refused
		}
	}
	return nil
}

func recordPublicOutputRecoveryStoreKeys(capture nativeprocess.Capture, allowed map[string]bool) error {
	writes := map[uint64]nativeprocess.Event{}
	terminals := map[uint64]nativeprocess.Event{}
	for _, event := range capture.Events {
		if strings.HasPrefix(event.Kind, "generator-") {
			return errPublicConfigurationEvidence
		}
		if event.Kind == "http-start" && event.Sent && (event.Operation == "head-write" || event.Operation == "store-write") {
			writes[event.Sequence] = event
			allowed[event.ObjectKeySHA256] = true
		}
		if event.Kind == "store-result" && event.Sent {
			terminals[event.Sequence] = event
		}
	}
	for sequence, write := range writes {
		terminal, found := terminals[sequence]
		if !found || terminal.ObjectKeySHA256 != write.ObjectKeySHA256 || terminal.Operation != write.Operation || contract.WriteStatus(terminal.WriteStatus) == contract.WriteUnknown {
			return errPublicConfigurationEvidence
		}
	}
	return nil
}

func verifyPublicOutputRecoveryOrigin(input records.PublicOutputRecoveryInput, runs, root string, read func(string) ([]byte, error)) (map[string]bool, error) {
	refused := errPublicConfigurationEvidence
	for _, worker := range input.Workers {
		for _, pin := range input.Files {
			if pin.Path == filepath.Join(worker.StateDir, "public-cleanup-inventory.json") || pin.Path == filepath.Join(worker.StateDir, "public-cleanup-inventory.json.token-evidence.json") || worker.StateDir == input.OriginalState && pin.Path == filepath.Join(input.OriginalState, "public-output-recovery.json") {
				return nil, refused
			}
		}
	}
	directory := filepath.Dir(filepath.Dir(input.OriginalState))
	body, err := read(filepath.Join(directory, "run.json"))
	var original runRecord
	if err != nil || digestBytes(body) != input.OriginalRunSHA256 || decodeCleanupRecord(body, &original) != nil || original.RunID != input.OriginalRunID ||
		original.Provider != input.Provider || original.RecoveryRunID != "" || original.FinishedAt == nil || !runProcessesJoined(original) ||
		publicCleanupBuildDigest(original.BuildClosure) != input.OriginalBuildSHA256 {
		return nil, refused
	}
	var selected *scenarioResult
	for i := range original.Scenarios {
		if original.Scenarios[i].Entry == input.OriginalEntry {
			if selected != nil {
				return nil, refused
			}
			selected = &original.Scenarios[i]
		}
	}
	if selected == nil || selected.Outcome == "passed" {
		return nil, refused
	}
	caseBody, err := read(filepath.Join(directory, caseReceiptPath(selected.Sequence)))
	var receipt caseReceipt
	identity, identityErr := caseIdentitySHA256(original)
	if err != nil || digestBytes(caseBody) != input.OriginalCaseSHA256 || decodeCleanupRecord(caseBody, &receipt) != nil || identityErr != nil ||
		receipt.RunID != original.RunID || receipt.IdentitySHA256 != identity || receipt.Entry != selected.Entry || !reflect.DeepEqual(receipt.Result, *selected) {
		return nil, refused
	}
	var ledger records.PublicConfigurationOwnership
	body, err = read(filepath.Join(input.OriginalState, "public-ownership.json"))
	if err != nil || decodeCleanupRecord(body, &ledger) != nil || !ledger.PreflightEmpty || ledger.RunID != input.OriginalRunID || ledger.Prefix != input.Prefix ||
		ledger.Binding != input.Binding || ledger.Source != input.Source || ledger.ControlledInventory != "" {
		return nil, refused
	}
	var originalInput workerInput
	data, inputErr := read(filepath.Join(input.OriginalState, "input.json"))
	if inputErr != nil || decodeCleanupRecord(data, &originalInput) != nil {
		return nil, refused
	}
	captures := slices.Clone(ledger.Captures)
	parents := map[string]runRecord{original.RunID: original}
	for _, pin := range input.Files {
		if filepath.Base(pin.Path) != "run.json" || pin.Path == filepath.Join(directory, "run.json") {
			continue
		}
		data, err := read(pin.Path)
		var parent runRecord
		if err != nil || decodeCleanupRecord(data, &parent) != nil || parent.RecoveryRunID != original.RunID || parent.FinishedAt == nil || !runProcessesJoined(parent) ||
			parent.CoverageScope != "cleanup_recovery" || parents[parent.RunID].RunID != "" {
			return nil, refused
		}
		parents[parent.RunID] = parent
	}
	expected := map[string]workerEvidence{}
	workers, routes, err := publicConfigurationWorkerRoutes(*selected)
	if err != nil {
		return nil, refused
	}
	for i, worker := range workers {
		expected[filepath.Join(input.OriginalState, routes[i])] = worker
	}
	for runID, parent := range parents {
		if runID == original.RunID {
			continue
		}
		var parentDirectory string
		for _, pin := range input.Files {
			if filepath.Base(pin.Path) != "run.json" {
				continue
			}
			data, err := read(pin.Path)
			var value struct {
				RunID string `json:"run_id"`
			}
			if err == nil && json.Unmarshal(data, &value) == nil && value.RunID == runID {
				parentDirectory = filepath.Dir(pin.Path)
			}
		}
		if parentDirectory == "" {
			return nil, refused
		}
		for _, result := range parent.Scenarios {
			if result.Scenario != input.OriginalEntry.Scenario {
				continue
			}
			name, err := recordedCaseDirectory(result.Entry)
			if err != nil {
				return nil, refused
			}
			state := filepath.Join(parentDirectory, "private", name)
			var saved workerInput
			data, err := read(filepath.Join(state, "input.json"))
			if err != nil || decodeCleanupRecord(data, &saved) != nil {
				return nil, refused
			}
			if saved.Prefix != input.Prefix {
				continue
			}
			if result.Writer != nil || result.Rerun != nil || len(result.Children)+len(result.PostExit) != 0 || result.CleanupWorker == nil {
				return nil, refused
			}
			expected[filepath.Join(state, "cleanup")] = *result.CleanupWorker
			if saved.OutputRecovery != nil {
				prior := saved.OutputRecovery
				if prior.Validate() != nil || prior.OriginalState != input.OriginalState || prior.OriginalRunID != original.RunID || prior.RecoveryRunID != runID || prior.Prefix != input.Prefix || prior.Provider != input.Provider {
					return nil, refused
				}
				pins := map[string]records.PublicOutputRecoveryFile{}
				for _, pin := range input.Files {
					pins[pin.Path] = pin
				}
				for _, pin := range prior.Files {
					if pins[pin.Path] != pin {
						return nil, refused
					}
				}
				var proof records.PublicOutputRecoveryProof
				proofBody, proofErr := read(filepath.Join(saved.OutputRecovery.StateDir, "public-output-recovery.json"))
				if proofErr != nil || decodeCleanupRecord(proofBody, &proof) != nil || !proof.BeforeStore(*saved.OutputRecovery) {
					return nil, refused
				}
				priorBody, _ := json.Marshal(saved.OutputRecovery)
				var owner records.PublicOutputRecoveryCaptureOwner
				data, err := read(filepath.Join(saved.OutputRecovery.StateDir, "public-output-recovery-captures.json"))
				if err != nil || decodeCleanupRecord(data, &owner) != nil || owner.Version != 1 || owner.RunID != runID || owner.OriginalRunID != original.RunID || owner.InputSHA256 != digestBytes(priorBody) {
					return nil, refused
				}
				var prepared *records.PublicOutputRecoveryPreparedPair
				preparedPath := filepath.Join(saved.OutputRecovery.StateDir, "public-output-recovery-prepared-pair.json")
				for _, pin := range input.Files {
					if pin.Path == preparedPath {
						var image records.PublicOutputRecoveryPreparedPair
						data, err := read(preparedPath)
						if err != nil || decodeCleanupRecord(data, &image) != nil {
							return nil, refused
						}
						prepared = &image
					}
				}
				data, err = read(filepath.Join(state, "cleanup/worker.json"))
				var raw records.WorkerResult
				if err != nil || decodeCleanupRecord(data, &raw) != nil || raw.BudgetReserved == nil || publicOutputRecoveryCommands(*saved.OutputRecovery, proof, owner, originalInput, *raw.BudgetReserved, prepared, read) != nil {
					return nil, refused
				}
				captures = append(captures, owner.Captures...)
			}
		}
	}
	captureSet := map[string]records.PublicConfigurationCaptureRegistration{}
	for _, capture := range captures {
		if _, duplicate := captureSet[capture.Path]; duplicate {
			return nil, refused
		}
		captureSet[capture.Path] = capture
	}
	if len(expected) != len(input.Workers) || len(captureSet) != len(input.Captures) {
		return nil, refused
	}
	for _, capture := range input.Captures {
		if captureSet[capture.Path] != capture {
			return nil, refused
		}
	}
	for _, worker := range input.Workers {
		evidence, found := expected[worker.OutputDir]
		parent, parentFound := parents[worker.RunID]
		physical, err := outputRecoveryOriginPath(runs, worker.OutputDir)
		physicalMap, mapErr := outputRecoveryOriginPath(runs, worker.SourceMap)
		if !found || !parentFound || parent.BuildClosure == nil || err != nil || mapErr != nil {
			return nil, refused
		}
		join, err := publicCleanupJoinedWorker(filepath.Join(root, physical), records.Invocation{RunID: worker.RunID, Scenario: input.OriginalEntry.Scenario,
			StateDir: worker.StateDir, OutputDir: worker.OutputDir, Input: worker.Input}, evidence, filepath.Join(root, physicalMap))
		if err != nil || join != worker.PublicConfigurationWorkerJoin {
			return nil, refused
		}
		mapBody, err := read(worker.SourceMap)
		if err != nil || digestBytes(mapBody) != parent.BuildClosure.FailureSourcesSHA256 {
			return nil, refused
		}
		if worker.Role == "cleanup" {
			data, err := read(filepath.Join(worker.OutputDir, "worker.json"))
			var raw records.WorkerResult
			if err != nil || decodeCleanupRecord(data, &raw) != nil || raw.BudgetReserved == nil || raw.Cleanup == nil || !reflect.DeepEqual(raw.BudgetReserved, raw.Cleanup.BudgetReserved) {
				return nil, refused
			}
			matched := false
			for _, debit := range input.CleanupDebits {
				matched = matched || debit.RunID == worker.RunID && debit.Worker == worker.Worker && debit.Nonce == worker.Nonce && reflect.DeepEqual(&debit.Reserved, raw.BudgetReserved)
			}
			if !matched {
				return nil, refused
			}
		}
	}
	allowed := map[string]bool{}
	for _, capture := range input.Captures {
		data, err := read(capture.Path)
		parsed, parseErr := nativeprocess.InspectCapture(data)
		if err != nil || parseErr != nil || digestBytes(data) != capture.SHA256 || uint64(len(data)) != capture.Bytes || len(parsed.Events) == 0 || parsed.Events[len(parsed.Events)-1].Code != capture.ExitCode ||
			recordPublicOutputRecoveryStoreKeys(parsed, allowed) != nil {
			return nil, refused
		}
	}
	return allowed, nil
}
