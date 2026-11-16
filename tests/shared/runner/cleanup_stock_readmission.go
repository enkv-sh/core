package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type stockRecoveryFailedPredecessor struct {
	Predecessor      *records.StockPluginRecoveryPredecessor
	Run              runRecord
	Input            workerInput
	OriginalInput    workerInput
	Invocation       records.Invocation
	Proof            records.StockPluginRecoveryEvidence
	FixtureRemaining limits
}

func readStockRecoveryFailedPredecessor(state string, admission records.StockPluginRecoveryInput, claim records.StockPluginFile) (stockRecoveryFailedPredecessor, error) {
	refused := errors.New("stock recovery predecessor evidence unavailable")
	_, runs, originalID, err := records.PrivateOwner(state)
	if err != nil || originalID != admission.OriginalRunID {
		return stockRecoveryFailedPredecessor{}, refused
	}
	directory, err := records.ResolveRun(runs, admission.RecoveryRunID)
	if errors.Is(err, os.ErrNotExist) {
		directory, err = records.SafePath(runs, admission.RecoveryRunID)
	}
	if err != nil {
		return stockRecoveryFailedPredecessor{}, refused
	}
	prior := &records.StockPluginRecoveryPredecessor{RunID: admission.RecoveryRunID, Claim: claim}
	var record runRecord
	prior.Run, _, err = stockRecoveryFile(filepath.Join(directory, "run.json"))
	if err != nil || records.ReadJSON(prior.Run.Path, &record) != nil || record.SchemaVersion != records.SchemaVersion || record.RunID != admission.RecoveryRunID ||
		record.Suite != "live" || record.RecoveryRunID != admission.OriginalRunID || record.Outcome != "failed" || record.FinishedAt == nil || record.FinishedAt.Before(record.StartedAt) ||
		!validSource(record.Source) || !runProcessesJoined(record) || len(record.Scenarios) != 1 || record.CleanupRecoveryBasis == nil || record.CleanupRecoveryBasis.Decision != "stock_failed_writer_recovery" ||
		record.CleanupRecoveryBasis.OriginalRunID != admission.OriginalRunID || record.CleanupRecoveryBasis.OriginalRunSHA256 != admission.OriginalRun.SHA256 ||
		record.CleanupRecoveryBasis.StockRecoveryClaimSHA256 != "" && record.CleanupRecoveryBasis.StockRecoveryClaimSHA256 != admission.ClaimSHA256() {
		return stockRecoveryFailedPredecessor{}, refused
	}
	result := record.Scenarios[0]
	worker := result.CleanupWorker
	name, err := recordedCaseDirectory(result.Entry)
	if err != nil || result.Scenario != records.StockPluginScenario || name != filepath.Base(state) || result.Outcome != "failed" ||
		worker == nil || worker.Role != "cleanup" || !worker.Started || !worker.Joined || worker.Outcome != "failed" || worker.Process != "process_failed" ||
		result.Writer != nil || result.Rerun != nil || len(result.Children) != 0 || len(result.PostExit) != 0 || len(result.Reconstruction) != 0 || len(result.CleanupAttempts) != 0 ||
		result.StockPluginRecovery != nil || result.StockPluginEvidence != nil || result.CorrectnessPassed {
		return stockRecoveryFailedPredecessor{}, refused
	}
	output := filepath.Join(directory, "private", name, "cleanup")
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return stockRecoveryFailedPredecessor{}, refused
	}
	prior.Invocation, _, err = stockRecoveryFile(filepath.Join(output, "invocation.json"))
	var inv records.Invocation
	invErr := records.ReadJSON(prior.Invocation.Path, &inv)
	if err != nil || invErr != nil || inv.ValidateEvidence() != nil || inv.RunID != admission.RecoveryRunID || inv.Scenario != records.StockPluginScenario || inv.Role != "cleanup" || inv.Worker != worker.Worker || inv.StateDir != state || inv.OutputDir != output || inv.Input != filepath.Join(directory, "private", name, "input.json") {
		return stockRecoveryFailedPredecessor{}, refused
	}
	priorAllowance, marshalErr := json.Marshal(record.Limits)
	if marshalErr != nil || digestBytes(priorAllowance) != admission.CleanupLimitsSHA256 {
		return stockRecoveryFailedPredecessor{}, refused
	}
	prior.Input, _, err = stockRecoveryFile(inv.Input)
	var input workerInput
	if err != nil || records.ReadJSON(inv.Input, &input) != nil || input.StockRecovery == nil || !reflect.DeepEqual(*input.StockRecovery, admission) || input.RunID != admission.OriginalRunID || input.CleanupGrant != nil || input.CleanupRetry != nil ||
		input.Limits == nil || record.Limits == nil || *input.Limits != *record.Limits || record.CleanupRecoveryBasis.OriginalCaseReceiptSHA256 == "" {
		return stockRecoveryFailedPredecessor{}, refused
	}
	prior.Failure, _, err = stockRecoveryFile(filepath.Join(output, "failure.json"))
	assertions := worker.Assertions
	var marker records.FailureMarker
	if err != nil || records.ReadJSON(prior.Failure.Path, &marker) != nil || marker.ValidateIdentity(inv) != nil || assertions == nil || assertions.Validate() != nil || assertions.Marker != "valid_failure_marker" || assertions.Checkpoint != "no_checkpoint" || assertions.MarkerWriteError || marker.Completed != assertions.Completed || marker.Phase != "cleanup" || len(worker.Phases) != 1 || marker.Sequence != worker.Phases[0].Sequence || worker.Phases[0].Name != marker.Phase || worker.Phases[0].Outcome != "incomplete" {
		return stockRecoveryFailedPredecessor{}, refused
	}
	var raw records.WorkerResult
	prior.Worker, _, err = stockRecoveryFile(filepath.Join(output, "worker.json"))
	if err != nil || records.ReadJSON(prior.Worker.Path, &raw) != nil || raw.SchemaVersion != records.SchemaVersion || raw.RunID != inv.RunID || raw.Worker != inv.Worker || raw.Role != "cleanup" || raw.Scenario != inv.Scenario || raw.Outcome != "failed" || len(raw.Children) != 0 || len(raw.FreshChecks) != 0 || !reflect.DeepEqual(raw.Phases, worker.Phases) || raw.Actor != worker.Actor {
		return stockRecoveryFailedPredecessor{}, refused
	}
	fixtureReserved, reservationErr := workerReservation(inv, true)
	if reservationErr != nil || fixtureReserved.GeneratorRetires != 0 || result.Cleanup.BudgetReserved == nil || raw.Cleanup == nil || raw.Cleanup.BudgetReserved == nil ||
		!reflect.DeepEqual(fixtureReserved, result.Cleanup.BudgetReserved) || !reflect.DeepEqual(fixtureReserved, raw.Cleanup.BudgetReserved) {
		return stockRecoveryFailedPredecessor{}, refused
	}
	fixtureRemaining := *record.Limits
	if debitBudget(&fixtureRemaining, &records.BudgetReservation{}, fixtureReserved, 0, result.CleanupElapsed) != nil {
		return stockRecoveryFailedPredecessor{}, refused
	}
	prior.Result, _, err = stockRecoveryFile(filepath.Join(output, "stock-recovery.json"))
	proof, proofErr := records.ReadStockPluginRecoveryEvidence(prior.Result.Path)
	var grant records.StockPluginGrant
	var originalInput workerInput
	originalBody, originalErr := readRecordBytes(admission.OriginalInput.Path)
	if err != nil || prior.Result.Length > records.MaximumStockPluginEvidenceBytes || proofErr != nil || records.ReadJSON(admission.OriginalGrant.Path, &grant) != nil ||
		originalErr != nil || decodeCleanupRecord(originalBody, &originalInput) != nil || originalInput.PublicConfiguration == nil || originalInput.PublicConfiguration.Stock == nil ||
		!reflect.DeepEqual(input.PublicConfiguration, originalInput.PublicConfiguration) || !reflect.DeepEqual(input.Participants, originalInput.Participants) || input.Prefix != originalInput.Prefix {
		return stockRecoveryFailedPredecessor{}, refused
	}

	// Historical source maps belonged to disposable native stages. The retained
	// invocation, exact marker identity and supervisor assertions own this proof.
	return stockRecoveryFailedPredecessor{Predecessor: prior, Run: record, Input: input, OriginalInput: originalInput, Invocation: inv, Proof: proof, FixtureRemaining: fixtureRemaining}, nil
}

func stockRecoveryFixtureFits(want, remaining limits) bool {
	return want.CleanupRequests <= remaining.CleanupRequests && want.CleanupBytes <= remaining.CleanupBytes && want.CleanupSeconds <= remaining.CleanupSeconds
}

func selectStockRecoveryPredecessor(state string, selected *records.StockPluginRecoveryInput, allowance limits) error {
	refused := errors.New("stock recovery predecessor unavailable or successor consumed")
	if _, err := os.Lstat(filepath.Join(state, records.StockPluginRecoveryPreAdmissionClaim)); !os.IsNotExist(err) {
		return refused
	}
	if _, err := os.Lstat(filepath.Join(state, "stock-recovery-successor-claim.json")); err == nil {
		return selectStockRecoveryPreAdmission(state, selected, allowance)
	} else if !os.IsNotExist(err) {
		return refused
	}
	return selectStockRecoveryNoDispatchPredecessor(state, selected, allowance)
}

func selectStockRecoveryNoDispatchPredecessor(state string, selected *records.StockPluginRecoveryInput, allowance limits) error {
	refused := errors.New("stock recovery predecessor unavailable or successor consumed")
	allowanceBody, err := json.Marshal(allowance)
	if err != nil || selected.PreAdmission != nil || selected.CleanupLimitsSHA256 != digestBytes(allowanceBody) {
		return refused
	}
	claimPath, err := records.SafePath(state, "stock-recovery-claim.json")
	if err != nil {
		return refused
	}
	if _, err := os.Lstat(claimPath); os.IsNotExist(err) {
		if selected.Predecessor != nil {
			return refused
		}
		return nil
	} else if err != nil {
		return refused
	}
	var first records.StockPluginRecoveryInput
	claim, _, err := stockRecoveryFile(claimPath)
	if err != nil || records.ReadJSON(claimPath, &first) != nil || first.Predecessor != nil || first.PreAdmission != nil || first.Validate(selected.OriginalRunID, first.RecoveryRunID) != nil || first.RecoveryRunID == selected.RecoveryRunID {
		return refused
	}
	baseline := *selected
	baseline.RecoveryRunID, baseline.Predecessor, baseline.ProductRemaining = first.RecoveryRunID, nil, first.ProductRemaining
	baseline.CleanupLimitsSHA256 = first.CleanupLimitsSHA256
	if !reflect.DeepEqual(baseline, first) {
		return refused
	}
	prior, err := readStockRecoveryFailedPredecessor(state, first, claim)
	var grant records.StockPluginGrant
	if err != nil || !stockRecoveryFixtureFits(allowance, prior.FixtureRemaining) || records.ReadJSON(first.OriginalGrant.Path, &grant) != nil ||
		prior.Proof.ValidateNoDispatch(first, grant, prior.OriginalInput.PublicConfiguration.Stock.Artifact.CLI.SHA256) != nil || prior.Predecessor.ValidateFiles() != nil {
		return refused
	}
	elapsed := max(prior.Proof.ProductElapsedSeconds, elapsedSeconds(prior.Run.Scenarios[0].CleanupElapsed))
	remaining, err := stockRecoveryOriginalRemaining(state, first, prior.OriginalInput)
	if err != nil || records.LiveLimits(remaining) != first.ProductRemaining || elapsed > uint64((1<<63-1)/int64(time.Second)) ||
		debitBudget(&remaining, prior.Proof.ProductReserved, &records.BudgetReservation{}, time.Duration(elapsed)*time.Second, 0) != nil {
		return refused
	}
	if selected.Predecessor != nil {
		if !reflect.DeepEqual(selected.Predecessor, prior.Predecessor) || selected.ProductRemaining != records.LiveLimits(remaining) {
			return refused
		}
	} else if selected.RecoveryRunID != "" && selected.ProductRemaining != records.LiveLimits(remaining) {
		return refused
	}
	selected.Predecessor, selected.ProductRemaining = prior.Predecessor, records.LiveLimits(remaining)
	return nil
}

func stockRecoveryJoinedPreAdmission(state, directory string, admission records.StockPluginRecoveryInput, claim records.StockPluginFile) (stockRecoveryFailedPredecessor, records.StockPluginFile, records.StockPluginFile, error) {
	refused := errors.New("stock recovery joined pre-admission proof unavailable")
	prior, err := readStockRecoveryFailedPredecessor(state, admission, claim)
	if err != nil {
		return stockRecoveryFailedPredecessor{}, records.StockPluginFile{}, records.StockPluginFile{}, refused
	}
	output := prior.Invocation.OutputDir
	if filepath.Dir(filepath.Dir(output)) != filepath.Join(directory, "private") {
		return stockRecoveryFailedPredecessor{}, records.StockPluginFile{}, records.StockPluginFile{}, refused
	}
	indexFile, _, err := stockRecoveryFile(filepath.Join(output, "stock-plugin-evidence.json"))
	index, indexErr := records.ReadStockPluginEvidence(indexFile.Path)
	diagnosticFile, body, diagnosticErr := stockRecoveryFile(filepath.Join(output, fmt.Sprintf("stock-result-%02d.json", admission.OriginalCommands)))
	original, originalErr := records.ReadStockPluginEvidence(admission.OriginalEvidence.Path)
	var grant records.StockPluginGrant
	if err != nil || indexErr != nil || diagnosticErr != nil || originalErr != nil || records.ReadJSON(admission.OriginalGrant.Path, &grant) != nil ||
		prior.Run.CleanupRecoveryBasis.StockRecoveryClaimSHA256 != admission.ClaimSHA256() || prior.Invocation.FailureSources == nil ||
		prior.Proof.ValidatePreAdmission(admission, grant, prior.OriginalInput.PublicConfiguration.Stock.Artifact, prior.Invocation, original, index, body) != nil ||
		prior.Proof.Commands[0].Actor != prior.Input.Participants["apply"] {
		return stockRecoveryFailedPredecessor{}, records.StockPluginFile{}, records.StockPluginFile{}, refused
	}
	if validateStockRecoveryPreAdmissionOutput(output, diagnosticFile.Path) != nil {
		return stockRecoveryFailedPredecessor{}, records.StockPluginFile{}, records.StockPluginFile{}, refused
	}
	return prior, indexFile, diagnosticFile, nil
}

func stockRecoveryJoinedPreAdmissionTerminal(state, directory string) error {
	claim, _, err := stockRecoveryFile(filepath.Join(state, "stock-recovery-successor-claim.json"))
	var admission records.StockPluginRecoveryInput
	if err != nil || records.ReadJSON(claim.Path, &admission) != nil {
		return errors.New("stock recovery joined pre-admission claim unavailable")
	}
	_, _, _, err = stockRecoveryJoinedPreAdmission(state, directory, admission, claim)
	return err
}

func validateStockRecoveryPreAdmissionOutput(output, diagnostic string) error {
	refused := errors.New("stock recovery predecessor has extra or unfinished work")
	for _, name := range []string{"stock-prefix-cleanup.json", "checkpoint.json"} {
		if _, err := os.Lstat(filepath.Join(output, name)); !os.IsNotExist(err) {
			return refused
		}
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) > 256 {
		return refused
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || len(entry.Name()) >= len("stock-result-") && entry.Name()[:len("stock-result-")] == "stock-result-" && filepath.Join(output, entry.Name()) != diagnostic {
			return refused
		}
		if len(entry.Name()) >= len("stock-command-") && entry.Name()[:len("stock-command-")] == "stock-command-" {
			if !entry.IsDir() {
				return refused
			}
			children, err := os.ReadDir(filepath.Join(output, entry.Name()))
			if err != nil || len(children) != 0 {
				return refused
			}
		}
	}
	return nil
}

func selectStockRecoveryPreAdmission(state string, selected *records.StockPluginRecoveryInput, allowance limits) error {
	refused := errors.New("stock recovery joined pre-admission unavailable or consumed")
	allowanceBody, err := json.Marshal(allowance)
	if err != nil || selected.CleanupLimitsSHA256 != digestBytes(allowanceBody) {
		return refused
	}
	var additional records.StockPluginRecoveryAdditionalAccounting
	if records.ReadStockPluginRecoveryAdditionalAccounting(filepath.Join(state, records.StockPluginRecoveryAdditionalAccountingName), &additional) != nil || !additional.ReviewedProducer() {
		return refused
	}
	var first, priorInput records.StockPluginRecoveryInput
	if records.ReadJSON(filepath.Join(state, "stock-recovery-claim.json"), &first) != nil || first.Predecessor != nil || first.PreAdmission != nil ||
		first.Validate(selected.OriginalRunID, first.RecoveryRunID) != nil {
		return refused
	}
	claim, _, err := stockRecoveryFile(filepath.Join(state, "stock-recovery-successor-claim.json"))
	if err != nil || records.ReadJSON(claim.Path, &priorInput) != nil || priorInput.Predecessor == nil || priorInput.PreAdmission != nil ||
		priorInput.Validate(first.OriginalRunID, priorInput.RecoveryRunID) != nil || priorInput.Predecessor.RunID != first.RecoveryRunID || priorInput.RecoveryRunID == selected.RecoveryRunID {
		return refused
	}
	baseline := *selected
	baseline.Predecessor, baseline.PreAdmission = nil, nil
	baseline.RecoveryRunID, baseline.ProductRemaining, baseline.CleanupLimitsSHA256 = first.RecoveryRunID, first.ProductRemaining, first.CleanupLimitsSHA256
	baseline.PriorCommands, baseline.PriorVerifications = first.PriorCommands, first.PriorVerifications
	if !reflect.DeepEqual(baseline, first) {
		return refused
	}
	_, runs, _, err := records.PrivateOwner(state)
	if err != nil {
		return refused
	}
	directory, err := records.ResolveRun(runs, priorInput.RecoveryRunID)
	if errors.Is(err, os.ErrNotExist) {
		directory, err = records.SafePath(runs, priorInput.RecoveryRunID)
	}
	if err != nil {
		return refused
	}
	prior, index, diagnostic, err := stockRecoveryJoinedPreAdmission(state, directory, priorInput, claim)
	if err != nil || !stockRecoveryFixtureFits(allowance, prior.FixtureRemaining) {
		return refused
	}
	checked := priorInput
	if selectStockRecoveryNoDispatchPredecessor(state, &checked, *prior.Run.Limits) != nil || !reflect.DeepEqual(checked, priorInput) {
		return refused
	}
	facts, err := stockRecoveryAdditionalDiagnostic(state, first)
	if err != nil || !facts.Accounting.ReviewedProducer() {
		return refused
	}
	remaining := limits(priorInput.ProductRemaining)
	elapsed := max(prior.Proof.ProductElapsedSeconds, elapsedSeconds(prior.Run.Scenarios[0].CleanupElapsed))
	if elapsed > uint64((1<<63-1)/int64(time.Second)) || debitBudget(&remaining, prior.Proof.ProductReserved, &records.BudgetReservation{}, time.Duration(elapsed)*time.Second, 0) != nil || records.LiveLimits(remaining) != facts.Before ||
		debitBudget(&remaining, &facts.Reservation, &records.BudgetReservation{}, facts.Elapsed, 0) != nil || records.LiveLimits(remaining) != facts.After ||
		facts.Fixture.CleanupRequests != prior.FixtureRemaining.CleanupRequests || facts.Fixture.CleanupBytes != prior.FixtureRemaining.CleanupBytes || facts.Fixture.CleanupSeconds != prior.FixtureRemaining.CleanupSeconds {
		return refused
	}
	commands, verifications := priorInput.PriorCommands+uint32(len(prior.Proof.Commands))+facts.Commands, priorInput.PriorVerifications+facts.Verifications
	if commands > records.MaximumStockPluginCommands-2 || verifications > records.MaximumStockPluginVerifications {
		return refused
	}
	p := &records.StockPluginRecoveryPreAdmission{Predecessor: *prior.Predecessor, CommandIndex: index, Diagnostic: diagnostic, Accounting: facts.File}
	files := append(prior.Predecessor.Files(), priorInput.Predecessor.Files()...)
	files = append(files, index, diagnostic, facts.File, first.OriginalRun, first.OriginalInput, first.OriginalEvidence, first.OriginalGrant, first.Accounting)
	files = append(files, first.Sources...)
	for _, pin := range facts.Files {
		files = append(files, pin.File)
	}
	var originalAccounting records.StockPluginRecoveryAccounting
	if records.ReadJSON(first.Accounting.Path, &originalAccounting) != nil {
		return refused
	}
	for _, d := range originalAccounting.Diagnostics {
		files = append(files, d.Scope, d.Result)
	}
	byPath := map[string]records.StockPluginFile{}
	for _, file := range files {
		if previous, ok := byPath[file.Path]; ok && previous != file {
			return refused
		}
		byPath[file.Path] = file
	}
	for _, file := range byPath {
		pin, _, err := records.ReadStockPluginRecoveryPin(file, file == facts.Accounting.Stderr)
		if err != nil {
			return refused
		}
		p.Files = append(p.Files, pin)
	}
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].File.Path < p.Files[j].File.Path })
	if selected.PreAdmission != nil && !reflect.DeepEqual(selected.PreAdmission, p) || selected.Predecessor != nil && !reflect.DeepEqual(selected.Predecessor, priorInput.Predecessor) {
		return refused
	}
	if selected.RecoveryRunID != "" && (selected.ProductRemaining != records.LiveLimits(remaining) || selected.PriorCommands != commands || selected.PriorVerifications != verifications) {
		return refused
	}
	selected.Predecessor, selected.PreAdmission, selected.ProductRemaining = priorInput.Predecessor, p, records.LiveLimits(remaining)
	selected.PriorCommands, selected.PriorVerifications = commands, verifications
	if p.VerifyFiles(*selected) != nil {
		return refused
	}
	return nil
}

func stockRecoveryOriginalRemaining(state string, first records.StockPluginRecoveryInput, input workerInput) (limits, error) {
	refused := errors.New("stock recovery original cumulative allowance unavailable")
	for _, want := range []records.StockPluginFile{first.OriginalRun, first.OriginalInput, first.OriginalEvidence, first.OriginalGrant, first.Accounting} {
		actual, _, err := stockRecoveryFile(want.Path)
		if err != nil || actual != want {
			return limits{}, refused
		}
	}
	if stockRecoverySources(state, first.Sources) != nil {
		return limits{}, refused
	}
	var original runRecord
	originalBody, err := readRecordBytes(first.OriginalRun.Path)
	if err != nil || decodeCleanupRecord(originalBody, &original) != nil || original.RunID != first.OriginalRunID || original.Limits == nil || len(original.Scenarios) != 1 || input.Limits == nil || *input.Limits != *original.Limits {
		return limits{}, refused
	}
	name, nameErr := recordedCaseDirectory(original.Scenarios[0].Entry)
	if nameErr != nil || name != filepath.Base(state) {
		return limits{}, refused
	}
	var accounting records.StockPluginRecoveryAccounting
	evidence, err := records.ReadStockPluginEvidence(first.OriginalEvidence.Path)
	if err != nil || records.ReadJSON(first.Accounting.Path, &accounting) != nil || accounting.Schema != 1 || !accounting.Complete || accounting.RunID != first.OriginalRunID ||
		accounting.OriginalRunSHA256 != first.OriginalRun.SHA256 || accounting.OriginalInputSHA256 != first.OriginalInput.SHA256 || accounting.OriginalEvidenceSHA256 != first.OriginalEvidence.SHA256 || accounting.OriginalGrantSHA256 != first.OriginalGrant.SHA256 ||
		!reflect.DeepEqual(accounting.Sources, first.Sources) || len(accounting.Diagnostics) > records.MaximumStockPluginCommands || uint32(len(evidence.Commands)) != first.OriginalCommands {
		return limits{}, refused
	}
	remaining, commands, originals, err := stockRecoveryHistory(original, evidence, accounting, state, *input.PublicConfiguration.Stock)
	if err != nil || commands != first.PriorCommands || evidence.ServiceVerifications != first.PriorVerifications || originals != nil && !reflect.DeepEqual(originals, first.Originals) {
		return limits{}, refused
	}
	return remaining, nil
}
