package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"time"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact/credentialroute"
)

func checkStockRecoveryCredential() error {
	refused := errors.New("stock recovery Cloudflare environment bearer unavailable")
	bearer := os.Getenv("CLOUDFLARE_API_TOKEN")
	if len(bearer) < 40 || len(bearer) > 80 {
		return refused
	}
	for i := range len(bearer) {
		b := bearer[i]
		if b != '_' && b != '-' && (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return refused
		}
	}
	return nil
}

func stockRecoveryFile(path string) (records.StockPluginFile, []byte, error) {
	body, err := readRecordBytes(path)
	if err != nil {
		return records.StockPluginFile{}, nil, err
	}
	return records.StockPluginFile{Path: path, SHA256: digestBytes(body), Length: uint64(len(body))}, body, nil
}

func stockRecoverySources(state string, sources []records.StockPluginFile) error {
	refused := errors.New("stock recovery original source changed")
	source := filepath.Join(state, "stock-source", "configuration.json")
	_, body, err := stockRecoveryFile(source)
	var document struct {
		Generated string `json:"generated"`
	}
	if err != nil || json.Unmarshal(body, &document) != nil || document.Generated == "" || filepath.IsAbs(document.Generated) || filepath.Clean(document.Generated) != document.Generated {
		return refused
	}
	generated, err := records.SafePath(filepath.Dir(source), document.Generated)
	if err != nil {
		return refused
	}
	want := []string{source, generated}
	sort.Strings(want)
	if len(sources) != len(want) {
		return refused
	}
	for i, path := range want {
		file, _, err := stockRecoveryFile(path)
		if err != nil || file != sources[i] {
			return refused
		}
	}
	return nil
}

func stockDiagnosticReservation(diagnostic records.StockPluginRecoveryDiagnostic, source []records.StockPluginFile, state string, cli records.StockPluginFile) (records.BudgetReservation, time.Duration, error) {
	refused := errors.New("stock recovery diagnostic accounting refused")
	scopeFile, scopeBody, err := stockRecoveryFile(diagnostic.Scope.Path)
	resultFile, resultBody, resultErr := stockRecoveryFile(diagnostic.Result.Path)
	if err != nil || resultErr != nil || scopeFile != diagnostic.Scope || resultFile != diagnostic.Result {
		return records.BudgetReservation{}, 0, refused
	}
	var scope map[string]json.RawMessage
	var result map[string]json.RawMessage
	allowNull := func(string) bool { return true }
	if checkedJSONKeys(json.NewDecoder(bytes.NewReader(scopeBody)), "", allowNull, nil) != nil ||
		checkedJSONKeys(json.NewDecoder(bytes.NewReader(resultBody)), "", allowNull, nil) != nil ||
		json.Unmarshal(scopeBody, &scope) != nil || json.Unmarshal(resultBody, &result) != nil {
		return records.BudgetReservation{}, 0, refused
	}
	for _, name := range []string{"started", "joined", "copied_source_unchanged", "original_source_unchanged", "original_registry_unchanged", "support_unchanged"} {
		if !bytes.Equal(result[name], []byte("true")) {
			return records.BudgetReservation{}, 0, refused
		}
	}
	for _, name := range []string{"timeout", "stdout_overflow", "stderr_overflow", "capture_error", "wait_error"} {
		if !bytes.Equal(result[name], []byte("false")) {
			return records.BudgetReservation{}, 0, refused
		}
	}
	if !bytes.Equal(result["exit_code"], []byte("0")) {
		return records.BudgetReservation{}, 0, refused
	}
	for _, name := range []string{"generator_creates", "generator_retires", "mutation_objects", "mutation_object_bytes"} {
		if !bytes.Equal(scope[name], []byte("0")) {
			return records.BudgetReservation{}, 0, refused
		}
	}
	if !bytes.Equal(scope["no_cloudflare_or_github_credentials"], []byte("true")) {
		return records.BudgetReservation{}, 0, refused
	}
	// Historical readers saved an explanation here, not a Boolean grant.
	// The description supplies no command, budget or mutation authority.
	var derivation *string
	if json.Unmarshal(scope["no_subprocess_derivation"], &derivation) != nil || derivation == nil || len(*derivation) == 0 || len(*derivation) > 2048 {
		return records.BudgetReservation{}, 0, refused
	}
	if !bytes.Equal(scope["child_commands"], []byte("1")) {
		return records.BudgetReservation{}, 0, refused
	}
	var requests, bodyBytes, seconds *uint64
	requestName, bodyName := "maximum_logical_requests", "maximum_body_bytes"
	_, maximumRequests := scope[requestName]
	_, maximumBody := scope[bodyName]
	_, plannedRequests := scope["planned_logical_request_reservation"]
	_, plannedBody := scope["planned_body_byte_reservation"]
	if maximumRequests != maximumBody || plannedRequests != plannedBody || maximumRequests == plannedRequests {
		return records.BudgetReservation{}, 0, refused
	}
	if plannedRequests {
		requestName, bodyName = "planned_logical_request_reservation", "planned_body_byte_reservation"
	}
	if json.Unmarshal(scope[requestName], &requests) != nil || requests == nil || *requests == 0 || *requests > maximumBudgetRequests ||
		json.Unmarshal(scope[bodyName], &bodyBytes) != nil || bodyBytes == nil || *bodyBytes == 0 || *bodyBytes > maximumBudgetBodyBytes ||
		json.Unmarshal(scope["timeout_seconds"], &seconds) != nil || seconds == nil || *seconds == 0 || *seconds > 120 {
		return records.BudgetReservation{}, 0, refused
	}
	var snapshot struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
			Length uint64 `json:"length"`
		} `json:"files"`
	}
	if json.Unmarshal(scope["original_source_before"], &snapshot) != nil || len(snapshot.Files) != len(source) {
		return records.BudgetReservation{}, 0, refused
	}
	for _, file := range source {
		relative, err := filepath.Rel(filepath.Join(state, "stock-source"), file.Path)
		fact, exists := snapshot.Files[filepath.ToSlash(relative)]
		if err != nil || !exists || fact.SHA256 != file.SHA256 || fact.Length != file.Length {
			return records.BudgetReservation{}, 0, refused
		}
	}
	var support struct {
		SHA256 string `json:"sha256"`
		Length uint64 `json:"length"`
	}
	if raw, direct := scope["support_cli_before"]; direct {
		if json.Unmarshal(raw, &support) != nil {
			return records.BudgetReservation{}, 0, refused
		}
	} else {
		var before struct {
			CLI json.RawMessage `json:"cli"`
		}
		if json.Unmarshal(scope["support_before"], &before) != nil || json.Unmarshal(before.CLI, &support) != nil {
			return records.BudgetReservation{}, 0, refused
		}
	}
	if support.SHA256 != cli.SHA256 || support.Length != cli.Length {
		return records.BudgetReservation{}, 0, refused
	}
	return records.BudgetReservation{Requests: *requests, BodyBytes: *bodyBytes}, time.Duration(*seconds) * time.Second, nil
}

func stockRecoveryOriginals(path string, stock records.StockPluginAcceptanceInput) ([]records.StockPluginRecoveryOriginal, bool, error) {
	refused := errors.New("stock recovery original work relations unavailable")
	_, body, err := stockRecoveryFile(path)
	var record struct {
		Product struct {
			Complete bool              `json:"complete"`
			Issues   []json.RawMessage `json:"issues"`
			Attempts struct {
				Count  int    `json:"count"`
				Status string `json:"status"`
				Rows   []struct {
					Facts  map[string]json.RawMessage `json:"facts"`
					Status string                     `json:"status"`
				} `json:"rows"`
			} `json:"attempts"`
			Hazards struct {
				Count  int    `json:"count"`
				Status string `json:"status"`
				Rows   []struct {
					Facts  map[string]json.RawMessage `json:"facts"`
					Status string                     `json:"status"`
					Target struct {
						Status string `json:"status"`
					} `json:"target"`
				} `json:"rows"`
			} `json:"hazards"`
		} `json:"product"`
	}
	if err != nil || json.Unmarshal(body, &record) != nil {
		return nil, false, refused
	}
	product := record.Product
	if !product.Complete {
		return nil, false, nil
	}
	if len(product.Issues) != 0 || product.Attempts.Status != "complete" || product.Attempts.Count != len(product.Attempts.Rows) ||
		product.Hazards.Status != "complete" || product.Hazards.Count != len(product.Hazards.Rows) || len(product.Hazards.Rows) == 0 || len(product.Hazards.Rows) > 128 || len(product.Attempts.Rows) != len(product.Hazards.Rows) {
		return nil, true, refused
	}
	known := func(fields map[string]json.RawMessage, name string, destination any) bool {
		var fact struct {
			Status string          `json:"status"`
			Value  json.RawMessage `json:"value"`
		}
		return json.Unmarshal(fields[name], &fact) == nil && fact.Status == "known" && json.Unmarshal(fact.Value, destination) == nil
	}
	facts, err := stock.Artifact.GeneratorA.Metadata.GeneratorFacts()
	if err != nil {
		return nil, true, refused
	}
	route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
	routeID, routeErr := credentialroute.Identity(route)
	if err != nil || routeErr != nil {
		return nil, true, refused
	}
	var originals []records.StockPluginRecoveryOriginal
	for _, row := range product.Hazards.Rows {
		var original records.StockPluginRecoveryOriginal
		var eligible uint64
		var qualified, fenced bool
		var exposure, config string
		if row.Status != "projected" || row.Target.Status != "null" ||
			!known(row.Facts, "original_operation_id", &original.OperationID) || !known(row.Facts, "original_attempt_id", &original.AttemptID) ||
			!known(row.Facts, "owner_id", &original.OwnerID) || !known(row.Facts, "hazard_id", &original.HazardID) ||
			!known(row.Facts, "resource_incarnation_id", &original.ResourceID) || !known(row.Facts, "descriptor_id", &original.DescriptorID) ||
			!known(row.Facts, "executor_id", &original.ExecutorID) || !known(row.Facts, "credential_route_id", &original.CredentialRoute) ||
			!known(row.Facts, "result_contract_id", &original.ResultContractID) || !known(row.Facts, "config_contract_id", &config) ||
			!known(row.Facts, "eligibility", &eligible) || eligible != 0 || !known(row.Facts, "cleanup_implementation_qualified", &qualified) || qualified ||
			!known(row.Facts, "fenced", &fenced) || !fenced || !known(row.Facts, "exposure", &exposure) || exposure != "possible-live" ||
			original.DescriptorID != facts.DescriptorID.String() || original.ExecutorID != facts.ExecutorID.String() || original.CredentialRoute != hex.EncodeToString(routeID[:]) || config != facts.Descriptor.Generator.ConfigContractID.String() {
			return nil, true, refused
		}
		matched := 0
		for _, attempt := range product.Attempts.Rows {
			var operation, id, resource, descriptor, executor, credential, contractID, hazard, state string
			if attempt.Status != "projected" || !known(attempt.Facts, "operation_id", &operation) || !known(attempt.Facts, "attempt_id", &id) ||
				!known(attempt.Facts, "planned_resource_incarnation_id", &resource) || !known(attempt.Facts, "descriptor_id", &descriptor) ||
				!known(attempt.Facts, "executor_id", &executor) || !known(attempt.Facts, "credential_route_id", &credential) ||
				!known(attempt.Facts, "result_contract_id", &contractID) || !known(attempt.Facts, "hazard_id", &hazard) || !known(attempt.Facts, "state", &state) {
				return nil, true, refused
			}
			if operation == original.OperationID && id == original.AttemptID && resource == original.ResourceID && descriptor == original.DescriptorID &&
				executor == original.ExecutorID && credential == original.CredentialRoute && contractID == original.ResultContractID && hazard == original.HazardID && state == "closed-with-residue" {
				matched++
			}
		}
		if matched != 1 {
			return nil, true, refused
		}
		originals = append(originals, original)
	}
	sort.Slice(originals, func(i, j int) bool { return originals[i].HazardID < originals[j].HazardID })
	return originals, true, nil
}

func prepareStockRecovery(root, directory string, original runRecord, ordinary recoveryPlan) (recoveryPlan, *cleanupRecoveryBasis, error) {
	if err := checkStockRecoveryCredential(); err != nil {
		return recoveryPlan{}, nil, err
	}
	refused := errors.New("failed stock recovery accounting or original support unavailable")
	if len(ordinary.Entries) != 1 || len(original.Scenarios) != 1 || len(original.CaseReceipts) != 1 || original.BuildClosure == nil ||
		original.BuildClosure.StockPlugins == nil || original.Resolved == nil || original.Failure == nil || original.Failure.Stage != "execution" || original.Outcome != "failed" ||
		original.RecoveryRunID != "" || original.Scenarios[0].Scenario != records.StockPluginScenario || original.Limits == nil ||
		validateCaseReceiptSet(directory, original) != nil {
		return recoveryPlan{}, nil, refused
	}
	if _, known := recordedRunRace(original); !known {
		return recoveryPlan{}, nil, refused
	}
	entry := ordinary.Entries[0]
	input := entry.Input
	if input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil || input.StockRecovery != nil || input.CleanupGrant != nil || input.CleanupRetry != nil ||
		input.RunID != original.RunID || input.Limits == nil || *input.Limits != *original.Limits ||
		ordinary.Limits.CleanupRequests > 8192 || ordinary.Limits.CleanupBytes > 16<<30 || ordinary.Limits.CleanupSeconds > 900 {
		return recoveryPlan{}, nil, refused
	}
	stock := input.PublicConfiguration.Stock
	closure, err := stockPluginClosureFromArtifact(filepath.Join(directory, "private", "build"), stock.Artifact)
	if err != nil || !reflect.DeepEqual(closure, original.BuildClosure.StockPlugins) || !sameSource(stock.Artifact.Source, original.Source) {
		return recoveryPlan{}, nil, refused
	}
	originalRun, _, err := stockRecoveryFile(filepath.Join(directory, "run.json"))
	originalInput, _, inputErr := stockRecoveryFile(entry.InputPath)
	originalEvidence, evidenceBody, evidenceErr := stockRecoveryFile(filepath.Join(entry.State, "stock-plugin-evidence.json"))
	originalGrant, grantBody, grantErr := stockRecoveryFile(filepath.Join(entry.State, "stock-plugin-grant.json"))
	accountingFile, accountingBody, accountingErr := stockRecoveryFile(filepath.Join(entry.State, "stock-recovery-accounting.json"))
	if err != nil || inputErr != nil || evidenceErr != nil || grantErr != nil || accountingErr != nil {
		return recoveryPlan{}, nil, refused
	}
	var accounting records.StockPluginRecoveryAccounting
	evidence, safeEvidenceErr := records.ReadStockPluginEvidence(originalEvidence.Path)
	var grant records.StockPluginGrant
	if decodeCleanupRecord(accountingBody, &accounting) != nil || accounting.Schema != 1 || accounting.RunID != original.RunID || !accounting.Complete ||
		accounting.OriginalRunSHA256 != originalRun.SHA256 || accounting.OriginalInputSHA256 != originalInput.SHA256 ||
		accounting.OriginalEvidenceSHA256 != originalEvidence.SHA256 || accounting.OriginalGrantSHA256 != originalGrant.SHA256 ||
		stockRecoverySources(entry.State, accounting.Sources) != nil || len(accounting.Diagnostics) > records.MaximumStockPluginCommands ||
		safeEvidenceErr != nil || len(evidenceBody) == 0 || decodeCleanupRecord(grantBody, &grant) != nil || grant.Validate() != nil ||
		evidence.RunID != original.RunID || evidence.Prefix != input.Prefix || evidence.Scenario != records.StockPluginScenario || evidence.FixtureID != stock.Fixture.FixtureID ||
		evidence.CLISHA256 != stock.Artifact.CLI.SHA256 || len(evidence.Commands) == 0 || len(evidence.Generations) != 0 || len(evidence.Creates) != 0 || len(evidence.Duties) != 0 || len(evidence.Outputs) != 0 || len(evidence.Assertions) != 0 ||
		grant.RunID != original.RunID || grant.Prefix != input.Prefix || !reflect.DeepEqual(grant.Fixture, stock.Fixture) {
		return recoveryPlan{}, nil, refused
	}
	for i, command := range evidence.Commands {
		if command.Ordinal != uint32(i) || !command.Started || !command.Joined || command.Worker != original.Scenarios[0].Writer.Worker ||
			command.Actor != input.Participants[command.Role] || !hexString(command.Nonce, 32) || !hexString(command.ResultSHA256, 64) {
			return recoveryPlan{}, nil, refused
		}
	}
	limitsBody, err := json.Marshal(original.Limits)
	if err == nil {
		wrapped, wrapErr := restoreCleanupLimits(append([]byte(`{"limits":`), append(limitsBody, '}')...), original.Limits, original.historicalLimits)
		if wrapErr != nil {
			return recoveryPlan{}, nil, refused
		}
		var envelope struct {
			Limits json.RawMessage `json:"limits"`
		}
		if json.Unmarshal(wrapped, &envelope) != nil {
			return recoveryPlan{}, nil, refused
		}
		limitsBody = envelope.Limits
	}
	if err != nil || grant.LimitsSHA256 != digestBytes(limitsBody) {
		return recoveryPlan{}, nil, refused
	}
	remaining, commands, originals, err := stockRecoveryHistory(original, evidence, accounting, entry.State, *stock)
	if err != nil {
		return recoveryPlan{}, nil, refused
	}
	cleanupBody, err := json.Marshal(ordinary.Limits)
	if err != nil || commands > records.MaximumStockPluginCommands-2 || len(originals) == 0 {
		return recoveryPlan{}, nil, refused
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if verifyStockPluginArtifact(ctx, stock.Artifact, ordinary.Provider) != nil {
		return recoveryPlan{}, nil, refused
	}
	ordinary.StockRecovery = &records.StockPluginRecoveryInput{Schema: 1, OriginalRunID: original.RunID,
		OriginalRun: originalRun, OriginalInput: originalInput, OriginalEvidence: originalEvidence, OriginalGrant: originalGrant,
		Accounting: accountingFile, Sources: accounting.Sources, Originals: originals, OriginalLimitsSHA256: grant.LimitsSHA256, CleanupLimitsSHA256: digestBytes(cleanupBody),
		ProductRemaining: records.LiveLimits(remaining), OriginalCommands: uint32(len(evidence.Commands)), PriorCommands: commands, PriorVerifications: evidence.ServiceVerifications}
	if err := selectStockRecoveryPredecessor(entry.State, ordinary.StockRecovery, ordinary.Limits); err != nil {
		return recoveryPlan{}, nil, err
	}
	ordinary.Grant = &cleanupGrantInput{Ordinal: 2, OriginalCaseReceiptSHA256: original.CaseReceipts[0].SHA256}
	basis := &cleanupRecoveryBasis{OriginalRunID: original.RunID, OriginalRunSHA256: originalRun.SHA256,
		OriginalCaseReceiptSHA256: original.CaseReceipts[0].SHA256, Entry: original.Scenarios[0].Entry, Decision: "stock_failed_writer_recovery"}
	return ordinary, basis, nil
}

func claimStockRecovery(plan recoveryPlan, record runRecord) error {
	if err := checkStockRecoveryCredential(); err != nil {
		return err
	}
	refused := errors.New("failed stock recovery admission unavailable or consumed")
	input := plan.StockRecovery
	if input == nil || len(plan.Entries) != 1 || record.CleanupRecoveryBasis == nil || record.CleanupRecoveryBasis.Decision != "stock_failed_writer_recovery" ||
		record.RecoveryRunID != input.OriginalRunID || record.RunID != input.RecoveryRunID || input.Validate(input.OriginalRunID, record.RunID) != nil ||
		record.CleanupRecoveryBasis.OriginalRunSHA256 != input.OriginalRun.SHA256 || plan.Grant == nil ||
		record.CleanupRecoveryBasis.OriginalCaseReceiptSHA256 != plan.Grant.OriginalCaseReceiptSHA256 || !validSource(record.Source) {
		return refused
	}
	body, err := json.Marshal(plan.Limits)
	if err != nil || digestBytes(body) != input.CleanupLimitsSHA256 || record.Limits == nil || *record.Limits != plan.Limits {
		return refused
	}
	state := plan.Entries[0].State
	lockPath, err := records.SafePath(state, "inventory.lock")
	if err != nil {
		return refused
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return refused
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return refused
	}
	for _, want := range []records.StockPluginFile{input.OriginalRun, input.OriginalInput, input.OriginalEvidence, input.OriginalGrant, input.Accounting} {
		got, _, err := stockRecoveryFile(want.Path)
		if err != nil || got != want {
			return refused
		}
	}
	if stockRecoverySources(state, input.Sources) != nil {
		return refused
	}
	if err := selectStockRecoveryPredecessor(state, input, plan.Limits); err != nil {
		return refused
	}
	if input.PreAdmission != nil {
		var original workerInput
		body, readErr := readRecordBytes(input.OriginalInput.Path)
		if readErr != nil || decodeCleanupRecord(body, &original) != nil || original.PublicConfiguration == nil || original.PublicConfiguration.Stock == nil || !records.StockPluginRecoveryProducerCompatible(original.PublicConfiguration.Stock.Artifact) {
			return refused
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := verifyStockPluginArtifact(ctx, original.PublicConfiguration.Stock.Artifact, plan.Provider)
		cancel()
		if err != nil {
			return refused
		}
	}
	if input.Validate(input.OriginalRunID, record.RunID) != nil {
		return refused
	}
	record.CleanupRecoveryBasis.StockRecoveryClaimSHA256 = input.ClaimSHA256()
	path, err := records.SafePath(state, input.ClaimName())
	if err != nil || records.WriteJSONExclusive(path, input, records.MaximumJSONBytes) != nil {
		return refused
	}
	return nil
}

func (s *runState) stockRecoveryCleanupEvidence(inv records.Invocation, raw *records.Cleanup) (*records.StockPluginRecoveryEvidence, error) {
	refused := errors.New("stock failed-writer recovery closure unavailable")
	var input workerInput
	if raw == nil || raw.Outcome != "passed" || raw.Failure != nil || raw.HarnessFailure != nil || raw.RemainingOwnedObjects == nil || *raw.RemainingOwnedObjects != 0 || raw.UnknownEffects == nil || *raw.UnknownEffects != 0 ||
		records.ReadJSON(inv.Input, &input) != nil || input.StockRecovery == nil || input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil || input.StockRecovery.RecoveryRunID != s.record.RunID || inv.RunID != s.record.RunID {
		return nil, refused
	}
	admission := input.StockRecovery
	if admission.Validate(input.RunID, inv.RunID) != nil {
		return nil, refused
	}
	for _, want := range []records.StockPluginFile{admission.OriginalRun, admission.OriginalInput, admission.OriginalEvidence, admission.OriginalGrant, admission.Accounting} {
		got, _, err := stockRecoveryFile(want.Path)
		if err != nil || got != want {
			return nil, refused
		}
	}
	if stockRecoverySources(inv.StateDir, admission.Sources) != nil {
		return nil, refused
	}
	var grant records.StockPluginGrant
	result, resultErr := records.ReadStockPluginRecoveryEvidence(filepath.Join(inv.OutputDir, "stock-recovery.json"))
	var prefix records.StockPluginPrefixCleanup
	if admission.ValidateClaim(inv.StateDir) != nil ||
		records.ReadJSON(admission.OriginalGrant.Path, &grant) != nil || resultErr != nil ||
		records.ReadJSON(filepath.Join(inv.OutputDir, "stock-prefix-cleanup.json"), &prefix) != nil || result.PrefixObservation == nil || prefix != *result.PrefixObservation ||
		result.ValidateClosed(*admission, grant, input.PublicConfiguration.Stock.Artifact.CLI.SHA256) != nil {
		return nil, refused
	}
	for _, command := range result.Commands {
		if command.Worker != inv.Worker || command.Nonce != inv.Nonce || command.Actor != input.Participants[command.Role] {
			return nil, refused
		}
	}
	return &result, nil
}

func validateStockRecoveryCase(parent runRecord, result scenarioResult) error {
	refused := errors.New("stock failed-writer recovery case unavailable")
	proof := result.StockPluginRecovery
	if proof == nil || result.Scenario != records.StockPluginScenario || parent.Suite != "live" || parent.RecoveryRunID == "" ||
		parent.CleanupRecoveryBasis == nil || parent.CleanupRecoveryBasis.Decision != "stock_failed_writer_recovery" ||
		parent.CleanupRecoveryBasis.OriginalRunID != parent.RecoveryRunID || parent.CleanupRecoveryBasis.OriginalRunSHA256 != proof.OriginalRunSHA256 ||
		proof.ValidateRecorded(parent.RecoveryRunID, parent.RunID) != nil || parent.CleanupRecoveryBasis.StockRecoveryClaimSHA256 != proof.AdmissionSHA256 || proof.OriginalGrant.Fixture.Provider != parent.Provider ||
		result.StockPluginEvidence != nil || result.PublicConfigurationEvidence != nil || result.CorrectnessPassed || result.Writer != nil || result.Rerun != nil || len(result.Children) != 0 || len(result.PostExit) != 0 ||
		result.CleanupWorker == nil || !result.CleanupWorker.Started || !result.CleanupWorker.Joined || result.CleanupWorker.Process != "passed" || result.CleanupWorker.Outcome != "passed" ||
		!scenarioCleanupPassed(result) || !reflect.DeepEqual(result.BudgetReserved, proof.ProductReserved) || elapsedSeconds(result.WorkloadElapsed) != proof.ProductElapsedSeconds {
		return refused
	}
	for _, command := range proof.Commands {
		if command.Worker != result.CleanupWorker.Worker {
			return refused
		}
	}
	return nil
}

func stockRecoveryHistory(original runRecord, evidence records.StockPluginEvidence, accounting records.StockPluginRecoveryAccounting, state string, stock records.StockPluginAcceptanceInput) (limits, uint32, []records.StockPluginRecoveryOriginal, error) {
	refused := errors.New("stock recovery cumulative history unavailable")
	if original.Limits == nil || len(original.Scenarios) != 1 {
		return limits{}, 0, nil, refused
	}
	remaining := *original.Limits
	result := original.Scenarios[0]
	if debitBudget(&remaining, result.BudgetReserved, result.Cleanup.BudgetReserved, result.WorkloadElapsed, result.CleanupElapsed) != nil {
		return limits{}, 0, nil, refused
	}
	commands := uint32(len(evidence.Commands))
	seen := map[string]bool{}
	var originals []records.StockPluginRecoveryOriginal
	for _, diagnostic := range accounting.Diagnostics {
		if seen[diagnostic.Scope.Path] || seen[diagnostic.Result.Path] || diagnostic.Scope.Path == diagnostic.Result.Path {
			return limits{}, 0, nil, refused
		}
		seen[diagnostic.Scope.Path], seen[diagnostic.Result.Path] = true, true
		reservation, elapsed, err := stockDiagnosticReservation(diagnostic, accounting.Sources, state, stock.Artifact.CLI)
		if err != nil || debitBudget(&remaining, &reservation, &records.BudgetReservation{}, elapsed, 0) != nil {
			return limits{}, 0, nil, refused
		}
		commands++
		observed, complete, err := stockRecoveryOriginals(diagnostic.Result.Path, stock)
		if err != nil || complete && originals != nil && !reflect.DeepEqual(originals, observed) {
			return limits{}, 0, nil, refused
		}
		if complete {
			originals = observed
		}
	}

	return remaining, commands, originals, nil
}
