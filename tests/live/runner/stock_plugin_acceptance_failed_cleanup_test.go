package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
)

func stockRecoveryCommandAllowed(input liveRunInput, phase, role, credential string, stdin []byte, args []string) bool {
	if input.StockRecovery == nil || len(stdin) != 0 {
		return false
	}
	var source string
	for _, file := range input.StockRecovery.Sources {
		if filepath.Base(file.Path) == "configuration.json" {
			source = file.Path
		}
	}
	command := "cleanup"
	if phase == "generated-list" && role == "reader" && credential == "" {
		command = "list"
	} else if phase != "failed-writer-cleanup" || role != "apply" || credential != "a" {
		return false
	}
	return source != "" && slices.Equal(args, []string{"generated", command, "--source", source, "--source-format", "json", "--json"})
}

func stockRecoveryInputsUnchanged(inv records.Invocation, input liveRunInput) bool {
	recovery := input.StockRecovery
	if recovery == nil || recovery.Validate(input.RunID, inv.RunID) != nil {
		return false
	}
	want := []string{filepath.Join(filepath.Dir(filepath.Dir(inv.StateDir)), "run.json"), filepath.Join(inv.StateDir, "input.json"),
		filepath.Join(inv.StateDir, "stock-plugin-evidence.json"), filepath.Join(inv.StateDir, "stock-plugin-grant.json"), filepath.Join(inv.StateDir, "stock-recovery-accounting.json")}
	files := []records.StockPluginFile{recovery.OriginalRun, recovery.OriginalInput, recovery.OriginalEvidence, recovery.OriginalGrant, recovery.Accounting}
	for i, file := range files {
		if file.Path != want[i] || !stockFileIdentityMatches(file, records.MaximumJSONBytes, false) {
			return false
		}
	}
	for _, file := range recovery.Sources {
		relative, err := filepath.Rel(filepath.Join(inv.StateDir, "stock-source"), file.Path)
		if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) || !stockFileIdentityMatches(file, 8<<20, false) {
			return false
		}
	}
	if recovery.PreAdmission != nil && (input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil || !records.StockPluginRecoveryProducerCompatible(input.PublicConfiguration.Stock.Artifact)) {
		return false
	}
	return recovery.ValidateClaim(inv.StateDir) == nil
}

func stockRecoverySupportUnchanged(ctx context.Context, input liveRunInput) bool {
	if input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil {
		return false
	}
	stock := input.PublicConfiguration.Stock
	if !stockFileMatches(stock.Artifact.CLI) || !stockFileIdentityMatches(stock.Artifact.Archive, artifact.MaxArchiveBytes, false) {
		return false
	}
	for _, build := range append([]records.StockPluginBuild{stock.Artifact.GeneratorA, stock.Artifact.GeneratorB, stock.Artifact.Renderer}, stock.Artifact.Outputs...) {
		actual, err := artifact.VerifyBuild(ctx, build.Directory)
		if err != nil || !reflect.DeepEqual(actual, build.Metadata) {
			return false
		}
	}
	return true
}

func stockRecoveryCleanupOutcome(body []byte, code int, originals []records.StockPluginRecoveryOriginal) (string, string, bool) {
	var product publicProductResult
	var document map[string]json.RawMessage
	if jsonv2.Unmarshal(body, &document) != nil || jsonv2.Unmarshal(body, &product) != nil || product.Schema != "ProductResult/v1" || product.Operation != "clean-owned-failure-residue" ||
		!publicRequestIdentityValid(product) || !publicIdentityHex(product.OperationID) || !stockFalsePresent(document["commit_may_have_occurred"]) {
		return "incomplete", "incomplete", false
	}
	for _, name := range []string{"effects_available", "summary_counts_available", "related_work_available"} {
		if !bytes.Equal(bytes.TrimSpace(document[name]), []byte("true")) {
			return "incomplete", "incomplete", false
		}
	}
	var unknown *uint32
	if jsonv2.Unmarshal(document["unknown_count"], &unknown) != nil || unknown == nil || *unknown != 0 {
		return "incomplete", "incomplete", false
	}
	var cleanup struct {
		Schema string `json:"schema"`
		Basis  struct {
			Kind           uint8  `json:"kind"`
			SourceKind     uint8  `json:"source_kind"`
			Source         string `json:"source_id"`
			Owner          string `json:"original_owner_id"`
			Operation      string `json:"original_operation_id"`
			Attempt        string `json:"original_attempt_id"`
			OriginalResult *struct {
				Schema uint16 `json:"schema"`
				Result string `json:"result_id"`
				Digest string `json:"body_digest"`
				Length uint64 `json:"length"`
			} `json:"original_result"`
			Target *struct {
				Resource       string `json:"resource_incarnation_id"`
				Operation      string `json:"original_operation_id"`
				Attempt        string `json:"original_attempt_id"`
				ResultContract string `json:"result_contract_id"`
			} `json:"target"`
		} `json:"basis"`
		RemainingDuties  []string `json:"remaining_duty_ids"`
		RemainingHazards []string `json:"remaining_hazard_ids"`
		RemainingInboxes []string `json:"remaining_inbox_ids"`
	}
	var fields map[string]json.RawMessage
	if jsonv2.Unmarshal(document["cleanup"], &cleanup) != nil || jsonv2.Unmarshal(document["cleanup"], &fields) != nil || cleanup.Schema != "CleanupPayload/v2" {
		return "incomplete", "incomplete", false
	}
	revision, snapshot := stockRecoverySelectedBasis(body)
	if !publicIdentityHex(revision) || !publicIdentityHex(snapshot) {
		return "incomplete", "incomplete", false
	}
	for _, name := range []string{"remaining_duty_ids", "remaining_hazard_ids", "remaining_inbox_ids"} {
		if !stockArrayPresent(fields[name]) {
			return "incomplete", "incomplete", false
		}
	}
	reflection, retirement := "not-required", "not-required"
	switch cleanup.Basis.Kind {
	case 1:
		if cleanup.Basis.Source != "" || cleanup.Basis.Owner != "" || cleanup.Basis.Operation != "" || cleanup.Basis.Attempt != "" || cleanup.Basis.Target != nil || cleanup.Basis.OriginalResult != nil {
			return "incomplete", "incomplete", false
		}
		return reflection, retirement, false
	case 2, 3:
		matched := false
		for _, original := range originals {
			if cleanup.Basis.Owner != original.OwnerID || !(cleanup.Basis.SourceKind == 11 && cleanup.Basis.Source == original.HazardID || cleanup.Basis.SourceKind == 10 && publicIdentityHex(cleanup.Basis.Source)) {
				continue
			}
			targetMatches := cleanup.Basis.Target != nil && cleanup.Basis.Target.Resource == original.ResourceID && cleanup.Basis.Target.Operation == original.OperationID && cleanup.Basis.Target.Attempt == original.AttemptID && cleanup.Basis.Target.ResultContract == original.ResultContractID
			if cleanup.Basis.Kind == 2 {
				matched = cleanup.Basis.Operation == original.OperationID && cleanup.Basis.Attempt == original.AttemptID && (cleanup.Basis.Target == nil || targetMatches)
			} else {
				matched = targetMatches && cleanup.Basis.Operation == product.OperationID && cleanup.Basis.Operation != original.OperationID && publicIdentityHex(cleanup.Basis.Attempt) && cleanup.Basis.Attempt != original.AttemptID
			}
			if matched {
				break
			}
		}
		if !matched {
			return "incomplete", "incomplete", false
		}
		if cleanup.Basis.Kind == 2 {
			result := cleanup.Basis.OriginalResult
			if result == nil || result.Schema == 0 || !publicIdentityHex(result.Result) || !publicIdentityHex(result.Digest) || result.Length == 0 || result.Length > 4<<20 {
				return "incomplete", "incomplete", false
			}
			reflection = "observed"
		} else {
			if cleanup.Basis.Target == nil || cleanup.Basis.OriginalResult != nil {
				return "incomplete", "incomplete", false
			}
			var acknowledged *uint32
			if jsonv2.Unmarshal(document["deletion_acknowledged_count"], &acknowledged) != nil || acknowledged == nil || *acknowledged == 0 {
				return "incomplete", "incomplete", false
			}
			retirement = "deletion-acknowledged"
		}
	default:
		return "incomplete", "incomplete", false
	}
	closed := code == 0 && product.State == "success" && cleanup.Basis.Target != nil && len(cleanup.RemainingDuties) == 0 && len(cleanup.RemainingHazards) == 0 && len(cleanup.RemainingInboxes) == 0
	var warnings stockGeneratedWarnings
	if !stockWarningsKnown(document["effect_warnings"]) || jsonv2.Unmarshal(document["effect_warnings"], &warnings) != nil || warnings.PossibleLive || warnings.LateEffect {
		closed = false
	}
	return reflection, retirement, closed
}

func stockRecoverySelectedBasis(body []byte) (string, string) {
	var result struct {
		Cleanup struct {
			Basis struct {
				Revision string `json:"head_revision_id"`
				Snapshot struct {
					Object string `json:"object_id"`
				} `json:"snapshot"`
			} `json:"remaining_work_basis"`
		} `json:"cleanup"`
	}
	if jsonv2.Unmarshal(body, &result) != nil {
		return "", ""
	}
	return result.Cleanup.Basis.Revision, result.Cleanup.Basis.Snapshot.Object
}

func stockRecoveryListClosed(body []byte, code int, revision, snapshot string) bool {
	var document map[string]json.RawMessage
	var result stockGeneratedResult
	if code != 0 || jsonv2.Unmarshal(body, &document) != nil || jsonv2.Unmarshal(body, &result) != nil || result.Schema != "ProductResult/v1" ||
		result.Operation != "generated-list" || result.State != "success" || !publicIdentityHex(result.Revision) || !publicIdentityHex(result.Snapshot) ||
		result.Revision != revision || result.Snapshot != snapshot ||
		!bytes.Equal(bytes.TrimSpace(document["active_operation"]), []byte("null")) || !stockWarningsKnown(document["effect_warnings"]) || result.Warnings.PossibleLive || result.Warnings.LateEffect {
		return false
	}
	for _, name := range []string{"current_generations", "duties", "hazards", "pending_releases", "next_actions"} {
		var rows []json.RawMessage
		if !stockArrayPresent(document[name]) || jsonv2.Unmarshal(document[name], &rows) != nil || len(rows) != 0 {
			return false
		}
	}
	return stockArrayPresent(document["attempts"])
}

func runStockFailedWriterCleanup(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("stock recovery worker owner unavailable")
	}
	worker.Result.Actor = input.Participants["cleanup"]
	worker.Result.Cleanup = &records.Cleanup{Outcome: "unresolved"}
	cleanupLimits := input.Limits
	cleanupLimits.Requests, cleanupLimits.BodyBytes, cleanupLimits.GeneratorCreates = input.Limits.CleanupRequests, input.Limits.CleanupBytes, 0
	cleanupBudget := &runBudget{limits: cleanupLimits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, cleanupBudget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("stock recovery original owner unavailable")
	}
	defer lease.Close()
	if !livePublicConfigurationAdmitted(input) || !stockRecoveryInputsUnchanged(inv, input) {
		t.Fatal("stock recovery original inputs or one-use admission changed")
	}
	recovery := input.StockRecovery
	stock := input.PublicConfiguration.Stock
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), time.Duration(input.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	if !stockRecoverySupportUnchanged(ctx, input) {
		t.Fatal("stock recovery retained CLI or plugin support changed")
	}
	productBudget := &runBudget{limits: recovery.ProductRemaining, keys: map[string]bool{}}
	r := stockExistingRun(t, inv, input, productBudget)
	if uint32(len(r.evidence.Commands)) != recovery.OriginalCommands {
		t.Fatal("stock recovery original command accounting changed")
	}
	var grant records.StockPluginGrant
	if records.ReadJSON(recovery.OriginalGrant.Path, &grant) != nil || grant.Validate() != nil || grant.LimitsSHA256 != recovery.OriginalLimitsSHA256 || grant.RunID != input.RunID || grant.Prefix != input.Prefix || !reflect.DeepEqual(grant.Fixture, stock.Fixture) {
		t.Fatal("stock recovery original prefix grant changed")
	}
	result := records.StockPluginRecoveryEvidence{AdmissionSHA256: recovery.ClaimSHA256(), Schema: 1, OriginalRunID: input.RunID, RecoveryRunID: inv.RunID, Prefix: input.Prefix,
		FixtureID: stock.Fixture.FixtureID, CLISHA256: stock.Artifact.CLI.SHA256, OriginalRunSHA256: recovery.OriginalRun.SHA256,
		OriginalEvidenceSHA256: recovery.OriginalEvidence.SHA256, AccountingSHA256: recovery.Accounting.SHA256,
		OriginalGrant: grant, ProductAllowance: recovery.ProductRemaining, OriginalCommands: recovery.OriginalCommands, PriorCommands: recovery.PriorCommands,
		Reflection: "not-entered", Retirement: "not-entered", ResidualExposure: "unknown", StoreCleanup: "not-entered"}
	path := filepath.Join(inv.OutputDir, "stock-recovery.json")
	started := time.Now()
	productContext, stopProduct := context.WithTimeout(ctx, time.Duration(recovery.ProductRemaining.ElapsedSeconds)*time.Second)
	productFinished := false
	updateProductElapsed := func() {
		elapsed := time.Since(started)
		result.ProductElapsedSeconds = uint64(elapsed / time.Second)
		if elapsed%time.Second != 0 {
			result.ProductElapsedSeconds++
		}
	}
	finishProduct := func() {
		if !productFinished {
			updateProductElapsed()
			productFinished = true
			stopProduct()
		}
	}
	save := func() error {
		result.Commands = slices.Clone(r.evidence.Commands[recovery.OriginalCommands:])
		result.ProductReserved = liveReservation(productBudget)
		if !productFinished {
			updateProductElapsed()
		}
		return records.WriteJSON(path, result, 0600)
	}
	r.saveRecovery = save
	defer func() {
		finishProduct()
		if err := save(); err != nil {
			t.Error("stock recovery result could not be retained")
		}
	}()
	if err := save(); err != nil {
		t.Fatal("stock recovery initial result could not be retained")
	}
	source := filepath.Join(inv.StateDir, "stock-source", "configuration.json")
	image := publicSourceImage(t, source)
	r.selectPlugins(source, false)
	sequence := liveBeginPhase(t, worker, "cleanup", true)
	child := r.command(productContext, "failed-writer-cleanup", "apply", "a", nil, "generated", "cleanup", "--source", source, "--source-format", "json", "--json")
	result.ProductResultSHA256 = bodyDigest(child.Body)
	reflection, retirement, closed := stockRecoveryCleanupOutcome(child.Body, child.Code, recovery.Originals)
	result.WorkRevisionID, result.WorkSnapshotID = stockRecoverySelectedBasis(child.Body)
	clear(child.Body)
	result.Reflection, result.Retirement = reflection, retirement
	if err := save(); err != nil {
		t.Fatal("stock recovery Product result could not be retained")
	}
	publicImageUnchanged(t, image)
	if !closed || !stockRecoveryInputsUnchanged(inv, input) {
		result.ResidualExposure = "possible-live"
		t.Fatal("stock recovery left unqualified or unfinished original provider work")
	}
	observed := r.command(productContext, "generated-list", "reader", "", nil, "generated", "list", "--source", source, "--source-format", "json", "--json")
	result.ListResultSHA256 = bodyDigest(observed.Body)
	closed = stockRecoveryListClosed(observed.Body, observed.Code, result.WorkRevisionID, result.WorkSnapshotID)
	clear(observed.Body)
	finishProduct()
	if err := save(); err != nil {
		t.Fatal("stock recovery current-work observation could not be retained")
	}
	publicImageUnchanged(t, image)
	if !closed || !stockRecoveryInputsUnchanged(inv, input) {
		result.ResidualExposure = "possible-live"
		t.Fatal("stock recovery current provider work remains")
	}
	result.ResidualExposure = "none"
	if records.ReadJSON(recovery.OriginalGrant.Path, &grant) != nil || grant.Validate() != nil || grant.LimitsSHA256 != recovery.OriginalLimitsSHA256 || grant.RunID != input.RunID || grant.Prefix != input.Prefix || !reflect.DeepEqual(grant.Fixture, stock.Fixture) {
		t.Fatal("stock recovery original prefix grant changed")
	}
	store, err := openStockStorePrefix(ctx, input, inv.StateDir, &stockPrefixInspection{Empty: grant.PreflightEmpty, Identity: grant.BucketIdentity, Prefix: grant.Prefix})
	if err != nil {
		t.Fatal("stock recovery exact Store prefix unavailable")
	}
	inspection, err := store.Inspect(ctx, cleanupBudget)
	if err != nil || inspection.Identity != grant.BucketIdentity || inspection.Prefix != grant.Prefix {
		t.Fatal("stock recovery Store identity changed")
	}
	attempt := records.StockPluginPrefixCleanup{Schema: 1, RunID: input.RunID, FixtureID: grant.Fixture.FixtureID, Prefix: input.Prefix, BucketIdentity: grant.BucketIdentity, Started: true}
	attemptPath := filepath.Join(inv.OutputDir, "stock-prefix-cleanup.json")
	if records.WriteJSONExclusive(attemptPath, attempt, records.MaximumJSONBytes) != nil {
		t.Fatal("stock recovery prefix cleanup intent could not be retained")
	}
	empty, err := store.Clean(ctx, cleanupBudget)
	if err != nil || !empty {
		result.StoreCleanup = "incomplete"
		t.Fatal("stock recovery prefix cleanup did not establish absence")
	}
	attempt.Completed, attempt.ObservedEmpty = true, true
	result.StoreCleanup, result.PrefixObservation = "observed-empty", &attempt
	if attempt.Validate(grant) != nil || records.WriteJSON(attemptPath, attempt, 0600) != nil || save() != nil || result.ValidateClosed(*recovery, grant, stock.Artifact.CLI.SHA256) != nil {
		t.Fatal("stock recovery final closure could not be retained")
	}
	zero := int64(0)
	worker.Result.Cleanup.RemainingOwnedObjects, worker.Result.Cleanup.UnknownEffects = &zero, &zero
	worker.Result.Cleanup.Outcome = "passed"
	liveEndPhase(t, worker, sequence, true)
}

// full_only: false
func TestStockFailedWriterRecoveryCommandsRefuseReplay(t *testing.T) {
	source := "/original/stock-source/configuration.json"
	input := liveRunInput{StockRecovery: &records.StockPluginRecoveryInput{Sources: []records.StockPluginFile{{Path: source}}}}
	for _, command := range []string{"cleanup", "list"} {
		phase, role, credential := "failed-writer-cleanup", "apply", "a"
		if command == "list" {
			phase, role, credential = "generated-list", "reader", ""
		}
		args := []string{"generated", command, "--source", source, "--source-format", "json", "--json"}
		if !stockRecoveryCommandAllowed(input, phase, role, credential, nil, args) {
			t.Fatal("exact recovery command refused", command)
		}
	}
	for _, condition := range []string{"apply-replay", "risk-acceptance", "wrong-source", "wrong-role", "wrong-credential", "operation-replay", "stdin"} {
		t.Run(condition, func(t *testing.T) {
			args := []string{"generated", "cleanup", "--source", source, "--source-format", "json", "--json"}
			role, credential, stdin := "apply", "a", []byte(nil)
			switch condition {
			case "apply-replay":
				args = []string{"apply", "--source", source, "--source-format", "json", "--json"}
			case "risk-acceptance":
				args[1] = "accept-retirement-risk"
			case "wrong-source":
				args[3] = "/original/sibling/configuration.json"
			case "wrong-role":
				role = "authority"
			case "wrong-credential":
				credential = "b"
			case "operation-replay":
				args = append(args, "--operation", strings.Repeat("a", 64))
			case "stdin":
				stdin = []byte("not permitted")
			}
			if stockRecoveryCommandAllowed(input, "failed-writer-cleanup", role, credential, stdin, args) {
				t.Fatal("unadmitted recovery command reached execution", condition)
			}
		})
	}
}

// full_only: false
func TestStockFailedWriterCleanupRequiresCompleteCurrentClosure(t *testing.T) {
	id := strings.Repeat("a", 64)
	t.Run("pre-admission-failure-keeps-original-work-open", func(t *testing.T) {
		body := strings.ReplaceAll(publicPreAdmissionJSON, "apply-declaration", "clean-owned-failure-residue")
		body = strings.Replace(body, `"state_result":"refused"`, `"state_result":"unavailable"`, 1)
		body = strings.Replace(body, `"stage":"capture"`, `"stage":"observation"`, 1)
		body = strings.Replace(body, `"code":"missing-required-field"`, `"code":"evidence-unavailable"`, 1)
		body = strings.Replace(body, `"payload":null`, `"payload":null,"effect_summary":"effect-no-change","output_summary":"not-applicable","evidence_ceiling":"unavailable","commit_may_have_occurred":false`, 1)
		reflection, retirement, closed := stockRecoveryCleanupOutcome([]byte(body), 3, nil)
		if closed || reflection != "incomplete" || retirement != "incomplete" {
			t.Fatal("pre-admission terminal proved closure of original provider work")
		}
	})
	// This no-work literal has no provider target. The selected recovery scope
	// leaves that result blocked even when its remaining vectors are empty.
	base := `{"schema":"ProductResult/v1","operation_kind":"clean-owned-failure-residue","state_result":"no-op","operation_id":"` + id + `","request_identity":"` + id + `","commit_may_have_occurred":false,"effects_available":true,"summary_counts_available":true,"related_work_available":true,"unknown_count":0,"effect_warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false},"cleanup":{"schema":"CleanupPayload/v2","basis":{"kind":1,"source_kind":0,"source_id":null,"original_owner_id":null,"original_operation_id":null,"original_attempt_id":null,"original_result":null,"target":null},"remaining_work_basis":{"head_revision_id":"` + id + `","snapshot":{"object_id":"` + id + `"}},"remaining_duty_ids":[],"remaining_hazard_ids":[],"remaining_inbox_ids":[]}}`
	reflection, retirement, closed := stockRecoveryCleanupOutcome([]byte(base), 0, nil)
	if closed || reflection != "not-required" || retirement != "not-required" {
		t.Fatal("no-target observation released the original recovery dependency")
	}
	value := func(digit string) string { return strings.Repeat(digit, 64) }
	original := records.StockPluginRecoveryOriginal{OperationID: value("1"), AttemptID: value("2"), OwnerID: value("3"), HazardID: value("4"), ResourceID: value("5"), ResultContractID: value("6")}
	target := `{"resource_incarnation_id":"` + original.ResourceID + `","original_operation_id":"` + original.OperationID + `","original_attempt_id":"` + original.AttemptID + `","result_contract_id":"` + original.ResultContractID + `"}`
	basis := `{"kind":3,"source_kind":11,"source_id":"` + original.HazardID + `","original_owner_id":"` + original.OwnerID + `","original_operation_id":"` + id + `","original_attempt_id":"` + value("b") + `","original_result":null,"target":` + target + `}`
	owned := strings.Replace(base, `{"kind":1,"source_kind":0,"source_id":null,"original_owner_id":null,"original_operation_id":null,"original_attempt_id":null,"original_result":null,"target":null}`, basis, 1)
	owned = strings.Replace(owned, `"state_result":"no-op"`, `"state_result":"success"`, 1)
	owned = strings.Replace(owned, `"unknown_count":0`, `"unknown_count":0,"deletion_acknowledged_count":1`, 1)
	originals := []records.StockPluginRecoveryOriginal{{OwnerID: value("9")}, original}
	reflection, retirement, closed = stockRecoveryCleanupOutcome([]byte(owned), 0, originals)
	if !closed || reflection != "not-required" || retirement != "deletion-acknowledged" {
		t.Fatal("exact original target acknowledgement did not close")
	}
	reflected := strings.Replace(owned, `"kind":3`, `"kind":2`, 1)
	reflected = strings.Replace(reflected, `"original_operation_id":"`+id+`"`, `"original_operation_id":"`+original.OperationID+`"`, 1)
	reflected = strings.Replace(reflected, `"original_attempt_id":"`+value("b")+`"`, `"original_attempt_id":"`+original.AttemptID+`"`, 1)
	reflected = strings.Replace(reflected, `"original_result":null`, `"original_result":{"schema":1,"result_id":"`+value("c")+`","body_digest":"`+value("d")+`","length":100}`, 1)
	reflected = strings.Replace(reflected, `"remaining_duty_ids":[]`, `"remaining_duty_ids":["`+value("e")+`"]`, 1)
	reflection, retirement, closed = stockRecoveryCleanupOutcome([]byte(reflected), 0, originals)
	if closed || reflection != "observed" || retirement != "not-required" {
		t.Fatal("qualified reflection lost its distinct unfinished retirement")
	}
	for _, condition := range []string{"remaining-hazard", "null-vector", "unknown-effect", "commit-unknown", "wrong-operation", "missing-payload", "failed-exit", "foreign-original", "unacknowledged", "later-target-member"} {
		t.Run(condition, func(t *testing.T) {
			body, code := owned, 0
			switch condition {
			case "remaining-hazard":
				body = strings.Replace(body, `"remaining_hazard_ids":[]`, `"remaining_hazard_ids":["`+id+`"]`, 1)
			case "null-vector":
				body = strings.Replace(body, `"remaining_duty_ids":[]`, `"remaining_duty_ids":null`, 1)
			case "unknown-effect":
				body = strings.Replace(body, `"unknown_count":0`, `"unknown_count":1`, 1)
			case "commit-unknown":
				body = strings.Replace(body, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":true`, 1)
			case "wrong-operation":
				body = strings.Replace(body, "clean-owned-failure-residue", "apply-declaration", 1)
			case "missing-payload":
				body = strings.Replace(body, `"schema":"CleanupPayload/v2"`, `"schema":"CleanupPayload/v1"`, 1)
			case "failed-exit":
				code = 2
			case "foreign-original":
				body = strings.Replace(body, `"original_owner_id":"`+original.OwnerID+`"`, `"original_owner_id":"`+value("9")+`"`, 1)
			case "unacknowledged":
				body = strings.Replace(body, `"deletion_acknowledged_count":1`, `"deletion_acknowledged_count":0`, 1)
			case "later-target-member":
				body = strings.Replace(body, `"result_contract_id":"`+original.ResultContractID+`"`, `"result_contract_id":"`+value("9")+`"`, 1)
			}
			if _, _, closed := stockRecoveryCleanupOutcome([]byte(body), code, originals); closed {
				t.Fatal("incomplete or foreign cleanup observation closed provider work", condition)
			}
		})
	}
	list := `{"schema":"ProductResult/v1","operation_kind":"generated-list","state_result":"success","observed_revision_id":"` + id + `","snapshot_id":"` + id + `","active_operation":null,"effect_warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false},"current_generations":[],"attempts":[],"duties":[],"hazards":[],"pending_releases":[],"next_actions":[]}`
	if !stockRecoveryListClosed([]byte(list), 0, id, id) || stockRecoveryListClosed([]byte(strings.Replace(list, `"hazards":[]`, `"hazards":[{}]`, 1)), 0, id, id) || stockRecoveryListClosed([]byte(list), 0, value("f"), id) {
		t.Fatal("current-work closure ignored an unfinished Hazard")
	}
}

// full_only: false
func TestStockRecoveryJSONInputsKeepPrivateDataModes(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old, current, id := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 64)
	state := filepath.Join(base, "runs", old, "private", "state")
	output := filepath.Join(base, "runs", current, "private", "cleanup")
	for _, directory := range []string{state, output, filepath.Join(state, "stock-source", ".enkv")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	file := func(path string) records.StockPluginFile {
		t.Helper()
		body := []byte("{}\n")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		return records.StockPluginFile{Path: path, SHA256: hex.EncodeToString(digest[:]), Length: uint64(len(body))}
	}
	recovery := &records.StockPluginRecoveryInput{Schema: 1, OriginalRunID: old, RecoveryRunID: current,
		OriginalRun: file(filepath.Join(filepath.Dir(filepath.Dir(state)), "run.json")), OriginalInput: file(filepath.Join(state, "input.json")),
		OriginalEvidence: file(filepath.Join(state, "stock-plugin-evidence.json")), OriginalGrant: file(filepath.Join(state, "stock-plugin-grant.json")), Accounting: file(filepath.Join(state, "stock-recovery-accounting.json")),
		Sources:              []records.StockPluginFile{file(filepath.Join(state, "stock-source", ".enkv", "generated.json")), file(filepath.Join(state, "stock-source", "configuration.json"))},
		Originals:            []records.StockPluginRecoveryOriginal{{OperationID: id, AttemptID: id, OwnerID: id, HazardID: id, ResourceID: id, DescriptorID: id, ExecutorID: id, CredentialRoute: id, ResultContractID: id}},
		OriginalLimitsSHA256: id, CleanupLimitsSHA256: id, OriginalCommands: 2, PriorCommands: 4,
		ProductRemaining: liveLimits{Requests: 256, BodyBytes: 32 << 20, Objects: 128, ObjectBytes: 32 << 20, GeneratorRetires: 3, ElapsedSeconds: 240}}
	if err := records.WriteJSON(filepath.Join(state, "stock-recovery-claim.json"), recovery, 0600); err != nil {
		t.Fatal(err)
	}
	input := liveRunInput{RunID: old, StockRecovery: recovery}
	inv := records.Invocation{RunID: current, StateDir: state, OutputDir: output}
	if !stockRecoveryInputsUnchanged(inv, input) {
		t.Fatal("unchanged private JSON records were refused because they are not executable")
	}
	t.Run("successor-binds-predecessor", func(t *testing.T) {
		firstBody, err := os.ReadFile(filepath.Join(state, "stock-recovery-claim.json"))
		if err != nil {
			t.Fatal(err)
		}
		firstDigest := sha256.Sum256(firstBody)
		predecessor := &records.StockPluginRecoveryPredecessor{RunID: current, Claim: records.StockPluginFile{Path: filepath.Join(state, "stock-recovery-claim.json"), SHA256: hex.EncodeToString(firstDigest[:]), Length: uint64(len(firstBody))},
			Run: file(filepath.Join(base, "runs", current, "run.json")), Input: file(filepath.Join(filepath.Dir(output), "input.json")), Invocation: file(filepath.Join(output, "invocation.json")), Result: file(filepath.Join(output, "stock-recovery.json")), Worker: file(filepath.Join(output, "worker.json")), Failure: file(filepath.Join(output, "failure.json"))}
		jsonBinding := func(path string, value any) records.StockPluginFile {
			t.Helper()
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, '\n')
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			return records.StockPluginFile{Path: path, SHA256: hex.EncodeToString(digest[:]), Length: uint64(len(body))}
		}
		sourcePath := filepath.Join(output, "failure-sources.json")
		sourceFile := jsonBinding(sourcePath, records.FailureSources{SchemaVersion: 1, BinarySHA256: strings.Repeat("1", 64), OverlaySHA256: strings.Repeat("2", 64), Paths: map[string]string{"enkv.sh/core/internal/testmain/coordinator_test.go": "tests/shared/runner/coordinator_test.go"}})
		priorInv := records.Invocation{SchemaVersion: records.SchemaVersion, Scenario: records.StockPluginScenario, RunID: current, Worker: "stock-cleanup", Role: "cleanup", Nonce: strings.Repeat("1", 32), Input: predecessor.Input.Path, StateDir: state, OutputDir: output, FailureSources: &records.FailureSourceBinding{Path: sourcePath, SHA256: sourceFile.SHA256}}
		predecessor.Invocation = jsonBinding(predecessor.Invocation.Path, priorInv)
		predecessor.Failure = jsonBinding(predecessor.Failure.Path, records.FailureMarker{FailureIdentity: records.FailureIdentity{SchemaVersion: 1, RunID: current, Worker: priorInv.Worker, Role: priorInv.Role, Scenario: priorInv.Scenario, Nonce: priorInv.Nonce}, Phase: "bootstrap", Code: "fatal", Source: "tests/shared/runner/coordinator_test.go", Line: 1, Completed: records.CompletedCheckpoint{Code: "none"}})
		next := *recovery
		next.Predecessor, next.RecoveryRunID = predecessor, strings.Repeat("d", 32)
		if err := records.WriteJSON(filepath.Join(state, next.ClaimName()), next, 0600); err != nil {
			t.Fatal(err)
		}
		nextInput := input
		nextInput.StockRecovery = &next
		nextInv := inv
		nextInv.RunID = next.RecoveryRunID
		if !stockRecoveryInputsUnchanged(nextInv, nextInput) {
			t.Fatal("unchanged selected successor relation refused")
		}
		for _, binding := range []records.StockPluginFile{predecessor.Claim, predecessor.Run, predecessor.Input, predecessor.Invocation, predecessor.Result, predecessor.Worker, predecessor.Failure} {
			before, err := os.ReadFile(binding.Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(binding.Path, []byte("changed\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if stockRecoveryInputsUnchanged(nextInv, nextInput) {
				t.Fatal("worker accepted changed predecessor evidence")
			}
			if err := os.WriteFile(binding.Path, before, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := records.WriteJSON(filepath.Join(output, "stock-plugin-evidence.json"), records.StockPluginEvidence{Commands: []records.StockPluginCommand{{Started: false}}}, 0600); err != nil {
			t.Fatal(err)
		}
		if stockRecoveryInputsUnchanged(nextInv, nextInput) {
			t.Fatal("worker accepted a durable predecessor command intent")
		}
	})
	if err := os.WriteFile(recovery.Sources[1].Path, []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if stockRecoveryInputsUnchanged(inv, input) {
		t.Fatal("changed source record was admitted")
	}
	archiveBody := []byte("recorded read-only archive bytes")
	archivePath := filepath.Join(output, "archive.tar.gz")
	if err := os.WriteFile(archivePath, archiveBody, 0444); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(archiveBody)
	archive := records.StockPluginFile{Path: archivePath, SHA256: hex.EncodeToString(archiveDigest[:]), Length: uint64(len(archiveBody))}
	if stockFileMatches(archive) || !stockFileIdentityMatches(archive, artifact.MaxArchiveBytes, false) || stockFileIdentityMatches(archive, archive.Length-1, false) {
		t.Fatal("archive data identity lost its permission or byte bound")
	}
}

// full_only: false
func TestStockRecoveryStartFailurePreservesOriginalEvidence(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	output, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(state, 0700) != nil || os.Chmod(output, 0700) != nil {
		t.Fatal("controlled recovery directories are not private")
	}
	old := strings.Repeat("b", 32)
	inv := records.Invocation{StateDir: state, OutputDir: output, Worker: "cleanup-worker", Nonce: strings.Repeat("a", 32)}
	input := liveRunInput{RunID: old, StockRecovery: &records.StockPluginRecoveryInput{}, PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Artifact: records.StockPluginArtifact{CLI: records.StockPluginFile{SHA256: strings.Repeat("c", 64)}}}}}
	before := []byte("original evidence must remain unchanged\n")
	if err := os.WriteFile(stockEvidencePath(inv), before, 0600); err != nil {
		t.Fatal(err)
	}
	r := stockPluginRun{t: t, inv: inv, input: input, evidence: records.StockPluginEvidence{Commands: []records.StockPluginCommand{{Ordinal: 0, Worker: inv.Worker, Nonce: inv.Nonce, Phase: "failed-writer-cleanup", ExitCode: -1}}}}
	if err := r.recordStartFailure(false); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(stockEvidencePath(inv))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery command start failure replaced original stock evidence", err)
	}
	index, err := records.ReadStockPluginEvidence(stockEvidencePath(r.evidenceInvocation()))
	if err != nil || len(index.Commands) != 1 || index.Commands[0].Started || index.Commands[0].DiagnosticStatus != "unavailable" {
		t.Fatal("separate recovery start-failure evidence was not retained", err)
	}
}

// full_only: false
func TestStockRecoveryCommandIntentRetainsSeparatePrivateOwners(t *testing.T) {
	for _, condition := range []string{"retained", "index-save-failure", "reservation-save-failure"} {
		t.Run(condition, func(t *testing.T) {
			state, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			output, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			inv := records.Invocation{StateDir: state, OutputDir: output}
			original := []byte("original evidence\n")
			if os.WriteFile(stockEvidencePath(inv), original, 0600) != nil {
				t.Fatal("original evidence unavailable")
			}
			proofPath := filepath.Join(output, "stock-recovery.json")
			reserved := records.BudgetReservation{Requests: 128, BodyBytes: 16 << 20, Objects: 128, ObjectBytes: 32 << 20, GeneratorRetires: 3}
			run := stockPluginRun{inv: inv, input: liveRunInput{StockRecovery: &records.StockPluginRecoveryInput{}}, evidence: records.StockPluginEvidence{Commands: []records.StockPluginCommand{{Ordinal: 2, Phase: "failed-writer-cleanup", ExitCode: -1}}}}
			run.saveRecovery = func() error {
				return records.WriteJSON(proofPath, records.StockPluginRecoveryEvidence{ProductReserved: &reserved}, 0600)
			}
			if condition == "index-save-failure" && os.Mkdir(stockEvidencePath(run.evidenceInvocation()), 0700) != nil {
				t.Fatal("index failure fixture unavailable")
			}
			if condition == "reservation-save-failure" && os.Mkdir(proofPath, 0700) != nil {
				t.Fatal("reservation failure fixture unavailable")
			}
			err = run.retainCommandIntent()
			if (err == nil) != (condition == "retained") {
				t.Fatal("private intent save result differs", err)
			}
			if condition != "index-save-failure" {
				index, err := records.ReadStockPluginEvidence(stockEvidencePath(run.evidenceInvocation()))
				if err != nil || len(index.Commands) != 1 || index.Commands[0].Started || index.Commands[0].Joined || index.Commands[0].ExitCode != -1 {
					t.Fatal("dispatch intent lost its unstarted state", err)
				}
			}
			if condition == "retained" {
				proof, err := records.ReadStockPluginRecoveryEvidence(proofPath)
				if err != nil || proof.ProductReserved == nil || *proof.ProductReserved != reserved {
					t.Fatal("private reservation was not retained with intent", err)
				}
			}
			after, err := os.ReadFile(stockEvidencePath(inv))
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("recovery intent changed original evidence", err)
			}
		})
	}
}
