package records

import (
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestStockPluginFailedRecoveryProofPreservesOriginalFailureAndLimits(t *testing.T) {
	id := func(value string) string { return strings.Repeat(value, 64) }
	old, current := strings.Repeat("a", 32), strings.Repeat("b", 32)
	file := func(path string) StockPluginFile {
		return StockPluginFile{Path: "/recorded/" + path, SHA256: id("1"), Length: 100}
	}
	allowance := LiveLimits{Requests: 1000, BodyBytes: 1 << 30, Objects: 256, ObjectBytes: 1 << 30, GeneratorCreates: 6, GeneratorRetires: 24, ElapsedSeconds: 3000, CleanupRequests: 8192, CleanupBytes: 16 << 30, CleanupSeconds: 900}
	input := StockPluginRecoveryInput{Schema: 1, OriginalRunID: old, RecoveryRunID: current,
		OriginalRun: file("run.json"), OriginalInput: file("input.json"), OriginalEvidence: file("evidence.json"), OriginalGrant: file("grant.json"), Accounting: file("accounting.json"),
		Sources:              []StockPluginFile{file("source/.enkv/generated.json"), file("source/configuration.json")},
		Originals:            []StockPluginRecoveryOriginal{{OperationID: id("1"), AttemptID: id("2"), OwnerID: id("3"), HazardID: id("4"), ResourceID: id("5"), DescriptorID: id("6"), ExecutorID: id("7"), CredentialRoute: id("8"), ResultContractID: id("9")}},
		OriginalLimitsSHA256: id("2"), CleanupLimitsSHA256: id("3"), ProductRemaining: allowance, OriginalCommands: 2, PriorCommands: 4}
	grant := StockPluginGrant{Schema: 1, Fixture: stockFixtureLiteral("aws"), RunID: old, Scenario: StockPluginScenario, Prefix: "enkv-test/" + old + "/stock-case", LimitsSHA256: input.OriginalLimitsSHA256, PreflightEmpty: true, BucketIdentity: "original-bucket"}
	prefix := StockPluginPrefixCleanup{Schema: 1, RunID: old, FixtureID: grant.Fixture.FixtureID, Prefix: grant.Prefix, BucketIdentity: grant.BucketIdentity, Started: true, Completed: true, ObservedEmpty: true}
	good := StockPluginRecoveryEvidence{AdmissionSHA256: input.ClaimSHA256(), Schema: 1, OriginalRunID: old, RecoveryRunID: current, Prefix: grant.Prefix, FixtureID: grant.Fixture.FixtureID, CLISHA256: id("4"),
		OriginalRunSHA256: input.OriginalRun.SHA256, OriginalEvidenceSHA256: input.OriginalEvidence.SHA256, AccountingSHA256: input.Accounting.SHA256,
		OriginalGrant: grant, ProductAllowance: allowance, OriginalCommands: 2, PriorCommands: 4,
		ProductReserved: &BudgetReservation{Requests: 256, BodyBytes: 32 << 20, Objects: 128, ObjectBytes: 32 << 20, GeneratorRetires: 3}, ProductElapsedSeconds: 1,
		ProductResultSHA256: id("5"), ListResultSHA256: id("6"), Reflection: "observed", Retirement: "not-required", ResidualExposure: "none", StoreCleanup: "observed-empty", PrefixObservation: &prefix,
		WorkRevisionID: id("9"), WorkSnapshotID: id("a"),
		Commands: []StockPluginCommand{
			{Ordinal: 2, Worker: "cleanup-worker", Nonce: strings.Repeat("c", 32), Role: "apply", Actor: "publisher", Phase: "failed-writer-cleanup", Started: true, Joined: true, ResultSHA256: id("5"), DiagnosticSHA256: id("7"), DiagnosticBytes: 100, DiagnosticStatus: "observed"},
			{Ordinal: 3, Worker: "cleanup-worker", Nonce: strings.Repeat("c", 32), Role: "reader", Actor: "reader", Phase: "generated-list", Started: true, Joined: true, ResultSHA256: id("6"), DiagnosticSHA256: id("8"), DiagnosticBytes: 100, DiagnosticStatus: "observed"},
		}}
	if good.ValidateClosed(input, grant, good.CLISHA256) != nil || good.ValidateRecorded(old, current) != nil {
		t.Fatal("separate exact failed-work recovery proof refused")
	}
	// A successor proof binds the complete selected private admission by digest.
	successor := input
	successor.RecoveryRunID = strings.Repeat("d", 32)
	successor.Predecessor = &StockPluginRecoveryPredecessor{RunID: current, Claim: file("stock-recovery-claim.json"), Run: file("predecessor/run.json"), Input: file("predecessor/input.json"), Invocation: file("predecessor/invocation.json"), Result: file("predecessor/stock-recovery.json"), Worker: file("predecessor/worker.json"), Failure: file("predecessor/failure.json")}
	successorProof := good
	successorProof.RecoveryRunID, successorProof.AdmissionSHA256 = successor.RecoveryRunID, successor.ClaimSHA256()
	if successor.Validate(old, successor.RecoveryRunID) != nil || successor.ClaimName() != "stock-recovery-successor-claim.json" || successorProof.ValidateClosed(successor, grant, good.CLISHA256) != nil {
		t.Fatal("exact successor admission did not bind its final closed proof")
	}
	changed := *successor.Predecessor
	changed.Result.SHA256 = id("f")
	successor.Predecessor = &changed
	if successorProof.ValidateClosed(successor, grant, good.CLISHA256) == nil {
		t.Fatal("closed proof accepted a different predecessor")
	}
	t.Run("third-claim-binds-fixed-predecessors", func(t *testing.T) {
		third := input
		third.RecoveryRunID = strings.Repeat("e", 32)
		third.Predecessor = &StockPluginRecoveryPredecessor{RunID: current, Claim: file("stock-recovery-claim.json"), Run: file("predecessor/run.json"), Input: file("predecessor/input.json"), Invocation: file("predecessor/invocation.json"), Result: file("predecessor/stock-recovery.json"), Worker: file("predecessor/worker.json"), Failure: file("predecessor/failure.json")}
		third.PreAdmission = &StockPluginRecoveryPreAdmission{Predecessor: StockPluginRecoveryPredecessor{RunID: strings.Repeat("d", 32), Claim: file("stock-recovery-successor-claim.json"), Run: file("joined/run.json"), Input: file("joined/input.json"), Invocation: file("joined/cleanup/invocation.json"), Result: file("joined/cleanup/stock-recovery.json"), Worker: file("joined/cleanup/worker.json"), Failure: file("joined/cleanup/failure.json")}, CommandIndex: file("joined/cleanup/stock-plugin-evidence.json"), Diagnostic: file("joined/cleanup/stock-result-02.json"), Accounting: file(StockPluginRecoveryAdditionalAccountingName), Files: []StockPluginRecoveryPinnedFile{{File: file("pinned"), Mode: 0600}}}
		proof := good
		proof.RecoveryRunID, proof.AdmissionSHA256 = third.RecoveryRunID, third.ClaimSHA256()
		if third.Validate(old, third.RecoveryRunID) != nil || third.ClaimName() != StockPluginRecoveryPreAdmissionClaim || proof.ValidateClosed(third, grant, good.CLISHA256) != nil {
			t.Fatal("typed third claim did not bind its fixed relation")
		}
		third.PreAdmission.Files[0].File.SHA256 = id("f")
		if proof.ValidateClosed(third, grant, good.CLISHA256) == nil {
			t.Fatal("closed proof accepted different pinned predecessor bytes")
		}
	})
	noDispatch := good
	noDispatch.Commands = []StockPluginCommand{}
	noDispatch.ProductReserved = &BudgetReservation{Requests: 128, BodyBytes: 16 << 20, Objects: 128, ObjectBytes: 32 << 20, GeneratorRetires: 3}
	noDispatch.WorkRevisionID, noDispatch.WorkSnapshotID, noDispatch.ProductResultSHA256, noDispatch.ListResultSHA256 = "", "", "", ""
	noDispatch.Reflection, noDispatch.Retirement, noDispatch.ResidualExposure, noDispatch.StoreCleanup = "not-entered", "not-entered", "unknown", "not-entered"
	noDispatch.PrefixObservation = nil
	if noDispatch.ValidateNoDispatch(input, grant, good.CLISHA256) != nil || noDispatch.ValidateClosed(input, grant, good.CLISHA256) == nil {
		t.Fatal("no-dispatch proof changed historical provider-closure meaning")
	}
	t.Run("joined-failure-keeps-original-work-open", func(t *testing.T) {
		joined := noDispatch
		command := good.Commands[0]
		command.ExitCode = 3
		joined.Commands = []StockPluginCommand{command}
		joined.ProductResultSHA256 = command.ResultSHA256
		joined.Reflection, joined.Retirement, joined.ResidualExposure = "incomplete", "incomplete", "possible-live"
		if joined.ValidateNoDispatch(input, grant, good.CLISHA256) == nil || joined.ValidateClosed(input, grant, good.CLISHA256) == nil {
			t.Fatal("joined failed cleanup became no dispatch or proved original closure")
		}
	})
	for _, condition := range []string{"foreign-run", "foreign-claim", "foreign-prefix", "unjoined", "replay", "creates", "underreported-budget", "refilled-budget", "unknown", "prefix-incomplete", "foreign-digest", "command-slots"} {
		t.Run(condition, func(t *testing.T) {
			value, selected := good, input
			value.Commands = slices.Clone(good.Commands)
			reservation, observation := *good.ProductReserved, *good.PrefixObservation
			value.ProductReserved, value.PrefixObservation = &reservation, &observation
			switch condition {
			case "foreign-run":
				value.OriginalRunID = current
			case "foreign-claim":
				value.AdmissionSHA256 = id("f")
			case "foreign-prefix":
				value.Prefix += "-other"
			case "unjoined":
				value.Commands[0].Joined = false
			case "replay":
				value.Commands[0].Phase = "a0-created"
			case "creates":
				value.ProductReserved.GeneratorCreates = 1
			case "underreported-budget":
				value.ProductReserved.Requests--
			case "refilled-budget":
				value.ProductAllowance.Requests++
			case "unknown":
				value.ResidualExposure = "unknown"
			case "prefix-incomplete":
				value.PrefixObservation.Completed = false
			case "foreign-digest":
				value.OriginalEvidenceSHA256 = id("9")
			case "command-slots":
				selected.PriorCommands = MaximumStockPluginCommands - 1
			}
			if value.ValidateClosed(selected, grant, good.CLISHA256) == nil {
				t.Fatal("different, incomplete or refilled recovery proof admitted", condition)
			}
		})
	}
}
