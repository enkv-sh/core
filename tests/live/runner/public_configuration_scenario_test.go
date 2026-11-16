package core

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

func runPublicConfiguration(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("public worker unavailable")
	}
	worker.Result.Actor = input.Participants["authority"]
	budget := &runBudget{limits: input.Limits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("public inventory owner unavailable")
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), time.Duration(input.Limits.ElapsedSeconds)*time.Second)
	defer cancel()
	row, ok := catalog.PublicConfiguration(input.Scenarios[0])
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	administrative := publicAuthorityOperator(input)
	if !known || !ok && !administrative || len(execution.Writer) != 3 {
		t.Fatal("public scenario contract unavailable")
	}
	begin := func(index int) uint64 {
		sequence, err := worker.BeginStep(execution.Writer[index].Step, input.Participants[execution.Writer[index].Step.Role])
		if err != nil {
			t.Fatal("public step record unavailable")
		}
		return sequence
	}
	sequence := begin(0)
	directory := filepath.Join(inv.StateDir, "public-source")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("new public source owner unavailable")
	}
	source := filepath.Join(directory, "configuration.json")
	publicSetupSource(t, input, source)
	marker := contract.Hash([]byte(input.Prefix))
	cleaner, err := openPublicPrefixCleaner(ctx, input, marker, inv.StateDir)
	if err != nil {
		t.Fatal("public cleanup context unavailable")
	}
	if !budget.reserve(16, 16*operationBodyAllowance, "", 0) || cleaner.Check(ctx) != nil {
		t.Fatal("public fixture bucket admission failed")
	}
	keys, err := scanOperatorPrefix(ctx, cleaner, budget, input.Prefix+"/")
	if err != nil || len(keys) != 0 {
		t.Fatal("public unique-prefix empty preflight failed")
	}
	ledger := publicOwnership{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: settingsBinding(input.Settings), Source: source, PreflightEmpty: true}
	if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
		t.Fatal("public ownership ledger unavailable")
	}
	liveEndPhase(t, worker, sequence, true)
	sequence = begin(1)
	initRole := "authority"
	if row.DeniedRole != "" {
		initRole = row.DeniedRole
	}
	var operatorFacts *publicOperatorFacts
	var replacementFacts *publicReplacementFacts
	var inspectionFacts *publicInspectionFacts
	var capacityGCFacts *publicCapacityGCFacts
	var materializationFacts *publicMaterializationFacts
	var manifestFacts *publicManifestFacts
	var outputFacts []publicOutputCoordinate
	var initialized publicChildResult
	initialSource := source
	setupDigest := contract.Hash(publicSourceImage(t, source).Files[source])
	if row.Condition == "empty-initialization" {
		// The same selected authority login can enroll this public key while its
		// actual recipient decrypt permission is independently denied.
		publicRecipientPrivateDenied(t, ctx, inv, input, budget)
		initialized, initialSource = publicCompetingInitialization(t, ctx, inv, input, budget, source)
	} else {
		initialized = publicCLI(t, ctx, inv, input, budget, initRole, false, nativeprocess.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json")
	}
	initialProduct := publicProduct(t, initialized, "initialize-empty-domain")
	clear(initialized.Body)
	denied := row.DeniedRole != ""
	if denied {
		if initialized.Code == 0 || initialProduct.Payload.Domain != "" || initialProduct.Receipt != "" || initialProduct.OperationPayload != "none" || initialProduct.State == "success" || initialProduct.State == "exact-resume" {
			t.Fatal("failed qualification advertised a ready domain")
		}
		role := map[string]string{"denied-public": "public", "denied-normal-signing": "normal", "denied-authority-private": "authority", "denied-recovery-signing": "recovery-signing", "denied-recovery-private": "recovery-private"}[row.DeniedRole]
		if err := publicDenied(initialized.Capture, role); err != nil {
			t.Fatal(err)
		}
		// The exact delivered pair is observed with a separately selected GET-only
		// context. Absence cannot be converted into a local ready assertion.
		result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "plan", "--trusted", source, "--trusted-format", "json", "--json")
		product := publicProduct(t, result, contract.ReaderCompareOperation)
		clear(result.Body)
		if result.Code == 0 || product.State == "success" {
			t.Fatal("failed qualification became publicly ready")
		}
		// No HEAD is expected; LIST is a fixture-only independent visibility check.
		keys, err = scanOperatorPrefix(ctx, cleaner, budget, input.Prefix+"/")
		if err != nil || slices.Contains(keys, input.Prefix+"/HEAD") {
			t.Fatal("failed qualification published HEAD")
		}
	} else {
		if initialized.Code != 0 || initialProduct.State != "success" || initialProduct.Payload.Domain == "" {
			t.Fatal("public initialization did not authenticate empty domain")
		}
		head := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
		publicAssertInitialization(t, ctx, input, initialSource, setupDigest, initialProduct, head)
		if administrative {
			publicOperatorPlainSet(t, ctx, inv, input, budget, source)
			env, selected, consumer, genesis := publicOperatorSetup(t, ctx, inv, input, budget, source)
			env.FreshCurrent = func(tb testing.TB, _ OpenContext, current *StateSession) {
				operatorFacts = &publicOperatorFacts{Basis: current.admission.publicBasis(), Descriptor: current.store.Descriptor(), Genesis: genesis, Consumer: consumer, Expected: observeSelectedState(tb, current)}
			}
			_, source = runPublicAuthorityOperatorScenario(t, ctx, env, selected, input.Scenarios[0], inv, input, budget, source)
			if operatorFacts == nil {
				t.Fatal("administrative complete fresh facts unavailable")
			}
		} else if row.Condition == "manifest" {
			manifestFacts, outputFacts = runPublicManifest(t, ctx, inv, input, budget, row, source)
		} else if row.Condition == "materialization" {
			materializationFacts = runPublicMaterialization(t, ctx, inv, input, budget, source)
		} else if row.Condition == "capacity-gc" {
			capacityGCFacts = runPublicCapacityGC(t, ctx, inv, input, budget, source)
		} else if row.Condition == "inspection-receipts" {
			inspectionFacts = runPublicInspectionReceipts(t, ctx, inv, input, budget, source, initialProduct)
		} else if row.Output {
			outputFacts = runPublicOutput(t, ctx, inv, input, budget, row, source)
		} else if row.Generated {
			runPublicGeneratedLifecycle(t, ctx, inv, input, budget, row, source)
		} else if row.Replacement != nil {
			source, replacementFacts = runPublicReplacement(t, ctx, inv, input, budget, *row.Replacement, source)
		} else if row.Condition == "recipient-lifecycle" {
			source = runPublicRecipientLifecycle(t, ctx, inv, input, budget, source)
		} else if row.Condition == "prepare-complete-loss" {
			source = runPublicPrepareCompleteLoss(t, ctx, inv, input, budget, source)
		} else if row.Condition != "empty-initialization" {
			source = runPublicConfigurationTransition(t, ctx, inv, input, budget, row, source)
		}
	}
	liveEndPhase(t, worker, sequence, true)
	sequence = begin(2)
	if inspectionFacts != nil {
		portable := publicPortablePair(t, source, filepath.Join(inv.StateDir, "portable-pair"))
		publicInspectionReceiptsFresh(t, ctx, inv, input, budget, portable, *inspectionFacts)
	} else if !denied && !administrative {
		portable := publicPortablePair(t, source, filepath.Join(inv.StateDir, "portable-pair"))
		if materializationFacts != nil {
			publicObserveMaterializationPair(t, ctx, inv, input, budget, portable, *materializationFacts)
		} else {
			publicObservePair(t, ctx, inv, input, budget, portable)
		}
		if row.Condition == "portable-validation" {
			publicObserveMismatch(t, ctx, inv, input, budget, source)
			publicRefuseDamagedPairs(t, ctx, inv, input, budget, source)
		}
		publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
	} else if denied {
		keys, err = scanOperatorPrefix(ctx, cleaner, budget, input.Prefix+"/")
		if err != nil || slices.Contains(keys, input.Prefix+"/HEAD") {
			t.Fatal("qualification failure left ready HEAD")
		}
	} else {
		publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
	}
	domain, domainErr := publicSourceDomain(source)
	if !denied && domainErr != nil {
		t.Fatal("ready public Domain unavailable")
	}
	if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil {
		t.Fatal("public ledger lost")
	}
	if domainErr == nil {
		ledger.Domain = hex.EncodeToString(domain[:])
	}
	if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
		t.Fatal("public Domain evidence unavailable")
	}
	facts := publicProcessFacts{RunID: input.RunID, Prefix: input.Prefix, Source: publicPortablePair(t, source, filepath.Join(inv.StateDir, "fresh-pair")), Domain: ledger.Domain, ExpectReady: !denied, Operator: operatorFacts, Replacement: replacementFacts}
	facts.Outputs = outputFacts
	facts.Inspection = inspectionFacts
	facts.CapacityGC = capacityGCFacts
	facts.Materialization = materializationFacts
	facts.Manifest = manifestFacts
	if writeNewLiveJSON(filepath.Join(inv.StateDir, "after.json"), facts) != nil {
		t.Fatal("public fresh observation facts unavailable")
	}
	worker.Result.FreshChecks = []records.FreshCheck{{Facts: "after.json"}}
	liveEndPhase(t, worker, sequence, true)
}

func publicFreshPairSourceValid(stateDir, source string) bool {
	path, err := records.SafePath(stateDir, filepath.Join("fresh-pair", filepath.Base(source)))
	if err != nil || path != source {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func runPublicConfigurationFresh(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("public fresh worker unavailable")
	}
	role := "reader"
	if publicAuthorityOperator(input) {
		role = "recipient-consumer"
	}
	worker.Result.Actor = input.Participants[role]
	budget := &runBudget{limits: input.Limits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, budget)
	var facts publicProcessFacts
	path, err := records.SafePath(inv.StateDir, inv.Facts)
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if err != nil || !known || len(execution.FreshAfter) != 1 || inv.Role != "fresh_after" || records.ReadJSON(path, &facts) != nil || facts.RunID != input.RunID || facts.Prefix != input.Prefix || !publicFreshPairSourceValid(inv.StateDir, facts.Source) {
		t.Fatal("public fresh pair facts refused")
	}
	sequence, err := worker.BeginStep(execution.FreshAfter[0].Step, input.Participants[role])
	if err != nil {
		t.Fatal("public fresh step record unavailable")
	}
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), 2*time.Minute)
	defer cancel()
	row, _ := catalog.PublicConfiguration(input.Scenarios[0])
	if !publicCapacityGCFreshFactsValid(row.Condition, facts, input.RunID, input.Prefix) {
		t.Fatal("fresh capacity/GC fact variant refused")
	}
	if !publicMaterializationFreshFactsValid(row.Condition, facts) {
		t.Fatal("fresh materialization fact variant refused")
	}
	if !publicManifestFreshFactsValid(row.Condition, facts) {
		t.Fatal("fresh manifest fact variant refused")
	}
	if row.Condition == "manifest" {
		publicManifestFresh(t, ctx, inv, input, budget, facts.Source, *facts.Manifest)
		liveEndPhase(t, worker, sequence, true)
		return
	}
	if row.Condition == "materialization" {
		publicMaterializationFresh(t, ctx, inv, input, budget, facts.Source, *facts.Materialization)
		liveEndPhase(t, worker, sequence, true)
		return
	}
	if publicAuthorityOperator(input) {
		if facts.Operator == nil || !facts.ExpectReady || facts.Domain != operatorIDText(facts.Operator.Expected.Root.Domain) {
			t.Fatal("administrative fresh public basis unavailable")
		}
		publicOperatorFresh(t, ctx, inv, input, budget, *facts.Operator)
		liveEndPhase(t, worker, sequence, true)
		return
	}
	if row.Condition == "capacity-gc" || facts.CapacityGC != nil {
		publicCapacityGCFresh(t, ctx, inv, input, budget, facts.Source, *facts.CapacityGC)
		liveEndPhase(t, worker, sequence, true)
		return
	}
	if row.Condition == "inspection-receipts" || facts.Inspection != nil {
		if row.Condition != "inspection-receipts" || facts.Inspection == nil || facts.Operator != nil || facts.Replacement != nil || !facts.ExpectReady || facts.Domain != facts.Inspection.Domain {
			t.Fatal("fresh inspection facts refused")
		}
		publicInspectionReceiptsFresh(t, ctx, inv, input, budget, facts.Source, *facts.Inspection)
		liveEndPhase(t, worker, sequence, true)
		return
	}
	if facts.Replacement != nil {
		row, known := catalog.PublicConfiguration(input.Scenarios[0])
		if !known || row.Replacement == nil || facts.Operator != nil || !facts.ExpectReady || facts.Replacement.Target != row.Replacement.Target {
			t.Fatal("fresh replacement facts refused")
		}
		publicReplacementFresh(t, ctx, inv, input, budget, facts.Source, *facts.Replacement)
		liveEndPhase(t, worker, sequence, true)
		return
	}
	if facts.Operator != nil {
		t.Fatal("ordinary public scenario received administrative facts")
	}
	if facts.ExpectReady {
		publicObservePair(t, ctx, inv, input, budget, facts.Source)
		if row, ok := catalog.PublicConfiguration(input.Scenarios[0]); ok && row.Generated {
			result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "generated", "list", "--source", facts.Source, "--source-format", "json", "--json")
			view := publicGeneratedOutcome(t, result, "success", 0)
			if len(view.Current) != 0 || len(view.Duties) != 0 {
				t.Fatal("fresh public generated terminal observation differs")
			}
		}
	} else {
		image := publicSourceImage(t, facts.Source)
		result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "plan", "--trusted", facts.Source, "--trusted-format", "json", "--json")
		product := publicProduct(t, result, contract.ReaderCompareOperation)
		clear(result.Body)
		if result.Code == 0 || product.State == "success" {
			t.Fatal("fresh failed-qualification pair advertised readiness")
		}
		publicImageUnchanged(t, image)
	}
	// Child-native captures remain the separate evidence for the executable.
	// A failed qualification cannot turn reader unavailability into absence:
	// S3 GET without ListBucket can return403 for an absent object. The exact
	// independently selected cleanup context owns the complete LIST proof.
	domain := contract.Hash([]byte(input.Prefix))
	if facts.Domain != "" {
		raw, err := hex.DecodeString(facts.Domain)
		if err != nil || len(raw) != len(domain) {
			t.Fatal("fresh public Domain malformed")
		}
		copy(domain[:], raw)
	}
	if !facts.ExpectReady {
		cleaner, err := openPublicPrefixCleaner(ctx, input, domain, inv.StateDir)
		if err != nil {
			t.Fatal("fresh owned absence observation unavailable")
		}
		keys, err := scanOperatorPrefix(ctx, cleaner, budget, input.Prefix+"/")
		if err != nil || slices.Contains(keys, input.Prefix+"/HEAD") {
			t.Fatal("fresh failed qualification has no complete absence proof")
		}
		liveEndPhase(t, worker, sequence, true)
		return
	}
	// Worker-local telemetry describes this independent ready-state GET.
	store, err := openPublicReaderStore(ctx, input, domain, inv.StateDir)
	if err != nil {
		t.Fatal("fresh independent GET context unavailable")
	}
	read, _ := cleanupRead(ctx, recordedStore{Store: store, budget: budget}, input.Prefix+"/HEAD", contract.MaxHeadLength)
	if read.Status != contract.ReadOK {
		t.Fatal("fresh independently selected HEAD differs")
	}
	liveEndPhase(t, worker, sequence, true)
}
