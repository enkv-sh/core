package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

type stockPrefixInspection struct {
	Empty    bool
	Identity string
	Prefix   string
}

type stockStorePrefix struct {
	Inspect func(context.Context, *runBudget) (stockPrefixInspection, error)
	Clean   func(context.Context, *runBudget) (bool, error)
}

func stockExistingRun(t testing.TB, inv records.Invocation, input liveRunInput, budget *runBudget) *stockPluginRun {
	t.Helper()
	evidence, err := records.ReadStockPluginEvidence(stockEvidencePath(inv))
	if err != nil || evidence.RunID != input.RunID || evidence.Scenario != records.StockPluginScenario || evidence.Provider != input.Settings.Provider || evidence.Prefix != input.Prefix || evidence.FixtureID != input.PublicConfiguration.Stock.Fixture.FixtureID || evidence.CLISHA256 != input.PublicConfiguration.Stock.Artifact.CLI.SHA256 {
		t.Fatal("stock original safe evidence unavailable")
	}
	return &stockPluginRun{t: t, inv: inv, input: input, budget: budget, homes: map[string]string{}, evidence: evidence}
}

func runStockPluginAcceptanceFresh(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("stock independent Reader owner unavailable")
	}
	worker.Result.Actor = input.Participants["reader"]
	budget := &runBudget{limits: input.Limits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("stock independent Reader private owner unavailable")
	}
	defer lease.Close()
	if !livePublicConfigurationAdmitted(input) || inv.Role != "fresh_after" {
		t.Fatal("stock independent Reader admission refused")
	}
	var facts publicProcessFacts
	path, err := records.SafePath(inv.StateDir, inv.Facts)
	execution, known := catalog.ExecutionForRecovery(input.Scenarios[0], "live", input.RecoveryMode)
	if err != nil || !known || len(execution.FreshAfter) != 1 || records.ReadJSON(path, &facts) != nil || facts.RunID != input.RunID || facts.Prefix != input.Prefix || !facts.ExpectReady || !publicFreshPairSourceValid(inv.StateDir, facts.Source) {
		t.Fatal("stock exact portable Reader pair refused")
	}
	sequence, err := worker.BeginStep(execution.FreshAfter[0].Step, worker.Result.Actor)
	if err != nil {
		t.Fatal("stock independent Reader step unavailable")
	}
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), 2*time.Minute)
	defer cancel()
	r := stockExistingRun(t, inv, input, budget)
	image := publicSourceImage(t, facts.Source)
	child := r.command(ctx, "post-exit-reader", "reader", "", nil, "plan", "--trusted", facts.Source, "--trusted-format", "json", "--json")
	defer clear(child.Body)
	product := publicProduct(t, child, contract.ReaderCompareOperation)
	if child.Code != 0 || product.State != "success" || product.Payload.Verdict != "match" || !product.Payload.Complete || len(product.Payload.Scope) != 12 {
		t.Fatal("stock post-exit Reader did not completely match")
	}
	for _, scope := range product.Payload.Scope {
		if scope.Status != "complete" {
			t.Fatal("stock post-exit Reader scope incomplete")
		}
	}
	current := r.list(ctx, facts.Source)
	if len(current.Current) != 0 || len(current.Duties) != 0 || len(current.Hazards) != 0 {
		t.Fatal("stock post-exit generated work remains")
	}
	publicImageUnchanged(t, image)
	r.assert("post-exit-reader")
	liveEndPhase(t, worker, sequence, true)
}

// Stock cleanup requires successful provider teardown and every original child
// join. Missing evidence never becomes a reason to scan or delete a token name.
func stockProviderWorkClosed(evidence records.StockPluginEvidence) bool {
	for _, required := range []string{"final-generation-retired", "post-exit-reader", "outputs-published", "cloud-output-values-equal", "manifest-complete", "reconstruction-canonical"} {
		if !slices.Contains(evidence.Assertions, required) {
			return false
		}
	}
	if len(evidence.Generations) != 3 || len(evidence.Duties) != 3 || len(evidence.Commands) == 0 || len(evidence.Commands) > stockMaximumCommands {
		return false
	}
	for _, command := range evidence.Commands {
		if !command.Started || !command.Joined {
			return false
		}
	}
	if len(evidence.Outputs) == 0 {
		return false
	}
	for _, output := range evidence.Outputs {
		if !output.Published || output.Deletion != "absent" && output.Deletion != "scheduled" && output.Deletion != "acknowledged" {
			return false
		}
	}
	return true
}

func runStockPluginAcceptanceCleanup(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	if input.StockRecovery != nil {
		runStockFailedWriterCleanup(t, inv, input, failure)
		return
	}
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("stock cleanup owner unavailable")
	}
	worker.Result.Actor = input.Participants["cleanup"]
	worker.Result.Cleanup = &records.Cleanup{Outcome: "unresolved"}
	limits := input.Limits
	limits.Requests, limits.BodyBytes = limits.CleanupRequests, limits.CleanupBytes
	limits.GeneratorCreates = 0
	budget := &runBudget{limits: limits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("stock cleanup private owner unavailable")
	}
	defer lease.Close()
	if !livePublicConfigurationAdmitted(input) {
		t.Fatal("stock cleanup admission refused")
	}
	if validateStockSDKContext(input, "cleanup") != nil {
		t.Fatal("stock cleanup credential source changed")
	}
	r := stockExistingRun(t, inv, input, budget)
	if !stockProviderWorkClosed(r.evidence) || r.evidence.ValidateBeforeCleanup(*input.PublicConfiguration.Stock) != nil {
		t.Fatal("stock unresolved provider work or original child prevents prefix cleanup")
	}
	var grant records.StockPluginGrant
	if records.ReadJSON(stockGrantPath(inv), &grant) != nil || grant.Validate() != nil || grant.RunID != input.RunID || grant.Scenario != input.Scenarios[0] || grant.Prefix != input.Prefix || !reflect.DeepEqual(grant.Fixture, input.PublicConfiguration.Stock.Fixture) {
		t.Fatal("stock original prefix grant refused")
	}
	limitBody, err := json.Marshal(input.Limits)
	if err != nil || bodyDigest(limitBody) != grant.LimitsSHA256 {
		t.Fatal("stock original fixture allowance changed")
	}
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), time.Duration(input.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	sequence := liveBeginPhase(t, worker, "cleanup", true)
	original := &stockPrefixInspection{Empty: grant.PreflightEmpty, Identity: grant.BucketIdentity, Prefix: grant.Prefix}
	store, err := openStockStorePrefix(ctx, input, inv.StateDir, original)
	if err != nil {
		t.Fatal("stock exact Store prefix cleanup context unavailable")
	}
	inspection, err := store.Inspect(ctx, budget)
	if err != nil || inspection.Identity != grant.BucketIdentity || inspection.Prefix != grant.Prefix {
		t.Fatal("stock Store prefix or bucket identity changed")
	}
	attemptPath := filepath.Join(inv.StateDir, "stock-prefix-cleanup.json")
	attempt := records.StockPluginPrefixCleanup{Schema: 1, RunID: input.RunID, FixtureID: grant.Fixture.FixtureID, Prefix: input.Prefix, BucketIdentity: grant.BucketIdentity, Started: true}
	if _, err := os.Lstat(attemptPath); !os.IsNotExist(err) {
		t.Fatal("stock original prefix cleanup already entered; unresolved attempt is not replayable")
	}
	if records.WriteJSONExclusive(attemptPath, attempt, records.MaximumJSONBytes) != nil {
		t.Fatal("stock prefix cleanup intent could not be retained")
	}
	empty, err := store.Clean(ctx, budget)
	if err != nil || !empty {
		t.Fatal("stock prefix cleanup did not observe absence; original attempt retained")
	}
	attempt.Completed, attempt.ObservedEmpty = true, true
	if attempt.Validate(grant) != nil || records.WriteJSON(attemptPath, attempt, 0600) != nil {
		t.Fatal("stock final prefix observation could not be retained")
	}
	r.assert("store-prefix-observed-empty")
	remaining, unknown := int64(0), int64(0)
	for _, output := range r.evidence.Outputs {
		if output.Deletion == "scheduled" {
			remaining++
		}
	}
	worker.Result.Cleanup.RemainingOwnedObjects = &remaining
	worker.Result.Cleanup.UnknownEffects = &unknown
	worker.Result.Cleanup.Outcome = "passed"
	liveEndPhase(t, worker, sequence, true)
}

// full_only: false
func TestStockPrefixCleanupRequiresClosedProviderWorkAndOriginalJoins(t *testing.T) {
	base := records.StockPluginEvidence{Assertions: []string{"final-generation-retired", "post-exit-reader", "outputs-published", "cloud-output-values-equal", "manifest-complete", "reconstruction-canonical"}, Generations: make([]records.StockPluginGeneration, 3), Duties: make([]records.StockPluginDuty, 3), Commands: []records.StockPluginCommand{{Started: true, Joined: true}}, Outputs: []records.StockPluginOutput{{Published: true, Deletion: "absent"}}}
	for _, condition := range []string{"exact", "unjoined", "unstarted", "pending-output", "missing-provider-step", "missing-lineage"} {
		t.Run(condition, func(t *testing.T) {
			v := base
			v.Commands = slices.Clone(base.Commands)
			v.Outputs = slices.Clone(base.Outputs)
			switch condition {
			case "unjoined":
				v.Commands[0].Joined = false
			case "unstarted":
				v.Commands[0].Started = false
			case "pending-output":
				v.Outputs[0].Deletion = ""
			case "missing-provider-step":
				v.Assertions = v.Assertions[1:]
			case "missing-lineage":
				v.Generations = v.Generations[:2]
			}
			if stockProviderWorkClosed(v) != (condition == "exact") {
				t.Fatal("stock cleanup lost its original provider/join prerequisites")
			}
		})
	}
}
