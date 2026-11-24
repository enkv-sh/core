package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGCProtectsAbsentOriginalReplyAndDoesNotAdoptLateRecreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env, before, original, packet := resultlessCreateObligation(t, ctx, custody.GeneratedTerminalFailure)
	store := newGCInterleavingStore(env.Store.(*memoryStore))
	t.Cleanup(func() {
		t.Logf("original reply GC inventory: deletes=%d creates=%d cas=%d phases=%v", len(store.deleteCalls), store.creates, store.cas, store.phases)
	})
	key, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, original.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	_, present := store.objects[key]
	store.mu.Unlock()
	if present || len(packet) == 0 {
		t.Fatal("original result fixture did not retain a real absent reply coordinate")
	}
	preview, encoded := gcInterleavingPreview(t, ctx, before, store, []string{key}, "protected absent original reply")
	if len(preview.Targets) != 0 || len(preview.Candidates) != 1 || preview.Candidates[0].Classification != contract.GCCandidateProtected {
		t.Fatal("GC did not protect the absent retained original reply coordinate")
	}
	engine := gcInterleavingEngine(t, before, store, []string{key}, env.Trust)
	creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
	empty := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(env.Domain, "protected absent apply"), EncodedPlan: encoded})
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if empty.Validate() != nil || empty.StateResult != "no-op" || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs || len(store.deleteCalls) != 0 {
		t.Fatal("protected absent reply acquired GC mutation rights", empty.Result)
	}
	work := mustSelectedGeneratedWork(t, before)
	var successor generatedAttempt
	for _, attempt := range work.attempts {
		if attempt.record.PredecessorAttemptID == original.record.AttemptID {
			successor = attempt
		}
	}
	if successor.record.AttemptID.IsZero() {
		t.Fatal("original result fixture lost its actual successor")
	}
	warnings := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	ended := endGeneratedObligation(t, ctx, env, before, original.expected.Template.HazardID,
		[]contract.ID{original.expected.Template.HazardID, successor.expected.Template.HazardID}, before.currentEntryInputs(), warnings, original.material.Core.OperationMaterialID)
	// This exact packet came from the original producer before its Record was
	// lost. A later transport completion may still publish it after local exit.
	store.put(key, packet)
	plan, encoded := gcInterleavingPreview(t, ctx, ended, store, []string{key}, "ended original reply")
	if len(plan.Targets) != 1 {
		t.Fatal("ended original reply did not become reclaimable garbage")
	}
	engine = gcInterleavingEngine(t, ended, store, []string{key}, env.Trust)
	cleaned := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(env.Domain, "ended original apply"), EncodedPlan: encoded})
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if cleaned.Validate() != nil || cleaned.StateResult != "success" || len(store.deleteCalls) != 1 {
		t.Fatal("ended original GC did not confirm exact absence", cleaned.Result)
	}
	store.mu.Lock()
	_, present = store.objects[key]
	store.mu.Unlock()
	if present {
		t.Fatal("successful original GC did not establish the observed absence")
	}
	// A later duplicate PUT is outside the completed local observation. It
	// recreates garbage and cannot recreate the selected original owner.
	store.put(key, packet)
	current := gcInterleavingCurrent(t, ctx, OpenContext{admission: &ended.admission}, store)
	admitted := generatedPlanInputFixture(t, current).context
	admitted.AdmissionID, admitted.SessionID = fixtureID(env.Domain, "late GC Record admission"), fixtureID(env.Domain, "late GC Record session")
	reads, creates, cas := store.reads, store.creates, store.cas
	public, private := env.Custody.Calls()
	if plan, err := current.generatedRecordRequest(ctx, original.record.AttemptID, packet, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
		t.Fatal("late recreation regained original Record admission", err)
	}
	if plan, err := current.generatedFinalRequest(ctx, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
		t.Fatal("late recreation regained original Final admission", err)
	}
	if body, present, result := current.ReadGeneratedResult(ctx, original.record.AttemptID); len(body) != 0 || present || result != refused(AdmissionInvalid) {
		t.Fatal("late recreation regained an owner-based result read", result)
	}
	if result := current.persistGeneratedResult(ctx, generatedResultWrite{attempt: original.record.AttemptID, body: packet}); result != refused(AdmissionInvalid) {
		t.Fatal("late recreation regained an owner-based result write", result)
	}
	if store.reads != reads || store.creates != creates || store.cas != cas || len(store.deleteCalls) != 1 || !bytes.Equal(store.objects[key].Body, packet) {
		t.Fatal("late result refusal acquired effect rights or erased new garbage")
	}
	if p, q := env.Custody.Calls(); p != public || q != private {
		t.Fatal("late result refusal entered private custody")
	}
	resumer := gcInterleavingEngine(t, current, store, []string{key}, env.Trust)
	resumed := resumer.Continue(ctx, GCContinueRequest{RequestNonce: fixtureID(env.Domain, "completed GC continuation"), OperationID: plan.OperationID})
	if err := resumer.Close(); err != nil {
		t.Fatal(err)
	}
	if resumed.StateResult == "success" || len(store.deleteCalls) != 1 || !bytes.Equal(store.objects[key].Body, packet) {
		t.Fatal("completed GC inferred historical success or deleted a recreated object", resumed.Result)
	}
	t.Logf("original reply lifetime: producer_packet=1 protected_noop=1 local_exit=1 delete_joined=1 late_put=1 owner_refusals=4")
}

// full_only: false
func TestGCActiveLocalAndMixedGraphPublicReadersProtectAdmittedInboxes(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "local"
		if mixed {
			name = "managed with future local"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			author := buildInstalledLocalAuthor(t, false)
			local := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: author.config.Artifact.ConfigContractID, Intent: installedLocalCanonicalIntent()}
			input := []ApplyEntryInput{{Name: "omega", ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: local}}
			if mixed {
				process, _ := installedGeneratedRetirementProcess(t, "acknowledged")
				f.env.GeneratedProcess = process
				remote := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual, ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
				input = append([]ApplyEntryInput{{Name: "alpha", ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: remote}}, input...)
			}
			admissions := 0
			engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions)
			t.Cleanup(engine.Close)
			producer := engine.installation.Generated.AdmitProducer
			checked := false
			var checkOnce sync.Once
			observationContext := ctx
			engine.installation.Generated.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := producer(ctx, q, control, input, implementation, deadline)
				if err != nil {
					return nil, err
				}
				invoke := owner.InvokeProducer
				owner.InvokeProducer = func(ctx context.Context, attempt, transmission contract.ID) contract.GeneratedProducerResult {
					checkOnce.Do(func() {
						checked = true
						ctx := observationContext
						selected := f.open(t, ctx)
						g := mustSelectedGeneratedWork(t, selected)
						if g.parent == nil || g.phase == nil || g.phase.LineageIndex != 0 {
							t.Fatal("first real producer has no initial selected frontier")
						}
						graph := g.bundles[0]
						var inboxes []contract.ID
						localCount, managedCount, cleanupCount := 0, 0, 0
						for _, lineage := range graph.Lineages {
							switch {
							case lineage.Purpose == contract.GeneratorLineageCreate && lineage.Name == "omega":
								if lineage.TemplateCount != 1 || lineage.Templates[0].LifecycleMode != contract.GeneratorLifecycleNone {
									t.Fatal("local CREATE has managed branches")
								}
								inboxes = append(inboxes, lineage.Templates[0].InboxID)
								localCount++
							case lineage.Purpose == contract.GeneratorLineageCreate && lineage.Name == "alpha":
								if !mixed || lineage.TemplateCount != 2 || lineage.Templates[0].LifecycleMode != contract.GeneratorLifecycleManaged {
									t.Fatal("managed CREATE fixture changed")
								}
								for _, create := range lineage.Templates[:lineage.TemplateCount] {
									inboxes = append(inboxes, create.InboxID)
								}
								managedCount++
							case lineage.Purpose == contract.GeneratorLineageCleanup:
								if !mixed || lineage.TemplateCount != 1 {
									t.Fatal("unexpected cleanup lineage")
								}
								inboxes = append(inboxes, lineage.Templates[0].InboxID)
								cleanupCount++
							default:
								t.Fatal("unplanned lineage in active graph")
							}
						}
						wantCount := 1
						if mixed {
							wantCount = 5
						}
						if localCount != 1 || len(inboxes) != wantCount || mixed && (managedCount != 1 || cleanupCount != 2) {
							t.Fatal("wrong admitted lifecycle closure", localCount, managedCount, cleanupCount, len(inboxes))
						}
						want := gcExpectedSelectedKeys(selected)
						var keys []string
						for _, inbox := range inboxes {
							key := fmt.Sprintf("%s/%x/result/%x", selected.admission.store.Prefix, selected.root.Domain, inbox)
							keys = append(keys, key)
							want = append(want, key)
							if read := f.env.Store.Read(ctx, key, uint32(contract.GeneratedResultRecordMaxLength)); read.Status != contract.ReadMissing {
								t.Fatal("pre-producer adoptable inbox is not absent", read.Status)
							}
						}
						marks, err := gcMarkSelected(g.image, g, selected.admission.store)
						if err != nil {
							t.Fatal("valid installed lifecycle graph blocked GC marking", err)
						}
						gcCheckMarkKeys(t, selected, marks, want)
						reader, err := NewInstalledCapacityReader(gcInterleavingReadInput(t, selected, f.env.Store, keys))
						if err != nil {
							t.Fatal(err)
						}
						defer reader.Close()
						capacity := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: fixtureID(selected.root.Domain, name+" active capacity")})
						if capacity.StateResult != PublicQuerySuccess {
							t.Fatal("valid installed graph blocked capacity", capacity.Result)
						}
						preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: fixtureID(selected.root.Domain, name+" active GC preview"), OperationID: fixtureID(selected.root.Domain, name+" active GC operation")})
						if preview.StateResult != PublicQuerySuccess || preview.Payload == nil || len(preview.Payload.Plan.Targets) != 0 || len(preview.Payload.Plan.Candidates) != len(keys) {
							t.Fatal("valid active graph blocked GC preview", preview.Result)
						}
						for _, candidate := range preview.Payload.Plan.Candidates {
							if candidate.Classification != contract.GCCandidateProtected {
								t.Fatal("absent admitted inbox became collectible", candidate.Classification)
							}
						}
						proof, result := reader.ValidateGCPlan(ctx, preview.Payload.EncodedPlan)
						if proof == nil || result.Outcome != ObservedCurrent {
							t.Fatal("valid active graph blocked plan validation", result)
						}
					})
					return invoke(ctx, attempt, transmission)
				}
				return owner, nil
			}
			result := engine.Apply(ctx, fixtureID(f.env.Domain, name+" mark reservation"), input)
			engine.Close()
			if !checked || result.Result.Outcome != ObservedCurrent {
				t.Fatal("installed generation did not finish after GC reads", checked, result.Result)
			}
			cold := f.open(t, ctx)
			if !cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.GeneratedCurrent != uint32(len(input)) {
				t.Fatal("GC observation changed terminal generation progress")
			}
		})
	}
}
