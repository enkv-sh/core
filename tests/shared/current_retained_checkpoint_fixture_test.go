package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This controlled current fixture changes only the old source-key convention.
// Its value, private packets and actual named Hazard owners come from current
// production operations. It is not a conversion of the historical captures.
func currentMaterialKeyedRetainedSource(t *testing.T, env fixtureEnvironment, selected *StateSession, material contract.ID) *StateSession {
	t.Helper()
	selected = retainedReaderColdOpen(t, selected, env.Store)
	bad := *selected
	bad.support = slices.Clone(selected.support)
	for i := range bad.support {
		bad.support[i].Records = slices.Clone(selected.support[i].Records)
	}
	generatedMaterializeFixtureSupport(t, &bad)
	rows := bad.supportRecords()
	var source contract.ID
	for i := range rows {
		if rows[i].Kind != contract.RetainedCanonicalSupportKind {
			continue
		}
		canonical, err := contract.DecodeRetainedCanonicalRecord(rows[i].Body)
		if err != nil {
			t.Fatal("current material-keyed fixture source record", err)
		}
		if canonical.Entry.ValueState == material {
			if !source.IsZero() || rows[i].RecordID == material {
				t.Fatal("current baseline requires one modern retained source")
			}
			source, rows[i].RecordID = rows[i].RecordID, material
		}
	}
	if source.IsZero() {
		t.Fatal("current baseline omitted retained material")
	}
	work := mustSelectedGeneratedWork(t, selected)
	// The public cold Open already validated the complete original vectors.
	// Read each real owner's exact consumer vector from those selected facts.
	vectors := work.vectors
	var err error
	var carriers []contract.SupportRecord
	owners := make(map[contract.ID]bool)
	for i := range rows {
		if rows[i].Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		hazard, err := contract.InspectGeneratedHazardRecord(rows[i].Body)
		if err != nil {
			t.Fatal("current material-keyed fixture Hazard record", err)
		}
		consumers, err := vectors.resolve(contract.GeneratedHazardSupportKind, hazard.HazardID, contract.GeneratorVectorConsumers, hazard.Consumers)
		if err != nil {
			t.Fatal("current material-keyed fixture owner consumer vector", err)
		}
		changed := false
		for j, body := range consumers {
			consumer, err := contract.InspectGeneratorConsumer(body)
			if err != nil {
				t.Fatal("current material-keyed fixture consumer row", err)
			}
			if consumer.SubjectKind == contract.GeneratorConsumerRetainedCanonicalValue && consumer.SubjectID == source {
				consumer.SubjectID, changed = material, true
				consumers[j], err = contract.EncodeGeneratorConsumer(consumer)
				if err != nil {
					t.Fatal("current material-keyed fixture consumer encoding", err)
				}
			}
		}
		if !changed {
			continue
		}
		slices.SortFunc(consumers, bytes.Compare)
		descriptor, replacement := generatedVectorRowsForDomain(t, selected.root.Domain, contract.GeneratedHazardSupportKind, hazard.HazardID, contract.GeneratorVectorConsumers, consumers)
		hazard.Consumers = descriptor
		rows[i].Body, err = contract.EncodeGeneratedHazardRecord(hazard)
		if err != nil {
			t.Fatal("current material-keyed fixture Hazard encoding", err)
		}
		owners[hazard.HazardID] = true
		carriers = append(carriers, replacement...)
	}
	if len(owners) == 0 {
		t.Fatal("current source remap has no real outside owner")
	}
	rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal("current material-keyed fixture carrier record", err)
		}
		return carrier.OwnerKind == contract.GeneratedHazardSupportKind && owners[carrier.OwnerID] && carrier.VectorKind == contract.GeneratorVectorConsumers
	})
	rows = append(rows, carriers...)
	generatedRepackSupport(t, &bad, rows, work.bundles)
	if bad.head.Generator == nil || bad.head.Generator.Purpose != contract.GeneratorAuthorityFinal {
		t.Fatal("current source fixture requires the actual terminal Final")
	}
	for i := range bad.support {
		bad.support[i].Object, err = contract.GeneratorPhasePageID(bad.head.Generator.PhaseID, contract.RequiredSupportKind, bad.support[i].Index)
		if err != nil {
			t.Fatal("current material-keyed fixture phase page identity", err)
		}
	}
	generatedRefreshSupport(t, &bad, work.bundles...)
	// The fixture owns all refreshed bodies. Drop selected-reader facts before
	// deriving work records; they do not yet carry an authenticated root binding.
	generatedMaterializeFixtureSupport(t, &bad)
	store := cloneCheckpointStore(requireAdmittedMemoryStore(t, env.Store))
	for _, page := range bad.support {
		records := make([]contract.SupportRecord, len(page.Records))
		for i, row := range page.Records {
			records[i] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: records})
		if err != nil {
			t.Fatal("current material-keyed fixture support page encoding", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("current material-keyed fixture support page reference", err)
		}
		store.put(mustKey(t, store.desc.Prefix, ref), body)
	}
	shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
	if err != nil {
		t.Fatal("current material-keyed fixture administrative index encoding", err)
	}
	for _, shard := range shards {
		store.put(mustKey(t, store.desc.Prefix, shard.Ref), shard.Body)
	}
	subject := *bad.head.Generator
	bad.head.Generator = &subject
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: bad.root.Snapshot, Transition: bad.root.Transition, Revision: bad.head.Core.Revision}
	for _, ref := range bad.root.ValueEntryPages {
		if ref != nil {
			identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
		}
	}
	for _, ref := range bad.root.CurrentAccess.Core.AccessPageRefs {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	for _, ref := range bad.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		t.Fatal("current material-keyed fixture Final identity descriptor", err)
	}
	after, err := bad.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("current material-keyed fixture complete work records", err)
	}
	subject.AfterWork, err = bad.workSupportDescriptor(after)
	if err != nil {
		t.Fatal("current material-keyed fixture complete work descriptor", err)
	}
	store = retainedReaderSignedState(t, retainedReaderFixture{env: env, selected: selected}, &bad, store)
	opened := retainedReaderColdOpen(t, selected, store)
	if _, ok := mustSelectedGeneratedWork(t, opened).canonical[material]; !ok {
		t.Fatal("current authenticated source remap did not select legacy key")
	}
	// The next actual operation must use the controlled backing, not the
	// untouched healthy baseline Store.
	original := requireAdmittedMemoryStore(t, env.Store)
	original.objects, original.generation = store.objects, store.generation
	opened.store = env.Store
	return opened
}

// Produce a real healthy checkpoint first. The sole image edit then reproduces
// the historical saved-protection defect under the current authenticated format.
func currentUnsafeRetainedCheckpoint(t *testing.T, name string) (*StateSession, historicalRetainedCheckpointCapture, processFixture) {
	t.Helper()
	owners, mask := 0, uint8(contract.GeneratorValueChangeMembership)
	if name == "content-surviving-owner" {
		owners, mask = 1, contract.GeneratorValueChangeContent|contract.GeneratorValueChangeMembership
	} else if name != "membership-last-owner" {
		t.Fatal("unknown current retained checkpoint case")
	}
	prefix := newCurrentRetainedFinalPrefix(t, owners, mask, false, true)
	env, recorded := prefix.env, prefix.recorded
	prepared := prepareCheckpointFinal(t, env, recorded, t.Name()+" current positive checkpoint")
	candidate, result := recorded.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("current positive checkpoint claim", result)
	}
	checkpoint, result := recorded.selectCandidate(t.Context(), candidate)
	if checkpoint == nil || result.Outcome != ObservedCurrent {
		t.Fatal("current positive checkpoint selection", result)
	}
	env.Custody.RetireGenerated()
	checkpoint = retainedReaderColdOpen(t, checkpoint, env.Store)
	work := mustSelectedGeneratedWork(t, checkpoint)
	image, err := checkpoint.generatedFinalPreparationImage(t.Context(), work)
	if err != nil || len(image.Supplied) != 1 || len(image.Generated) != 1 {
		t.Fatal("current positive checkpoint image", err)
	}
	defer image.Clear()
	plan := checkpointFinalPlan(t, checkpoint, t.Name()+" current positive replay")
	defer plan.clearOwnedInputs()
	needs, err := checkpoint.generatedFinalPreparationNeedsReplacement(t.Context(), work, plan)
	if err != nil || needs {
		t.Fatal("healthy current checkpoint did not prove direct reuse", needs, err)
	}
	entry, err := contract.DecodeValueEntry(image.Supplied[0].EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicExclusionProtection(t, prefix.original, entry)
	fixture := finalizationCheckpointFixture{env: env, store: requireAdmittedMemoryStore(t, env.Store)}
	store := recommitCheckpointImageFixture(t, fixture, checkpoint, "valid", func(saved *contract.GeneratedFinalPreparationImage) {
		row := &saved.Supplied[0]
		legacy := ownScenarioValueEntry(prefix.original)
		legacy.Recipients = []contract.ID{prefix.authority}
		row.EntryBytes, err = contract.EncodeValueEntry(legacy)
		if err != nil {
			t.Fatal(err)
		}
		access := prefix.originalAccess
		access.Wraps = slices.Clone(access.Wraps)
		if mask&contract.GeneratorValueChangeContent != 0 {
			access.Wraps = slices.DeleteFunc(access.Wraps, func(w contract.WrapRow) bool {
				return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID != prefix.authority
			})
		}
		row.AccessRecord, err = contract.EncodeAccessRecord(access)
		if err != nil {
			t.Fatal(err)
		}
	})
	checkpoint = retainedReaderColdOpen(t, checkpoint, store)
	work = mustSelectedGeneratedWork(t, checkpoint)
	unsafeImage, err := checkpoint.generatedFinalPreparationImage(t.Context(), work)
	if err != nil {
		t.Fatal("controlled current unsafe image", err)
	}
	defer unsafeImage.Clear()
	admitted := generatedPlanInputFixture(t, checkpoint).context
	saved, err := checkpoint.generatedFinalRequestWithPreparation(t.Context(), admitted, true)
	if err != nil || saved == nil || saved.materialization == nil {
		t.Fatal("controlled current legacy image did not reach saved plan", err)
	}
	defer saved.clearOwnedInputs()
	if needs, err := checkpoint.generatedFinalPreparationNeedsReplacement(t.Context(), work, saved); err != nil || !needs {
		t.Fatal("controlled current legacy image missed replacement branch", needs, err)
	}
	capture := historicalRetainedCheckpointCapture{Original: prefix.original, OriginalAccess: prefix.originalAccess,
		OlderOwners: slices.Clone(prefix.owners), Mask: mask, CheckpointArtifacts: make(map[string][]byte)}
	capture.PreparedImage, err = contract.EncodeGeneratedFinalPreparationImage(unsafeImage)
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.DecodeAccessRecord(unsafeImage.Supplied[0].AccessRecord)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrap := range access.Wraps {
		if wrap.SubjectKind == contract.OrdinaryWrapSubject {
			capture.PreparedReaders = append(capture.PreparedReaders, wrap.SubjectID)
		}
	}
	for key, object := range store.objects {
		if key != store.desc.HeadKey {
			capture.CheckpointArtifacts[key] = bytes.Clone(object.Body)
		}
	}
	input := selectedGeneratedProcessFacts(t, checkpoint)
	input.Objects, input.Generation, input.GeneratedFinal = store.objects, store.generation, true
	input.GeneratedFinalCheckpoint = &generatedFinalCheckpointExpectation{Mode: "reuse", ImageID: work.preparation.Image.ContentID,
		MaterializationPhaseID: mustGeneratedPhaseID(work.preparation.MaterializationPhase)}
	capture.Checkpoint = input
	return checkpoint, capture, input
}
