package core

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
func TestEndWorkReserveFallbackFromAuthenticHistory(t *testing.T) {
	ctx := t.Context()
	env := memoryScenarioEnvironmentMode(t, false)
	env.Context = ctx
	store := env.Store.(*memoryStore)
	if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal("reserve history file-backed Store", err)
	}
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
	fixture.admission = capacityFixtureAdmission(t, fixture.admission)
	fixture.session.admission = *fixture.admission.admission
	seed := *fixture.session.valueEntry(0)
	cold := func(t *testing.T, store *memoryStore, selected *StateSession) *StateSession {
		t.Helper()
		opened, result := Open(t.Context(), OpenContext{admission: &selected.admission}, store)
		if opened == nil || result.Outcome != ObservedCurrent {
			t.Fatal("reserve history cold Open", result)
		}
		return opened
	}
	measure := func(t *testing.T, label string, store *memoryStore, selected *StateSession) int64 {
		t.Helper()
		indexBytes, err := format.AdministrativeIndexEncodedLength(selected.adminIndex)
		if err != nil {
			t.Fatal("reserve history selected index", err)
		}
		shards, err := format.AdministrativeIndexShardCount(indexBytes)
		if err != nil || shards != uint32(1+len(selected.root.AdministrativeIndexShards)) {
			t.Fatal("reserve history selected shard count", err)
		}
		var expansion uint64
		for _, page := range selected.adminIndex.Pages {
			for _, span := range page.Spans {
				expansion += uint64(span.Count-1) * uint64(7+2*len(span.GroupIndexes))
			}
		}
		var intentPages, intentIndexBytes uint64
		if selected.root.Generated.GeneratedCurrent != 0 {
			// The absolute selected-current bound has 49 fragments and 25 pages.
			intentPages = 25
			intentIndexBytes = 115*25 + 37*49 + 2*49*uint64(len(selected.adminIndex.Groups))
		}
		boundShards, err := format.AdministrativeIndexShardCount(indexBytes + 19211 + expansion + intentIndexBytes)
		if err != nil {
			t.Fatal("reserve history fast-path index bound", err)
		}
		fastChildren := int64(selected.root.ChildCount) + 2 + int64(intentPages) + int64(boundShards) - int64(shards)
		if err := selected.reserveFirstEndWork(t.Context()); err != nil {
			t.Fatal("admitted reserve history first-exit reserve", err)
		}
		store.mu.Lock()
		objects := len(store.objects)
		var immutableBytes uint64
		for key, value := range store.objects {
			if key == store.desc.HeadKey {
				continue
			}
			if value.bodyPath != "" {
				immutableBytes += value.bodyLength
			} else {
				immutableBytes += uint64(len(value.Body))
			}
		}
		store.mu.Unlock()
		store.fileBodies.mu.Lock()
		fileBytes, fileCount := store.fileBodies.used, store.fileBodies.next
		store.fileBodies.mu.Unlock()
		t.Logf("reserve history %s: selected_children=%d selected_child_bytes=%d support_pages=%d fragments=%d groups=%d duties=%d hazards=%d current_generated=%d index_bytes=%d index_shards=%d span_expansion=%d intent_pages=%d intent_index_bytes=%d fast_bound_shards=%d fast_children=%d fast_predicate=%t store_objects=%d store_immutable_object_bytes=%d shared_body_file_bytes_written=%d shared_body_files=%d",
			label, selected.root.ChildCount, selected.root.ChildEncodedBytes, len(selected.root.RequiredSupport),
			len(selected.root.Generated.Fragments), len(selected.adminIndex.Groups), selected.root.Generated.Duties,
			selected.root.Generated.Hazards, selected.root.Generated.GeneratedCurrent, indexBytes, shards, expansion,
			intentPages, intentIndexBytes, boundShards, fastChildren, fastChildren <= contract.MaxChildPages,
			objects, immutableBytes, fileBytes, fileCount)
		return fastChildren
	}
	publicPlan := func(t *testing.T, label string, store *memoryStore, selected *StateSession, input generatedPlanInput) error {
		t.Helper()
		store.mu.Lock()
		beforeHead := store.objects[store.desc.HeadKey]
		beforeHead.Body = bytes.Clone(beforeHead.Body)
		beforeCreates, beforeCAS, beforeGeneration := store.creates, store.cas, store.generation
		store.mu.Unlock()
		trust := env.Trust.(*fixtureTrust)
		beforeSigns := trust.signs
		beforePublic, beforePrivate := env.Custody.Calls()
		plan, planErr := selected.generatedPlanRequest(t.Context(), input)
		store.mu.Lock()
		afterHead := store.objects[store.desc.HeadKey]
		unchanged := store.creates == beforeCreates && store.cas == beforeCAS && store.generation == beforeGeneration &&
			afterHead.Token == beforeHead.Token && bytes.Equal(afterHead.Body, beforeHead.Body)
		store.mu.Unlock()
		public, private := env.Custody.Calls()
		if !unchanged || trust.signs != beforeSigns || public != beforePublic || private != beforePrivate {
			t.Fatal("public reservation changed HEAD or used writes, signing or a key route", label)
		}
		// This public request has no private producer or effect capability.
		if (planErr != nil && !errors.Is(planErr, contract.ErrRecordCapacity)) || (planErr == nil && plan == nil) {
			t.Fatal("reserve history public plan", label, planErr)
		}
		work, err := selected.selectedGeneratedWork(t.Context())
		if err != nil {
			t.Fatal("reserve history public predecessor", err)
		}
		declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
		if err != nil {
			t.Fatal("reserve history declaration", err)
		}
		shape, err := selected.generatedAdmissionShape(t.Context(), input.graph, declaration, work)
		if err != nil {
			t.Fatal("reserve history admitted shape", err)
		}
		shape.DeclarationBytes = uint64(len(input.declaration))
		projection, err := planGeneratedCurrentIntents(t.Context(), selected, work, selectedGeneratedLocations(work))
		if err != nil {
			t.Fatal("reserve history public current-intent projection", err)
		}
		if projection.changed && projection.emit {
			shape.ProjectedCurrentIntentFragments = uint64(projection.fragments)
		}
		groups, err := generatedCapacityWithProjectedBacklog(shape, work, &projection)
		if err != nil {
			t.Fatal("reserve history physical capacity groups", label, err)
		}
		indexBytes, err := selected.generatedAdministrativeReservedLength(shape)
		if err != nil {
			t.Fatal("reserve history public index reserve", err)
		}
		shards, err := selected.generatedAdministrativeShardReserve(shape)
		if err != nil {
			t.Fatal("reserve history public shard reserve", err)
		}
		exitShards, err := selected.generatedAdministrativeFirstExitShardReserve(shape)
		if err != nil {
			t.Fatal("reserve history public first-exit shard reserve", err)
		}
		var pages uint32
		for _, group := range groups {
			pages += group.MaxPages
		}
		if planErr == nil && (pages+shards > ordinaryChildPageLimit || pages+2+exitShards > contract.MaxChildPages) {
			t.Fatal("public plan accepted excess reserved child pages")
		}
		if planErr != nil && pages+shards <= ordinaryChildPageLimit && pages+2+exitShards <= contract.MaxChildPages {
			t.Fatal("public capacity refusal has no measured child-capacity cause", label, planErr)
		}
		t.Logf("reserve history public %s: declaration_bytes=%d physical_group_pages=%d index_reserved_bytes=%d index_shards=%d reserved_children=%d first_exit_shards=%d first_exit_reserved_children=%d capacity_refused=%t groups=%+v",
			label, len(input.declaration), pages, indexBytes, shards, pages+shards, exitShards, pages+2+exitShards, planErr != nil, groups)
		return planErr
	}
	type originalIntent struct {
		body        []byte
		blob, whole contract.ID
		total       uint64
		fragments   int
		rows        map[uint16]contract.SupportRecordDigest
	}
	intents := make(map[contract.ID]originalIntent)
	oldRows := make(map[generatedRecordKey][]byte)
	assertOld := func(t *testing.T, selected *StateSession, prefix int) *generatedSelection {
		t.Helper()
		work, err := selected.selectedGeneratedWork(t.Context())
		if err != nil || len(work.attempts) != 2*prefix || selected.root.Generated.Duties != uint32(prefix) ||
			selected.root.Generated.Hazards != uint32(prefix) || len(selected.adminIndex.Groups) != 2*prefix {
			t.Fatal("reserve history lost real old owners", err)
		}
		for key, want := range oldRows {
			if row, present := work.records[key]; !present || !bytes.Equal(row.Body, want) {
				t.Fatal("reserve history changed an exact old owner row", key.kind)
			}
		}
		for id, want := range intents {
			body, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength)
			if err != nil || !bytes.Equal(body, want.body) || work.content.locations[generatedContentKey{contract.GeneratorContentIntent, id}].BlobID != want.blob {
				t.Fatal("reserve history changed old Intent or containing blob", err)
			}
			var count int
			for location, fact := range selected.fragmentFacts {
				if location.BlobID != want.blob {
					continue
				}
				if fact.total != want.total || fact.whole != want.whole || int(fact.count) != want.fragments {
					t.Fatal("reserve history changed the complete old declaration blob")
				}
				if row, present := want.rows[location.FragmentIndex]; !present || fact.row != row {
					t.Fatal("reserve history changed exact retained fragment bytes")
				}
				count++
			}
			if count != want.fragments {
				t.Fatal("reserve history dropped old physical declaration fragments", count, want.fragments)
			}
		}
		return work
	}
	mixedInput := func(t *testing.T, selected *StateSession, prefix, plainCount int) (generatedPlanInput, []string, []byte, contract.ID) {
		t.Helper()
		sources := make([]contract.GeneratorDeclarationEntry, plainCount)
		for i := range sources {
			sources[i] = contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
				Name: fmt.Sprintf("plain-%03d-%03d", prefix, i), Recipients: []contract.ID{selected.admission.recipient},
				Payload: bytes.Repeat([]byte{byte(i + 1)}, 65536)}
		}
		intent := hermeticSizedGeneratorIntent(fmt.Sprintf("reserve real aggregate %03d plain %03d", prefix, plainCount), 'x', 393216)
		id, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(intent))
		if err != nil {
			t.Fatal("reserve history Intent digest", err)
		}
		names := []string{fmt.Sprintf("failed-%03d-alpha", prefix), fmt.Sprintf("failed-%03d-omega", prefix)}
		input := generatedPlanInputForGenerationsIntent(t, selected, fixtureID(env.Domain, fmt.Sprintf("reserve mixed operation %03d plain %03d", prefix, plainCount)),
			names, intent, defaultGeneratedFixtureProfile(), sources...)
		input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		return input, names, intent, id
	}
	selected := cold(t, store, fixture.session)
	measure(t, "seed", store, selected)
	var pairIDs [2]contract.ID
	var pairIntent contract.ID
	var current *StateSession
	var currentStore *memoryStore
	var probe *StateSession
	var probeStore *memoryStore
	var prefix, refusedPrefix, saturatedPrefix int
	const heavyPlainCount = 124
	plainCount := heavyPlainCount
	// Heavy aggregates establish saturation and recovery for a 126*64 KiB
	// desired set. Smaller admitted aggregates can extend that real history
	// to the independently measured fallback boundary.
	const maximumPrefixes = 48
	for next := 1; next <= maximumPrefixes; next++ {
		input, names, intent, id := mixedInput(t, selected, next, plainCount)
		if _, reused := intents[id]; reused {
			t.Fatal("reserve history reused a prior Intent digest")
		}
		if err := publicPlan(t, fmt.Sprintf("failed prefix %d", next), store, selected, input); err != nil {
			if plainCount == 0 {
				t.Fatal("compact history could not reach the fallback boundary", next, err)
			}
			refusedPrefix, saturatedPrefix = next, prefix
			probeStore = selectedMemoryStoreCopy(store)
			probe = cold(t, probeStore, selected)
			plainCount = 0
			input, names, intent, id = mixedInput(t, selected, next, plainCount)
			if err := publicPlan(t, fmt.Sprintf("compact failed prefix %d", next), store, selected, input); err != nil {
				t.Fatal("compact history refused after heavy-family saturation", next, err)
			}
		}
		selected, _ = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, nil)
		selected = cold(t, store, selected)
		prefix = next
		if selected.root.ValueEntryCount != 1 || !reflect.DeepEqual(selected.valueEntry(0), &seed) {
			t.Fatal("failed mixed history changed the exact current seed")
		}
		work := assertOld(t, selected, prefix)
		for key, row := range work.records {
			if key.kind == contract.GeneratedAttemptSupportKind || key.kind == contract.GeneratedDutySupportKind || key.kind == contract.GeneratedHazardSupportKind {
				oldRows[key] = bytes.Clone(row.Body)
			}
		}
		if len(oldRows) != 4*prefix {
			t.Fatal("reserve history lacks exact old Attempts, Duties and Hazards")
		}
		location, present := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, id}]
		if !present {
			t.Fatal("new failed history lacks its original Intent location")
		}
		original := originalIntent{body: bytes.Clone(intent), blob: location.BlobID, whole: contract.Hash(input.declaration),
			total: uint64(len(input.declaration)), fragments: (len(input.declaration) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload,
			rows: make(map[uint16]contract.SupportRecordDigest)}
		for fragment, fact := range selected.fragmentFacts {
			if fragment.BlobID == original.blob {
				original.rows[fragment.FragmentIndex] = fact.row
			}
		}
		if len(original.rows) != original.fragments {
			t.Fatal("new failed history lacks exact complete fragment-row digests")
		}
		intents[id] = original
		assertOld(t, selected, prefix)
		measure(t, fmt.Sprintf("failed prefix %d", prefix), store, selected)
		if prefix == 1 {
			pairIntent = id
			for _, group := range selected.adminIndex.Groups {
				switch group.OwnerKind {
				case format.AdministrativeGeneratedDuty:
					pairIDs[0] = group.GroupID
				case format.AdministrativeGeneratedHazard:
					pairIDs[1] = group.GroupID
				}
			}
		}
		if prefix == 8 {
			t.Log("reserve history admitted eight distinct real failed aggregates")
		}
		// Three extra selected children only trigger a distinct-success trial.
		// Its actual candidate and cold successor must independently cross the
		// fast bound; this trigger does not prove the branch.
		if selected.root.ChildCount+3+2+25 <= contract.MaxChildPages {
			continue
		}
		trialStore := selectedMemoryStoreCopy(store)
		trialEnv := env
		trialEnv.Context, trialEnv.Store = ctx, trialStore
		before := cold(t, trialStore, selected)
		newIntent := hermeticGeneratorIntent([]byte("reserve distinct current Intent at the real history boundary"))
		input = generatedPlanInputForGenerationsIntent(t, before, fixtureID(env.Domain, fmt.Sprintf("reserve successful operation %03d", prefix)),
			[]string{"current"}, newIntent, defaultGeneratedFixtureProfile())
		input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		if err := publicPlan(t, fmt.Sprintf("success after %d", prefix), trialStore, before, input); err != nil {
			t.Fatalf("distinct success refused at the measured boundary: prefix=%d error=%v", prefix, err)
		}
		// The existing in-process sequence exposes the actual Final candidate
		// here so both it and the independently cold-opened successor qualify.
		prior, _ := preparePrivateGeneratedReservation(t, trialEnv, before, input, nil)
		recorded, _, _, _ := selectActualGeneratedPacketRecord(t, trialEnv, before, prior, custody.StandardValue, true, nil)
		finalContext := generatedPlanInputFixture(t, recorded).context
		finalContext.AdmissionID, finalContext.SessionID = testID("reserve boundary final admission"), testID("reserve boundary final session")
		finalPlan, err := recorded.generatedFinalRequest(ctx, finalContext)
		if err != nil {
			t.Fatal("reserve boundary Final request", err)
		}
		recorded, final := preparePrivateGeneratedFinal(t, trialEnv, recorded, finalPlan)
		candidateFast := measure(t, "distinct success Final candidate", trialStore, final.reservation.state)
		trial, outcome := recorded.selectCandidate(ctx, final.reservation.candidate)
		if trial == nil || outcome.Outcome != ObservedCurrent || !trial.root.Generated.ActiveOwner.IsZero() {
			t.Fatal("reserve boundary Final selection", outcome)
		}
		env.Custody.RetireGenerated()
		trial = cold(t, trialStore, trial)
		entry := trial.valueEntry(0)
		digest, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(newIntent))
		if err != nil || entry == nil || trial.root.ValueEntryCount != 1 || trial.root.Generated.GeneratedCurrent != 1 ||
			entry.Name != "current" || entry.ValueSource != contract.Generated || entry.Generated.IntentDigest != digest {
			t.Fatal("reserve prefix success lost its exact current generation", err)
		}
		if _, reused := intents[digest]; reused {
			t.Fatal("reserve prefix success reused an old Intent")
		}
		work = assertOld(t, trial, prefix)
		body, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, digest, contract.GeneratorIntentMaxLength)
		if err != nil || !bytes.Equal(body, newIntent) {
			t.Fatal("reserve prefix success changed its exact current Intent", err)
		}
		coldFast := measure(t, "distinct success cold successor", trialStore, trial)
		if candidateFast != coldFast {
			t.Fatal("Final candidate and cold successor have different fast bounds")
		}
		if coldFast > contract.MaxChildPages {
			current, currentStore = trial, trialStore
			break
		}
	}
	if current == nil {
		t.Fatalf("authentic family did not reach reserve fallback: last_admitted_prefix=%d capacity_refused_prefix=%d", prefix, refusedPrefix)
	}
	// Keep recovery on the first heavy-refused predecessor. The fallback witness
	// can contain additional compact history and owns a separate Store copy.
	if probeStore == nil {
		refusedPrefix, saturatedPrefix = prefix+1, prefix
		probeStore = selectedMemoryStoreCopy(store)
		probe = cold(t, probeStore, selected)
	}
	refusedInput, _, _, _ := mixedInput(t, probe, refusedPrefix, heavyPlainCount)
	if err := publicPlan(t, "next heavy family on the closed failed prefix", probeStore, probe, refusedInput); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatal("closed failed prefix has not saturated this legal heavy family", err)
	}
	var pair [2]format.AdministrativeGroup
	var indexes [2]uint16
	for i, group := range current.adminIndex.Groups {
		for j, id := range pairIDs {
			if group.GroupID == id {
				pair[j], indexes[j] = group, uint16(i)
			}
		}
	}
	for i, group := range pair {
		_, scope, err := current.administrativeWorkClosure(group.GroupID)
		if group.GroupID.IsZero() || err != nil || len(scope) != 1 || scope[0].GroupID != group.GroupID || len(group.RelatedGroupIndexes) != 0 {
			t.Fatal("real pair is not independently endable", err)
		}
		for _, other := range current.adminIndex.Groups {
			if slices.Contains(other.RelatedGroupIndexes, indexes[i]) {
				t.Fatal("another selected group depends on the real pair target")
			}
		}
	}
	if pair[0].OwnerKind != format.AdministrativeGeneratedDuty || pair[0].DutyKind != contract.GeneratedDutyUnselectedCleanup ||
		pair[1].OwnerKind != format.AdministrativeGeneratedHazard {
		t.Fatal("real failed aggregate lacks its exact Duty and Hazard")
	}
	var shared bool
	for _, page := range current.adminIndex.Pages {
		for _, span := range page.Spans {
			shared = shared || slices.Contains(span.GroupIndexes, indexes[0]) && slices.Contains(span.GroupIndexes, indexes[1])
		}
	}
	if !shared {
		t.Fatal("real independent owners do not share authenticated physical support")
	}
	currentWork, err := current.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("real boundary work", err)
	}
	duty, err := contract.InspectGeneratedDutyRecord(currentWork.records[generatedRecordKey{contract.GeneratedDutySupportKind, pair[0].GroupID}].Body)
	if err != nil {
		t.Fatal("real boundary Duty", err)
	}
	bundle, err := currentWork.retainedGraph(duty.OriginalOperationID)
	if err != nil {
		t.Fatal("real boundary pair lacks its original Graph", err)
	}
	pairGraph := bundle.UsePlan.PlanGraphID
	pairGraphBlob := currentWork.content.locations[generatedContentKey{contract.GeneratorContentGraph, pairGraph}].BlobID
	if pairGraphBlob.IsZero() {
		t.Fatal("real boundary pair lacks its original Graph location")
	}
	endOne := func(t *testing.T, store *memoryStore, before *StateSession, id contract.ID) *StateSession {
		t.Helper()
		ctx := t.Context()
		var target format.AdministrativeGroup
		beforeGroups := make(map[contract.ID]format.AdministrativeGroup)
		for _, group := range before.adminIndex.Groups {
			beforeGroups[group.GroupID] = group
			if group.GroupID == id {
				target = group
			}
		}
		if target.GroupID.IsZero() {
			t.Fatal("real exit target is absent")
		}
		beforeWork, err := before.selectedGeneratedWork(ctx)
		if err != nil {
			t.Fatal("real exit predecessor work", err)
		}
		ownerKind := contract.GeneratedDutySupportKind
		var originalAttempt contract.ID
		wantDuties, wantHazards := before.root.Generated.Duties, before.root.Generated.Hazards
		if target.OwnerKind == format.AdministrativeGeneratedDuty {
			wantDuties--
			row, err := contract.InspectGeneratedDutyRecord(beforeWork.records[generatedRecordKey{ownerKind, target.GroupID}].Body)
			if err != nil {
				t.Fatal("real exit Duty", err)
			}
			originalAttempt = row.OriginalAttemptID
		} else {
			wantHazards--
			ownerKind = contract.GeneratedHazardSupportKind
			row, err := contract.InspectGeneratedHazardRecord(beforeWork.records[generatedRecordKey{ownerKind, target.GroupID}].Body)
			if err != nil {
				t.Fatal("real exit Hazard", err)
			}
			originalAttempt = row.OriginalAttemptID
		}
		beforeWindows, err := before.receiptWindows(ctx)
		if err != nil {
			t.Fatal("real exit predecessor receipts", err)
		}
		beforePublic, beforePrivate := env.Custody.Calls()
		beforeCreates, beforeCAS := store.creates, store.cas
		candidate, prepared := prepareTestEndSelectedWork(t, before, ctx, id, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent || store.cas != beforeCAS {
			t.Fatal("real history EndWork preparation", prepared)
		}
		if next, outcome := before.selectCandidate(ctx, candidate); next == nil || outcome.Outcome != ObservedCurrent ||
			store.cas != beforeCAS+1 || store.creates <= beforeCreates {
			t.Fatal("real history EndWork selection", outcome)
		}
		after := cold(t, store, before)
		if public, private := env.Custody.Calls(); public != beforePublic || private != beforePrivate {
			t.Fatal("EndWork used a public or private key route")
		}
		assertEndWorkSelectedDeletePermissionCount(t, before, 0)
		warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
		q := after.head.EndWork
		if after.head.AuthKind != format.AdministrativeAuth || q == nil || q.TargetGroupID != target.GroupID ||
			q.TargetOwnerID != target.OwnerID || q.TargetID != target.TargetID || q.TargetKind != target.OwnerKind ||
			q.SelectedEvidenceSummary != target.SelectedEvidenceSummary || q.DependentGroups.Count != 1 ||
			q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) ||
			q.PredecessorToken != before.token || q.BeforeWarningBits != before.root.WarningBits ||
			q.AfterWarningBits != warning || after.root.WarningBits != warning ||
			q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(after.root.ChildCount) ||
			q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != after.root.ChildEncodedBytes {
			t.Fatal("real history EndWork envelope changed its exact target or warning")
		}
		if len(after.adminIndex.Groups) != len(beforeGroups)-1 {
			t.Fatal("real history EndWork changed the wrong number of groups")
		}
		for _, group := range after.adminIndex.Groups {
			want, present := beforeGroups[group.GroupID]
			if !present || group.GroupID == id || group.OwnerKind != want.OwnerKind || group.OwnerID != want.OwnerID ||
				group.TargetID != want.TargetID || group.SelectedEvidenceSummary != want.SelectedEvidenceSummary {
				t.Fatal("real history EndWork changed a surviving owner")
			}
			delete(beforeGroups, group.GroupID)
		}
		if len(beforeGroups) != 1 || beforeGroups[id].GroupID != id {
			t.Fatal("real history EndWork removed a different group")
		}
		work, err := after.selectedGeneratedWork(ctx)
		if err != nil || len(work.attempts) != len(beforeWork.attempts)-1 || after.root.Generated.Duties != wantDuties || after.root.Generated.Hazards != wantHazards {
			t.Fatal("real history EndWork changed the old Attempt count", err)
		}
		for key, row := range beforeWork.records {
			if key.kind != contract.GeneratedAttemptSupportKind && key.kind != contract.GeneratedDutySupportKind && key.kind != contract.GeneratedHazardSupportKind {
				continue
			}
			got, present := work.records[key]
			removed := key == (generatedRecordKey{ownerKind, target.GroupID}) || key == (generatedRecordKey{contract.GeneratedAttemptSupportKind, originalAttempt})
			if removed && present || !removed && (!present || !bytes.Equal(got.Body, row.Body)) {
				t.Fatal("real history EndWork changed an unrelated owner or kept its discarded owner", key.kind)
			}
		}
		keptIntents := make(map[contract.ID]bool)
		for _, attempt := range work.attempts {
			keptIntents[attempt.expected.Template.IntentDigest] = true
		}
		for id := range keptIntents {
			want, present := intents[id]
			body, readErr := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength)
			if !present || readErr != nil || !bytes.Equal(body, want.body) || work.content.locations[generatedContentKey{contract.GeneratorContentIntent, id}].BlobID != want.blob {
				t.Fatal("real history exit changed a surviving old Intent", readErr)
			}
			var count int
			for location, fact := range after.fragmentFacts {
				if location.BlobID == want.blob {
					if fact.total != want.total || fact.whole != want.whole || int(fact.count) != want.fragments {
						t.Fatal("real history exit changed a surviving whole declaration blob")
					}
					if row, present := want.rows[location.FragmentIndex]; !present || fact.row != row {
						t.Fatal("real history exit changed exact surviving fragment bytes")
					}
					count++
				}
			}
			if count != want.fragments {
				t.Fatal("real history exit dropped a surviving physical declaration fragment")
			}
		}
		if !reflect.DeepEqual(after.valueEntry(0), before.valueEntry(0)) || !reflect.DeepEqual(after.root.ValueEntryPages, before.root.ValueEntryPages) ||
			!reflect.DeepEqual(after.root.Names, before.root.Names) || !reflect.DeepEqual(after.root.Recipients, before.root.Recipients) ||
			after.root.ValueEntryCount != before.root.ValueEntryCount || after.root.Generated.GeneratedCurrent != before.root.Generated.GeneratedCurrent ||
			after.root.RawBytes != before.root.RawBytes || after.root.MembershipCount != before.root.MembershipCount {
			t.Fatal("real history EndWork changed the exact current value set")
		}
		entry := before.valueEntry(0)
		if entry.ValueSource == contract.Generated {
			key := generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}
			if !bytes.Equal(work.records[key].Body, beforeWork.records[key].Body) {
				t.Fatal("real history EndWork changed exact current evidence")
			}
			beforeAccess, beforePresent := before.materialAccess(contract.ValueMaterialKind, entry.ValueState)
			afterAccess, afterPresent := after.materialAccess(contract.ValueMaterialKind, entry.ValueState)
			beforeIntent, beforeErr := beforeWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			afterIntent, afterErr := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			beforeCore, beforePayload, _, beforeOK := before.selectedValue(0)
			afterCore, afterPayload, _, afterOK := after.selectedValue(0)
			if !beforePresent || !afterPresent || !reflect.DeepEqual(beforeAccess, afterAccess) || beforeErr != nil || afterErr != nil ||
				!bytes.Equal(beforeIntent, afterIntent) || !beforeOK || !afterOK || !reflect.DeepEqual(beforeCore, afterCore) || !reflect.DeepEqual(beforePayload, afterPayload) {
				t.Fatal("real history EndWork changed exact current access, bytes or Intent", beforeErr, afterErr)
			}
			consumed := env.Custody.Consume(ctx, sessionConsumerSelection(t, after, after.admission.recipient, entry.Name), custody.StandardValue)
			if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
				t.Fatal("current value is not privately readable after the real history exit", consumed)
			}
		}
		windows, err := after.receiptWindows(ctx)
		if err != nil || len(windows.Successes) != len(beforeWindows.Successes)+1 ||
			!reflect.DeepEqual(windows.Successes[:len(beforeWindows.Successes)], beforeWindows.Successes) || !reflect.DeepEqual(windows.Failures, beforeWindows.Failures) {
			t.Fatal("real history EndWork changed prior receipts", err)
		}
		receipt := windows.Successes[len(windows.Successes)-1]
		if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID ||
			receipt.StateResult != contract.ReceiptStateWorkEnded || receipt.EffectSummary != contract.ReceiptEffectNotApplicable ||
			receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.AdministrativeTargetKind != target.OwnerKind ||
			receipt.AdministrativeTargetID != target.TargetID || receipt.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary ||
			receipt.WarningBits != uint64(warning) || receipt.AdministrativeWarningChanges != warning&^before.root.WarningBits ||
			receipt.PredecessorRevisionID != before.head.Core.Revision || receipt.ObservedRevisionID != after.head.Core.Revision {
			t.Fatal("real history EndWork receipt lost its exact local disposition")
		}
		measure(t, fmt.Sprintf("exit kind=%d", target.OwnerKind), store, after)
		return after
	}
	for _, order := range [][2]format.AdministrativeGroup{pair, {pair[1], pair[0]}} {
		t.Run(fmt.Sprintf("first_owner_%d", order[0].OwnerKind), func(t *testing.T) {
			store := selectedMemoryStoreCopy(currentStore)
			after := cold(t, store, current)
			for step, target := range order {
				after = endOne(t, store, after, target.GroupID)
				work, err := after.selectedGeneratedWork(t.Context())
				if err != nil {
					t.Fatal("real pair exit work", err)
				}
				if step == 0 {
					got, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, pairIntent, contract.GeneratorIntentMaxLength)
					if err != nil || !bytes.Equal(got, intents[pairIntent].body) {
						t.Fatal("first real exit lost the surviving shared owner's Intent", err)
					}
				} else {
					if _, present := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, pairIntent}]; present {
						t.Fatal("last real pair exit retained its obsolete Intent location")
					}
					for _, fragment := range after.root.Generated.Fragments {
						if fragment.BlobID == intents[pairIntent].blob {
							t.Fatal("last real pair exit retained an exclusive old declaration fragment")
						}
					}
					if slices.ContainsFunc(work.bundles, func(bundle contract.GeneratorPlanBundle) bool {
						return bundle.Header.OperationID == duty.OriginalOperationID
					}) {
						t.Fatal("last real pair exit retained its obsolete operation Graph")
					}
					if _, present := work.content.locations[generatedContentKey{contract.GeneratorContentGraph, pairGraph}]; present {
						t.Fatal("last real pair exit retained its obsolete Graph location")
					}
					for _, fragment := range after.root.Generated.Fragments {
						if fragment.BlobID == pairGraphBlob {
							t.Fatal("last real pair exit retained an exclusive old Graph fragment")
						}
					}
				}
			}
		})
	}
	t.Run("same_heavy_family_admits_after_real_exits", func(t *testing.T) {
		store := selectedMemoryStoreCopy(probeStore)
		after := cold(t, store, probe)
		for _, target := range pair {
			after = endOne(t, store, after, target.GroupID)
		}
		input, names, _, _ := mixedInput(t, after, refusedPrefix, heavyPlainCount)
		if err := publicPlan(t, "same heavy family after the real pair exits", store, after, input); err != nil {
			t.Fatal("real pair exits did not restore admission for the refused family", err)
		}
		progressEnv := env
		progressEnv.Context, progressEnv.Store = t.Context(), store
		progress, _ := selectPrivateOwnedUnusableAggregateFromInput(t, progressEnv, after, names, input, nil)
		progress = cold(t, store, progress)
		if progress.root.ValueEntryCount != 1 || !reflect.DeepEqual(progress.valueEntry(0), &seed) ||
			progress.root.Generated.Duties != uint32(saturatedPrefix) || progress.root.Generated.Hazards != uint32(saturatedPrefix) ||
			len(progress.adminIndex.Groups) != 2*saturatedPrefix || !progress.root.Generated.ActiveOwner.IsZero() {
			t.Fatal("recovered heavy family did not complete its actual nonselecting Final")
		}
		measure(t, "same heavy family completed after real exits", store, progress)
		warnings := progress.root.WarningBits
		usefulIntent := hermeticGeneratorIntent([]byte("new useful generation after genuine capacity recovery"))
		usefulInput := generatedPlanInputForGenerationsIntent(t, progress, fixtureID(env.Domain, "reserve useful progress operation"),
			[]string{"recovered-current"}, usefulIntent, defaultGeneratedFixtureProfile())
		usefulInput.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		if err := publicPlan(t, "small useful generation after recovered admission", store, progress, usefulInput); err != nil {
			t.Fatal("capacity recovery did not admit small useful progress", err)
		}
		useful := selectPrivateGeneratedOperationInProcess(t, progressEnv, progress, usefulInput, "reserve useful progress")
		useful = cold(t, store, useful)
		entry := useful.valueEntry(0)
		digest, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(usefulIntent))
		if err != nil || entry == nil || entry.Name != "recovered-current" || entry.ValueSource != contract.Generated || entry.Generated.IntentDigest != digest ||
			useful.root.ValueEntryCount != 1 || useful.root.Generated.GeneratedCurrent != 1 || !useful.root.Generated.ActiveOwner.IsZero() ||
			useful.root.Generated.Duties != uint32(saturatedPrefix) || useful.root.Generated.Hazards != uint32(saturatedPrefix) ||
			len(useful.adminIndex.Groups) != 2*saturatedPrefix || useful.root.WarningBits&warnings != warnings {
			t.Fatal("useful progress lost its exact desired current or prior warnings", err)
		}
		work, err := useful.selectedGeneratedWork(t.Context())
		if err != nil {
			t.Fatal("useful progress cold work", err)
		}
		body, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, digest, contract.GeneratorIntentMaxLength)
		if err != nil || !bytes.Equal(body, usefulIntent) {
			t.Fatal("useful progress lost its exact current Intent", err)
		}
		consumed := env.Custody.Consume(t.Context(), sessionConsumerSelection(t, useful, useful.admission.recipient, entry.Name), custody.StandardValue)
		if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
			t.Fatal("new useful value is not privately readable after capacity recovery", consumed)
		}
		measure(t, "useful generation selected after capacity recovery", store, useful)
	})
}
