package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type retainedReaderReadObservation struct {
	key    string
	status contract.ReadStatus
	token  contract.Token
	digest contract.ID
}

type retainedReaderObservingStore struct {
	*memoryStore
	observationMu sync.Mutex
	observations  []retainedReaderReadObservation
}

func (s *retainedReaderObservingStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	read := s.memoryStore.Read(ctx, key, limit)
	s.observationMu.Lock()
	s.observations = append(s.observations, retainedReaderReadObservation{
		key: key, status: read.Status, token: read.Token, digest: contract.Hash(read.Body),
	})
	s.observationMu.Unlock()
	return read
}

func (s *retainedReaderObservingStore) readsFor(key string) []retainedReaderReadObservation {
	s.observationMu.Lock()
	defer s.observationMu.Unlock()
	var reads []retainedReaderReadObservation
	for _, read := range s.observations {
		if read.key == key {
			reads = append(reads, read)
		}
	}
	return reads
}

type retainedReaderFixture struct {
	env           fixtureEnvironment
	keys          *custody.Fixture
	selected      *StateSession
	value         contract.ValueEntry
	access        contract.AccessRecord
	current       contract.ValueEntry
	currentAccess contract.AccessRecord
	owners        map[contract.ID][]byte
	retainedRef   format.Ref
}

func newRetainedReaderFixture(t *testing.T, recovery bool, recipientCount int) retainedReaderFixture {
	t.Helper()
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, recovery, recipientCount)
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	originalReaders := []contract.ID{authority, reader}
	slices.SortFunc(originalReaders, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(f, []ApplyEntryInput{sharingSecretNamed(t, env, "shared", "retained partial reader source", originalReaders)})
	_, original := lifecycleEntry(t, f.session, "shared")
	wantValue := ownScenarioValueEntry(*original)
	originalAccess, present := f.session.materialAccess(contract.ValueMaterialKind, wantValue.ValueState)
	if !present {
		t.Fatal("setup: predecessor old material access absent")
	}

	// The old positive control reaches this state through two independent
	// primary owners and an actual Membership-only Final, without content work.
	selected := f.session
	owners := make(map[contract.ID][]byte)
	for i := range 2 {
		sources, canonical := generatedCurrentDeclaration(t, selected)
		label := fmt.Sprintf("%s retained owner %d", t.Name(), i)
		names := []string{fmt.Sprintf("failed-%d", i)}
		input := generatedPlanInputForGenerations(t, selected, testID(label+" operation"), names, defaultGeneratedFixtureProfile(), sources...)
		input.context.AdmissionID, input.context.SessionID = testID(label+" admission"), testID(label+" session")
		var failed generatedAttempt
		selected, failed = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
		selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
		work := mustSelectedGeneratedWork(t, selected)
		ownerID := failed.expected.Template.HazardID
		owners[ownerID] = bytes.Clone(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, ownerID}].Body)
		if _, result := selected.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, ownerID, wantValue.ValueState, reader); result.Outcome != ObservedCurrent {
			t.Fatal("setup: old owner lacks the exact historical reader", result)
		}
	}
	if selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != 2 || len(owners) != 2 {
		t.Fatal("setup: two real canonical owners were not selected")
	}
	sources, canonical := generatedCurrentDeclaration(t, selected)
	if len(sources) != 1 || len(canonical) != 1 || sources[0].Kind != contract.GeneratorDeclarationRetained {
		t.Fatal("setup: exact retained source is absent")
	}
	sources[0].Recipients = []contract.ID{authority}
	input := generatedPlanInputForGenerations(t, selected, fixtureID(env.Domain, "partial reader Final selecting operation"),
		[]string{"generated"}, defaultGeneratedFixtureProfile(), sources...)
	input.context.AdmissionID, input.context.SessionID = testID(t.Name()+" reservation admission"), testID(t.Name()+" reservation session")
	// Match the historical positive control's admitted Membership-only graph.
	// The source5 fixture initially marks every supplied secret as Content.
	for i := range input.graph.ValueEntryPlans {
		if input.graph.ValueEntryPlans[i].Name == "shared" {
			input.graph.ValueEntryPlans[i].ChangeMask &^= contract.GeneratorValueChangeContent
			input.graph.ValueEntryPlans[i].ChangeMask |= contract.GeneratorValueChangeMembership
		}
	}
	var err error
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
		t.Fatal("setup: retained Membership-only graph is invalid", err)
	}
	sharedPlans := 0
	for _, entry := range input.graph.ValueEntryPlans {
		if entry.Name == "shared" {
			sharedPlans++
			if entry.ChangeMask != contract.GeneratorValueChangeMembership {
				t.Fatal("setup: retained plan is not Membership-only")
			}
		}
	}
	if sharedPlans != 1 {
		t.Fatal("setup: retained plan is absent or duplicated")
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, canonical)
	recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, selected, prior, custody.StandardValue, true, nil)
	acceptedWork := mustSelectedGeneratedWork(t, recorded)
	acceptedPlans := 0
	for _, bundle := range acceptedWork.bundles {
		if bundle.Header.OperationID != input.graph.Header.OperationID {
			continue
		}
		if bundle.UsePlan.PlanGraphID != input.graph.UsePlan.PlanGraphID || contract.ValidateGeneratorEffectGraph(bundle) != nil {
			t.Fatal("setup: selected accepted graph differs from the Membership-only input")
		}
		for _, entry := range bundle.ValueEntryPlans {
			if entry.Name == "shared" {
				acceptedPlans++
				if entry.ChangeMask != contract.GeneratorValueChangeMembership {
					t.Fatal("setup: selected accepted retained plan is not Membership-only")
				}
			}
		}
	}
	if acceptedPlans != 1 {
		t.Fatal("setup: selected accepted retained plan is absent or duplicated")
	}
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" Final admission"), testID(t.Name()+" Final session")
	plan, err := recorded.generatedFinalRequest(ctx, admitted)
	if err != nil || plan == nil || !plan.selecting {
		t.Fatal("setup: selecting Final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
	selected, result := recorded.selectCandidate(ctx, final.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("setup: selecting Final selection", result)
	}
	keys.RetireGenerated()
	_, current := lifecycleEntry(t, selected, "shared")
	assertPublicExclusionProtection(t, wantValue, *current)
	if !slices.Equal(current.Recipients, []contract.ID{authority}) {
		t.Fatal("setup: Final did not select fresh current protection and remove the reader")
	}
	currentAccess, ok := selected.materialAccess(contract.ValueMaterialKind, current.ValueState)
	if !ok || len(currentAccess.Wraps) != 1+boolInt(recovery) || currentAccess.Wraps[0].SubjectKind != contract.OrdinaryWrapSubject || currentAccess.Wraps[0].SubjectID != authority || recovery && (currentAccess.Wraps[1].SubjectKind != contract.RecoveryWrapSubject || currentAccess.Wraps[1].SubjectID != selected.root.CurrentAccess.Core.Recovery.RoleID) {
		t.Fatal("setup: fresh current access is absent or inexact")
	}
	wantAccess, ok := selected.materialAccess(contract.ValueMaterialKind, wantValue.ValueState)
	if !ok || len(wantAccess.Wraps) != len(originalReaders)+boolInt(recovery) || !reflect.DeepEqual(wantAccess, originalAccess) {
		t.Fatal("setup: retained access row has an inexact wrap count")
	}
	for i, wrap := range wantAccess.Wraps[:len(originalReaders)] {
		if wrap.SubjectKind != contract.OrdinaryWrapSubject || wrap.SubjectID != originalReaders[i] {
			t.Fatal("setup: retained access row has an unexpected ordinary subject")
		}
	}

	// Locate the actual retained body and its authenticated page classification.
	// The administrative reader must omit this physical page, even though the
	// full reader needs its historical reader list to validate the access union.
	var retainedRef format.Ref
	retainedRows := 0
	for i, page := range selected.support {
		for j, row := range page.Records {
			if row.Kind != contract.RetainedCanonicalSupportKind {
				continue
			}
			retainedRows++
			retained, err := contract.InspectRetainedCanonicalRecord(row.Body)
			if err != nil {
				t.Fatal("setup: selected canonical body is invalid", err)
			}
			retainedEntry, err := retained.Entry.Own()
			if err != nil || retained.Entry.ValueState != wantValue.ValueState || !reflect.DeepEqual(retainedEntry, wantValue) {
				t.Fatal("setup: selected canonical body changed its exact historical entry", err)
			}
			indexed := selected.adminIndex.Pages[i]
			if indexed.ReadRequired || slices.ContainsFunc(indexed.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) ||
				j >= len(indexed.Rows) || indexed.Rows[j].Kind != row.Kind || indexed.Rows[j].RecordID != row.RecordID || indexed.Rows[j].BodyLength != uint32(len(row.Body)) {
				t.Fatal("setup: retained canonical body is not on a wholly optional indexed page")
			}
			retainedRef = indexed.Ref
		}
	}
	if retainedRows != 1 {
		t.Fatal("setup: expected one exact selected retained canonical row", retainedRows)
	}
	return retainedReaderFixture{env: env, keys: keys, selected: selected, value: wantValue, access: wantAccess, current: ownScenarioValueEntry(*current), currentAccess: currentAccess, owners: owners, retainedRef: retainedRef}
}

// full_only: false
func TestAdministrativeReaderPreservesCurrentAccessWithSkippedRetainedCanonical(t *testing.T) {
	ctx := t.Context()
	fixture := newRetainedReaderFixture(t, false, 2)
	env, keys, selected := fixture.env, fixture.keys, fixture.selected
	wantValue, wantAccess, owners, retainedRef := fixture.value, fixture.access, fixture.owners, fixture.retainedRef
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	store := env.Store.(*memoryStore)
	retainedKey, err := format.Key(store.desc.Prefix, retainedRef)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	frozenObjects := make(map[string]stored, len(store.objects))
	for key, object := range store.objects {
		object.Body = bytes.Clone(object.Body)
		frozenObjects[key] = object
	}
	creates, cas, generation := store.creates, store.cas, store.generation
	store.mu.Unlock()
	pinnedAdmission := selected.admission
	pinnedAdmission.publicKey, pinnedAdmission.descriptor = bytes.Clone(pinnedAdmission.publicKey), bytes.Clone(pinnedAdmission.descriptor)
	pinnedAdmission.current = pinnedAdmission.current.clone()
	openContext := OpenContext{admission: &selected.admission}
	checkFrozen := func() {
		t.Helper()
		store.mu.Lock()
		defer store.mu.Unlock()
		if !reflect.DeepEqual(store.objects, frozenObjects) || store.creates != creates || store.cas != cas || store.generation != generation ||
			!reflect.DeepEqual(selected.admission, pinnedAdmission) {
			t.Fatal("reader changed the pinned Store bytes, token, basis or identities")
		}
	}
	checkHeadRead := func(observed *retainedReaderObservingStore) {
		t.Helper()
		reads := observed.readsFor(store.desc.HeadKey)
		if len(reads) == 0 || slices.ContainsFunc(reads, func(read retainedReaderReadObservation) bool {
			return read.status != contract.ReadOK || read.token != selected.token || read.digest != contract.Hash(selected.body)
		}) {
			t.Fatal("reader did not observe the exact pinned HEAD on every HEAD read")
		}
	}
	fullStore := &retainedReaderObservingStore{memoryStore: store}
	full, result := Open(ctx, openContext, fullStore)
	checkFrozen()
	checkHeadRead(fullStore)
	if full == nil || result.Outcome != ObservedCurrent {
		t.Fatal("setup: complete cold Open refused the healthy pinned image", result)
	}
	retainedReads := fullStore.readsFor(retainedKey)
	if len(retainedReads) == 0 || slices.ContainsFunc(retainedReads, func(read retainedReaderReadObservation) bool { return read.status != contract.ReadOK }) {
		t.Fatal("setup: full cold Open did not read the retained canonical page")
	}
	if !reflect.DeepEqual(full.root, selected.root) || !bytes.Equal(full.body, selected.body) || full.token != selected.token ||
		!reflect.DeepEqual(full.access, selected.access) {
		t.Fatal("setup: full reader changed the pinned selected image")
	}
	work := mustSelectedGeneratedWork(t, full)
	if full.root.Generated.Duties != 0 || full.root.Generated.Hazards != 2 {
		t.Fatal("setup: healthy cold image lost either old canonical owner")
	}
	for ownerID, body := range owners {
		if !bytes.Equal(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, ownerID}].Body, body) {
			t.Fatal("setup: healthy cold image changed an old owner")
		}
		selection, result := full.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, ownerID, wantValue.ValueState, reader)
		if result.Outcome != ObservedCurrent {
			t.Fatal("setup: healthy cold image lost the exact old reader selection", result)
		}
		if check := keys.ConsumeGenerated(ctx, selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("setup: old canonical reader could not consume unchanged value", check)
		}
	}
	if check := keys.Consume(ctx, sessionConsumerSelection(t, full, authority, "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("setup: full cold image lost current authority access", check)
	}
	t.Logf("prerequisites complete: actual Membership-only Final; two selected old owners; exact authority+reader wraps; healthy full cold Open; retained page index=%d full reads=%d", retainedRef.Index, len(retainedReads))

	partialStore := &retainedReaderObservingStore{memoryStore: store}
	partial, result := openAdministrative(ctx, openContext, partialStore)
	checkFrozen()
	checkHeadRead(partialStore)
	if len(partialStore.readsFor(retainedKey)) != 0 {
		t.Fatal("setup: administrative reader read the optional retained canonical page")
	}
	for _, ref := range selected.root.CurrentAccess.Core.AccessPageRefs {
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		reads := partialStore.readsFor(key)
		if len(reads) == 0 || slices.ContainsFunc(reads, func(read retainedReaderReadObservation) bool {
			return read.status != contract.ReadOK || read.digest != ref.Digest
		}) {
			t.Fatal("setup: administrative reader omitted or changed a mandatory access page")
		}
	}
	t.Logf("administrative observation: same HEAD, basis and Store; optional retained page index=%d reads=0; current access pages read=%d; outcome=%d reason=%d", retainedRef.Index, len(selected.root.CurrentAccess.Core.AccessPageRefs), result.Outcome, result.Reason)
	if partial == nil || result.Outcome != ObservedCurrent {
		t.Fatal("healthy administrative partial reader must accept the pinned image after skipping optional retained canonical bytes", result)
	}
	access, ok := partial.materialAccess(contract.ValueMaterialKind, wantValue.ValueState)
	if !ok || !reflect.DeepEqual(access, wantAccess) || !reflect.DeepEqual(partial.root.CurrentAccess, full.root.CurrentAccess) ||
		!reflect.DeepEqual(partial.access, full.access) || !bytes.Equal(partial.body, full.body) || partial.token != full.token {
		t.Fatal("administrative partial reader changed exact current access or selected HEAD")
	}
	_, partialEntry := lifecycleEntry(t, partial, "shared")
	_, fullEntry := lifecycleEntry(t, full, "shared")
	if !reflect.DeepEqual(*partialEntry, *fullEntry) {
		t.Fatal("administrative partial reader changed the current entry")
	}
}

func retainedReaderOwnerIDs(f retainedReaderFixture) []contract.ID {
	var ids []contract.ID
	for id := range f.owners {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

// full_only: false
func TestSignerRestorationPreservesSkippedCanonicalUntilOwnerDisposition(t *testing.T) {
	for _, last := range []bool{false, true} {
		t.Run(fmt.Sprintf("last_owner=%t", last), func(t *testing.T) {
			f := newRetainedReaderFixture(t, true, 2)
			owners := retainedReaderOwnerIDs(f)
			if last {
				f.selected = retainedReaderEndWork(t, f.selected, owners[0], f.env.Trust)
				f.selected = retainedReaderColdOpen(t, f.selected, f.env.Store)
				owners = owners[1:]
			}
			store := &retainedReaderObservingStore{memoryStore: f.env.Store.(*memoryStore)}
			key := mustKey(t, store.desc.Prefix, f.retainedRef)
			store.readHook = retainedReaderFault("missing", key)
			partial, result := openAdministrative(t.Context(), OpenContext{admission: &f.selected.admission}, store)
			if partial == nil || result.Outcome != ObservedCurrent || len(store.readsFor(key)) != 0 {
				t.Fatal("partial Open read optional canonical", result)
			}
			beforeAccess, beforeIndex := partial.access, partial.adminIndex
			replacement := syntheticFreshAuthorityReplacementEnvironment(t, f.env)
			actors := replacement.ReplacementActors(t, t.Context(), partial, contract.SuccessionReplaceAuthority,
				contract.SuccessionChangeNormalSigner, contract.RecoverySigningRole)
			permit := admitAuthorityReplacement(t, partial, actors.Keys, actors.After, contract.SuccessionReplaceAuthority,
				contract.RecoverySigningRole, contract.SuccessionChangeNormalSigner, actors.Source)
			candidate, result := partial.PrepareSuccession(t.Context(), permit, actors.Signers)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("signer restoration needs skipped canonical", result)
			}
			admission := deliverSuccessionBasis(t, candidate)
			if result := partial.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
				t.Fatal("signer restoration selection", result)
			}
			restored, result := openAdministrative(t.Context(), admission, store)
			if restored == nil || result.Outcome != ObservedCurrent || len(store.readsFor(key)) != 0 ||
				!reflect.DeepEqual(restored.access, beforeAccess) || !reflect.DeepEqual(restored.adminIndex, beforeIndex) ||
				!reflect.DeepEqual(restored.pages, partial.pages) {
				t.Fatal("signer restoration changed opaque source/access commitments", result)
			}
			creates, cas := store.creates, store.cas
			if !last {
				candidate, result := prepareTestEndSelectedWork(t, restored, t.Context(), owners[0], actors.Signers.NormalSuccessor)
				if candidate != nil || result != (Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}) ||
					store.creates != creates || store.cas != cas || len(store.readsFor(key)) == 0 {
					t.Fatal("surviving canonical was not required before writes", result)
				}
				store.readHook = nil
				restored, result = openAdministrative(t.Context(), admission, store)
				if restored == nil || result.Outcome != ObservedCurrent {
					t.Fatal("fresh admission after exact body restoration", result)
				}
			}
			next := retainedReaderEndWork(t, restored, owners[0], actors.Signers.NormalSuccessor)
			if last && len(store.readsFor(key)) != 0 {
				t.Fatal("last-owner disposal read discarded canonical")
			}
			next = retainedReaderColdOpen(t, next, store)
			checkRetainedReaderAccess(t, next, f, !last)
			if !last {
				selection, result := next.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owners[1], f.value.ValueState, fixtureID(f.env.Domain, "reader"))
				if result.Outcome != ObservedCurrent {
					t.Fatal("surviving owner source", result)
				}
				if check := f.keys.ConsumeGenerated(t.Context(), selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("surviving retained use after signer restoration", check)
				}
			}
		})
	}
}

func retainedReaderEndWork(t *testing.T, s *StateSession, owner contract.ID, trust contract.Trust) *StateSession {
	t.Helper()
	candidate, result := prepareTestEndSelectedWork(t, s, t.Context(), owner, trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("EndWork preparation refused", result)
	}
	next, result := s.selectCandidate(t.Context(), candidate)
	if next == nil || result.Outcome != ObservedCurrent {
		t.Fatal("EndWork selection refused", result)
	}
	return next
}

func retainedReaderColdOpen(t *testing.T, s *StateSession, store contract.Store) *StateSession {
	t.Helper()
	next, result := Open(t.Context(), OpenContext{admission: &s.admission}, store)
	if next == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold complete Open refused", result)
	}
	return next
}

func checkRetainedReaderAccess(t *testing.T, s *StateSession, f retainedReaderFixture, retained bool) {
	t.Helper()
	authority := fixtureID(f.env.Domain, "recipient")
	old, present := s.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
	if retained {
		if !present || !reflect.DeepEqual(old, f.access) {
			t.Fatal("surviving owner lost exact old material access")
		}
	} else if present {
		t.Fatal("last owner left old material access")
	}
	_, current := lifecycleEntry(t, s, "shared")
	if f.current.ValueState.IsZero() || !reflect.DeepEqual(*current, f.current) {
		t.Fatal("owner disposition changed fresh current value or membership")
	}
	assertPublicExclusionProtection(t, f.value, *current)
	access, present := s.materialAccess(contract.ValueMaterialKind, current.ValueState)
	if !present || !reflect.DeepEqual(access, f.currentAccess) {
		t.Fatal("owner disposition changed fresh current access")
	}
	if check := f.keys.Consume(t.Context(), sessionConsumerSelection(t, s, authority, "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("current authority lost value consumption", check)
	}
}

// full_only: false
func TestAdministrativeEndWorkProjectsSurvivingCanonicalReaders(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("recovery=%t/reverse=%t", recovery, reverse), func(t *testing.T) {
				f := newRetainedReaderFixture(t, recovery, 3)
				owners := retainedReaderOwnerIDs(f)
				if reverse {
					slices.Reverse(owners)
				}
				store := &retainedReaderObservingStore{memoryStore: f.env.Store.(*memoryStore)}
				key := mustKey(t, store.desc.Prefix, f.retainedRef)
				partial, result := openAdministrative(t.Context(), OpenContext{admission: &f.selected.admission}, store)
				if partial == nil || result.Outcome != ObservedCurrent || len(store.readsFor(key)) != 0 {
					t.Fatal("healthy partial Open did not omit the optional canonical page", result)
				}
				next := retainedReaderEndWork(t, partial, owners[0], f.env.Trust)
				if len(store.readsFor(key)) == 0 {
					t.Fatal("EndWork did not read the surviving canonical reader evidence")
				}
				next = retainedReaderColdOpen(t, next, store)
				checkRetainedReaderAccess(t, next, f, true)
				work := mustSelectedGeneratedWork(t, next)
				if next.root.Generated.Hazards != 1 || !bytes.Equal(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, owners[1]}].Body, f.owners[owners[1]]) {
					t.Fatal("EndWork failed to preserve the exact other canonical owner")
				}
				reader := fixtureID(f.env.Domain, "reader")
				selection, result := next.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owners[1], f.value.ValueState, reader)
				if result.Outcome != ObservedCurrent {
					t.Fatal("remaining owner lost its historical reader", result)
				}
				if check := f.keys.ConsumeGenerated(t.Context(), selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("remaining owner's historical reader cannot consume unchanged value", check)
				}
				lastStore := &retainedReaderObservingStore{memoryStore: store.memoryStore}
				last, result := openAdministrative(t.Context(), OpenContext{admission: &next.admission}, lastStore)
				if last == nil || result.Outcome != ObservedCurrent || len(lastStore.readsFor(key)) != 0 {
					t.Fatal("last-owner partial Open read optional canonical evidence", result)
				}
				last = retainedReaderEndWork(t, last, owners[1], f.env.Trust)
				if len(lastStore.readsFor(key)) != 0 {
					t.Fatal("last-owner EndWork read discarded canonical evidence")
				}
				last = retainedReaderColdOpen(t, last, lastStore)
				checkRetainedReaderAccess(t, last, f, false)
				if last.root.Generated.Hazards != 0 {
					t.Fatal("last-owner EndWork left canonical owner rights")
				}
			})
		}
	}
}

func retainedReaderFault(fault string, key string) func(string, contract.ReadResult) contract.ReadResult {
	return func(actual string, read contract.ReadResult) contract.ReadResult {
		if actual != key {
			return read
		}
		switch fault {
		case "missing":
			return contract.ReadResult{Status: contract.ReadMissing}
		case "denied":
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
		default:
			read.Body = bytes.Clone(read.Body)
			read.Body[len(read.Body)-1] ^= 1
			return read
		}
	}
}

// full_only: false
func TestAdministrativeEndWorkRequiresSurvivingCanonicalEvidence(t *testing.T) {
	for _, fault := range []string{"missing", "changed", "denied"} {
		t.Run(fault, func(t *testing.T) {
			f := newRetainedReaderFixture(t, false, 3)
			store := &retainedReaderObservingStore{memoryStore: f.env.Store.(*memoryStore)}
			key := mustKey(t, store.desc.Prefix, f.retainedRef)
			store.readHook = retainedReaderFault(fault, key)
			partial, result := openAdministrative(t.Context(), OpenContext{admission: &f.selected.admission}, store)
			if partial == nil || result.Outcome != ObservedCurrent || len(store.readsFor(key)) != 0 {
				t.Fatal("partial admission did not preserve optional damage tolerance", result)
			}
			creates, cas := store.creates, store.cas
			candidate, result := prepareTestEndSelectedWork(t, partial, t.Context(), retainedReaderOwnerIDs(f)[0], f.env.Trust)
			want := Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}
			switch fault {
			case "changed":
				want = Result{Outcome: IntegrityFailure, Reason: InvalidReference}
			case "denied":
				want = Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}
			}
			if candidate != nil || result != want || len(store.readsFor(key)) == 0 || store.creates != creates || store.cas != cas {
				t.Fatal("EndWork failed to preserve required canonical read failure before writes", result, want)
			}
		})
	}
}

// full_only: false
func TestAdministrativeEndWorkDiscardsUnreadableExclusiveCanonicalEvidence(t *testing.T) {
	for _, fault := range []string{"missing", "changed", "denied"} {
		t.Run(fault, func(t *testing.T) {
			f := newRetainedReaderFixture(t, true, 3)
			owners := retainedReaderOwnerIDs(f)
			next := retainedReaderEndWork(t, f.selected, owners[0], f.env.Trust)
			next = retainedReaderColdOpen(t, next, f.env.Store)
			checkRetainedReaderAccess(t, next, f, true)
			store := &retainedReaderObservingStore{memoryStore: f.env.Store.(*memoryStore)}
			key := mustKey(t, store.desc.Prefix, f.retainedRef)
			store.readHook = retainedReaderFault(fault, key)
			partial, result := openAdministrative(t.Context(), OpenContext{admission: &next.admission}, store)
			if partial == nil || result.Outcome != ObservedCurrent || len(store.readsFor(key)) != 0 {
				t.Fatal("last-owner partial admission read damaged optional canonical evidence", result)
			}
			last := retainedReaderEndWork(t, partial, owners[1], f.env.Trust)
			last = retainedReaderColdOpen(t, last, store)
			if len(store.readsFor(key)) != 0 {
				t.Fatal("last-owner EndWork fetched discarded canonical evidence")
			}
			checkRetainedReaderAccess(t, last, f, false)
			for _, page := range last.adminIndex.Pages {
				if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
					return row.Kind == contract.RetainedCanonicalSupportKind
				}) {
					t.Fatal("last-owner EndWork kept the exclusive canonical row")
				}
			}
		})
	}
}

// The signer controls this deliberately invalid image. This is an authenticated
// relation test, not a claim that Store alone can produce a valid signature.
func retainedReaderSignedAccess(t *testing.T, f retainedReaderFixture, material contract.ID, grants map[contract.ID][]contract.ID, change func(*contract.AccessRecord)) *memoryStore {
	t.Helper()
	original := f.env.Store.(*memoryStore)
	store := &memoryStore{desc: original.desc, configuration: original.configuration, generation: original.generation, objects: make(map[string]stored)}
	for key, value := range original.objects {
		value.Body = bytes.Clone(value.Body)
		store.objects[key] = value
	}
	bad := *f.selected
	bad.root.CurrentAccess.Core.AccessPageRefs = slices.Clone(bad.root.CurrentAccess.Core.AccessPageRefs)
	bad.root.GrantPages = nil
	var grantRows []byte
	var records []contract.AccessRecord
	changed := false
	encode := func(page format.AccessPage) (format.Ref, []byte) {
		t.Helper()
		body, err := format.EncodeAccessPage(page)
		if err != nil {
			t.Fatal("signed test access encoding", err)
		}
		ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		return ref, body
	}
	for i, ref := range bad.root.CurrentAccess.Core.AccessPageRefs {
		page := *bad.access[ref.Index]
		page.Records = slices.Clone(page.Records)
		for j := range page.Records {
			if page.Records[j].MaterialKind == contract.ValueMaterialKind && page.Records[j].MaterialID == material {
				page.Records[j].Wraps = slices.Clone(page.Records[j].Wraps)
				change(&page.Records[j])
				changed = true
			}
		}
		ref, body := encode(page)
		bad.access[ref.Index], bad.root.CurrentAccess.Core.AccessPageRefs[i] = &page, ref
		if len(grants) != 0 {
			base, rows, err := format.SplitGrantPage(page, grants)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				ref, body = encode(base)
				bad.root.GrantPages = append(bad.root.GrantPages, ref)
				grantRows = append(grantRows, rows...)
			}
		}
		store.put(mustKey(t, store.desc.Prefix, ref), body)
		records = append(records, page.Records...)
	}
	if !changed {
		t.Fatal("signed test material is absent")
	}
	if !bytes.Equal(grantRows, bad.head.GrantWraps) {
		t.Fatal("changing the access relation changed the selected grant")
	}
	slices.SortFunc(records, func(a, b contract.AccessRecord) int {
		return compareMaterial(a.MaterialKind, a.MaterialID, b.MaterialKind, b.MaterialID)
	})
	var err error
	bad.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(bad.root.Domain, records)
	if err != nil {
		t.Fatal(err)
	}
	bad.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(bad.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	return retainedReaderSignedState(t, f, &bad, store)
}

func retainedReaderSignedState(t *testing.T, f retainedReaderFixture, bad *StateSession, store *memoryStore) *memoryStore {
	t.Helper()
	bad.recountChildren()
	rootBody, err := format.EncodeRoot(bad.root)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, err := format.Reference(format.RootKind, bad.root.Domain, bad.root.Snapshot, 0, rootBody)
	if err != nil || bad.head.Generator == nil || !validAggregate(bad.root) {
		t.Fatal("signed retained-reader test did not preserve valid root framing and aggregates", err)
	}
	store.put(mustKey(t, store.desc.Prefix, rootRef), rootBody)
	head := bad.head
	subject := *head.Generator
	head.Generator, head.Core.Root = &subject, rootRef
	subject.AfterRootDigest, subject.AfterAccessDigest = rootRef.Digest, bad.root.CurrentAccess.AccessRoot
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := format.EncodeConditionalPlan(conditional(head.Core, coreBody))
	if err != nil {
		t.Fatal(err)
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(condition), uint32(len(condition))
	request, err := contract.NewGeneratorRequest(subject)
	head.AuthorizationSignature = currentBasisSign(t, f.env.Trust, request, err)
	if !bad.verifyHeadProofs(head, currentControlOf(f.selected)) {
		t.Fatal("signed retained-reader test failed independent HEAD proof verification")
	}
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store.put(store.desc.HeadKey, headBody)
	return store
}

func retainedReaderAddUnsupportedWrap(t *testing.T, f retainedReaderFixture, row *contract.AccessRecord) {
	t.Helper()
	id := fixtureID(f.env.Domain, "reader-002")
	binding := f.selected.recipientRecord(id)
	if binding == nil || binding.CurrentBinding == nil {
		t.Fatal("third registered binding is absent")
	}
	digest, err := contract.PublicBindingDigest(*binding.CurrentBinding)
	if err != nil {
		t.Fatal(err)
	}
	row.Wraps = append(row.Wraps, contract.WrapRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id,
		BindingID: binding.CurrentBinding.BindingID, BindingSerial: binding.CurrentBinding.BindingSerial,
		PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{0x95}, 384)})
	slices.SortFunc(row.Wraps, func(a, b contract.WrapRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
	})
}

// full_only: false
func TestAdministrativeEndWorkRemovesAuthenticatedUnsupportedRetainedWrap(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			f := newRetainedReaderFixture(t, recovery, 3)
			store := retainedReaderSignedAccess(t, f, f.value.ValueState, nil, func(row *contract.AccessRecord) { retainedReaderAddUnsupportedWrap(t, f, row) })
			admission := OpenContext{admission: &f.selected.admission}
			if full, result := Open(t.Context(), admission, store); full != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Fatal("complete reader accepted an authenticated unsupported ordinary wrap", result)
			}
			observed := &retainedReaderObservingStore{memoryStore: store}
			key := mustKey(t, store.desc.Prefix, f.retainedRef)
			partial, result := openAdministrative(t.Context(), admission, observed)
			if len(observed.readsFor(key)) != 0 {
				t.Fatal("partial negative control read optional canonical bytes")
			}
			if partial == nil {
				if result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
					t.Fatal("partial negative control refused for an unrelated reason", result)
				}
				t.Log("unsupported wrap refused during partial admission")
				return
			}
			if result.Outcome != ObservedCurrent {
				t.Fatal("partial negative control admission", result)
			}
			t.Run("EndWork selects exact surviving access", func(t *testing.T) {
				owners := retainedReaderOwnerIDs(f)
				next := retainedReaderEndWork(t, partial, owners[0], f.env.Trust)
				next = retainedReaderColdOpen(t, next, observed)
				checkRetainedReaderAccess(t, next, f, true)
				work := mustSelectedGeneratedWork(t, next)
				if next.root.Generated.Hazards != 1 || !bytes.Equal(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, owners[1]}].Body, f.owners[owners[1]]) {
					t.Fatal("unsupported-wrap correction discarded the other real owner")
				}
				if len(observed.readsFor(key)) == 0 {
					t.Fatal("EndWork did not establish the surviving canonical union")
				}
				t.Log("partial admission accepted; actual EndWork removed the unsupported wrap and preserved the other owner")
			})
		})
	}
}

// full_only: false
func TestAdministrativeReaderRefusesMandatoryAccessViolationsWithSkippedCanonical(t *testing.T) {
	for _, fault := range []string{"missing current wrap", "wrong current binding", "unsupported current-only wrap"} {
		t.Run(fault, func(t *testing.T) {
			f := newRetainedReaderFixture(t, false, 3)
			var grants map[contract.ID][]contract.ID
			if fault == "missing current wrap" {
				// Keep the signed access record structurally valid after removing
				// Authority. A real grant gives the current material two readers.
				before := f.current
				readers := []contract.ID{fixtureID(f.env.Domain, "recipient"), fixtureID(f.env.Domain, "reader-002")}
				slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				f.selected = selectRetainedMembership(t, f.env, f.selected, readers, "mandatory-access-grant")
				_, current := lifecycleEntry(t, f.selected, "shared")
				access, present := f.selected.materialAccess(contract.ValueMaterialKind, current.ValueState)
				if !present || !sameRetainedEntryValue(*current, before) || !slices.Equal(current.Recipients, readers) || len(access.Wraps) != 2 {
					t.Fatal("missing-wrap control requires unchanged protection and two real current readers")
				}
				for i, reader := range readers {
					if access.Wraps[i].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[i].SubjectID != reader {
						t.Fatal("grant did not establish two exact ordinary current wraps")
					}
				}
				f.current, f.currentAccess = ownScenarioValueEntry(*current), access
				grants = map[contract.ID][]contract.ID{current.ValueState: {fixtureID(f.env.Domain, "reader-002")}}
				f.retainedRef = format.Ref{}
				for i, page := range f.selected.support {
					for _, row := range page.Records {
						if row.Kind != contract.RetainedCanonicalSupportKind {
							continue
						}
						record, err := contract.InspectRetainedCanonicalRecord(row.Body)
						if err == nil && record.Entry.ValueState == f.value.ValueState {
							f.retainedRef = f.selected.adminIndex.Pages[i].Ref
						}
					}
				}
				if f.retainedRef.Object.IsZero() {
					t.Fatal("grant lost the unrelated old canonical page")
				}
			}
			material := f.current.ValueState
			if fault == "unsupported current-only wrap" {
				_, entry := lifecycleEntry(t, f.selected, "generated")
				material = entry.ValueState
				for _, source := range mustSelectedGeneratedWork(t, f.selected).canonical {
					if source.record.Entry.ValueState == material {
						t.Fatal("current-only negative control has a canonical owner")
					}
				}
			}
			store := retainedReaderSignedAccess(t, f, material, grants, func(row *contract.AccessRecord) {
				if fault == "unsupported current-only wrap" {
					retainedReaderAddUnsupportedWrap(t, f, row)
					return
				}
				authority := fixtureID(f.env.Domain, "recipient")
				i := slices.IndexFunc(row.Wraps, func(w contract.WrapRow) bool {
					return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == authority
				})
				if i < 0 {
					t.Fatal("mandatory current wrap is absent before signed test mutation")
				}
				if fault == "missing current wrap" {
					row.Wraps = slices.Delete(row.Wraps, i, i+1)
				} else {
					row.Wraps[i].BindingSerial++
				}
			})
			observed := &retainedReaderObservingStore{memoryStore: store}
			partial, result := openAdministrative(t.Context(), OpenContext{admission: &f.selected.admission}, observed)
			if partial != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || len(observed.readsFor(mustKey(t, store.desc.Prefix, f.retainedRef))) != 0 {
				t.Fatal("partial reader did not refuse a mandatory access violation with optional canonical bytes skipped", result)
			}
		})
	}
}

// full_only: false
func TestOrdinaryCandidateLeavesFourChildSlotsBeforeEffects(t *testing.T) {
	env := memoryScenarioEnvironmentMode(t, true)
	s := newEnvironmentFixture(t, context.Background(), env, nil, false).session
	for _, total := range []uint32{ordinaryChildPageLimit, ordinaryChildPageLimit + 1} {
		root := s.root
		root.RequiredSupport = slices.Clone(s.root.RequiredSupport)
		otherChildren := s.root.ChildCount - uint32(len(s.root.RequiredSupport))
		for uint32(len(root.RequiredSupport))+otherChildren < total {
			index := uint16(len(root.RequiredSupport))
			var object contract.ID
			object[0] = 0xe7
			binary.BigEndian.PutUint16(object[30:], index+1)
			root.RequiredSupport = append(root.RequiredSupport, format.Ref{Kind: contract.RequiredSupportKind,
				Format: format.Version, Domain: root.Domain, Object: object, Index: index,
				Digest: contract.Hash(object[:]), Length: contract.RequiredSupportPageHeaderLength + contract.SupportRecordMinLength})
			root.RequiredSupportRecordCount++
		}
		next := StateSession{root: root}
		next.recountChildren()
		if next.root.ChildCount != total {
			t.Fatal("wrong candidate fixture count", next.root.ChildCount, total)
		}
		body, err := format.EncodeRoot(next.root)
		if err != nil {
			t.Fatal("format refused boundary fixture", err)
		}
		ref, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, body)
		if err != nil {
			t.Fatal(err)
		}
		candidate := &Candidate{session: s, head: format.Head{Core: format.HeadCore{Root: ref}},
			objects: []objectImage{{ref: ref, body: body}}}
		if got := ordinaryCandidateCapacity(candidate); got != (total == ordinaryChildPageLimit) {
			t.Fatal("wrong four-slot ordinary reserve", total, got)
		}
		if total > ordinaryChildPageLimit {
			if prepared, result := s.persistCandidate(context.Background(), candidate, nil); prepared != nil || result.Reason != CapacityExceeded {
				t.Fatal("over-limit candidate reached Store or Trust effects", result)
			}
		}
	}
}

// A signed HEAD and root may retain a support commitment whose work bytes are
// unavailable. Only the administrative reader may inspect the preserved state.
// full_only: false
func TestAdministrativeReaderAuthenticatesHeadAndPreservesMissingSharedWork(t *testing.T) {
	ctx := context.Background()
	env := memoryScenarioEnvironmentMode(t, true)
	seed := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: seed.admission, session: seed.session}
	s := f.session
	domain := s.root.Domain
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
		Object: testID("missing shared work page"), Digest: testID("missing shared work digest"), Length: 323, Index: 0}
	groupDescriptor := contract.GeneratorDescriptor{Digest: testID("administrative group descriptor"), Length: 4}
	first, second := contract.ID{1}, contract.ID{2}
	firstRow := format.AdministrativeRowSummary{Kind: contract.GeneratedDutySupportKind, RecordID: first, BodyLength: 87}
	secondRow := format.AdministrativeRowSummary{Kind: contract.GeneratedHazardSupportKind, RecordID: second, BodyLength: 87}
	rowBytes := func(row format.AdministrativeRowSummary) []byte {
		b := append([]byte{row.Kind}, row.RecordID[:]...)
		return binary.BigEndian.AppendUint32(b, row.BodyLength)
	}
	index := format.AdministrativeIndex{Domain: domain, Object: testID("work index"), SliceSnapshot: s.root.Snapshot, Groups: []format.AdministrativeGroup{
		{GroupID: first, OwnerID: first, TargetID: first, OwnerKind: format.AdministrativeGeneratedDuty,
			DutyKind: contract.GeneratedDutyCreate, Affected: groupDescriptor, Dependencies: groupDescriptor,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Disposable:              administrativeDescriptor("selected-disposable", rowBytes(firstRow)),
			ChargedPages:            1, ChargedBytes: 124},
		{GroupID: second, OwnerID: second, TargetID: second, OwnerKind: format.AdministrativeGeneratedHazard,
			Affected: groupDescriptor, Dependencies: groupDescriptor,
			SelectedEvidenceSummary: contract.AdministrativeEvidencePossibleLive,
			Disposable:              administrativeDescriptor("selected-disposable", rowBytes(secondRow)),
			ChargedPages:            1, ChargedBytes: 124},
	}, Pages: []format.AdministrativePage{{Ref: ref, Spans: []format.AdministrativeSpan{
		{First: 0, Count: 1, GroupIndexes: []uint16{0}},
		{First: 1, Count: 1, GroupIndexes: []uint16{1}},
	}, Rows: []format.AdministrativeRowSummary{firstRow, secondRow}}}}
	ref.Index = uint16(len(s.root.RequiredSupport))
	index.Pages[0].Ref = ref
	index.Pages = append(slices.Clone(s.adminIndex.Pages), index.Pages...)
	indexPages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(indexPages) != 1 {
		t.Fatal(err)
	}
	indexBody, indexRef := indexPages[0].Body, indexPages[0].Ref
	root := s.root
	root.Snapshot, root.Transition = testID("administrative test snapshot"), testID("administrative test transition")
	root.RequiredSupport = append(slices.Clone(s.root.RequiredSupport), ref)
	root.RequiredSupportRecordCount += 2
	root.Generated.Duties, root.Generated.Hazards = 1, 1
	root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{first, second})
	if err != nil {
		t.Fatal(err)
	}
	root.ChildCount++
	root.ChildEncodedBytes += uint64(ref.Length) + uint64(indexRef.Length) - uint64(root.AdministrativeIndex.Length)
	root.AdministrativeIndex = indexRef
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, err := format.Reference(format.RootKind, domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	head := s.head
	head.Core.PreviousRevision, head.Core.PreviousDigest, head.Core.PreviousToken = s.head.Core.Revision, contract.Hash(s.body), s.token
	head.Core.Revision, head.Core.Root = testID("administrative test revision"), rootRef
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	condition, err := contract.MatchHeadCondition(head.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	planBody, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: head.Core.PreviousToken.Family,
		Store: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody,
		Condition: condition, HeadCore: head.Subject.HeadCore, HeadCoreLength: head.Subject.HeadCoreLength})
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.ConditionalPlan = contract.Hash(planBody)
	head.Subject.Request = requestCommitment(head.Core, head.Subject)
	request, err := contract.NewLifecycleRequest(head.Subject)
	if err != nil {
		t.Fatal(err)
	}
	signed := f.trust.Sign(ctx, request)
	if signed.Reason != contract.ReasonNone {
		t.Fatal("lifecycle signing refused", signed.Reason)
	}
	head.AuthorizationSignature = signed.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	put := func(key string, body []byte) {
		f.store.mu.Lock()
		defer f.store.mu.Unlock()
		f.store.put(key, body)
	}
	for _, object := range []struct {
		ref  format.Ref
		body []byte
	}{{indexRef, indexBody}, {rootRef, rootBody}} {
		key, err := format.Key(s.admission.store.Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		put(key, object.body)
	}
	put(s.admission.store.HeadKey, headBody)
	fresh := func() *StateSession {
		return &StateSession{admission: s.admission, store: s.store, key: s.key, cache: make(map[format.Ref][]byte)}
	}
	admin, result := fresh().readAdministrativeImage(ctx)
	if admin == nil || result.Outcome != ObservedCurrent {
		t.Fatal("administrative reader rejected signed preserved image", result)
	}
	preserved, err := admin.preservedState(t.Context(), contract.SuccessionChangeNormalSigner, true)
	if err != nil {
		t.Fatal("signer preservation required missing optional work", err)
	}
	changed := *admin
	changed.root.RequiredSupport = append([]format.Ref(nil), admin.root.RequiredSupport...)
	optionalPosition := len(s.root.RequiredSupport)
	changed.root.RequiredSupport[optionalPosition].Digest = testID("different missing work digest")
	changed.adminIndex.Pages = append([]format.AdministrativePage(nil), admin.adminIndex.Pages...)
	changed.adminIndex.Pages[optionalPosition].Ref = changed.root.RequiredSupport[optionalPosition]
	other, err := changed.preservedState(t.Context(), contract.SuccessionChangeNormalSigner, true)
	if err != nil || preserved == other {
		t.Fatal("signer preservation lost unavailable work commitment", err)
	}
	used := admin.signerOnlyClosureIDs()
	if used == nil || !used[first] || !used[second] || !used[ref.Object] || !used[index.Object] {
		t.Fatal("signer-only identity inventory required optional work bytes")
	}
	after := currentControlOf(admin)
	successor, binding := f.trust.Successor(t, after.NormalSigning)
	after.NormalSigning = binding
	after.AccessGeneration++
	permit := admitAuthorityReplacement(t, admin, env.Custody, after, contract.SuccessionReplaceAuthority,
		contract.RecoverySigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
	f.trust.SetUnavailable(true)
	candidate, restored := admin.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: env.Recovery, NormalSuccessor: successor})
	if candidate == nil || restored.Outcome != ObservedCurrent || candidate.succession == nil || candidate.succession.basis == nil {
		t.Fatal("recovery signer-only restoration required missing optional work", restored)
	}
	if ordinary, result := fresh().readCurrent(ctx); ordinary != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary reader accepted missing selected work", result)
	}
	remaining, err := admin.administrativeWorkDisposition(first)
	if err != nil || len(remaining.Groups) != 1 || remaining.Groups[0].GroupID != second ||
		len(remaining.Pages) != len(s.adminIndex.Pages)+1 || !slices.EqualFunc(remaining.Pages[:len(s.adminIndex.Pages)], s.adminIndex.Pages, func(a, b format.AdministrativePage) bool {
		return a.Ref == b.Ref && a.ReadRequired == b.ReadRequired && slices.Equal(a.Rows, b.Rows) &&
			slices.EqualFunc(a.Spans, b.Spans, func(a, b format.AdministrativeSpan) bool {
				return a.First == b.First && a.Count == b.Count && a.Mandatory == b.Mandatory && slices.Equal(a.GroupIndexes, b.GroupIndexes)
			})
	}) ||
		remaining.Pages[optionalPosition].Ref != ref || len(remaining.Pages[optionalPosition].Spans) != 1 ||
		remaining.Pages[optionalPosition].Spans[0].First != 1 {
		t.Fatal("other damaged group or page commitment changed", err)
	}
	currentRef := *root.ValueEntryPages[0]
	currentKey, err := format.Key(s.admission.store.Prefix, currentRef)
	if err != nil {
		t.Fatal(err)
	}
	f.store.mu.Lock()
	current := f.store.objects[currentKey]
	delete(f.store.objects, currentKey)
	f.store.mu.Unlock()
	if image, result := fresh().readAdministrativeImage(ctx); image != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("administrative reader accepted missing current entry", result)
	}
	f.store.mu.Lock()
	f.store.objects[currentKey] = current
	f.store.mu.Unlock()
	indexKey, err := format.Key(s.admission.store.Prefix, indexRef)
	if err != nil {
		t.Fatal(err)
	}
	f.store.mu.Lock()
	selectedIndex := f.store.objects[indexKey]
	delete(f.store.objects, indexKey)
	f.store.mu.Unlock()
	if image, result := fresh().readAdministrativeImage(ctx); image != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("administrative reader accepted missing mandatory index", result)
	}
	f.store.mu.Lock()
	f.store.objects[indexKey] = selectedIndex
	f.store.mu.Unlock()
	f.store.mu.Lock()
	selectedHead := f.store.objects[s.admission.store.HeadKey]
	f.store.mu.Unlock()
	damagedHead := append([]byte(nil), headBody...)
	damagedHead[len(damagedHead)-1] ^= 1
	put(s.admission.store.HeadKey, damagedHead)
	if image, result := fresh().readAdministrativeImage(ctx); image != nil || result.Outcome != IntegrityFailure {
		t.Fatal("administrative reader accepted damaged HEAD proof", result)
	}
	f.store.mu.Lock()
	f.store.objects[s.admission.store.HeadKey] = selectedHead
	f.store.mu.Unlock()
	admission := deliverSuccessionBasis(t, candidate)
	if result := admin.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("signer-only recovery selection required missing optional work", result)
	}
	selected, result := openAdministrative(ctx, admission, f.store)
	if selected == nil || result.Outcome != ObservedCurrent || !slices.Contains(selected.root.RequiredSupport, ref) ||
		selected.root.WarningBits != root.WarningBits {
		t.Fatal("restored signer lost selected work or warning commitment", result)
	}
	if ordinary, result := Open(ctx, admission, f.store); ordinary != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary open accepted retained missing work after signer restoration", result)
	}
}

// full_only: false
func TestGeneratedSignerRestorationPreservesMissingAuxiliaryPage(t *testing.T) {
	ctx := t.Context()
	a := newGeneratedActualOperation(t, true, custody.StandardValue)
	store := a.env.Store.(*memoryStore)
	before := a.fixture.session
	work := mustSelectedGeneratedWork(t, before)
	if work.parent == nil || work.parent.OperationID != a.expected.Plan.OperationID || len(before.adminIndex.Groups) != 2 ||
		before.root.Generated.Duties != 1 || before.root.Generated.Materials != 1 || len(before.accessRecords()) != 1 {
		t.Fatal("restoration fixture lacks the exact parent/Create-Duty/seed closure")
	}
	rows, err := before.workSupportRecords(ctx)
	if err != nil {
		t.Fatal("restoration predecessor work rows", err)
	}
	configuration := before.root.OutputConfiguration
	configurationFacts, err := before.selectedOutputFactsByRecord()
	if err != nil || len(configurationFacts) == 0 || len(configurationFacts) != int(configuration.SliceCount) {
		t.Fatal("restoration predecessor configuration facts", err)
	}
	assertConfiguration := func(selected *StateSession) {
		t.Helper()
		facts, err := selected.selectedOutputFactsByRecord()
		if err != nil || selected.root.OutputConfiguration != configuration || len(facts) != len(configurationFacts) {
			t.Fatal("restoration changed mandatory configuration descriptor or slice count", err)
		}
		for id, original := range configurationFacts {
			if fact, present := facts[id]; !present || fact.row != original.row {
				t.Fatal("restoration changed an authenticated configuration slice", id)
			}
		}
	}
	parentID, dutyID := work.parent.OperationID, a.expected.Template.DutyID
	var target format.AdministrativeGroup
	for _, group := range before.adminIndex.Groups {
		if group.GroupID == parentID && group.OwnerKind == format.AdministrativeGeneratedParent {
			target = group
		} else if group.GroupID != dutyID || group.OwnerKind != format.AdministrativeGeneratedDuty || group.DutyKind != contract.GeneratedDutyCreate {
			t.Fatal("restoration fixture has an unrelated owner")
		}
	}
	if target.GroupID.IsZero() {
		t.Fatal("restoration fixture lacks its actual parent group")
	}
	var disposable *format.Ref
	for _, page := range before.adminIndex.Pages {
		mandatory := false
		blobDetail := false
		for _, span := range page.Spans {
			mandatory = mandatory || span.Mandatory
		}
		for _, row := range page.Rows {
			blobDetail = blobDetail || row.Kind == contract.GeneratedFragmentSupportKind
		}
		if !mandatory && !page.ReadRequired && blobDetail {
			ref := page.Ref
			disposable = &ref
			break
		}
	}
	if disposable == nil {
		t.Fatal("active generated image has no optional detail page")
	}
	selected := false
	for _, page := range before.adminIndex.Pages {
		if page.Ref != *disposable {
			continue
		}
		for _, row := range page.Rows {
			selected = selected || row.Kind == contract.GeneratedFragmentSupportKind
		}
	}
	if !selected {
		t.Fatal("selected missing page has no optional blob detail")
	}
	key, err := format.Key(before.admission.store.Prefix, *disposable)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	missing := store.objects[key]
	delete(store.objects, key)
	store.mu.Unlock()
	if len(missing.Body) == 0 {
		t.Fatal("selected auxiliary page was absent before simulated loss")
	}
	admin, result := openAdministrative(ctx, OpenContext{admission: &before.admission}, store)
	if admin == nil || result.Outcome != ObservedCurrent {
		t.Fatal("active generated administrative open needed auxiliary bytes", result)
	}
	if normal, result := Open(ctx, OpenContext{admission: &before.admission}, store); normal != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("normal open accepted missing selected auxiliary bytes", result)
	}
	replacement := syntheticFreshAuthorityReplacementEnvironment(t, a.env)
	actors := replacement.ReplacementActors(t, ctx, admin, contract.SuccessionReplaceAuthority,
		contract.SuccessionChangeNormalSigner, contract.RecoverySigningRole)
	permit := admitAuthorityReplacement(t, admin, actors.Keys, actors.After, contract.SuccessionReplaceAuthority,
		contract.RecoverySigningRole, contract.SuccessionChangeNormalSigner, actors.Source)
	candidate, result := admin.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signer restoration needed auxiliary bytes", result)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if result := admin.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("signer restoration selection needed auxiliary bytes", result)
	}
	restored, result := openAdministrative(ctx, admission, store)
	if restored == nil || result.Outcome != ObservedCurrent ||
		restored.root.RequiredSupport[disposable.Index] != *disposable {
		t.Fatal("restoration lost selected auxiliary commitment", result)
	}
	assertConfiguration(restored)
	if normal, result := Open(ctx, admission, store); normal != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary open accepted missing work after restoration", result)
	}
	// The original Store copy keeps the existing exact-repair control. Disposal
	// starts from its independently copied, still-damaged restored HEAD.
	store.mu.Lock()
	discardStore := &memoryStore{desc: store.desc, configuration: store.configuration, generation: store.generation, fileBodies: store.fileBodies,
		objects: make(map[string]stored, len(store.objects))}
	for objectKey, object := range store.objects {
		object.Body = bytes.Clone(object.Body)
		discardStore.objects[objectKey] = object
	}
	store.mu.Unlock()
	discard, result := openAdministrative(ctx, admission, discardStore)
	if discard == nil || result.Outcome != ObservedCurrent {
		t.Fatal("restored damaged Store copy did not cold-open", result)
	}
	windows, err := discard.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal("restored predecessor receipt windows", err)
	}
	creates, cas := discardStore.creates, discardStore.cas
	issueTestEndWorkInvocation(t, discard)
	if denied, result := discard.prepareEndSelectedWork(ctx, parentID, a.env.Recovery); denied != nil ||
		result.Outcome != AdmissionRefused || result.Reason != AdmissionInvalid || discardStore.creates != creates || discardStore.cas != cas {
		t.Fatal("Recovery gained administrative exit authority", result)
	}
	public, private := a.env.Custody.Calls()
	exit, result := prepareTestEndSelectedWork(t, discard, ctx, parentID, actors.Signers.NormalSuccessor)
	if exit == nil || result.Outcome != ObservedCurrent || exit.firstSend != nil {
		t.Fatal("restored Authority could not prepare disposal with absent detail", result)
	}
	if selected, result := discard.selectCandidate(ctx, exit); selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("restored Authority disposal selection", result)
	}
	after, result := Open(ctx, admission, discardStore)
	if after == nil || result.Outcome != ObservedCurrent {
		t.Fatal("restored Authority disposal did not cold-open", result)
	}
	adminAfter, result := openAdministrative(ctx, admission, discardStore)
	if adminAfter == nil || result.Outcome != ObservedCurrent || !bytes.Equal(adminAfter.body, after.body) || adminAfter.token != after.token {
		t.Fatal("restored disposal readers disagree", result)
	}
	kept := mustSelectedGeneratedWork(t, after)
	if kept.parent != nil || kept.phase != nil || len(kept.attempts) != 0 || len(kept.bundles) != 0 || len(after.adminIndex.Groups) != 0 ||
		after.root.Generated.Materials != 0 || after.root.Generated.Duties != 0 || after.root.Generated.Hazards != 0 ||
		after.root.Generated.Results != 0 || after.root.Generated.PendingReleases != 0 || len(after.accessRecords()) != 0 ||
		!reflect.DeepEqual(after.currentEntryInputs(), restored.currentEntryInputs()) ||
		!reflect.DeepEqual(after.root.ValueEntryPages, restored.root.ValueEntryPages) || !reflect.DeepEqual(after.root.Recipients, restored.root.Recipients) ||
		after.root.ValueEntryCount != restored.root.ValueEntryCount || after.root.RawBytes != restored.root.RawBytes ||
		after.root.MembershipCount != restored.root.MembershipCount {
		t.Fatal("restored Authority disposal changed current state or retained its exact exclusive closure")
	}
	assertConfiguration(after)
	for _, row := range rows {
		if row.Kind == contract.OutputConfigurationSliceSupportKind {
			continue
		}
		if _, present := kept.records[generatedRecordKey{row.Kind, row.RecordID}]; present {
			t.Fatal("restored disposal retained an exclusive work row", row.Kind, row.RecordID)
		}
	}
	if len(kept.content.locations) != 0 || len(after.root.Generated.Fragments) != 1 ||
		slices.Contains(after.root.RequiredSupport, *disposable) {
		t.Fatal("restored disposal retained exclusive Intent/graph/blob locations")
	}
	if _, present := discardStore.objects[key]; present {
		t.Fatal("restored Authority disposal repaired its absent auxiliary page")
	}
	ids := []contract.ID{parentID, dutyID}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	// Independent ended-groups framing: u32 count, then u32 length32 + ID.
	framing := binary.BigEndian.AppendUint32(nil, 2)
	for _, id := range ids {
		framing = binary.BigEndian.AppendUint32(framing, 32)
		framing = append(framing, id[:]...)
	}
	digest := sha256.Sum256(append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), framing...))
	dependent := contract.GeneratorDescriptor{Digest: contract.ID(digest), Length: 76, Count: 2}
	warning := restored.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	q := after.head.EndWork
	if q == nil || q.TargetGroupID != parentID || q.TargetOwnerID != target.OwnerID || q.TargetKind != target.OwnerKind || q.TargetID != target.TargetID ||
		q.SelectedEvidenceSummary != target.SelectedEvidenceSummary || q.DependentGroups != dependent ||
		q.PredecessorRevisionID != restored.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(restored.body) || q.PredecessorToken != restored.token ||
		q.BeforeWarningBits != restored.root.WarningBits || q.AfterWarningBits != warning || after.root.WarningBits != warning ||
		q.BeforeChildCount != uint16(restored.root.ChildCount) || q.AfterChildCount != uint16(after.root.ChildCount) ||
		q.BeforeChildBytes != restored.root.ChildEncodedBytes || q.AfterChildBytes != after.root.ChildEncodedBytes {
		t.Fatal("restored disposal lost its exact envelope or permanent warning")
	}
	got, err := after.receiptWindows(ctx)
	if err != nil || len(got.Successes) != len(windows.Successes)+1 ||
		!slices.Equal(got.Successes[:len(windows.Successes)], windows.Successes) || !slices.Equal(got.Failures, windows.Failures) {
		t.Fatal("restored disposal changed prior receipt windows", err)
	}
	receipt := got.Successes[len(got.Successes)-1]
	if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID || receipt.StateResult != contract.ReceiptStateWorkEnded ||
		receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected ||
		receipt.AdministrativeTargetKind != target.OwnerKind || receipt.AdministrativeTargetID != target.TargetID ||
		receipt.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary || receipt.WarningBits != uint64(warning) ||
		receipt.AdministrativeWarningChanges != warning&^restored.root.WarningBits || receipt.PredecessorRevisionID != restored.head.Core.Revision ||
		receipt.ObservedRevisionID != after.head.Core.Revision {
		t.Fatal("restored Authority receipt lost the exact local disposition")
	}
	if p, k := a.env.Custody.Calls(); p != public || k != private || a.sends != 1 {
		t.Fatal("restored administrative disposal invoked a custody key route or repeated the producer")
	}
	store.mu.Lock()
	store.objects[key] = missing
	store.mu.Unlock()
	if normal, result := Open(ctx, admission, store); normal == nil || result.Outcome != ObservedCurrent {
		t.Fatal("restored normal authority did not reopen after exact page repair", result)
	}
}

// full_only: false
func TestAdministrativeReaderRefusesMissingSliceProjectionPage(t *testing.T) {
	ctx := context.Background()
	a := newGeneratedActualOperation(t, true, custody.StandardValue)
	store := a.env.Store.(*memoryStore)
	selected := a.fixture.session
	var readRequired *format.Ref
	for _, page := range selected.adminIndex.Pages {
		if page.ReadRequired {
			ref := page.Ref
			readRequired = &ref
			break
		}
	}
	if readRequired == nil {
		t.Fatal("generated image has no readable Slice projection page")
	}
	key, err := format.Key(selected.admission.store.Prefix, *readRequired)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	missing := store.objects[key]
	delete(store.objects, key)
	store.mu.Unlock()
	if len(missing.Body) == 0 {
		t.Fatal("Slice projection page was absent before loss")
	}
	if image, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store); image != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("administrative reader accepted missing core Slice projection", result)
	}
	store.mu.Lock()
	store.objects[key] = missing
	store.mu.Unlock()
	if image, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store); image == nil || result.Outcome != ObservedCurrent {
		t.Fatal("restored exact Slice projection did not reopen", result)
	}
}

// full_only: false
func TestGeneratedAdministrativeIndexBindsSelectedDutyToParent(t *testing.T) {
	a := newGeneratedActualOperation(t, true, custody.StandardValue)
	store := a.env.Store.(*memoryStore)
	selected := selectFreshGeneratedRecord(t, store, a.fixture.session, a.expected.Template.AttemptID, a.result)
	parent := -1
	for i, group := range selected.adminIndex.Groups {
		if group.OwnerKind == format.AdministrativeGeneratedParent {
			parent = i
			break
		}
	}
	if parent < 0 {
		t.Fatal("selected generated parent has no mandatory ownership envelope")
	}
	duties := 0
	for _, group := range selected.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativeGeneratedDuty {
			continue
		}
		duties++
		if len(group.RelatedGroupIndexes) != 1 || group.RelatedGroupIndexes[0] != uint16(parent) {
			t.Fatal("duty lost selected parent dependency")
		}
	}
	if duties == 0 {
		t.Fatal("recorded result has no selected duty to test")
	}
	for _, page := range selected.adminIndex.Pages {
		mandatory, disposable := false, false
		for _, span := range page.Spans {
			mandatory = mandatory || span.Mandatory
			disposable = disposable || len(span.GroupIndexes) != 0
		}
		if mandatory && disposable {
			t.Fatal("current evidence and optional duty share one damage unit", page.Ref.Index)
		}
	}
}

func signedPublicationReadFixture(t *testing.T) (fixtureEnvironment, *environmentFixture, contract.PublicationCoordinate, contract.PublicationMarker) {
	return signedPublicationSelectionFixture(t, format.LifecycleAuth, true)
}

func signedPublicationSelectionFixture(t *testing.T, authKind uint8, recovery bool) (fixtureEnvironment, *environmentFixture, contract.PublicationCoordinate, contract.PublicationMarker) {
	t.Helper()
	env, _ := genesisEnvironment(t, contract.GCP, recovery)
	f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	current := *f.session
	current.support = slices.Clone(current.support)
	store := env.Store.(*memoryStore)
	for i, ref := range current.root.RequiredSupport {
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		read := store.Read(t.Context(), key, ref.Length)
		if read.Status != contract.ReadOK {
			t.Fatal("fixture selected support unavailable")
		}
		current.support[i], err = format.InspectRequiredSupportPage(read.Body)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, current.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	coordinate.LastAdmissionOrdinal, marker.AdmissionOrdinal = 3, 3
	history := publicationRelationID(111)
	coordinate.LastValueAckAttemptID, coordinate.LastValueDigest = publicationRelationID(112), publicationRelationID(113)
	coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = history, 1
	coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest = publicationRelationID(114), publicationRelationID(115)
	coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = history, 2
	coordinate.LastDeleteAckAttemptID = publicationRelationID(116)
	coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal = history, 2

	marker.Projection.ConfigurationDigest = current.root.OutputConfiguration.ConfigurationDigest
	var projectionErr error
	marker.ProjectionCommitment, projectionErr = contract.PublicationProjectionCommitment(marker.Projection)
	if projectionErr != nil {
		t.Fatal(projectionErr)
	}
	reserve := contract.OutputReserveSubject{Schema: 5, Action: marker.Projection.Action,
		DomainID: marker.DomainID, OperationID: marker.OperationID, AttemptID: marker.AttemptID,
		PredecessorRevisionID: current.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(current.body), PredecessorToken: current.token,
		CurrentAccessRoot: current.root.CurrentAccess.AccessRoot, ConfigurationDigest: marker.Projection.ConfigurationDigest,
		CoordinateID: coordinate.CoordinateID, PublicationIncarnationID: marker.PublicationIncarnationID, AdmissionOrdinal: marker.AdmissionOrdinal,
		BindingIncarnationID: marker.Projection.BindingIncarnationID, EntryIncarnationID: marker.Projection.EntryIncarnationID,
		TargetRowDigest: marker.Projection.TargetRowDigest, PolicyDigest: marker.Projection.PolicyDigest,
		RequestContractDigest: marker.Projection.RequestContractDigest, DispatchContextDigest: publicationRelationID(122)}
	if authKind != format.LifecycleAuth {
		var err error
		marker.AuthoritySubjectDigest, err = contract.OutputReserveAdmissionDigest(reserve, marker)
		if err != nil {
			t.Fatal("publication fixture reservation admission", err)
		}
	}
	if authKind == format.OutputReserveAuth {
		marker.State = contract.PublicationMayHaveEntered
	}
	rows := publicationRelationRows(t, coordinate, marker)
	physical := generatedFixtureFreeSupportIndex(t, &current)
	current.support = append(current.support, format.RequiredSupportPageView{Domain: current.root.Domain,
		Object: publicationRelationID(120), Index: physical,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	current.root.Snapshot, current.root.Transition = fixtureID(env.Domain, "publication read snapshot"), fixtureID(env.Domain, "publication read transition")
	current.adminIndex.PublicationOrder = []format.PublicationCoordinateOrder{{CoordinateID: coordinate.CoordinateID, Incarnations: []contract.ID{history, coordinate.CurrentPublicationIncarnationID}}}
	generatedRefreshSupport(t, &current)
	for _, page := range current.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for i, row := range page.Records {
			rows[i] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.put(key, body)
	}
	indexes, err := format.EncodeAdministrativeIndexPages(current.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range indexes {
		key, err := format.Key(store.desc.Prefix, page.Ref)
		if err != nil {
			t.Fatal(err)
		}
		store.put(key, page.Body)
	}
	rootBody, err := format.EncodeRoot(current.root)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, err := format.Reference(format.RootKind, current.root.Domain, current.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := format.Key(store.desc.Prefix, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	store.put(rootKey, rootBody)
	h := current.head
	h.Core.Root, h.Core.Revision = rootRef, fixtureID(env.Domain, "publication read revision")
	h.Core.PreviousRevision, h.Core.PreviousDigest, h.Core.PreviousToken = f.session.head.Core.Revision, contract.Hash(f.session.body), f.session.token
	current.head.Core.Root = rootRef
	if !current.indexSelectedMaterials() {
		t.Fatal("publication fixture selected material relation")
	}
	h.Subject.Operation = fixtureID(env.Domain, "publication read operation")
	h.Subject.Normal.PublicState = current.publicState()
	h.Subject.Request = requestCommitment(h.Core, h.Subject)
	core, err := format.EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := format.EncodeConditionalPlan(conditional(h.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	h.Subject.HeadCore, h.Subject.HeadCoreLength, h.Subject.ConditionalPlan = contract.Hash(core), uint32(len(core)), contract.Hash(plan)
	q, err := contract.NewLifecycleRequest(h.Subject)
	h.AuthorizationSignature = currentBasisSign(t, env.Trust, q, err)

	switch authKind {
	case format.OutputReserveAuth:
		h.AuthKind, h.Subject, h.OutputReserve = authKind, contract.LifecycleSubject{}, &reserve
	case format.OutputCloseAuth:
		evidence, err := contract.EncodePublicationEvidence(marker.Evidence)
		if err != nil {
			t.Fatal(err)
		}
		h.AuthKind, h.Subject = authKind, contract.LifecycleSubject{}
		h.OutputClose = &contract.OutputCloseSubject{Schema: 4, Action: marker.Projection.Action,
			DomainID: marker.DomainID, OperationID: marker.OperationID, AttemptID: marker.AttemptID,
			ReservationAdmissionDigest: marker.AuthoritySubjectDigest,
			PredecessorRevisionID:      h.Core.PreviousRevision, PredecessorFullHEADDigest: h.Core.PreviousDigest, PredecessorToken: h.Core.PreviousToken,
			CurrentAccessRoot: reserve.CurrentAccessRoot, ConfigurationDigest: reserve.ConfigurationDigest,
			CoordinateID: marker.CoordinateID, BindingIncarnationID: marker.Projection.BindingIncarnationID,
			EntryIncarnationID: marker.Projection.EntryIncarnationID, TargetRowDigest: marker.Projection.TargetRowDigest,
			ActionProjectionCommitment: marker.ProjectionCommitment, EntryClass: marker.Evidence.Entry,
			ResultClass: marker.Evidence.Class, LateRisk: marker.LateEffectRisk, ResultEvidenceDigest: contract.Hash(evidence)}
	}
	storeSignedPublicationHead(t, env, h)
	selected, result := Open(t.Context(), f.admission, store)
	if selected == nil {
		t.Fatal("signed publication fixture cold read", result)
	}
	f.session = selected
	return env, f, coordinate, marker
}

// full_only: false
func TestSignedPublicationPartialReadKeepsHistoryWithoutCompleteProof(t *testing.T) {
	for _, fault := range []string{"missing", "changed", "denied"} {
		t.Run(fault, func(t *testing.T) {
			env, f, coordinate, marker := signedPublicationReadFixture(t)
			store := env.Store.(*memoryStore)
			var ref format.Ref
			for _, page := range f.session.adminIndex.Pages {
				if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.RecordID == marker.AttemptID }) {
					ref = page.Ref
				}
			}
			key, err := format.Key(store.desc.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual != key {
					return read
				}
				switch fault {
				case "missing":
					return contract.ReadResult{Status: contract.ReadMissing}
				case "denied":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				default:
					read.Body = bytes.Clone(read.Body)
					read.Body[len(read.Body)-1] ^= 1
					return read
				}
			}
			env.Custody.SetUnavailable(true)
			creates, cas := store.creates, store.cas
			partial, result := openAdministrative(t.Context(), f.admission, store)
			if partial == nil || result.Outcome != ObservedCurrent {
				t.Fatal("partial signed publication read refused", result)
			}
			coordinates, err := partial.publicationCoordinatesForDisposition()
			if err != nil || !reflect.DeepEqual(coordinates[coordinate.CoordinateID], coordinate) || !reflect.DeepEqual(partial.adminIndex.PublicationOrder, f.session.adminIndex.PublicationOrder) {
				t.Fatal("partial read changed exact coordinate or incarnation history", err)
			}
			if partial.publicationProof != nil {
				t.Fatal("partial read acquired complete publication proof")
			}
			if _, result, err := validateSelectedPublicationConfiguration(t.Context(), partial.selectedImage(), partial); result.Outcome == 0 && err == nil {
				t.Fatal("partial stamp replaced full action/result/ownership proof")
			}
			if _, err := selectedPublicationFilterProof(partial.selectedImage()); err == nil {
				t.Fatal("partial read authorized complete publication preservation")
			}
			want := Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}
			if fault == "changed" {
				want = Result{Outcome: IntegrityFailure, Reason: InvalidReference}
			}
			if fault == "denied" {
				want = Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}
			}
			if ordinary, result := Open(t.Context(), f.admission, store); ordinary != nil || result != want {
				t.Fatal("ordinary read omitted selected marker", result)
			}
			if store.creates != creates || store.cas != cas {
				t.Fatal("partial or refused read changed remote state")
			}
		})
	}
}

// full_only: false
func TestSignedPublicationReadRefusesMissingMandatoryPages(t *testing.T) {
	for _, kind := range []uint8{contract.OutputConfigurationSliceSupportKind, contract.PublicationCoordinateSupportKind} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			env, f, _, _ := signedPublicationReadFixture(t)
			store := env.Store.(*memoryStore)
			var ref format.Ref
			for _, page := range f.session.adminIndex.Pages {
				if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.Kind == kind }) {
					ref = page.Ref
				}
			}
			key, err := format.Key(store.desc.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			delete(store.objects, key)
			if selected, result := openAdministrative(t.Context(), f.admission, store); selected != nil || result != (Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}) {
				t.Fatal("partial reader omitted required publication state", result)
			}
		})
	}
}

func storeSignedPublicationHead(t *testing.T, env fixtureEnvironment, h format.Head) {
	t.Helper()
	if h.OutputReserve != nil || h.OutputClose != nil {
		core, err := format.EncodeHeadCore(h.Core)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := format.EncodeConditionalPlan(conditional(h.Core, core))
		if err != nil {
			t.Fatal(err)
		}
		var request contract.SignRequest
		if reserve := h.OutputReserve; reserve != nil {
			reserve.HeadCoreDigest, reserve.HeadCoreLength, reserve.ConditionalPlanDigest = contract.Hash(core), uint32(len(core)), contract.Hash(plan)
			request, err = contract.NewOutputReserveRequest(*reserve)
		} else {
			close := h.OutputClose
			close.HeadCoreDigest, close.HeadCoreLength, close.ConditionalPlanDigest = contract.Hash(core), uint32(len(core)), contract.Hash(plan)
			request, err = contract.NewOutputCloseRequest(*close)
		}
		h.AuthorizationSignature = currentBasisSign(t, env.Trust, request, err)
	}
	body, err := format.EncodeHead(h)
	if err != nil {
		t.Fatal("signed publication HEAD fixture", err)
	}
	store := env.Store.(*memoryStore)
	store.put(store.desc.HeadKey, body)
}

// full_only: false
func TestSignedOutputSelectionBindsRetainedAdmissionAndResult(t *testing.T) {
	for _, authKind := range []uint8{format.OutputReserveAuth, format.OutputCloseAuth} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", authKind, recovery), func(t *testing.T) {
				env, f, _, _ := signedPublicationSelectionFixture(t, authKind, recovery)
				changes := map[string]func(*format.Head){
					"configuration": func(h *format.Head) {
						if h.OutputReserve != nil {
							h.OutputReserve.ConfigurationDigest = publicationRelationID(123)
						} else {
							h.OutputClose.ConfigurationDigest = publicationRelationID(123)
						}
					},
					"current access": func(h *format.Head) {
						if h.OutputReserve != nil {
							h.OutputReserve.CurrentAccessRoot = publicationRelationID(124)
						} else {
							h.OutputClose.CurrentAccessRoot = publicationRelationID(124)
						}
					},
					"target": func(h *format.Head) {
						if h.OutputReserve != nil {
							h.OutputReserve.TargetRowDigest = publicationRelationID(125)
						} else {
							h.OutputClose.TargetRowDigest = publicationRelationID(125)
						}
					},
				}
				if authKind == format.OutputReserveAuth {
					changes["incarnation"] = func(h *format.Head) { h.OutputReserve.PublicationIncarnationID = publicationRelationID(127) }
					changes["ordinal"] = func(h *format.Head) { h.OutputReserve.AdmissionOrdinal++ }
				} else {
					changes["reservation admission"] = func(h *format.Head) { h.OutputClose.ReservationAdmissionDigest = publicationRelationID(128) }
					changes["result evidence"] = func(h *format.Head) { h.OutputClose.ResultEvidenceDigest = publicationRelationID(129) }
					changes["result class"] = func(h *format.Head) { h.OutputClose.ResultClass = contract.PublicationQualifiedNoEffect }
				}
				changes["wrong recovery basis"] = func(h *format.Head) { h.K3 = bytes.Clone(h.K1) }
				if recovery {
					changes["missing recovery basis"] = func(h *format.Head) { h.K3 = nil }
				}

				store := env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				public, private := env.Custody.Calls()
				env.Custody.SetUnavailable(true)
				t.Cleanup(func() {
					p, k := env.Custody.Calls()
					if store.creates != creates || store.cas != cas || p != public || k != private {
						t.Fatal("output selection read used Store mutation or private custody")
					}
				})
				if authKind == format.OutputReserveAuth {
					t.Run("dispatch signature", func(t *testing.T) {
						h := f.session.head
						reserve := *h.OutputReserve
						reserve.DispatchContextDigest = publicationRelationID(126)
						h.OutputReserve = &reserve
						// Dispatch is bound by the full signature, outside the retained admission digest.
						body, err := format.EncodeHead(h)
						if err != nil {
							t.Fatal("dispatch signature fixture", err)
						}
						store.put(store.desc.HeadKey, body)
						control, ok := f.session.selectedControl()
						if !ok || f.session.verifyHeadProofs(h, control) {
							t.Fatal("changed dispatch retained a valid original signature")
						}
						if selected, result := Open(t.Context(), f.admission, env.Store); selected != nil || result != (Result{Outcome: IntegrityFailure, Reason: InvalidProof}) {
							t.Fatal("changed dispatch accepted without a new full signature", result)
						}
					})
				}
				for name, change := range changes {
					t.Run(name, func(t *testing.T) {
						h := f.session.head
						if h.OutputReserve != nil {
							reserve := *h.OutputReserve
							h.OutputReserve = &reserve
						}
						if h.OutputClose != nil {
							close := *h.OutputClose
							h.OutputClose = &close
						}
						change(&h)
						storeSignedPublicationHead(t, env, h)
						control, ok := f.session.selectedControl()
						storedHead, err := format.DecodeHead(env.Store.(*memoryStore).objects[env.Store.Descriptor().HeadKey].Body)
						if !ok || err != nil || (name != "wrong recovery basis" && name != "missing recovery basis") && !f.session.verifyHeadProofs(storedHead, control) {
							t.Fatal("outer current signing proof fixture invalid")
						}
						if selected, result := Open(t.Context(), f.admission, env.Store); selected != nil || result != (Result{Outcome: IntegrityFailure, Reason: InvalidProof}) {
							t.Fatal("freshly signed output closure accepted stale selected fact", result)
						}
					})
				}
			})
		}
	}
}
