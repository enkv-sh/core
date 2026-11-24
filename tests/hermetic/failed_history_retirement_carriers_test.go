package core

import (
	"bytes"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestFailedHistoryKeepsLaterRetirementIntentCarriers(t *testing.T) {
	for _, bCount := range []int{20, 26} {
		t.Run(fmt.Sprintf("b%d", bCount), func(t *testing.T) {
			_ = actualFailedHistoryRetirementCarriers(t, bCount)
		})
	}
	t.Run("b20_two_failed_prefixes_plain_fill", func(t *testing.T) {
		f := actualFailedHistoryRetirementCarriersWithPrefixes(t, 20, 2)
		before := f.selected
		owned := sessionStateImage(t, before)
		beforeWindows, err := before.receiptWindows(t.Context())
		if err != nil {
			t.Fatal("Plain fill predecessor receipts", err)
		}
		oldWork := mustSelectedGeneratedWork(t, before)
		oldLocations := make(map[generatedContentKey]contract.GeneratorSliceLocation, len(oldWork.content.locations))
		for key, location := range oldWork.content.locations {
			oldLocations[key] = location
		}
		proposed := before.currentEntryInputs()
		for i := 0; i < 10; i++ {
			proposed = append(proposed, ApplyEntryInput{Name: fmt.Sprintf("plain-fill-%02d", i), Recipients: []contract.ID{before.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte{byte(i + 1)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		}
		parent := admitSuppliedComparison(t, before, f.env.Custody, proposed, staticGeneratedHandoffImplementation(t, f.env.Domain, defaultGeneratedFixtureProfile()))
		comparison, result := before.Compare(t.Context(), proposed, parent)
		if comparison == nil || result.Outcome != ObservedCurrent {
			t.Fatal("post-B Plain fill comparison", result)
		}
		store := requireAdmittedMemoryStore(t, f.env.Store)
		beforeCAS := store.cas
		candidate, result := before.Prepare(t.Context(), comparison, admit(t, before, comparison), f.env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent || store.cas != beforeCAS {
			t.Fatal("post-B Plain fill preparation", result)
		}
		selected, result := before.selectCandidate(t.Context(), candidate)
		if selected == nil || result.Outcome != ObservedCurrent || store.cas != beforeCAS+1 {
			t.Fatal("post-B Plain fill selection", result)
		}
		f.env.Custody.RetireApply()
		selected = generatedLifecycleReopen(t, t.Context(), selected, store)
		afterWindows, err := selected.receiptWindows(t.Context())
		if err != nil || !reflect.DeepEqual(afterWindows, beforeWindows) {
			t.Fatal("ordinary Plain fill changed retained receipt windows", err)
		}
		f.assertPressure(selected)
		work := mustSelectedGeneratedWork(t, selected)
		if selected.root.ValueEntryCount != 33 || !reflect.DeepEqual(selected.root.Generated, owned.Root.Generated) || !reflect.DeepEqual(work.content.locations, oldLocations) || !slices.Equal(selected.root.Generated.Fragments, owned.Root.Generated.Fragments) {
			t.Fatal("post-B Plain fill changed generated owners or exact physical locations")
		}
		for _, location := range owned.Root.Generated.Fragments {
			for _, ref := range owned.Root.RequiredSupport {
				if ref.Index == location.SupportPageIndex && !slices.Contains(selected.root.RequiredSupport, ref) {
					t.Fatal("post-B Plain fill changed an old whole fragment page")
				}
			}
		}
		for _, named := range owned.Root.Names {
			want := owned.Pages[named.Slot/format.PageSlots].Slots[named.Slot%format.PageSlots]
			if !reflect.DeepEqual(selected.valueEntry(named.Slot), want) {
				t.Fatal("post-B Plain fill changed an existing current entry", named.Name)
			}
		}
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("plain-fill-%02d", i)
			entry := selected.valueEntry(entrySlot(t, selected, name))
			if entry == nil || entry.ValueSource != format.Supplied || entry.ConfidentialityClass != format.Plain || !bytes.Equal(entry.ValueBytes, []byte{byte(i + 1)}) || !slices.Equal(entry.Recipients, []contract.ID{selected.admission.recipient}) {
				t.Fatal("post-B Plain fill has a wrong new value", name)
			}
		}
		oldValuePages, newValuePages := 0, 0
		for i := range owned.Root.ValueEntryPages {
			if owned.Root.ValueEntryPages[i] != nil {
				oldValuePages++
			}
			if selected.root.ValueEntryPages[i] != nil {
				newValuePages++
			}
		}
		if oldValuePages != 2 || newValuePages != 3 || selected.root.RawBytes != owned.Root.RawBytes+10 || selected.root.MembershipCount != owned.Root.MembershipCount+10 || !reflect.DeepEqual(selected.root.Recipients, owned.Root.Recipients) {
			t.Fatal("post-B Plain fill changed the exact value-page or membership charge")
		}
		for _, name := range []string{"a-01", "b-01"} {
			consumed := f.env.Custody.Consume(t.Context(), sessionConsumerSelection(t, selected, selected.admission.recipient, name), custody.StandardValue)
			if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
				t.Fatal("current cohort value is not privately consumable after Plain fill", name)
			}
		}
		if selected.root.ChildCount != owned.Root.ChildCount+1 || len(selected.root.RequiredSupport) != len(owned.Root.RequiredSupport) || !reflect.DeepEqual(selected.root.CurrentAccess, owned.Root.CurrentAccess) || len(selected.root.AdministrativeIndexShards) != len(owned.Root.AdministrativeIndexShards) {
			t.Fatal("post-B Plain fill did not add exactly one value page")
		}
		t.Logf("two-prefix Plain fill: children=%d->%d support=%d->%d access=%d->%d shards=%d->%d", owned.Root.ChildCount, selected.root.ChildCount, len(owned.Root.RequiredSupport), len(selected.root.RequiredSupport), len(owned.Root.CurrentAccess.Core.AccessPageRefs), len(selected.root.CurrentAccess.Core.AccessPageRefs), 1+len(owned.Root.AdministrativeIndexShards), 1+len(selected.root.AdministrativeIndexShards))
	})
}

type failedHistoryRetirementFixture struct {
	env            fixtureEnvironment
	selected       *StateSession
	a, b           contract.ValueEntry
	dutyA, dutyB   contract.ID
	aBlob, bBlob   contract.ID
	current        stateImage
	assertPressure func(*StateSession)
	assertCurrent  func(*StateSession)
}

func actualFailedHistoryRetirementCarriers(t *testing.T, bCount int) failedHistoryRetirementFixture {
	t.Helper()
	return actualFailedHistoryRetirementCarriersWithPrefixes(t, bCount, 1)
}

// Only the two retained one-prefix cohorts and the named two-prefix B20
// prerequisite are admitted here. This is not a scale loader.
func actualFailedHistoryRetirementCarriersWithPrefixes(t *testing.T, bCount, prefixes int) failedHistoryRetirementFixture {
	t.Helper()
	if prefixes != 1 && (prefixes != 2 || bCount != 20) {
		t.Fatal("unsupported named failed-history prefix", bCount, prefixes)
	}
	var bFragments, bPages, currentCount int
	var currentBytes uint32
	switch bCount {
	case 20:
		bFragments, bPages, currentCount, currentBytes = 8, 4, 22, 8650752
	case 26:
		bFragments, bPages, currentCount, currentBytes = 10, 5, 28, 11010048
	default:
		t.Fatal("unsupported named retirement cohort", bCount)
	}
	t.Logf("producer shape: %d failed aggregates, each with 124 Plain declarations of 65536 bytes and 2 original effects; then A4/B%d with %d distinct 393216-byte Intents; 2 retirements; no later generation", prefixes, bCount, bCount+4)
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	env.Context = ctx
	t.Cleanup(keys.RetireGenerated)
	t.Cleanup(keys.RetireApply)
	store := requireAdmittedMemoryStore(t, env.Store)
	if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal(err)
	}
	initial := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"}).session
	admitted := capacityFixtureAdmission(t, OpenContext{admission: &initial.admission})
	initial.admission = *admitted.admission
	seed := sessionStateImage(t, initial)
	selected := initial
	var pressureGroups []contract.ID
	var checks []func(*StateSession)
	pressureIDs := make(map[contract.ID]bool)
	for prefix := 1; prefix <= prefixes; prefix++ {
		sources := make([]contract.GeneratorDeclarationEntry, 124)
		for i := range sources {
			name := fmt.Sprintf("pressure-plain-%03d", i)
			if prefix == 2 {
				name = fmt.Sprintf("pressure-second-plain-%03d", i)
			}
			sources[i] = contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw,
				Name: name, Recipients: []contract.ID{initial.admission.recipient},
				Payload: bytes.Repeat([]byte{byte(i + 1)}, 65536)}
		}
		pressureIntent := hermeticSizedGeneratorIntent("failed history pressure intent", 'x', 393216)

		failedNames := []string{"failed-alpha", "failed-omega"}
		operation := "retained failed history operation"
		if prefix == 2 {
			operation += " second"
			failedNames = []string{"failed-second-alpha", "failed-second-omega"}
			pressureIntent = hermeticSizedGeneratorIntent("retained independent second failed aggregate", 'x', 393216)
		}
		input := generatedPlanInputForGenerationsIntent(t, selected, fixtureID(env.Domain, operation),
			failedNames, pressureIntent, defaultGeneratedFixtureProfile(), sources...)
		next, original := selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, failedNames, input, nil)
		selected = next
		selected = generatedLifecycleReopen(t, ctx, selected, store)
		t.Logf("failed aggregate selected: entries=%d generated=%d duties=%d hazards=%d releases=%d groups=%d children=%d child-bytes=%d declaration-bytes=%d",
			selected.root.ValueEntryCount, selected.root.Generated.GeneratedCurrent, selected.root.Generated.Duties,
			selected.root.Generated.Hazards, selected.root.Generated.PendingReleases, len(selected.adminIndex.Groups),
			selected.root.ChildCount, selected.root.ChildEncodedBytes, len(input.declaration))
		if selected.root.ValueEntryCount != 1 || !reflect.DeepEqual(selected.valueEntry(0), seed.Pages[0].Slots[0]) ||
			selected.root.Generated.Duties != uint32(prefix) || selected.root.Generated.Hazards != uint32(prefix) || selected.root.Generated.PendingReleases != 0 || len(selected.adminIndex.Groups) != 2*prefix {
			t.Fatal("actual failed aggregate changed its Plain predecessor or independent owners")
		}
		originalPacket := bytes.Clone(original.result)
		work := mustSelectedGeneratedWork(t, selected)
		if len(work.attempts) != 2*prefix || len(work.releases) != 0 || !selected.root.Generated.ActiveOwner.IsZero() ||
			!bytes.Equal(work.attempts[original.record.AttemptID].result, originalPacket) {
			t.Fatal("actual failed aggregate lost its original sealed result")
		}
		pressureSeedAccess, present := selected.materialAccess(contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID)
		if !present {
			t.Fatal("actual failed aggregate lost its operation seed access")
		}
		pressureSeedAccess.Wraps = slices.Clone(pressureSeedAccess.Wraps)
		for i := range pressureSeedAccess.Wraps {
			pressureSeedAccess.Wraps[i].RSACiphertext = bytes.Clone(pressureSeedAccess.Wraps[i].RSACiphertext)
		}
		prefixGroups := sharedIntentGroupIDs(t, selected)
		pressureGroups = slices.Clone(prefixGroups)
		pressureRows := make(map[generatedRecordKey][]byte)
		for key, row := range work.records {
			switch key.kind {
			case contract.OperationMaterialSupportKind, contract.GeneratedAttemptSupportKind, contract.GeneratedResultSupportKind, contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind:
				pressureRows[key] = bytes.Clone(row.Body)
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.VectorKind != contract.GeneratorVectorSlices {
					pressureRows[key] = bytes.Clone(row.Body)
				}
			}
		}
		pressureID, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(pressureIntent))
		if err != nil {
			t.Fatal(err)
		}
		if pressureIDs[pressureID] {
			t.Fatal("independent failed prefixes reused an Intent")
		}
		pressureIDs[pressureID] = true
		pressureLocation := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, pressureID}]
		graphID := original.expected.Plan.PlanGraphID
		pressureGraph, err := work.readSelectedSlice(ctx, contract.GeneratorContentGraph, graphID, contract.GeneratorGraphMaxLength)
		if err != nil {
			t.Fatal(err)
		}
		pressureGraph = bytes.Clone(pressureGraph)
		check := func(s *StateSession) {
			t.Helper()
			g := mustSelectedGeneratedWork(t, s)
			seedAccess, present := s.materialAccess(contract.OperationSeedMaterialKind, pressureSeedAccess.MaterialID)
			if !present || !reflect.DeepEqual(seedAccess, pressureSeedAccess) {
				t.Fatal("later operation changed independent failed history's exact seed access")
			}
			for key, body := range pressureRows {
				if row, ok := g.records[key]; !ok || !bytes.Equal(row.Body, body) {
					t.Fatal("later operation changed independent failed history", key.kind)
				}
			}
			if !bytes.Equal(g.attempts[original.record.AttemptID].result, originalPacket) || len(g.releases) != 0 {
				t.Fatal("later operation changed original result or invented a release")
			}
			for _, id := range prefixGroups {
				if !slices.Contains(sharedIntentGroupIDs(t, s), id) {
					t.Fatal("later operation lost an independent failed owner")
				}
			}
			intent, err := g.readSelectedSlice(ctx, contract.GeneratorContentIntent, pressureID, contract.GeneratorIntentMaxLength)
			if err != nil || !bytes.Equal(intent, pressureIntent) || g.content.locations[generatedContentKey{contract.GeneratorContentIntent, pressureID}] != pressureLocation {
				t.Fatal("later operation changed failed history's exact Intent carrier", err)
			}
			graph, err := g.readSelectedSlice(ctx, contract.GeneratorContentGraph, graphID, contract.GeneratorGraphMaxLength)
			if err != nil || !bytes.Equal(graph, pressureGraph) {
				t.Fatal("later operation changed independent operation graph", err)
			}
		}
		checks = append(checks, check)
		for _, prior := range checks {
			prior(selected)
		}
	}
	assertPressure := func(s *StateSession) {
		t.Helper()
		for _, check := range checks {
			check(s)
		}
	}
	known := make(map[string][]byte)
	generate := func(prefix string, count int) (generatedPlanInput, []string) {
		t.Helper()
		names := make([]string, count)
		for i := range names {
			names[i] = fmt.Sprintf("%s-%02d", prefix, i)
			body := hermeticSizedGeneratorIntent(names[i], prefix[0], 393216)
			known[names[i]] = body
		}
		in := generatedWriterPlanInput(t, selected, fixtureID(env.Domain, "retirement cohort "+prefix), names,
			func(name string) []byte { return known[name] }, 0, nil)
		selected = selectGeneratedWriterBatch(t, env, selected, in, prefix, custody.StandardValue)
		selected = generatedLifecycleReopen(t, ctx, selected, store)
		t.Logf("cohort %s selected: entries=%d generated=%d groups=%d children=%d child-bytes=%d declaration-bytes=%d",
			prefix, selected.root.ValueEntryCount, selected.root.Generated.GeneratedCurrent, len(selected.adminIndex.Groups), selected.root.ChildCount, selected.root.ChildEncodedBytes, len(in.declaration))
		assertPressure(selected)
		return in, names
	}
	_, aNames := generate("a", 4)
	bInput, bNames := generate("b", bCount)
	before := sessionStateImage(t, selected)
	if selected.root.Generated.GeneratedCurrent != uint32(bCount+4) || selected.root.ValueEntryCount != uint32(bCount+5) || len(selected.adminIndex.Groups) != 2*prefixes {
		t.Fatal("actual cohorts do not retain the exact predecessor set")
	}
	var aEntries []contract.ValueEntry
	seen := make(map[contract.ID]bool)
	cohortLocations := make(map[contract.ID]contract.GeneratorSliceLocation)
	for _, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		id, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(known[entry.Name]))
		if err != nil || id != entry.Generated.IntentDigest || seen[id] || pressureIDs[id] || len(known[entry.Name]) != 393216 {
			t.Fatal("cohort Intent is not exact, unique and independent", err)
		}
		seen[id] = true
		location, _, _, found := sharedIntentCarrier(t, selected, id)
		if !found {
			t.Fatal("selected cohort has no physical Intent carrier")
		}
		cohortLocations[id] = location
		if slices.Contains(aNames, entry.Name) {
			aEntries = append(aEntries, *entry)
		}
	}
	slices.SortFunc(aEntries, func(a, b contract.ValueEntry) int {
		return bytes.Compare(a.Generated.IntentDigest[:], b.Generated.IntentDigest[:])
	})
	var canonicalA []byte
	for _, entry := range aEntries {
		canonicalA = append(canonicalA, known[entry.Name]...)
	}
	aBlob, bBlob := contract.Hash(canonicalA), contract.Hash(bInput.declaration)
	if len(canonicalA) != 1572864 || aBlob == bBlob || (len(bInput.declaration)+contract.GeneratedFragmentMaxPayload-1)/contract.GeneratedFragmentMaxPayload != bFragments {
		t.Fatal("actual cohort declaration does not have the required two-blob shape")
	}
	var offset uint64
	for _, entry := range aEntries {
		location, _, _, found := sharedIntentCarrier(t, selected, entry.Generated.IntentDigest)
		if !found || location.BlobID != aBlob || location.Offset != offset || location.Length != 393216 || !bytes.Equal(canonicalA[offset:offset+uint64(location.Length)], known[entry.Name]) {
			t.Fatal("A carrier differs from independent digest-order concatenation")
		}
		offset += uint64(location.Length)
	}
	for _, name := range bNames {
		entry := selected.valueEntry(entrySlot(t, selected, name))
		location, _, _, found := sharedIntentCarrier(t, selected, entry.Generated.IntentDigest)
		if !found || location.BlobID != bBlob || location.Length != 393216 || location.Offset+uint64(location.Length) > uint64(len(bInput.declaration)) || !bytes.Equal(bInput.declaration[location.Offset:location.Offset+uint64(location.Length)], known[name]) {
			t.Fatal("B carrier does not name its actual declaration bytes")
		}
	}
	assertCohortPacking := func(s *StateSession) {
		t.Helper()
		for blob, want := range map[contract.ID]int{aBlob: 1, bBlob: bPages} {
			pages := make(map[uint16]bool)
			fragments := 0
			for _, location := range s.root.Generated.Fragments {
				if location.BlobID == blob {
					pages[location.SupportPageIndex], fragments = true, fragments+1
				}
			}
			if len(pages) != want || fragments != 2*want {
				t.Fatal("cohort fragments do not occupy complete paired pages", want, len(pages), fragments)
			}
		}
	}
	assertCohortPacking(selected)
	aSlot, bSlot := entrySlot(t, selected, aNames[0]), entrySlot(t, selected, bNames[0])
	a, b := *before.Pages[aSlot/format.PageSlots].Slots[aSlot%format.PageSlots], *before.Pages[bSlot/format.PageSlots].Slots[bSlot%format.PageSlots]
	proposed := slices.DeleteFunc(selected.currentEntryInputs(), func(row ApplyEntryInput) bool { return row.Name == a.Name || row.Name == b.Name })
	parent := admitSuppliedComparison(t, selected, env.Custody, proposed, staticGeneratedHandoffImplementation(t, env.Domain, defaultGeneratedFixtureProfile()))
	comparison, result := selected.Compare(ctx, proposed, parent)
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual cohort removal comparison", result)
	}
	candidate, result := selected.Prepare(ctx, comparison, admit(t, selected, comparison), env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual cohort removal preparation", result)
	}
	selected, result = selected.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual cohort removal selection", result)
	}
	keys.RetireApply()
	selected = generatedLifecycleReopen(t, ctx, selected, store)
	t.Logf("two retirements selected: entries=%d generated=%d retiring=%d duties=%d hazards=%d releases=%d groups=%d children=%d child-bytes=%d",
		selected.root.ValueEntryCount, selected.root.Generated.GeneratedCurrent, selected.root.Generated.Retiring, selected.root.Generated.Duties, selected.root.Generated.Hazards, selected.root.Generated.PendingReleases,
		len(selected.adminIndex.Groups), selected.root.ChildCount, selected.root.ChildEncodedBytes)
	if selected.root.ValueEntryCount != uint32(currentCount+1) || selected.root.Generated.GeneratedCurrent != uint32(currentCount) || selected.root.Generated.Retiring != 2 || selected.root.Generated.Duties != uint32(prefixes+2) || selected.root.Generated.Hazards != uint32(prefixes) || selected.root.Generated.PendingReleases != 0 || len(selected.adminIndex.Groups) != 2*prefixes+2 {
		t.Fatal("ordinary handoff changed the exact independent work set")
	}
	assertPressure(selected)
	assertCohortPacking(selected)
	for id, want := range cohortLocations {
		location, _, _, found := sharedIntentCarrier(t, selected, id)
		if !found || location != want {
			t.Fatal("ordinary handoff relocated a cohort Intent before the planned exit")
		}
	}
	wantGroups := slices.Clone(pressureGroups)
	duties := make([]contract.ID, 0, 2)
	for _, entry := range []contract.ValueEntry{a, b} {
		duty, err := contract.GeneratorDutyID(env.Domain, entry.Generated.OriginOperationID, entry.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
		if err != nil {
			t.Fatal(err)
		}
		wantGroups = append(wantGroups, duty)
		duties = append(duties, duty)
		location, mandatory, owners, found := sharedIntentCarrier(t, selected, entry.Generated.IntentDigest)
		wantBlob := aBlob
		if entry.Name == b.Name {
			wantBlob = bBlob
		}
		if !found || mandatory || location.BlobID != wantBlob || !slices.Equal(owners, []contract.ID{duty}) {
			t.Fatal("actual retirement lacks its exact old noncurrent Intent")
		}
	}
	slices.SortFunc(wantGroups, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	assertSharedIntentGroupIDs(t, selected, wantGroups)
	current := sessionStateImage(t, selected)
	assertCurrent := func(s *StateSession) {
		t.Helper()
		if len(s.root.Names) != len(current.Root.Names) {
			t.Fatal("later operation changed the complete current entry set")
		}
		wantAccess := make(map[contract.ID]contract.AccessRecord)
		for _, page := range before.Access {
			if page == nil {
				continue
			}
			for _, row := range page.Records {
				if row.MaterialKind == contract.ValueMaterialKind {
					wantAccess[row.MaterialID] = row
				}
			}
		}
		for _, named := range current.Root.Names {
			want := current.Pages[named.Slot/format.PageSlots].Slots[named.Slot%format.PageSlots]
			if !reflect.DeepEqual(s.valueEntry(named.Slot), want) {
				t.Fatal("later operation changed an exact surviving current entry", named.Name)
			}
			if want.ConfidentialityClass == contract.Secret {
				actual, ok := s.materialAccess(contract.ValueMaterialKind, want.ValueState)
				expected, present := wantAccess[want.ValueState]
				if !ok || !present || !reflect.DeepEqual(actual, expected) {
					t.Fatal("later operation changed exact surviving current access", named.Name)
				}
			}
		}
	}
	for _, named := range selected.root.Names {
		want := before.Pages[named.Slot/format.PageSlots].Slots[named.Slot%format.PageSlots]
		if !reflect.DeepEqual(selected.valueEntry(named.Slot), want) {
			t.Fatal("ordinary retirement changed an exact surviving current entry", named.Name)
		}
	}
	assertCurrent(selected)
	if selected.root.Generated.GeneratedCurrent*393216 != currentBytes {
		t.Fatal("actual current Intent total differs from the bounded shape")
	}
	return failedHistoryRetirementFixture{env, selected, a, b, duties[0], duties[1], aBlob, bBlob, current, assertPressure, assertCurrent}
}
