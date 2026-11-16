package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// Live producer admissions must not retain one complete declaration buffer
// per producer. The parent plan owns its validated declaration separately.
// full_only: false
func TestGeneratedProducerAdmissionsDoNotRetainCallerDeclarations(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
	before := fixture.session
	bodyDirectory := filepath.Join(t.TempDir(), "bodies")
	fmt.Fprintln(os.Stderr, "producer ownership body directory", bodyDirectory)
	if err := env.Store.(*memoryStore).useFileBodies(bodyDirectory); err != nil {
		t.Fatal("producer ownership fixture Store", err)
	}
	const count = 64
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("alpha-%03d", i)
	}
	sources, _ := generatedCurrentDeclaration(t, before)
	operation := fixtureID(env.Domain, "producer declaration ownership")
	profile := defaultGeneratedFixtureProfile()
	intentForName := func(name string) []byte {
		intent := hermeticSizedGeneratorIntent(name, 0x5a, 384<<10)
		return intent
	}
	bound := generatedReservationInputForMembershipStateIntents(t, before, operation,
		[]contract.ID{before.admission.recipient}, names, intentForName, profile, 0, nil, nil, sources...)
	input := generatedPlanInputForGenerations(t, before, operation, names, profile, sources...)
	input.graph, input.declaration = bound.graph, bound.declaration
	input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(bound.requestBindings)
	input.context.AdmissionID = fixtureID(env.Domain, "producer ownership plan admission")
	input.context.SessionID = fixtureID(env.Domain, "producer ownership plan session")
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	if len(input.declaration) <= 24<<20 || len(input.declaration) > int(contract.GeneratorDeclarationMaxLength) {
		t.Fatal("ownership fixture declaration length", len(input.declaration))
	}
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	g, err := reservation.reservation.state.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("producer ownership selected work", err)
	}
	var attempts []contract.ID
	for _, lineage := range g.bundles[0].Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			attempts = append(attempts, lineage.Templates[0].AttemptID)
		}
	}
	if len(attempts) != count {
		t.Fatal("producer ownership attempt count", len(attempts))
	}
	keys := make([]*custody.Fixture, 8)
	producers := make([]*generatedPreparation, len(keys))
	for i := range keys {
		keys[i] = env.Custody
		if i != 0 {
			keys[i] = env.Custody.ForkGenerated(t)
		}
	}
	facts := acquireGeneratedProducerFixtureFacts(t, env, before, reservation)
	var middle, after runtime.MemStats
	for i := range keys {
		if i == 4 {
			runtime.GC() // Test-only reachability measurement; not a product memory remedy.
			runtime.ReadMemStats(&middle)
		}
		producers[i], _ = preparePrivateGeneratedOriginalProducerForAttempt(t, env, before, reservation,
			keys[i], attempts[i], facts, custody.StandardValue, nil, nil)
		if producers[i] == nil {
			t.Fatal("producer ownership preparation", i)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	retainedGrowth := uint64(0)
	if after.HeapAlloc > middle.HeapAlloc {
		retainedGrowth = after.HeapAlloc - middle.HeapAlloc
	}
	maxGrowth := uint64(2 * len(input.declaration))
	t.Logf("live producer admission retained growth=%d, maximum=%d, declaration=%d", retainedGrowth, maxGrowth, len(input.declaration))
	if retainedGrowth > maxGrowth {
		t.Fatal("four live producers retained declaration-sized caller buffers", retainedGrowth, maxGrowth)
	}
	runtime.KeepAlive(facts)
	runtime.KeepAlive(input)
	runtime.KeepAlive(keys)
	runtime.KeepAlive(producers)
	for _, key := range keys {
		key.RetireGenerated()
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
func TestGeneratedRecordPrefixPerformance(t *testing.T) {
	for _, count := range []int{8, 16, 32} {
		t.Run(fmt.Sprintf("records-%02d", count), func(t *testing.T) {
			runGeneratedRecordPrefixPerformance(t, count)
		})
	}
}

func runGeneratedRecordPrefixPerformance(t *testing.T, count int) {
	t.Helper()
	started := time.Now()
	ctx := context.Background()
	timing := startCapacityTimer(t)
	defer timing.finish()
	env, f, keys := maximumSuccessionMemoryFixture(t)
	timing.next("operation")
	env = syntheticAuthorityScenarioEnvironment(t, env)
	before := f.session
	input := generatedPlanInputFixture(t, before)
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	names := maximumLifecycleNames(fmt.Sprintf("generated-record-prefix-%d", count))
	bindings, err := before.currentBindings()
	if err != nil {
		t.Fatal("generated record prefix current bindings", err)
	}
	generatedRecipients := []contract.ID{before.admission.recipient}
	for _, binding := range bindings {
		if binding.SubjectKind == 1 && binding.SubjectID != before.admission.recipient && len(generatedRecipients) < 29 {
			generatedRecipients = append(generatedRecipients, binding.SubjectID)
		}
	}
	slices.SortFunc(generatedRecipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if len(generatedRecipients) != 29 {
		t.Fatal("generated record prefix recipient shape", len(generatedRecipients))
	}
	sources := make([]contract.GeneratorDeclarationEntry, len(names)-count)
	for i := range sources {
		sources[i] = contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
			Name: names[i+count], Recipients: []contract.ID{before.admission.recipient}}
	}
	graph, declaration, _ := generatedEffectPlanForGenerationMembershipState(t, &input.graph.Request, before.admission.recipient,
		generatedRecipients, names[:count], []byte(`{"capacity":"bounded-record-prefix"}`), defaultGeneratedFixtureProfile(), 0, nil, nil, sources...)
	input.graph = graph
	input.requestBindings = generatedFixtureRequestBindings(graph, input.requestBindings[0].Digest)
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal("generated record prefix declaration", err)
	}

	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	t.Logf("generated record prefix: records=0/%d reservation_elapsed=%s", count, time.Since(started))
	current, originals := sendParallelOriginals(t, ctx, env, before, reservation, custody.MaximumValue)
	for i, original := range originals {
		stepStarted := time.Now()
		recordContext := generatedPlanInputFixture(t, current).context
		recordContext.AdmissionID = fixtureID(env.Domain, fmt.Sprintf("bounded generated record admission %d/%d", i, count))
		recordContext.SessionID = fixtureID(env.Domain, fmt.Sprintf("bounded generated record session %d/%d", i, count))
		recordContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		recordPlan, recordErr := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, recordContext)
		if recordErr != nil {
			t.Fatal("generated record prefix request", i, recordErr)
		}
		prepared := preparePrivateGeneratedRecord(t, env, current, recordPlan)
		var outcome Result
		current, outcome = current.selectCandidate(ctx, prepared.reservation.candidate)
		if current == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("generated record prefix selection", i, outcome)
		}
		keys.RetireGenerated()
		t.Logf("generated record prefix: records=%d/%d step=%s elapsed=%s", i+1, count, time.Since(stepStarted), time.Since(started))
	}
	selected, err := current.selectedGeneratedWork(context.Background())
	if err != nil || selected.phase == nil || int(selected.phase.Phase) != count+1 || len(selected.attempts) != count {
		t.Fatal("generated record prefix selected closure", err, selected.phase, len(selected.attempts))
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestGeneratedMaximumSelectedSetFitsAccessReplacementOverlap(t *testing.T) {
	started := time.Now()
	t.Log("maximum generated replacement: build fixture")
	ctx := context.Background()
	timing := startCapacityTimer(t)
	defer timing.finish()
	env, f, keys := maximumSuccessionMemoryFixture(t)
	timing.next("operation")
	env = syntheticAuthorityScenarioEnvironment(t, env)
	before := f.session
	input := generatedPlanInputFixture(t, before)
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	names := maximumLifecycleNames("generated-replacement-capacity")
	bindings, err := before.currentBindings()
	if err != nil {
		t.Fatal("maximum generated current bindings", err)
	}
	generatedRecipients := []contract.ID{before.admission.recipient}
	for _, binding := range bindings {
		if binding.SubjectKind == 1 && binding.SubjectID != before.admission.recipient && len(generatedRecipients) < 29 {
			generatedRecipients = append(generatedRecipients, binding.SubjectID)
		}
	}
	slices.SortFunc(generatedRecipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if len(generatedRecipients) != 29 {
		t.Fatal("maximum generated recipient shape", len(generatedRecipients))
	}
	sources := make([]contract.GeneratorDeclarationEntry, 384)
	for i := range sources {
		sources[i] = contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
			Name: names[i+128], Recipients: []contract.ID{before.admission.recipient}}
	}
	graph, declaration, _ := generatedEffectPlanForGenerationMembershipState(t, &input.graph.Request, before.admission.recipient,
		generatedRecipients, names[:128], []byte(`{"capacity":"full-generated-replacement"}`), defaultGeneratedFixtureProfile(), 0, nil, nil, sources...)
	input.graph = graph
	input.requestBindings = generatedFixtureRequestBindings(graph, input.requestBindings[0].Digest)
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal("maximum generated replacement declaration", err)
	}

	// Replace one one-recipient plain row with a valid one-recipient generated
	// row. The entry and membership totals remain 512 and 4,096; only the
	// independent generated-lineage frontier becomes 129.
	excess := declaration
	excess.Entries = slices.Clone(declaration.Entries)
	plain := slices.IndexFunc(excess.Entries, func(entry contract.GeneratorDeclarationEntry) bool {
		return entry.Kind == contract.GeneratorDeclarationPlain
	})
	generated := slices.IndexFunc(excess.Entries, func(entry contract.GeneratorDeclarationEntry) bool {
		return entry.Kind == contract.GeneratorDeclarationGenerated
	})
	if plain < 0 || generated < 0 {
		t.Fatal("maximum declaration does not contain both source kinds")
	}
	excess.Entries[plain].Kind = contract.GeneratorDeclarationGenerated
	excess.Entries[plain].Payload = bytes.Clone(excess.Entries[generated].Payload)
	if body, encodeErr := contract.EncodeGeneratorDeclaration(excess); encodeErr != contract.ErrRecordCapacity || body != nil {
		t.Fatal("129th generated closure did not refuse at the codec capacity boundary", encodeErr)
	}
	entryBody, err := contract.EncodeGeneratorDeclarationEntry(excess.Entries[plain])
	if err != nil {
		t.Fatal("129th generated entry framing", err)
	}
	offset := 70
	for i := 0; i < plain; i++ {
		length, lengthErr := contract.GeneratorDeclarationEntryLength(declaration.Entries[i])
		if lengthErr != nil {
			t.Fatal(lengthErr)
		}
		offset += 4 + length
	}
	oldLength, err := contract.GeneratorDeclarationEntryLength(declaration.Entries[plain])
	if err != nil {
		t.Fatal(err)
	}
	excessBody := make([]byte, 0, len(input.declaration)-oldLength+len(entryBody))
	excessBody = append(excessBody, input.declaration[:offset]...)
	excessBody = binary.BigEndian.AppendUint32(excessBody, uint32(len(entryBody)))
	excessBody = append(excessBody, entryBody...)
	excessBody = append(excessBody, input.declaration[offset+4+oldLength:]...)
	creates, cas := env.Store.(*memoryStore).creates, env.Store.(*memoryStore).cas
	public, private := keys.Calls()
	excessInput := input
	excessInput.declaration = excessBody
	if plan, planErr := before.generatedPlanRequest(t.Context(), excessInput); planErr != contract.ErrRecordCapacity || plan != nil {
		t.Fatal("129th generated closure reached Core admission", planErr)
	}
	if env.Store.(*memoryStore).creates != creates || env.Store.(*memoryStore).cas != cas {
		t.Fatal("129th generated closure reached Store effects")
	}
	if p, k := keys.Calls(); p != public || k != private {
		t.Fatal("129th generated closure reached custody effects", p-public, k-private)
	}
	t.Logf("maximum generated replacement: 129th refusal complete elapsed=%s", time.Since(started))

	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	t.Logf("maximum generated replacement: reservation complete elapsed=%s", time.Since(started))
	current, originals := sendParallelOriginals(t, ctx, env, before, reservation, custody.MaximumValue)
	results := make(map[contract.ID][]byte, len(originals))
	effects := len(originals)
	for i, original := range originals {
		results[original.expected.Template.AttemptID] = bytes.Clone(original.result)
		recordContext := generatedPlanInputFixture(t, current).context
		recordContext.AdmissionID = fixtureID(env.Domain, "maximum generated record admission "+names[i])
		recordContext.SessionID = fixtureID(env.Domain, "maximum generated record session "+names[i])
		recordContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		recordPlan, recordErr := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, recordContext)
		if recordErr != nil {
			t.Fatal("maximum generated replacement record request", i, recordErr)
		}
		prepared := preparePrivateGeneratedRecord(t, env, current, recordPlan)
		var outcome Result
		current, outcome = current.selectCandidate(ctx, prepared.reservation.candidate)
		if current == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("maximum generated replacement record selection", i, outcome)
		}
		keys.RetireGenerated()
		if (i+1)%8 == 0 {
			t.Logf("maximum generated replacement: records=%d/128 elapsed=%s", i+1, time.Since(started))
		}
	}
	recorded := current
	finalContext := generatedPlanInputFixture(t, recorded).context
	finalContext.AdmissionID = fixtureID(env.Domain, "maximum generated replacement final admission")
	finalContext.SessionID = fixtureID(env.Domain, "maximum generated replacement final session")
	finalContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	finalPlan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
	if err != nil || finalPlan == nil {
		t.Fatal("maximum generated replacement final request", err)
	}
	if len(finalPlan.entryPlans) != 128 || len(finalPlan.results) != 128 || len(results) != 128 {
		t.Fatal("maximum generated replacement final shape", len(finalPlan.entryPlans), len(finalPlan.results), len(results))
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan)
	t.Logf("maximum generated replacement: Final prepared elapsed=%s", time.Since(started))
	selected, outcome := recorded.selectCandidate(ctx, final.reservation.candidate)
	if selected == nil || outcome.Outcome != ObservedCurrent || selected.root.ValueEntryCount != 512 ||
		selected.root.Generated.GeneratedCurrent != 128 || selected.root.AccessRecordCount != 128 ||
		selected.root.MembershipCount != 4096 || selected.root.RawBytes != 8<<20 || effects != 128 {
		t.Fatal("maximum generated set selection", outcome)
	}
	keys.RetireGenerated()
	t.Logf("maximum generated replacement: selected complete set children=%d index_shards=%d; start fresh child elapsed=%s",
		selected.root.ChildCount, 1+len(selected.root.AdministrativeIndexShards), time.Since(started))
	timing.next("fresh-child")
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), selected)
	timing.next("operation")
	t.Logf("maximum generated replacement: first fresh child complete elapsed=%s", time.Since(started))

	beforeWork, err := selected.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	actors := env.ReplacementActors(t, ctx, selected, 3, 12, contract.NormalSigningRole)
	permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, 3, contract.NormalSigningRole, 12, actors.Source)
	publicBeforeReplacement, privateBeforeReplacement := keys.Calls()
	candidate, outcome := selected.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("maximum generated access replacement preparation", outcome)
	}
	if p, k := keys.Calls(); p-publicBeforeReplacement != 1 || k-privateBeforeReplacement != int(selected.root.AccessRecordCount)+1 {
		t.Fatal("maximum generated access replacement did not open every live root exactly once", p-publicBeforeReplacement, k-privateBeforeReplacement)
	}
	overlap := retainedByteBuffers(selected, nil, candidate, nil).capacity()
	parent, child := custody.GeneratorProcessOwnedByteCeilings()
	if overlap+parent+child > 1664<<20 {
		t.Fatal("maximum generated access replacement exceeded the joint owned-buffer ceiling", overlap, parent, child)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if outcome = selected.Select(ctx, candidate); outcome.Outcome != ObservedCurrent {
		t.Fatal("maximum generated access replacement selection", outcome)
	}
	keys.RetireAccess()
	t.Logf("maximum generated replacement: access replacement selected; reopen elapsed=%s", time.Since(started))
	replaced, outcome := Open(ctx, admission, env.Store)
	if replaced == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("maximum generated access replacement reopen", outcome)
	}
	t.Logf("maximum generated replacement: selected key replacement children=%d index_shards=%d",
		replaced.root.ChildCount, 1+len(replaced.root.AdministrativeIndexShards))
	actors.Activate(t, replaced)
	afterWork, err := replaced.preservedWorkSupportRecords(t.Context())
	if err != nil || !reflect.DeepEqual(beforeWork, afterWork) || !reflect.DeepEqual(selected.pages, replaced.pages) ||
		!reflect.DeepEqual(selected.root.ValueEntryPages, replaced.root.ValueEntryPages) || selected.root.Generated.GeneratedCurrent != replaced.root.Generated.GeneratedCurrent {
		t.Fatal("maximum generated access replacement changed accepted work", err)
	}
	timing.next("fresh-child")
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), replaced)
	timing.next("operation")
	t.Logf("maximum generated replacement: replacement fresh child complete elapsed=%s", time.Since(started))

	t.Logf("generated=128 access_records=%d overlap_owned_bytes=%d process_parent_bytes=%d process_child_bytes=%d ceiling_bytes=%d",
		replaced.root.AccessRecordCount, overlap, parent, child, uint64(1664<<20))
	runtime.KeepAlive(results)
	runtime.KeepAlive(candidate)
	runtime.KeepAlive(replaced)
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
func TestGeneratedPurpose3CleanupAtJointMemberAndGenerationMaximum(t *testing.T) {
	started := time.Now()
	timing := startCapacityTimer(t)
	defer timing.finish()
	env, f, keys := maximumSuccessionMemoryFixtureReceiptMode(t, true)
	timing.next("operation")
	env = syntheticAuthorityScenarioEnvironment(t, env)
	before := f.session
	allNames := maximumLifecycleNames("purpose3-cleanup-capacity")
	generatedNames := slices.Clone(allNames[:128])

	var retainedEntry *contract.ValueEntry
	for _, entry := range before.root.Names {
		valueEntry := before.valueEntry(entry.Slot)
		if valueEntry == nil || valueEntry.ValueSource != contract.Supplied || valueEntry.ConfidentialityClass != contract.Secret || len(valueEntry.Recipients) != 8 {
			continue
		}
		payload, payloadErr := contract.InspectCanonicalPayload(valueEntry.ValueBytes)
		if payloadErr == nil && payload.ContentLength == 0 {
			copy := *valueEntry
			retainedEntry = &copy
			break
		}
	}
	if retainedEntry == nil {
		t.Fatal("joint cleanup fixture has no empty retained canonical source with the expected reader set")
	}
	canonicalSelection := sessionConsumerSelection(t, before, before.admission.recipient, retainedEntry.Name)
	retained := contract.RetainedCanonicalRecord{OriginalSlot: canonicalSelection.Slot, Entry: canonicalSelection.Entry}
	retainedBody, err := contract.EncodeRetainedCanonicalRecord(retained)
	if err != nil {
		t.Fatal("joint cleanup retained source", err)
	}
	sources := make([]contract.GeneratorDeclarationEntry, 0, 384)
	sources = append(sources, contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
		Name: retained.Entry.Name, Recipients: slices.Clone(retained.Entry.Recipients), Payload: retainedBody})
	for _, name := range allNames[128:511] {
		sources = append(sources, contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
			Name: name, Recipients: []contract.ID{before.admission.recipient}})
	}
	if len(sources) != 384 {
		t.Fatal("joint cleanup source count", len(sources))
	}

	input := generatedPlanInputFixture(t, before)
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	bindings, err := before.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	recipients := []contract.ID{before.admission.recipient}
	for _, binding := range bindings {
		if binding.SubjectKind == 1 && binding.SubjectID != before.admission.recipient && len(recipients) < 28 {
			recipients = append(recipients, binding.SubjectID)
		}
	}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if len(recipients) != 28 {
		t.Fatal("joint cleanup generated reader count", len(recipients))
	}
	graph, declaration, _ := generatedEffectPlanForGenerationMembershipState(t, &input.graph.Request, before.admission.recipient,
		recipients, generatedNames, []byte(`{"capacity":"purpose3-joint-maximum"}`), defaultGeneratedFixtureProfile(), 0, nil, nil, sources...)
	input.graph = graph
	input.requestBindings = generatedFixtureRequestBindings(graph, input.requestBindings[0].Digest)
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal("joint cleanup declaration", err)
	}
	input.registry, input.recoveryPolicy = graph.Request.Registry, graph.Request.RecoveryPolicyID
	if graph.Header.ValueEntryPlanCount != 512 || graph.Header.LineageCount != 128 || graph.Header.TemplateCount != 1280 {
		t.Fatal("joint cleanup graph shape", graph.Header.ValueEntryPlanCount, graph.Header.LineageCount, graph.Header.TemplateCount)
	}
	var memberships int
	for _, entryPlan := range graph.ValueEntryPlans {
		memberships += int(entryPlan.IntendedMembership.Count)
	}
	if memberships != 3975 || before.root.MembershipCount != 4096 {
		t.Fatal("joint cleanup planned/predecessor membership shape", memberships, before.root.MembershipCount)
	}
	plan, err := before.generatedPlanRequest(t.Context(), input)
	if err != nil || plan == nil {
		t.Fatal("joint cleanup capacity did not reserve purpose-3 continuation", err)
	}
	deleteGroup := plan.capacity.Groups[contract.GeneratorCapacityDeletes]
	ownerGroup := plan.capacity.Groups[contract.GeneratorCapacityOwners]
	if deleteGroup.MaxCount == 0 || ownerGroup.MaxCount == 0 {
		t.Fatal("joint cleanup capacity omitted purpose-3 groups", deleteGroup, ownerGroup)
	}

	// Change one one-reader supplied row to a 129th generated declaration.
	// This keeps 512 entries and raises intended memberships from 3,975 to
	// 4,002, below 4,096; only the generated frontier exceeds its public bound.
	excess := declaration
	excess.Entries = slices.Clone(declaration.Entries)
	plain := slices.IndexFunc(excess.Entries, func(entry contract.GeneratorDeclarationEntry) bool {
		return entry.Kind == contract.GeneratorDeclarationPlain
	})
	generated := slices.IndexFunc(excess.Entries, func(entry contract.GeneratorDeclarationEntry) bool {
		return entry.Kind == contract.GeneratorDeclarationGenerated
	})
	if plain < 0 || generated < 0 {
		t.Fatal("joint cleanup declaration source kinds")
	}
	excess.Entries[plain].Kind = contract.GeneratorDeclarationGenerated
	excess.Entries[plain].Payload = bytes.Clone(excess.Entries[generated].Payload)
	if body, encodeErr := contract.EncodeGeneratorDeclaration(excess); encodeErr != contract.ErrRecordCapacity || body != nil {
		t.Fatal("joint cleanup next generated frontier was admitted", encodeErr)
	}
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	public, private := keys.Calls()
	entryBody, err := contract.EncodeGeneratorDeclarationEntry(excess.Entries[plain])
	if err != nil {
		t.Fatal(err)
	}
	offset := 70
	for i := 0; i < plain; i++ {
		length, lengthErr := contract.GeneratorDeclarationEntryLength(declaration.Entries[i])
		if lengthErr != nil {
			t.Fatal(lengthErr)
		}
		offset += 4 + length
	}
	oldLength, err := contract.GeneratorDeclarationEntryLength(declaration.Entries[plain])
	if err != nil {
		t.Fatal(err)
	}
	excessBody := make([]byte, 0, len(input.declaration)-oldLength+len(entryBody))
	excessBody = append(excessBody, input.declaration[:offset]...)
	excessBody = binary.BigEndian.AppendUint32(excessBody, uint32(len(entryBody)))
	excessBody = append(excessBody, entryBody...)
	excessBody = append(excessBody, input.declaration[offset+4+oldLength:]...)
	excessInput := input
	excessInput.declaration = excessBody
	if invalid, planErr := before.generatedPlanRequest(t.Context(), excessInput); planErr != contract.ErrRecordCapacity || invalid != nil {
		t.Fatal("joint cleanup next-invalid declaration reached Core admission", planErr)
	}
	if store.creates != creates || store.cas != cas {
		t.Fatal("joint cleanup next-invalid declaration reached Store")
	}
	if p, k := keys.Calls(); p != public || k != private {
		t.Fatal("joint cleanup next-invalid declaration reached custody", p-public, k-private)
	}

	closed, _ := selectPrivateOwnedUnusableAggregateFromInput(t, env, before, generatedNames, input,
		[]custody.GeneratedCanonicalSelection{{Selection: canonicalSelection, Record: retained}})
	closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
	work := mustSelectedGeneratedWork(t, closed)
	if closed.root.ValueEntryCount != 512 || closed.root.MembershipCount != 4096 || closed.root.Generated.Duties != 127 ||
		closed.root.Generated.Hazards != 1 || len(work.attempts) != 128 {
		t.Fatal("failed joint aggregate did not preserve its maximum passive set and exact cleanup owners")
	}
	checkJointMaximumEndWorkOrders(t, env, closed)
	selection, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
	if err != nil || !ok || selection.kind != generatedCleanupDuty {
		t.Fatal("joint maximum purpose-3 Duty selection", err)
	}
	row := work.records[generatedRecordKey{10, selection.duty.DutyID}]
	cleanupInput, cleanupInputCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(239), row, selection.target)
	cleanupPlan, err := closed.generatedPlanRequest(t.Context(), cleanupInput)
	if err != nil || cleanupPlan == nil || cleanupPlan.input.graph.Lineages[0].Purpose != 3 {
		t.Fatal("joint maximum purpose-3 cleanup admission", err)
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, closed, cleanupInput, cleanupInputCanonical)
	recorded, _, expected, packet := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
	keys.RetireGenerated()
	cleaned := selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, expected.Template.AttemptID)
	cleaned = generatedLifecycleReopen(t, t.Context(), cleaned, env.Store)
	deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
	cleaned = selectActualGeneratedInboxRelease(t, t.Context(), env, cleaned, deleteStore, expected.Template.AttemptID, false)
	cleaned = selectActualGeneratedInboxRelease(t, t.Context(), env, cleaned, deleteStore, selection.attempt.record.AttemptID, false)
	after := mustSelectedGeneratedWork(t, cleaned)
	if cleaned.root.ValueEntryCount != 512 || cleaned.root.MembershipCount != 4096 || cleaned.root.Generated.Duties != 126 ||
		len(after.attempts) != 127 || len(after.releases) != 0 || len(packet) == 0 {
		t.Fatal("joint maximum cleanup did not close and release exactly one owner")
	}
	current := cleaned.valueEntry(retained.OriginalSlot)
	if current == nil || !sameRetainedEntryValue(*current, retained.Entry) {
		t.Fatal("joint maximum cleanup changed its source-2 canonical member")
	}
	if _, present := cleaned.materialAccess(1, retained.Entry.ValueState); !present {
		t.Fatal("joint maximum cleanup removed the retained canonical current access")
	}
	t.Logf("purpose3 joint maximum: members=512 memberships=4096 generated=128 cleanup-owners=128 elapsed=%s", time.Since(started))
}

// full_only: false
func TestGeneratedOriginalPreparationsReuseCommonFacts(t *testing.T) {
	if !t.Run("bounded_concurrency", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const count = 5
			started := make(chan int, count)
			finished := make(chan int, count)
			release := make(chan struct{})
			joined := make(chan struct{})
			calls := make([]int, count)
			go func() {
				runBoundedGeneratedOriginalPreparations(count, func(i int) {
					calls[i]++
					started <- i
					<-release
					finished <- i
				})
				close(joined)
			}()
			synctest.Wait()
			if len(started) != 3 {
				t.Error("bounded preparation must admit exactly three callbacks", len(started))
			}
			select {
			case <-joined:
				t.Error("preparation returned with blocked callbacks")
			default:
			}
			release <- struct{}{}
			synctest.Wait()
			if len(started) != 4 || len(finished) != 1 {
				t.Error("one completion must release exactly one waiting preparation", len(started), len(finished))
			}
			select {
			case <-joined:
				t.Error("preparation returned before all callbacks completed")
			default:
			}
			close(release)
			<-joined
			if len(started) != count || len(finished) != count {
				t.Error("preparation did not join the whole set", len(started), len(finished))
			}
			for i, callCount := range calls {
				if callCount != 1 {
					t.Error("preparation index did not run exactly once", i, callCount)
				}
			}
		})
	}) {
		return
	}
	env, _ := genesisEnvironment(t, contract.GCP, true)
	before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
	input := generatedPlanInputForGenerations(t, before, generatedVectorID(11), []string{"alpha", "delta", "omega"}, defaultGeneratedFixtureProfile())
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	facts := acquireGeneratedProducerFixtureFacts(t, env, before, reservation)
	graph, declaration, seed := bytes.Clone(facts.session.Graph), bytes.Clone(facts.plan.Declaration), bytes.Clone(facts.owned.SeedAccess)
	support := make([][]byte, len(facts.candidate.SupportRecords))
	for i, record := range facts.candidate.SupportRecords {
		support[i] = bytes.Clone(record.Body)
	}
	keys := []*custody.Fixture{env.Custody, env.Custody.ForkGenerated(t), env.Custody.ForkGenerated(t)}
	t.Cleanup(func() {
		for _, key := range keys {
			key.RetireGenerated()
		}
	})
	producers := make([]*generatedPreparation, len(keys))
	acquired := make([]bool, len(keys))
	entered := make([]int, len(keys))
	preparationsReady := make(chan struct{}, len(keys))
	release := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		runBoundedGeneratedOriginalPreparations(len(keys), func(i int) {
			steps := generatedProducerFixtureSteps{
				facts: facts,
				inputReady: func(actual custody.GeneratedProducerInput) {
					if &actual.Session.Graph[0] != &facts.session.Graph[0] || &actual.Plan.Declaration[0] != &facts.plan.Declaration[0] || &actual.Custody.SeedAccess[0] != &facts.owned.SeedAccess[0] || actual.Session.Output != facts.session.Output || !actual.Preparation.AttemptID.IsZero() || actual.Attempt.AttemptID != input.requestBindings[i].AttemptID {
						t.Error("original did not reuse acquired exact common input", i)
						return
					}
					acquired[i] = true
				},
				request: func(ctx context.Context, p *generatedPreparation, attempt contract.ID, admitted contract.ApplyContext) (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error) {
					if !acquired[i] {
						return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, fmt.Errorf("original preparation preceded input acquisition: %d", i)
					}
					q, preparation, err := before.generatedOriginalProducerRequest(ctx, p, attempt, admitted)
					if err == nil {
						preparationsReady <- struct{}{}
						<-release
					}
					return q, preparation, err
				},
				prepare: before.PrepareGeneratedOriginalProducer, claim: before.ClaimGeneratedOriginalProducer,
			}
			producers[i], _ = preparePrivateGeneratedProducerWithAdmission(t, env, before, reservation, keys[i], input.requestBindings[i].AttemptID, custody.StandardValue, func() { entered[i]++ }, nil, steps)
		})
	}()
	readyContext, cancelReady := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelReady()
ready:
	for i := range keys {
		select {
		case <-preparationsReady:
		case <-readyContext.Done():
			t.Error("three private preparations did not reach the preparation barrier", i)
			break ready
		}
	}
	close(release)
	<-joined
	if !bytes.Equal(graph, facts.session.Graph) || !bytes.Equal(declaration, facts.plan.Declaration) || !bytes.Equal(seed, facts.owned.SeedAccess) {
		t.Fatal("private preparation changed shared caller input")
	}
	for i, record := range facts.candidate.SupportRecords {
		if !bytes.Equal(support[i], record.Body) {
			t.Fatal("candidate binding changed common support", i)
		}
	}
	facts = nil
	for i := range producers {
		if !acquired[i] || entered[i] != 0 || producers[i] == nil {
			t.Fatal("original preparation acquired effects or lost membership", i)
		}
	}
	candidate, outcome := before.ClaimGeneratedOriginalSet(t.Context(), producers, env.Trust)
	if candidate == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("small complete-set claim", outcome)
	}
	for i, p := range producers {
		if candidate.originalProducers[p.attempt] != p || candidate.generated.originalClaims[p.attempt] != candidate.generated.authority || entered[i] != 0 {
			t.Fatal("small complete-set membership or pre-entry effects", i)
		}
	}
}
