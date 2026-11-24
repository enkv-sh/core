package core

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func hermeticChangedPolicyData(t testing.TB, body []byte) []byte {
	t.Helper()
	var subjects []string
	if json.Unmarshal(body, &subjects) != nil || len(subjects) < 2 || len(subjects[0]) == 0 {
		t.Fatal("fixture policy subjects unavailable")
	}
	prior := subjects[0]
	subjects[0] = prior[:len(prior)-1] + "y"
	if subjects[0] == prior || len(subjects[0]) != len(prior) || subjects[0] >= subjects[1] {
		t.Fatal("equal-width policy replacement invalid")
	}
	result, err := json.Marshal(subjects)
	if err != nil || len(result) != len(body) {
		t.Fatal("policy replacement framing changed", err)
	}
	return result
}

func logMaximumOutputPhase(t *testing.T, phase string, memory *memoryAccounting, before *StateSession, c *Comparison,
	candidate *Candidate, observed *StateSession, extra ...[]byte) {
	t.Helper()
	proof := memory.ordinary
	build, _ := debug.ReadBuildInfo()
	if proof == nil || ordinaryOutputEligibility(runtime.Version(), runtime.GOOS, runtime.GOARCH, os.Getenv("GODEBUG"), build) != nil ||
		proof.GODEBUG != os.Getenv("GODEBUG") || proof.BuildIdentity != build.String() {
		t.Fatal("conservative proof unavailable: ordinary runtime/debug identity changed")
	}
	image, err := readOrdinaryOutputImage()
	if err != nil || !sameOrdinaryOutputImage(*proof, image) {
		t.Fatal("conservative proof unavailable: loaded main artifact changed", err)
	}
	// Image inspection/hash and all backing observers finish before this
	// coherent snapshot. No GC is forced; observer workspace is retained.
	memory.sample(phase, before, c, candidate, observed, extra...)
	sample := &memory.samples[len(memory.samples)-1]
	if sample.GoTotalAlloc < memory.baseline.TotalAlloc {
		t.Fatal("conservative proof unavailable: allocation counter decreased", *sample)
	}
	if _, err := checkedOutputMemorySum(memory.baseline.HeapAlloc, sample.GoTotalAlloc-memory.baseline.TotalAlloc); err != nil {
		t.Fatal("conservative proof unavailable: cumulative diagnostic overflow", err, *sample)
	}
	sample.ArenaUpper, err = ordinaryOutputArenaUpper(*sample)
	if err != nil {
		t.Fatal("conservative proof unavailable", err, *sample)
	}
	parent, child := custody.GeneratorProcessOwnedByteCeilings()
	sample.ContractUpper, err = checkedOutputMemorySum(sample.ArenaUpper, proof.StaticUpper, parent, child)
	if err != nil {
		t.Fatal("conservative proof unavailable", err, *sample)
	}
	sample.SourceOwnedUpper = memory.sourceOwnedUpper
	sample.OrdinaryProof = proof
	body, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	selected := before
	if observed != nil {
		selected = observed
	}
	var selectedEncoded, logicalOutput, logicalRaw, written uint64
	if selected != nil {
		selectedEncoded = selected.root.ChildEncodedBytes + uint64(selected.head.Core.Root.Length) + uint64(len(selected.body))
		logicalOutput, logicalRaw = uint64(selected.root.OutputConfiguration.TotalLength), selected.root.RawBytes
	}
	if candidate != nil {
		for _, object := range candidate.objects {
			written += uint64(len(object.body))
		}
	}
	t.Logf("output phase %s; selected encoded bytes %d; logical output/raw bytes %d/%d; candidate object encoded bytes %d; native parent/child fixed backing %d/%d; memory %s",
		phase, selectedEncoded, logicalOutput, logicalRaw, written, parent, child, body)
	// HeapSys + StackInuse + GCSys is a sufficient current ordinary backing
	// upper, including free capacity and heap-to-workbuf transfers. Some GC
	// storage can be released, so the complete sum is not monotone. The source
	// bound counts live owners across the interval; arena/churn remain diagnostics.
	runtime.KeepAlive(extra)
	if err := memory.checkMaximumOutputMemory(*sample, before, before == nil && c == nil && candidate == nil && observed == nil); err != nil {
		t.Fatal(err)
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumPolicyTransitionMemory(t *testing.T) {
	testMaximumOutputConfigurationTransition(t, t.Context(), "policy_only")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumRoutingTransitionMemory(t *testing.T) {
	testMaximumOutputConfigurationTransition(t, t.Context(), "routing_only")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumEqualSourceConversionMemory(t *testing.T) {
	testMaximumOutputConfigurationTransition(t, t.Context(), "generated_to_supplied_equal")
}

func testMaximumOutputConfigurationTransition(t *testing.T, operationCtx context.Context, name string) {
	t.Helper()
	proof := newOrdinaryOutputProof(t)
	seed := newConfiguredSuccessionMemorySeed(t, true)
	env, f, keys := seed.openCase(t)
	before := f.session
	configuration, result := before.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal("maximum predecessor configuration", result)
	}
	want := configuration
	convert := ""
	switch name {
	case "policy_only":
		subjects := hermeticChangedPolicyData(t, want.Bindings[0].Targets[0].Policy.Data)
		want.Bindings[0].Destination.Policy.Data = subjects
		for i := range want.Bindings[0].Targets {
			want.Bindings[0].Targets[i].Policy.Data = subjects
		}
	case "routing_only":
		i := slices.IndexFunc(want.Routes, func(route contract.OutputRoute) bool { return len(route.Destinations) == 8 })
		if i < 0 {
			t.Fatal("maximum fixture lacks an eight-destination route")
		}
		route := &want.Routes[i]
		removed := route.Destinations[7]
		route.Destinations = slices.Clone(route.Destinations[:7])
		// A selected target exists for each effective entry/destination pair.
		// Removing this pair retains its binding and the other 15 targets.
		b := slices.IndexFunc(want.Bindings, func(binding contract.OutputBinding) bool { return binding.DestinationID == removed })
		if b < 0 {
			t.Fatal("removed route has no selected binding")
		}
		targets := want.Bindings[b].Targets
		j := slices.IndexFunc(targets, func(target contract.OutputTarget) bool { return target.EntryIncarnationID == route.EntryIncarnationID })
		if j < 0 || len(targets) != 16 {
			t.Fatal("removed route has no target in the full binding", len(targets))
		}
		want.Bindings[b].Targets = slices.Delete(slices.Clone(targets), j, j+1)
	case "generated_to_supplied_equal":
		for _, named := range before.root.Names {
			if before.valueEntry(named.Slot).ValueSource == contract.Generated {
				convert = named.Name
				break
			}
		}
	}
	input := maximumOutputApplyInput(t, before, want)
	entries := maximumOutputEntryInputs(t, env, before, convert)
	memory := startOrdinaryOutputAccounting(proof)
	sourceUpper, boundErr := maximumOutputOwnedUpper(proof, before, entries)
	if boundErr != nil {
		t.Fatal("maximum source proof unavailable", boundErr)
	}
	memory.sourceOwnedUpper = sourceUpper
	memory.sourceOwnedBefore = before
	var parent *AdmittedParentComparison
	var retirementSupport contract.GeneratorDescriptor
	{
		implementation := staticGeneratedHandoffImplementation(t, env.Domain, defaultGeneratedFixtureProfile())
		parent = admitSuppliedOutputComparison(t, before, keys, entries, input, implementation)
		if convert != "" {
			old := before.valueEntry(entrySlot(t, before, convert))
			retirementSupport = normalHandoffExpectedSupport(t, parent, *old, implementation)
		}
	}
	memory.stringBuffers = memory.stringBuffers[:0]
	visitOutputConfigurationStrings(want, memory.stringBuffers.addString)
	visitNormalOutputStrings(parent.support.Output, memory.stringBuffers.addString)
	if got := memory.stringBuffers.capacity(); got > (36<<20)+91360768 {
		t.Fatalf("fixture output string envelope: bytes=%d", got)
	}
	runtime.KeepAlive(want)
	runtime.KeepAlive(parent)
	c, result := before.compareWithOutput(t.Context(), entries, input, parent)
	if c == nil || result.Outcome != ObservedCurrent || !c.outputChanged && convert == "" {
		t.Fatal("maximum private output comparison", result)
	}
	logMaximumOutputPhase(t, "private-comparison", memory, before, c, nil, nil)
	memory.restartOrdinaryOutputAccounting()
	permit, _ := admitTransition(t, before, c)
	if convert != "" {
		slot := entrySlot(t, before, convert)
		old, fresh := before.valueEntry(slot).Incarnation, permit.plan.incarnations[slot]
		// Existing destination bindings retain their identities through source conversion.
		for i := range want.Bindings {
			for j := range want.Bindings[i].Targets {
				target := &want.Bindings[i].Targets[j]
				if target.EntryIncarnationID == old {
					target.EntryIncarnationID = fresh
				}
			}
			slices.SortFunc(want.Bindings[i].Targets, func(a, b contract.OutputTarget) int {
				return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
			})
		}
		for i := range want.Groups {
			for j := range want.Groups[i] {
				if want.Groups[i][j] == old {
					want.Groups[i][j] = fresh
				}
			}
			slices.SortFunc(want.Groups[i], func(a, b contract.ID) int {
				return bytes.Compare(a[:], b[:])
			})
		}
		slices.SortFunc(want.Groups, func(a, b []contract.ID) int {
			return bytes.Compare(a[0][:], b[0][:])
		})
		for i := range want.Routes {
			if want.Routes[i].EntryIncarnationID == old {
				want.Routes[i].EntryIncarnationID = fresh
			}
		}
		slices.SortFunc(want.Routes, func(a, b contract.OutputRoute) int {
			return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
		})
	}
	candidate, result := before.Prepare(t.Context(), c, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum output preparation", result)
	}
	logMaximumOutputPhase(t, "prepared", memory, before, c, candidate, nil)
	memory.restartOrdinaryOutputAccounting()
	selected, result := before.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum output selection", result)
	}
	logMaximumOutputPhase(t, "selected-observation", memory, before, c, candidate, selected)
	memory.restartOrdinaryOutputAccounting()
	keys.RetireApply()
	cold := generatedLifecycleReopen(t, operationCtx, selected, env.Store)
	assertMaximumOutputStatePreserved(t, before, cold, convert)
	actual, result := cold.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal("cold maximum complete configuration read", result)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("cold maximum complete configuration differs: schema_equal=%t domain_equal=%t bindings_equal=%t groups_equal=%t routes_equal=%t",
			actual.Schema == want.Schema, actual.DomainID == want.DomainID, reflect.DeepEqual(actual.Bindings, want.Bindings),
			reflect.DeepEqual(actual.Groups, want.Groups), reflect.DeepEqual(actual.Routes, want.Routes))
	}
	declaration, routing := capacityConfigurationLengths(t, want)
	if uint32(declaration+routing+4) != cold.root.OutputConfiguration.TotalLength || uint32(routing) != cold.root.OutputConfiguration.RoutingLength {
		t.Fatal("independent maximum section lengths differ")
	}
	assertMaximumPublicationTransition(t, before, cold, want)
	if convert != "" {
		assertCapacityCurrentIntents(t, cold, 127)
		old := before.valueEntry(entrySlot(t, before, convert))
		if cold.root.Generated.GeneratedCurrent != before.root.Generated.GeneratedCurrent-1 ||
			cold.root.Generated.Retiring != before.root.Generated.Retiring+1 {
			t.Fatal("conversion did not retain exactly one retirement obligation")
		}
		work, err := cold.selectedGeneratedWork(t.Context())
		if err != nil {
			t.Fatal("converted retirement closure", err)
		}
		retained := 0
		for _, page := range cold.support {
			for _, row := range page.Records {
				if row.Kind != contract.GeneratedDutySupportKind {
					continue
				}
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil {
					t.Fatal("converted retirement duty", err)
				}
				if duty.Kind != contract.GeneratedDutyRetirement || duty.OriginalAttemptID != old.Generated.OriginAttemptID {
					continue
				}
				target, err := work.retirementTarget(t.Context(), duty)
				if err != nil || duty.OriginalOperationID != old.Generated.OriginOperationID ||
					duty.ResourceID != old.Generated.ResourceIncarnationID || duty.Support != retirementSupport ||
					target.Name != old.Name || target.IncarnationID != old.Incarnation || target.Epoch != old.Generated.Epoch ||
					target.ResourceID != old.Generated.ResourceIncarnationID || target.ResourceDigest != old.Generated.ResourceDigest ||
					target.LifecycleMode != old.Generated.LifecycleMode || target.ConfigContractID != old.Generated.ConfigContractID ||
					target.ResourceContractID != old.Generated.ResourceContractID || target.OriginalOperationID != old.Generated.OriginOperationID ||
					target.OriginalAttemptID != old.Generated.OriginAttemptID || target.CompletionClass != old.Generated.CompletionClass {
					t.Fatal("conversion lost old retirement identity or deletion inputs", err)
				}
				retained++
			}
		}
		if retained != 1 {
			t.Fatal("conversion retirement whole set", retained)
		}
		selection := sessionConsumerSelection(t, cold, cold.admission.recipient, convert)
		if check := keys.Consume(t.Context(), selection, custody.MaximumValue); check.Code != contract.CryptoSuccess || !check.ValueMatched {
			t.Fatal("equal converted private value", check.Code)
		}
	}
	logMaximumOutputPhase(t, "retired-private-owner", memory, before, c, candidate, cold)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(permit)
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumPreparationPreCanceledMemory(t *testing.T) {
	testMaximumOutputConfigurationCancellation(t, "pre_canceled")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumLastConfigurationReadCanceledMemory(t *testing.T) {
	testMaximumOutputConfigurationCancellation(t, "last_configuration_read")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumLastLargeReadbackUnavailableMemory(t *testing.T) {
	testMaximumOutputConfigurationCancellation(t, "last_large_readback")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumSigningRefusedMemory(t *testing.T) {
	testMaximumOutputConfigurationCancellation(t, "signing_refused")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumSelectionPreCanceledMemory(t *testing.T) {
	testMaximumOutputConfigurationCancellation(t, "selection_pre_canceled")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumSelectionUnknownWithEffectMemory(t *testing.T) {
	testMaximumOutputConfigurationCancellation(t, "selection_unknown_with_effect")
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationMaximumSelectionUnknownWithoutEffectMemory(t *testing.T) {
	testMaximumOutputConfigurationCancellation(t, "selection_unknown_without_effect")
}

func testMaximumOutputConfigurationCancellation(t *testing.T, cut string) {
	t.Helper()
	proof := newOrdinaryOutputProof(t)
	seed := newConfiguredSuccessionMemorySeed(t, true)
	env, f, keys := seed.openCase(t)
	before, store, trust := f.session, env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	configuration, result := before.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal("maximum cancellation configuration", result)
	}
	input := maximumOutputApplyInput(t, before, configuration)
	wantConfiguration := configuration
	subjects := hermeticChangedPolicyData(t, input.bindings[0].targets[0].target.Policy.Data)
	input.bindings[0].destination.Policy.Data = subjects
	wantConfiguration.Bindings[0].Destination.Policy.Data = subjects
	for i := range input.bindings[0].targets {
		input.bindings[0].targets[i].target.Policy.Data = subjects
		wantConfiguration.Bindings[0].Targets[i].Policy.Data = subjects
	}

	entries := maximumOutputEntryInputs(t, env, before, "")
	sourceUpper, boundErr := maximumOutputOwnedUpper(proof, before, entries)
	if boundErr != nil {
		t.Fatal("maximum source proof unavailable", boundErr)
	}
	parent := admitSuppliedOutputComparison(t, before, keys, entries, input)
	head := store.objects[store.desc.HeadKey]
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Admission precedes this diagnostic baseline. The source bound includes
	// admission and retained fixture owners across the complete interval.
	memory := startOrdinaryOutputAccounting(proof)
	memory.sourceOwnedUpper, memory.sourceOwnedBefore = sourceUpper, before
	visitOutputConfigurationStrings(wantConfiguration, memory.stringBuffers.addString)
	visitNormalOutputStrings(parent.support.Output, memory.stringBuffers.addString)
	if got := memory.stringBuffers.capacity(); got > (36<<20)+91360768 {
		t.Fatalf("fixture output string envelope: bytes=%d", got)
	}
	runtime.KeepAlive(wantConfiguration)
	runtime.KeepAlive(parent)
	if cut == "last_configuration_read" {
		declaration, routing := capacityConfigurationLengths(t, configuration)
		length := declaration + 4 + routing
		if declaration != 32<<20 || routing != 284869 || uint32(length) != before.root.OutputConfiguration.TotalLength {
			t.Fatal("last-read fixture configuration dimensions", declaration, routing, before.root.OutputConfiguration.TotalLength)
		}
		wantReads := (length + contract.MaxOutputConfigurationSliceBytes - 1) / contract.MaxOutputConfigurationSliceBytes
		targetKey, visits := outputConfigurationCancellationTarget(t, before, store, uint16(wantReads-1))
		reads, seen := 0, 0
		creates, cas, signs := store.creates, store.cas, trust.signs
		public, private := keys.Calls()
		store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
			reads++
			if key == targetKey {
				seen++
				if seen == visits {
					cancel()
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				}
			}
			return read
		}
		comparison, result := before.compareWithOutput(ctx, entries, input, parent)
		store.readHook = nil
		want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonLimit}
		if comparison != nil || result != want || reads != wantReads || seen != visits || ctx.Err() != context.Canceled || parent.used {
			t.Fatalf("last configuration read: comparison=%t result=%+v reads=%d want=%d seen=%d visits=%d canceled=%t parent_used=%t", comparison != nil, result, reads, wantReads, seen, visits, ctx.Err() == context.Canceled, parent.used)
		}
		if p, k := keys.Calls(); p != public || k != private || creates != store.creates || cas != store.cas || signs != trust.signs {
			t.Fatalf("configuration cancellation call deltas: public=%d private=%d creates=%d CAS=%d signs=%d", p-public, k-private, store.creates-creates, store.cas-cas, trust.signs-signs)
		}
		keys.RetireApply()
		capacityConfigurationSupportRefs(t, before)
		logMaximumOutputPhase(t, "last-configuration-read-retired", memory, before, nil, nil, nil)
		return
	}
	c, result := before.compareWithOutput(t.Context(), entries, input, parent)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum cancellation comparison", result)
	}
	permit, _ := admitTransition(t, before, c)
	creates, cas, signs, reads := store.creates, store.cas, trust.signs, store.reads
	public, private := keys.Calls()
	memory.restartOrdinaryOutputAccounting()
	signer := env.Trust
	var fault *preparationFaultStore
	switch cut {
	case "pre_canceled":
		cancel()
	case "last_large_readback":
		var target *objectImage
		for i := range c.normalSupportObjects {
			object := &c.normalSupportObjects[i]
			if len(object.body) >= 1<<20 {
				target = object
			}
		}
		if target == nil {
			t.Fatal("maximum candidate has no large support object")
		}
		fault = &preparationFaultStore{memoryStore: store, target: mustKey(t, store.desc.Prefix, target.ref), mode: "readback-unavailable"}
		before.store = fault
	case "signing_refused":
		signer = &signResultTrust{Trust: env.Trust, result: contract.SignResult{Reason: contract.ReasonProof}}
	}
	candidate, result := before.Prepare(ctx, c, permit, signer)
	switch cut {
	case "pre_canceled":
		if candidate != nil || result != refused(AdmissionInvalid) || permit.used || before.prepared ||
			store.creates != creates || store.cas != cas || trust.signs != signs || store.reads != reads {
			t.Fatalf("pre-canceled preparation: candidate=%t result=%+v permit_used=%t prepared=%t reads=%d creates=%d CAS=%d signs=%d", candidate != nil, result, permit.used, before.prepared, store.reads-reads, store.creates-creates, store.cas-cas, trust.signs-signs)
		}
		if p, k := keys.Calls(); p != public || k != private {
			t.Fatalf("pre-canceled private call deltas: public=%d private=%d", p-public, k-private)
		}
	case "last_large_readback", "signing_refused":
		want := failure(IntegrityFailure, InvalidProof)
		if fault != nil {
			want = Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}
			attempted, targetWrites, unavailable := 0, 0, 0
			for _, event := range fault.events {
				if event.write != 0 {
					attempted++
					if event.key == fault.target {
						targetWrites++
					}
				}
				if event.key == fault.target && event.read == contract.ReadUnavailable {
					unavailable++
				}
			}
			if attempted < 18 || targetWrites != 1 || unavailable == 0 || store.creates-creates != attempted {
				t.Fatalf("large candidate readback: attempted=%d minimum18 target_writes=%d want1 unavailable=%d minimum1 creates=%d", attempted, targetWrites, unavailable, store.creates-creates)
			}
		}
		if fault == nil {
			refusedSigner := signer.(*signResultTrust)
			if refusedSigner.calls != 1 || store.creates-creates < 19 {
				t.Fatalf("signing refusal: calls=%d want1 creates=%d minimum19", refusedSigner.calls, store.creates-creates)
			}
		}
		for ref, body := range before.cache {
			if err := format.CheckReference(ref, body); err != nil {
				t.Fatal("failed preparation retained unverified immutable cache", err)
			}
		}
		if candidate != nil || result != want || !permit.used || store.cas != cas {
			t.Fatalf("failed candidate: candidate=%t result=%+v permit_used=%t CAS=%d", candidate != nil, result, permit.used, store.cas-cas)
		}
		if candidate, result := before.Prepare(t.Context(), c, permit, signer); candidate != nil || result != refused(AdmissionInvalid) {
			t.Fatal("failed accepted ordinary preparation permit remained usable", result)
		}
	default:
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("maximum selection cancellation preparation", result)
		}
		wrapper := &recordingCASStore{Store: store, cancelledReads: true}
		entered := 0
		wrapper.write = func(call context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
			entered++
			if cut == "selection_unknown_with_effect" {
				if write := store.CompareAndSwap(call, key, token, body); write.Status != contract.WriteAcknowledged {
					t.Fatal("entered maximum selection", write.Status)
				}
			}
			cancel()
			return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
		}
		before.store = wrapper
		want := Result{Outcome: UnresolvedCommit, Reason: ReadUnavailable, RequestedRevision: candidate.head.Core.Revision,
			CommitMayHaveOccurred: true, StoreReason: contract.ReasonLimit}
		if cut == "selection_pre_canceled" {
			cancel()
			want = refused(AdmissionInvalid)
		}
		if result := before.Select(ctx, candidate); result != want || wrapper.readCalls != 0 {
			t.Fatalf("canceled selection: result=%+v want=%+v reads=%d want0", result, want, wrapper.readCalls)
		}
		wantEntries := 1
		if cut == "selection_pre_canceled" {
			wantEntries = 0
		}
		if entered != wantEntries || wrapper.calls != wantEntries {
			t.Fatalf("canceled selection calls: entered=%d calls=%d want=%d", entered, wrapper.calls, wantEntries)
		}
		logMaximumOutputPhase(t, "canceled-selection", memory, before, c, candidate, nil)
	}
	keys.RetireApply()
	currentHead := store.objects[store.desc.HeadKey]
	if cut != "selection_unknown_with_effect" && (head.Token != currentHead.Token || !bytes.Equal(head.Body, currentHead.Body)) {
		t.Fatalf("failed transition HEAD: token_same=%t body_same=%t", head.Token == currentHead.Token, bytes.Equal(head.Body, currentHead.Body))
	}
	cold, result := Open(t.Context(), f.admission, store)
	if cold == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum canceled transition cold reopen", result)
	}
	assertMaximumOutputStatePreserved(t, before, cold, "")
	if cut == "selection_unknown_with_effect" {
		if candidate == nil || head.Token == currentHead.Token || bytes.Equal(head.Body, currentHead.Body) ||
			!bytes.Equal(currentHead.Body, candidate.body) || !bytes.Equal(cold.body, candidate.body) ||
			cold.head.Core.Revision != candidate.head.Core.Revision || cold.head.Core.Root != candidate.head.Core.Root {
			t.Fatalf("unknown selection effect: candidate=%t token_changed=%t body_changed=%t stored_candidate_same=%t cold_candidate_same=%t revision_same=%t root_same=%t", candidate != nil, head.Token != currentHead.Token, !bytes.Equal(head.Body, currentHead.Body), candidate != nil && bytes.Equal(currentHead.Body, candidate.body), candidate != nil && bytes.Equal(cold.body, candidate.body), candidate != nil && cold.head.Core.Revision == candidate.head.Core.Revision, candidate != nil && cold.head.Core.Root == candidate.head.Core.Root)
		}
		actual, result := cold.currentOutputConfigurationForApply(t.Context())
		if result.Outcome != 0 || !reflect.DeepEqual(actual, wantConfiguration) {
			t.Fatalf("unknown selection configuration: result=%+v configuration_same=%t", result, reflect.DeepEqual(actual, wantConfiguration))
		}
		assertMaximumPublicationTransition(t, before, cold, wantConfiguration)
	} else {
		assertCapacityConfigurationPreserved(t, before, cold)
	}
	logMaximumOutputPhase(t, "canceled-preparation-retired", memory, before, c, candidate, cold)
}
