package crypto

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// full_only: false
func TestGeneratedRetainedExclusionReleasesRowWorkspaceBeforeNextSource(t *testing.T) {
	// This root must remain nonparallel: allocation sampling is process-wide.
	// Neither OpenValue's plaintext nor openMaterialPacket's cloned keys have a
	// test-visible alias. The allocation stacks identify those owned buffers
	// without adding a production hook or measuring unrelated total heap use.
	previousRate := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	t.Cleanup(func() { runtime.MemProfileRate = previousRate })

	a, rows, route := generatedRetainedExclusionWorkspaceFixture(t)
	t.Cleanup(a.clear)
	request, err := contract.InspectCryptoGeneratedSuppliedRequest(generatedSuppliedBatchRequest(t, a, rows, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	opens, observed := 0, false
	route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
		opens++
		if opens == 4 {
			observed = true
			// MemProfile can lag by two collection cycles. At this boundary the
			// first three rows have finished and the fourth has no plaintext or
			// cloned key output yet. Only unfinished prior-row cleanup can keep
			// those buffers live.
			runtime.GC()
			runtime.GC()
			var records []runtime.MemProfileRecord
			for {
				n, _ := runtime.MemProfile(nil, true)
				records = make([]runtime.MemProfileRecord, n+16)
				n, ok := runtime.MemProfile(records, true)
				if ok {
					records = records[:n]
					break
				}
			}
			var allocatedPlain, livePlain, allocatedKeys, liveKeys int64
			for _, record := range records {
				var preparation, valueOpen, keyOpen bool
				frames := runtime.CallersFrames(record.Stack())
				for {
					frame, more := frames.Next()
					preparation = preparation || strings.HasSuffix(frame.Function, ".(*generatedAdmission).prepareSupplied")
					valueOpen = valueOpen || strings.HasSuffix(frame.Function, "/custody.OpenValue")
					keyOpen = keyOpen || strings.HasSuffix(frame.Function, "/crypto.openMaterialPacket")
					if !more {
						break
					}
				}
				if !preparation || record.AllocObjects == 0 {
					continue
				}
				allocationSize := record.AllocBytes / record.AllocObjects
				if valueOpen && allocationSize == contract.CryptoMaxRawValue {
					allocatedPlain += record.AllocBytes
					livePlain += record.InUseBytes()
				}
				if keyOpen && allocationSize == 64 {
					allocatedKeys += record.AllocBytes
					liveKeys += record.InUseBytes()
				}
			}
			// A missing stack match must not turn this into a vacuous pass.
			if allocatedPlain < 3*contract.CryptoMaxRawValue || allocatedKeys < 3*64 {
				t.Errorf("prior-row allocation sites were not observed: plaintext=%d keys=%d", allocatedPlain, allocatedKeys)
			}
			if livePlain != 0 || liveKeys != 0 {
				t.Errorf("completed retained rows still own workspace before fourth source: plaintext=%d keys=%d; want zero", livePlain, liveKeys)
			}
		}
		return route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
	}
	out := contract.CryptoResponse{}
	if code := a.prepareSupplied(t.Context(), route, request, &out); code != contract.CryptoSuccess {
		t.Fatal("retained exclusion batch refused", code)
	}
	if !observed || opens != 4 || len(a.purpose.final.supplied) != 4 || !a.purpose.final.suppliedFinal {
		t.Fatal("fixture did not complete four retained exclusion rows", observed, opens)
	}
}

// full_only: false
func TestGeneratedRetainedExclusionCancellationDoesNotPublishPartialBatch(t *testing.T) {
	a, rows, route := generatedRetainedExclusionWorkspaceFixture(t)
	t.Cleanup(a.clear)
	request, err := contract.InspectCryptoGeneratedSuppliedRequest(generatedSuppliedBatchRequest(t, a, rows, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	opens := 0
	route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
		opens++
		result := route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
		if opens == 4 {
			cancel()
		}
		return result
	}
	out := contract.CryptoResponse{}
	if code := a.prepareSupplied(ctx, route, request, &out); code != contract.CryptoCancelled {
		t.Fatal("cancellation after fourth source open was not returned", code)
	}
	final := a.purpose.final
	if opens != 4 || out.Body != nil || len(final.supplied) != 0 || final.suppliedNext != 0 || final.suppliedBatch != 0 || final.suppliedFinal {
		t.Fatal("cancelled retained batch published a partial result or advanced preparation", opens)
	}
	for i, source := range final.plan.canonicals {
		if source.opened != (i < 3) {
			t.Fatal("cancellation did not occur after three completed rows", i, source.opened)
		}
	}
	if len(route.returned) == 0 || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
		t.Fatal("cancelled source open retained its private packet capacity")
	}
	var materialOpens, materialWraps uint32
	for _, use := range out.KeyUseRows {
		if use.Outcome != contract.KeyUseCompleted {
			t.Fatal("cancelled batch lost completed key-use evidence", use)
		}
		switch use.Purpose {
		case contract.KeyUseMaterialOpen:
			materialOpens += use.Count
		case contract.KeyUseMaterialWrap:
			materialWraps += use.Count
		}
	}
	if materialOpens != 4 || materialWraps != 3 {
		t.Fatal("cancelled batch changed completed source-open or fresh-wrap accounting", materialOpens, materialWraps)
	}
}

// Keep the real generated sibling, and add four independently sealed current
// Supplied values. Their Retained declarations remove one reader. This reaches
// the existing private row engine with a validated complete graph/declaration;
// the connected Final tests own admission, checkpoint and publication evidence.
func generatedRetainedExclusionWorkspaceFixture(t *testing.T) (*generatedAdmission, []contract.IdentityRow, *consumerTestRoute) {
	t.Helper()
	f := generatedRuntimeEffectFixture(t, false)
	authority := f.reservation.Session.Bindings[applyBindingIndex(f.reservation.Session.Bindings, f.base.control.AuthorityRecipientID)]
	public := f.reservation.Session.BeforePublic
	var entries []generatedCandidateEntry
	var sources []generatedCanonicalSource
	for i := range 4 {
		name := fmt.Sprintf("retained-%03d", i)
		id := func(suffix string) contract.ID { return consumerID(name + " " + suffix) }
		core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
			DomainID: public.Domain, Name: name, ValueSource: contract.Supplied, EntryIncarnationID: id("incarnation"), ValueStateID: id("value"),
			OriginSnapshotID: id("snapshot"), OriginTransitionID: id("transition"), DataKeyID: id("data"), DataKeyEpoch: 1,
			CommitmentKeyID: id("commitment"), CommitmentKeyEpoch: 1, ContentLength: contract.CryptoMaxRawValue, InputEncoding: contract.InputEncodingRaw, RetainedLength: contract.CryptoMaxRawValue}
		plain := bytes.Repeat([]byte{byte(i + 1)}, contract.CryptoMaxRawValue)
		payload, keys, err := custody.SealValue(core, plain)
		clear(plain[:cap(plain)])
		if err != nil {
			t.Fatal(err)
		}
		readers := []contract.ID{authority.SubjectID, consumerID("reader")}
		slices.SortFunc(readers, func(x, y contract.ID) int { return bytes.Compare(x[:], y[:]) })
		access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind,
			MaterialID: core.ValueStateID, PackageCheck: payload.PackageCheck}
		var authorityWrap contract.WrapRow
		for _, binding := range f.reservation.Session.Bindings {
			if !slices.Contains(readers, binding.SubjectID) {
				continue
			}
			wrapCore, err := custody.ValueWrapCore(core, binding)
			if err != nil {
				clear(keys[:cap(keys)])
				t.Fatal(err)
			}
			wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
			if err != nil {
				clear(keys[:cap(keys)])
				t.Fatal(err)
			}
			access.MaterialContextDigest = wrapCore.MaterialContextDigest
			access.Wraps = append(access.Wraps, wrap)
			if binding.SubjectID == authority.SubjectID {
				authorityWrap = wrap
			}
		}
		clear(keys[:cap(keys)])
		value, err := contract.EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		entry := contract.ValueEntry{Name: name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID,
			OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: contract.Supplied,
			ConfidentialityClass: contract.Secret, ValueBytes: value, Recipients: readers, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(value) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(value) - contract.CanonicalPayloadOverhead)}
		slot := uint16(i + 1)
		record := contract.RetainedCanonicalRecord{OriginalSlot: slot, Entry: entry}
		body, err := contract.EncodeRetainedCanonicalRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		entryDigest, err := contract.PublicValueEntryDigest(public.Domain, slot, entry)
		if err != nil {
			t.Fatal(err)
		}
		sourceID, err := contract.AdmissionEntryDigest(record)
		if err != nil {
			t.Fatal(err)
		}
		accessBody, err := contract.EncodeAccessRecord(access)
		if err != nil {
			t.Fatal(err)
		}
		public.Rows = append(public.Rows, contract.PublicStateRow{Slot: slot, Name: name, EntryDigest: entryDigest})
		entries = append(entries, generatedCandidateEntry{Slot: slot, Entry: entry})
		sources = append(sources, generatedCanonicalSource{originalSlot: slot, body: contract.Hash(body), entryDigest: entryDigest,
			core: core, recipients: readers, sourceID: sourceID, wrap: authorityWrap, selectedAccess: access,
			access: contract.DigestLength{Digest: contract.Hash(accessBody), Length: uint64(len(accessBody))}, buffer: body})
		generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
			Name: name, Recipients: []contract.ID{authority.SubjectID}, Payload: body}, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema,
			Slot: slot, Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, EntryIncarnationID: entry.Incarnation,
			ChangeMask: contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership})
	}
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	phase := consumerID("retained exclusion workspace phase")
	a := &generatedAdmission{operation: consumerID("retained exclusion workspace operation"), request: f.compare, control: f.base.control,
		bindings: f.reservation.Session.Bindings, graph: graph, before: public, routeID: f.base.route.CredentialRoute(),
		purpose: generatedPurposeState{output: generatedEmptyOutputWitness(t, &public, entries, nil),
			final: &generatedFinalPreparationState{phaseID: phase, materializationPhaseID: phase, suppliedCount: 4}}}
	a.purpose.final.plan.declaration = f.declaration
	a.purpose.final.plan.canonicals = sources
	for _, binding := range a.bindings {
		digest, err := contract.PublicBindingDigest(binding.Binding)
		if err != nil {
			t.Fatal(err)
		}
		a.bindingDigests = append(a.bindingDigests, digest)
	}
	declaration, err := contract.InspectGeneratorDeclaration(f.declaration)
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.IdentityRow
	for i, plan := range graph.ValueEntryPlans {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		var readers []contract.ID
		for j := 0; j < len(entry.RecipientIDs); j += 32 {
			readers = append(readers, contract.ID(entry.RecipientIDs[j:j+32]))
		}
		a.purpose.final.plan.recipients = append(a.purpose.final.plan.recipients, readers)
		if plan.ValueSource != contract.Supplied {
			continue
		}
		identity, ok := a.finalFreshIdentity(i)
		if !ok {
			t.Fatal("fresh retained identity")
		}
		rows = append(rows, identity)
	}
	return a, rows, f.base.route
}
