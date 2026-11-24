package crypto

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func generatedOriginalSealedCurrent(t *testing.T, f *generatedRuntimeFixture, readers []contract.ID, plain []byte) contract.ConsumerSelection {
	t.Helper()
	authority := f.base.q.Bindings[applyBindingIndex(f.base.q.Bindings, f.base.control.AuthorityRecipientID)]
	core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
		DomainID: f.compare.Context.DomainID, Name: "alpha", ValueSource: contract.Supplied, EntryIncarnationID: consumerID("alpha incarnation"),
		ValueStateID: consumerID("alpha current value"), OriginSnapshotID: consumerID("alpha current snapshot"), OriginTransitionID: consumerID("alpha current transition"),
		DataKeyID: consumerID("alpha current data"), DataKeyEpoch: 1, CommitmentKeyID: consumerID("alpha current commitment"), CommitmentKeyEpoch: 1, ContentLength: uint32(len(plain)), InputEncoding: contract.InputEncodingRaw, RetainedLength: uint32(len(plain))}
	payload, keys, err := custody.SealValue(core, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID, PackageCheck: payload.PackageCheck}
	for _, binding := range f.base.q.Bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(readers, binding.SubjectID) {
			continue
		}
		wrapCore, err := custody.ValueWrapCore(core, binding)
		if err != nil {
			t.Fatal(err)
		}
		access.MaterialContextDigest = wrapCore.MaterialContextDigest
		wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = append(access.Wraps, wrap)
	}
	root, err := contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	selected := contract.ConsumerSelection{DomainID: core.DomainID, SnapshotID: root.Object, HEADDigest: f.compare.Context.PredecessorHEADDigest, AccessRoot: f.compare.Context.CurrentAccessRoot,
		Root: root, HEADRevision: consumerID("generated predecessor revision"), HEADToken: contract.Token{Family: contract.GCP, Value: "1"}, Slot: 1, Core: core, Payload: payload, Binding: authority, Access: access,
		Entry: contract.ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID, OriginSnapshot: core.OriginSnapshotID,
			OriginTransition: core.OriginTransitionID, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: slices.Clone(readers), InputEncoding: core.InputEncoding, OutputEncoding: contract.OutputEncodingRaw, ContentLength: core.ContentLength, RetainedLength: core.RetainedLength}}
	refreshConsumerSelection(t, &selected)
	return selected
}

// full_only: false
func TestGeneratedOriginalSealedInputRequiresPrivateEqualCurrentSubset(t *testing.T) {
	for _, condition := range []string{"repeat", "exclusion", "unequal", "damaged", "addition", "absent", "content-change", "conversion"} {
		t.Run(condition, func(t *testing.T) {
			f := generatedRuntimeEffectFixture(t, false)
			authority := f.base.control.AuthorityRecipientID
			readers := []contract.ID{authority}
			if condition == "exclusion" {
				readers = slices.Clone(f.base.q.Intent[0].Recipients)
			}
			plain := []byte("first secret")
			if condition == "unequal" {
				plain = []byte("different secret")
			}
			current := generatedOriginalSealedCurrent(t, &f, readers, plain)
			desired := []contract.ID{authority}
			if condition == "addition" {
				desired = slices.Clone(f.base.q.Intent[0].Recipients)
			}
			envelope, err := contract.DecodeSealedInputEnvelope(f.base.q.SealedInputs[0].EnvelopeBytes)
			if err != nil {
				t.Fatal(err)
			}
			if condition == "addition" {
				envelope.Core.IntendedRecipientBindingSetDigest = consumerID("different original binding")
				envelope, err = custody.SealInput(envelope.Core, current.Binding, []byte("first secret"))
				if err != nil {
					t.Fatal(err)
				}
			}
			if condition == "damaged" {
				envelope.Ciphertext = bytes.Clone(envelope.Ciphertext)
				envelope.Ciphertext[0] ^= 1
			}
			source, err := contract.EncodeSealedInputEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			mask := uint8(0)
			if condition == "exclusion" || condition == "addition" {
				mask = contract.GeneratorValueChangeMembership
			}
			if condition == "content-change" {
				mask |= contract.GeneratorValueChangeContent
			}
			incarnation := current.Entry.Incarnation
			if condition == "conversion" {
				incarnation = consumerID("different supplied incarnation")
			}
			generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "alpha", Recipients: desired, Payload: source},
				contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 1, Name: "alpha", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, EntryIncarnationID: incarnation, ChangeMask: mask})
			if condition != "absent" {
				f.reservation.Session.BeforePublic.Rows = append(f.reservation.Session.BeforePublic.Rows, contract.PublicStateRow{Slot: current.Slot, Name: current.Entry.Name, EntryDigest: current.EntryDigest})
				f.entries = append(f.entries, generatedCandidateEntry{Slot: current.Slot, Entry: current.Entry})
				f.reservation.Plan.CurrentValues = []contract.ConsumerSelection{current}
			}
			f.reservation.Session.Output = generatedEmptyOutputWitness(t, &f.reservation.Session.BeforePublic, f.entries, nil)
			graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
			if err != nil {
				t.Fatal(err)
			}
			f.reservation.Plan.LiveSourceUses = slices.Clone(graph.SourceUses)
			f.reservation.Accepted = map[contract.ID]contract.SealedInputCore{contract.Hash(source): envelope.Core}
			r := newConsumerRuntime(t, f.base.route)
			err = r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline)
			shapeEligible := condition == "repeat" || condition == "exclusion" || condition == "unequal" || condition == "damaged"
			if !shapeEligible {
				if err != ErrAdmission || f.base.route.privateCalls != 0 {
					t.Fatal("ineligible original sealed source reached private work", err)
				}
				return
			}
			if err != nil {
				t.Fatal("equal-only original sealed source refused", err)
			}
			a := r.generated
			if len(a.purpose.reservation.plan.sources) != 1 {
				t.Fatal("original source inventory differs")
			}
			admitted := &a.purpose.reservation.plan.sources[0]
			admitted.buffer = bytes.Clone(source)
			code := a.openSource(t.Context(), f.base.route, admitted, &contract.CryptoResponse{})
			want := contract.CryptoSuccess
			switch condition {
			case "unequal":
				want = contract.CryptoInvalidAdmission
			case "damaged":
				want = contract.CryptoSourceAuthenticationFailed
			}
			if code != want {
				t.Fatal("private original-source equality differs", code, want)
			}
		})
	}
}

func generatedOriginalSealedContinuationFixture(t *testing.T, replacement bool) generatedRuntimeFixture {
	t.Helper()
	f := generatedRuntimeEffectFixture(t, false)
	readers := slices.Clone(f.base.q.Intent[0].Recipients)
	plain := []byte("first secret")
	mask := uint8(0)
	if replacement {
		plain, mask = []byte("different secret"), contract.GeneratorValueChangeContent
	}
	current := generatedOriginalSealedCurrent(t, &f, readers, plain)
	source := f.base.q.SealedInputs[0].EnvelopeBytes
	generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "alpha", Recipients: readers, Payload: source},
		contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 1, Name: "alpha", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, EntryIncarnationID: current.Entry.Incarnation, ChangeMask: mask})
	f.reservation.Session.BeforePublic.Rows = append(f.reservation.Session.BeforePublic.Rows, contract.PublicStateRow{Slot: current.Slot, Name: current.Entry.Name, EntryDigest: current.EntryDigest})
	f.entries = append(f.entries, generatedCandidateEntry{Slot: current.Slot, Entry: current.Entry})
	f.reservation.Session.Output = generatedEmptyOutputWitness(t, &f.reservation.Session.BeforePublic, f.entries, nil)
	if !replacement {
		f.reservation.Plan.CurrentValues = []contract.ConsumerSelection{current}
	}
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Plan.LiveSourceUses = slices.Clone(graph.SourceUses)
	f.reservation.Accepted = map[contract.ID]contract.SealedInputCore{contract.Hash(source): f.base.accepted[contract.Hash(source)]}
	return generatedSealedFinalFromPlan(t, f)
}

// full_only: false
func TestGeneratedOriginalSealedContinuationRequiresCurrentEquality(t *testing.T) {
	for _, condition := range []string{"equal", "unequal", "missing-current", "pending-replacement"} {
		t.Run(condition, func(t *testing.T) {
			f := generatedOriginalSealedContinuationFixture(t, condition == "pending-replacement")
			switch condition {
			case "missing-current":
				f.final.Plan.CurrentValues = nil
			case "unequal":
				current := generatedOriginalSealedCurrent(t, &f, f.base.q.Intent[0].Recipients, []byte("different secret"))
				f.final.Plan.CurrentValues = []contract.ConsumerSelection{current}
				public := f.final.Session.BeforePublic
				public.Rows = slices.Clone(public.Rows)
				at := slices.IndexFunc(public.Rows, func(row contract.PublicStateRow) bool { return row.Slot == current.Slot })
				if at < 0 {
					t.Fatal("continuation current row absent")
				}
				public.Rows[at].EntryDigest = current.EntryDigest
				entries := slices.Clone(f.entries)
				at = slices.IndexFunc(entries, func(row generatedCandidateEntry) bool { return row.Slot == current.Slot })
				entries[at].Entry = current.Entry
				f.final.Session.Output = generatedEmptyOutputWitness(t, &public, entries, nil)
				f.final.Session.BeforePublic = public
			}
			r := newConsumerRuntime(t, f.base.route)
			err := r.admitGeneratedFinal(f.compare, f.final, f.base.deadline)
			if condition == "missing-current" {
				if err != ErrAdmission {
					t.Fatal("continuation omitted the exact current equality subject", err)
				}
				return
			}
			if err != nil {
				t.Fatal("exact continuation shape refused before private comparison", err)
			}
			body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
			want := contract.CryptoSuccess
			if condition == "unequal" {
				want = contract.CryptoInvalidAdmission
			}
			if reply.ResultCode != want {
				t.Fatal("continuation did not enforce the accepted current equality obligation", reply.ResultCode, want)
			}
		})
	}
}
