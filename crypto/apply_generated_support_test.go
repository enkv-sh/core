package crypto

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestNormalGeneratedWitnessPinsMetadataAndDoesNotClearParentBacking(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := applyFixture(t, recovery)
		ref, err := contract.DecodeRef(f.q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
		if err != nil {
			t.Fatal(err)
		}
		fragment := contract.GeneratedFragment{Schema: 1, BlobID: consumerID("immutable parent blob"), Count: 1, TotalLength: 16, WholeDigest: contract.Hash([]byte("parent-owned-row")), Payload: []byte("parent-owned-row")}
		fragment.TotalLength = uint64(len(fragment.Payload))
		body, err := contract.EncodeGeneratedFragment(fragment)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(fragment.BlobID, 0)
		if err != nil {
			t.Fatal(err)
		}
		rows := []contract.SupportRecord{{Kind: 3, RecordID: id, Body: body}}
		fact, err := contract.InspectSupportRecordDigest(f.q.Context.DomainID, rows[0])
		if err != nil {
			t.Fatal(err)
		}
		f.support, err = contract.RequiredSupportDescriptor(f.q.Context.DomainID, rows)
		if err != nil {
			t.Fatal(err)
		}
		recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: f.q.Context.DomainID, Refs: []contract.Ref{{Kind: contract.RecipientKind, Format: contract.CanonicalSchema, Domain: f.q.Context.DomainID, Object: consumerID("recipient page"), Digest: consumerID("recipient page digest"), Length: 1024}}})
		if err != nil {
			t.Fatal(err)
		}
		access, err := contract.AccessRecordsDescriptor(f.q.Context.DomainID, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := &contract.GeneratedSupportTransition{Schema: 1, DomainID: f.q.Context.DomainID, BeforeSnapshot: ref.Object, BeforeSliceSnapshot: ref.Object, BeforeRootDigest: ref.Digest, BeforeSupport: f.support, Records: rows, RecordFacts: []contract.SupportRecordDigest{fact}, BeforeAccess: contract.CurrentAccessCore{CurrentControl: f.control.CurrentControl, RecipientRefsDescriptor: recipients, AccessRecordsDescriptor: access}}
		f.q.Context.CurrentAccessRoot, err = contract.AccessRoot(w.BeforeAccess)
		if err != nil {
			t.Fatal(err)
		}
		r := newConsumerRuntime(t, f.route)
		if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline, w); err != nil {
			t.Fatal(err)
		}
		pinned := r.apply.supportTransition
		want := bytes.Clone(body)
		originalGeneration := pinned.BeforeAccess.AccessGeneration
		originalSlice := pinned.BeforeSliceSnapshot
		w.Records[0].RecordID = consumerID("later caller row metadata")
		w.Groups[0].MaxPages = 257
		w.BeforeAccess.AccessGeneration++
		w.BeforeSliceSnapshot = consumerID("later caller Slice owner")
		if pinned.Records[0].RecordID != id || pinned.Groups[0].MaxPages != 0 || pinned.BeforeAccess.AccessGeneration != originalGeneration || pinned.BeforeSliceSnapshot != originalSlice {
			t.Fatal("private admission retained caller-mutable metadata")
		}
		// Body is already immutable parent backing, not another C-sized image.
		if &pinned.Records[0].Body[0] != &body[0] {
			t.Fatal("private witness duplicated selected backing")
		}
		r.retireApply()
		if !bytes.Equal(body, want) || !bytes.Equal(rows[0].Body, want) {
			t.Fatal("Crypto disposal cleared parent-owned selected body")
		}
		if r.apply != nil || r.slot != nil {
			t.Fatal("private witness owner did not retire")
		}
	}
}

// full_only: false
func TestNormalOutputPredecessorDigestCheckedIndependently(t *testing.T) {
	f := applyFixture(t, false)
	domain := f.q.Context.DomainID
	ref, err := contract.DecodeRef(f.q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain}
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(domain, image)
	if err != nil {
		t.Fatal(err)
	}
	w := &contract.GeneratedSupportTransition{Schema: 1, DomainID: domain, BeforeSnapshot: ref.Object, BeforeSliceSnapshot: ref.Object, BeforeRootDigest: ref.Digest}
	for _, part := range parts {
		body, err := contract.EncodeOutputConfigurationSlice(part)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.OutputConfigurationSliceID(domain, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			t.Fatal(err)
		}
		row := contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body}
		fact, err := contract.InspectSupportRecordDigest(domain, row)
		if err != nil {
			t.Fatal(err)
		}
		w.Records, w.RecordFacts = append(w.Records, row), append(w.RecordFacts, fact)
	}
	w.BeforeSupport, err = contract.RequiredSupportDescriptorFromDigests(domain, w.RecordFacts)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: domain, Refs: []contract.Ref{{Kind: contract.RecipientKind, Format: contract.CanonicalSchema, Domain: domain, Object: consumerID("recipient page"), Digest: consumerID("recipient page digest"), Length: 1024}}})
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.AccessRecordsDescriptor(domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.BeforeAccess = contract.CurrentAccessCore{CurrentControl: f.control.CurrentControl, RecipientRefsDescriptor: recipients, AccessRecordsDescriptor: access}
	f.q.Context.CurrentAccessRoot, err = contract.AccessRoot(w.BeforeAccess)
	if err != nil {
		t.Fatal(err)
	}
	plain := contract.ValueEntry{Name: "plain", Incarnation: consumerID("plain incarnation"), ValueState: consumerID("plain value"), OriginSnapshot: consumerID("plain snapshot"), OriginTransition: consumerID("plain transition"), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.control.AuthorityRecipientID}, ValueBytes: []byte("before"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("before"))), RetainedLength: uint32(len([]byte("before")))}
	digest, err := contract.PublicValueEntryDigest(domain, 3, plain)
	if err != nil {
		t.Fatal(err)
	}
	before := []contract.MembershipRow{{Name: plain.Name, Slot: 3, Incarnation: plain.Incarnation, EntryDigest: digest, Recipients: plain.Recipients}}
	w.Output = &contract.NormalOutputTransition{Before: configuration, BeforeDescriptor: descriptor, EntriesBefore: append([]contract.MembershipRow(nil), before...), Intent: f.q.Intent, Slots: []uint16{0, 1}}
	if err := w.Inspect(); err != nil {
		t.Fatal("valid structural witness", err)
	}
	r := newConsumerRuntime(t, f.route)
	if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, before, w.BeforeSupport, f.deadline, w); err != nil {
		t.Fatal("valid independently checked predecessor", err)
	}
	r.retireApply()
	w.Output.EntriesBefore[0].EntryDigest[0] ^= 1
	if err := w.Inspect(); err != nil {
		t.Fatal("tamper stopped before independent Crypto check", err)
	}
	r = newConsumerRuntime(t, f.route)
	if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, before, w.BeforeSupport, f.deadline, w); err != ErrAdmission {
		t.Fatal("false predecessor digest admitted", err)
	}
	if r.apply != nil || r.slot != nil || f.route.privateCalls != 0 {
		t.Fatal("tampered predecessor reached private work")
	}
}
