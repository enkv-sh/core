package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func selectionAcceptanceFixture(t *testing.T) SelectionAcceptance {
	t.Helper()
	request := successionTestRequest(t, 1, 1, 1, false)
	page := Ref{Kind: RecipientKind, Format: CanonicalSchema, Domain: request.DomainID,
		Object: successionTestID(40), Digest: successionTestID(41), Length: recipientPageMinLength}
	recipients, err := RecipientRefsDescriptor(RecipientRefsProjection{DomainID: request.DomainID, Refs: []Ref{page}})
	if err != nil {
		t.Fatal(err)
	}
	accessRecords, err := AccessRecordsDescriptor(request.DomainID, nil)
	if err != nil {
		t.Fatal(err)
	}
	access := CurrentAccessSection{Core: CurrentAccessCore{CurrentControl: request.ProposedAfterControl.CurrentControl,
		RecipientRefsDescriptor: recipients, AccessRecordsDescriptor: accessRecords}}
	access.AccessRoot, err = AccessRoot(access.Core)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SigningBindingDigest(request.ProposedAfterControl.NormalSigning)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []SuccessorEvidenceRow{{TargetRole: SuccessorNormalSigner, EvidenceKind: SuccessorSignerEvidence,
		Trust: SuccessorTrustEvidence{SuccessorSignerFields: SuccessorSignerFields{ProbeAttemptID: successionTestID(42), SigningBindingDigest: digest},
			Signature: []byte{0x30, 6, 2, 1, 1, 2, 1, 1}}}}
	evidenceDigest, err := SuccessorEvidenceDigest(evidence)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := successionSubjectVector()
	subject.ChangeMask, subject.ReplacementCount, subject.SuccessorEvidenceCount, subject.CoverageCount = 1, 1, 1, 0
	subject.AfterAccessRoot, subject.SuccessorEvidenceDigest = access.AccessRoot, evidenceDigest
	core := bytes.Repeat([]byte{0x6b}, 420)
	subject.HeadCoreDigest, subject.HeadCoreLength = Hash(core), uint32(len(core))
	return SelectionAcceptance{HeadCore: core, CurrentAccess: access, AccessRoot: access.AccessRoot,
		Succession: subject, Authorizer: request.BeforeControl.NormalSigning, Evidence: evidence,
		Accepting: request.ProposedAfterControl.NormalSigning, Role: NormalSigningRole,
		Epoch: request.ProposedAfterControl.NormalSigning.Binding.Epoch}
}

// full_only: false
func TestSelectionAcceptanceBindsCompleteSelectionAndPurpose(t *testing.T) {
	v := selectionAcceptanceFixture(t)
	got, err := EncodeSelectionAcceptance(v)
	if err != nil {
		t.Fatal(err)
	}
	access := selectionAcceptanceExpectedAccess(t, v.CurrentAccess)
	subject := selectionAcceptanceExpectedSubject(t, v.Succession)
	authorizer := successionExpectedSigning(v.Authorizer)
	evidence := selectionAcceptanceExpectedEvidence(t, v.Evidence)
	accepting := successionExpectedSigning(v.Accepting)
	want := []byte("ENKV/SELECTION-ACCEPTANCE/v1\x00")
	for _, field := range [][]byte{v.HeadCore, access} {
		want = binary.BigEndian.AppendUint32(want, uint32(len(field)))
		want = append(want, field...)
	}
	want = append(want, v.AccessRoot[:]...)
	for _, field := range [][]byte{subject, authorizer, evidence, accepting} {
		want = binary.BigEndian.AppendUint32(want, uint32(len(field)))
		want = append(want, field...)
	}
	want = append(want, v.Role)
	want = binary.BigEndian.AppendUint64(want, v.Epoch)
	if !bytes.Equal(got, want) {
		t.Fatal("acceptance field order or framing changed")
	}
	q, err := NewSelectionAcceptanceRequest(v)
	if err != nil || q.Purpose() != SelectionAcceptancePurpose || q.Digest() != Hash(want) {
		t.Fatal("acceptance purpose or digest changed", err)
	}
	for name, change := range map[string]func(*SelectionAcceptance){
		"head core":        func(v *SelectionAcceptance) { v.HeadCore[0] ^= 1 },
		"access root":      func(v *SelectionAcceptance) { v.AccessRoot[0] ^= 1 },
		"accepting epoch":  func(v *SelectionAcceptance) { v.Epoch++ },
		"accepting role":   func(v *SelectionAcceptance) { v.Role = RecoverySigningRole },
		"missing evidence": func(v *SelectionAcceptance) { v.Evidence = nil },
		"wrong evidence":   func(v *SelectionAcceptance) { v.Evidence[0].Trust.SigningBindingDigest[0] ^= 1 },
		"wrong authorizer": func(v *SelectionAcceptance) { v.Authorizer.Role = RecoverySigningRole },
	} {
		t.Run(name, func(t *testing.T) {
			bad := selectionAcceptanceFixture(t)
			change(&bad)
			if _, err := NewSelectionAcceptanceRequest(bad); err == nil {
				t.Fatal("inconsistent acceptance admitted")
			}
		})
	}
}

// These test-only bytes use field order and standard big-endian operations;
// they do not call the current-access, subject, binding or evidence encoders.
func selectionAcceptanceExpectedAccess(t *testing.T, v CurrentAccessSection) []byte {
	t.Helper()
	if v.Core.Recovery != nil || len(v.Core.AccessPageRefs) != 0 {
		t.Fatal("independent fixture unexpectedly changed")
	}
	c := v.Core.CurrentControl
	ref := Ref{Kind: RecipientKind, Format: CanonicalSchema, Domain: c.DomainID,
		Object: successionTestID(40), Digest: successionTestID(41), Length: recipientPageMinLength}
	refBytes := append([]byte{byte(ref.Kind)}, 0, byte(ref.Format))
	refBytes = successionExpectedIDs(refBytes, ref.Domain, ref.Object, ref.Digest)
	refBytes = binary.BigEndian.AppendUint32(refBytes, ref.Length)
	refBytes = binary.BigEndian.AppendUint16(refBytes, ref.Index)
	recipientPreimage := successionExpectedIDs([]byte("ENKV/CRYPTO/v2/recipient-refs\x00"), c.DomainID)
	recipientPreimage = binary.BigEndian.AppendUint16(recipientPreimage, 1)
	recipientPreimage = append(recipientPreimage, refBytes...)
	recipient := DescriptorVector{Digest: sha256.Sum256(recipientPreimage), Length: uint64(len(recipientPreimage)), Count: 1}
	recordsPreimage := successionExpectedIDs([]byte("ENKV/CRYPTO/v2/access-records\x00"), c.DomainID)
	recordsPreimage = binary.BigEndian.AppendUint32(recordsPreimage, 0)
	records := DescriptorVector{Digest: sha256.Sum256(recordsPreimage), Length: uint64(len(recordsPreimage))}
	if recipient != v.Core.RecipientRefsDescriptor || records != v.Core.AccessRecordsDescriptor {
		t.Fatal("access descriptors differ from independent preimages")
	}
	descriptor := func(dst []byte, d DescriptorVector) []byte {
		dst = successionExpectedIDs(dst, d.Digest)
		dst = binary.BigEndian.AppendUint64(dst, d.Length)
		return binary.BigEndian.AppendUint32(dst, d.Count)
	}
	core := binary.BigEndian.AppendUint16(nil, c.Schema)
	core = binary.BigEndian.AppendUint16(core, c.Profile)
	core = successionExpectedIDs(core, c.CryptoSupportID, c.CompatibilityID, c.DomainID)
	core = append(core, byte(c.Provider))
	core = successionExpectedIDs(core, c.StoreID, c.CoordinateID, c.NonBodyID, c.TrustInterpretationID,
		c.AuthorityRecipientID, c.AccessIncarnationID)
	core = binary.BigEndian.AppendUint64(core, c.AccessGeneration)
	core = successionExpectedBlob(core, successionExpectedSigning(c.NormalSigning))
	core = append(core, 0) // no recovery binding
	core = descriptor(core, recipient)
	core = binary.BigEndian.AppendUint16(core, 0) // no access-page refs
	core = descriptor(core, records)
	rootPreimage := []byte("ENKV/CRYPTO/v2/current-access\x00")
	rootPreimage = binary.BigEndian.AppendUint32(rootPreimage, uint32(len(core)))
	rootPreimage = append(rootPreimage, core...)
	root := sha256.Sum256(rootPreimage)
	if root != v.AccessRoot {
		t.Fatal("access root differs from independent preimage")
	}
	section := binary.BigEndian.AppendUint32(nil, uint32(len(core)))
	section = append(section, core...)
	return successionExpectedIDs(section, root)
}

func selectionAcceptanceExpectedSubject(t *testing.T, v SuccessionSubject) []byte {
	t.Helper()
	base, _ := successionSubjectVector()
	base.AfterAccessRoot, base.SuccessorEvidenceDigest, base.HeadCoreDigest = v.AfterAccessRoot, v.SuccessorEvidenceDigest, v.HeadCoreDigest
	base.CoverageCount, base.ReplacementCount, base.SuccessorEvidenceCount, base.ChangeMask = v.CoverageCount, v.ReplacementCount, v.SuccessorEvidenceCount, v.ChangeMask
	if base != v {
		t.Fatal("subject fixture extends beyond the independent vector")
	}
	wire := []byte("ENKV/SUCCESSION/v9\x00")
	wire = binary.BigEndian.AppendUint16(wire, 11)
	wire = append(wire, v.OperationKind, v.ApprovalRole)
	for _, id := range []ID{v.OperationID, v.AdmissionID, v.RequestCoreDigest, v.RequestIdentityDigest, v.IdentityPlanDigest,
		v.BeforeControlDigest, v.AfterControlDigest, v.BeforeAccessRoot, v.AfterAccessRoot,
		v.PreservedStateDigest, v.CoverageDigest, v.ReplacementPlanDigest, v.SuccessorEvidenceDigest,
		v.ReceiptDeltaDigest, v.HeadCoreDigest, v.ConditionalPlanDigest} {
		wire = append(wire, id[:]...)
	}
	wire = binary.BigEndian.AppendUint32(wire, v.IdentityPlanLength)
	wire = binary.BigEndian.AppendUint32(wire, v.HeadCoreLength)
	wire = binary.BigEndian.AppendUint32(wire, v.CoverageCount)
	wire = binary.BigEndian.AppendUint16(wire, v.ReplacementCount)
	wire = append(wire, v.SuccessorEvidenceCount, v.ReceiptDeltaCount, v.ChangeMask, v.MaterialSourceRole)
	return wire
}

func selectionAcceptanceExpectedEvidence(t *testing.T, rows []SuccessorEvidenceRow) []byte {
	t.Helper()
	if len(rows) != 1 || rows[0].TargetRole != SuccessorNormalSigner || rows[0].EvidenceKind != SuccessorSignerEvidence {
		t.Fatal("independent evidence fixture unexpectedly changed")
	}
	r := rows[0]
	b := []byte{1, r.TargetRole, r.EvidenceKind}
	b = successionExpectedIDs(b, r.Trust.ProbeAttemptID, r.Trust.SigningBindingDigest)
	b = binary.BigEndian.AppendUint16(b, uint16(len(r.Trust.Signature)))
	return append(b, r.Trust.Signature...)
}
