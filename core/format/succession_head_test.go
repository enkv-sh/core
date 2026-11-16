package format

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

func successionBlob(dst, value []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}
func successionIDs(dst []byte, ids ...ID) []byte {
	for _, id := range ids {
		dst = append(dst, id[:]...)
	}
	return dst
}

// The expected encodings below follow the fixed field order in spec 007
// sections 3.12, 3.13 and 3.19 using only big-endian primitives and literals.
func successionHeadCoreBytes(h HeadCore) []byte {
	b := successionIDs([]byte{'E', 'N', 'K', 'V', 5, 0, 11, 1}, h.Domain, h.Revision, h.PreviousRevision, h.PreviousDigest)
	b = successionBlob(append(b, byte(h.PreviousToken.Family)), []byte(h.PreviousToken.Value))
	b = append(b, byte(h.Root.Kind), 0, 11)
	b = successionIDs(b, h.Root.Domain, h.Root.Object, h.Root.Digest)
	b = binary.BigEndian.AppendUint32(b, h.Root.Length)
	b = binary.BigEndian.AppendUint16(b, h.Root.Index)
	b = successionIDs(b, h.Store, h.Trust, h.Coordinate, h.NonBody, h.Interpretation)
	b = binary.BigEndian.AppendUint64(b, h.Epoch)
	return binary.BigEndian.AppendUint32(b, h.Unsupported)
}
func successionConditionalBytes(h HeadCore, digest ID, length uint32) []byte {
	b := []byte{'E', 'N', 'K', 'V', 6, 0, 11, byte(h.PreviousToken.Family)}
	method := "PUT"
	if h.PreviousToken.Family == contract.GCP {
		method = "POST"
	}
	b = successionBlob(b, []byte(method))
	b = successionIDs(b, h.Store, h.Coordinate, h.NonBody)
	b = successionBlob(append(b, byte(h.PreviousToken.Family)), []byte(h.PreviousToken.Value))
	b = successionIDs(b, digest)
	return binary.BigEndian.AppendUint32(b, length)
}
func successionAuthorizerBytes(a contract.PublicSigningBinding) []byte {
	b := successionIDs([]byte{0, 11, a.Role, byte(a.Provider), 0, 1}, a.BindingID)
	b = successionBlob(b, []byte(a.KeySelector))
	b = successionBlob(b, a.SPKI)
	b = successionIDs(b, a.Fingerprint)
	s := a.Binding
	bound := successionIDs([]byte("ENKV/K1-BINDING/v2\x00"), s.Domain, s.Coordinate, s.Store, s.Trust, s.PublicKey, s.Interpretation, s.ControlIncarnationID)
	bound = binary.BigEndian.AppendUint64(bound, s.Epoch)
	return successionBlob(b, bound)
}
func successionSubjectBytes(s contract.SuccessionSubject) []byte {
	b := append([]byte("ENKV/SUCCESSION/v9\x00"), 0, 11, s.OperationKind, s.ApprovalRole)
	b = successionIDs(b, s.OperationID, s.AdmissionID, s.RequestCoreDigest, s.RequestIdentityDigest, s.IdentityPlanDigest, s.BeforeControlDigest, s.AfterControlDigest, s.BeforeAccessRoot, s.AfterAccessRoot, s.PreservedStateDigest, s.CoverageDigest, s.ReplacementPlanDigest, s.SuccessorEvidenceDigest, s.ReceiptDeltaDigest, s.HeadCoreDigest, s.ConditionalPlanDigest)
	for _, n := range []uint32{s.IdentityPlanLength, s.HeadCoreLength, s.CoverageCount} {
		b = binary.BigEndian.AppendUint32(b, n)
	}
	b = binary.BigEndian.AppendUint16(b, s.ReplacementCount)
	return append(b, s.SuccessorEvidenceCount, s.ReceiptDeltaCount, s.ChangeMask, s.MaterialSourceRole)
}
func successionWireFixture(t testing.TB) ([]byte, HeadCore, contract.SuccessionSubject, contract.PublicSigningBinding) {
	t.Helper()
	a := currentControlFixture(t).NormalSigning
	h := HeadCore{Form: 1, Domain: a.Binding.Domain, Revision: fid(20), PreviousRevision: fid(21), PreviousDigest: fid(22), PreviousToken: contract.Token{Family: contract.AWS, Value: `"etag"`}, Root: Ref{Kind: RootKind, Format: Version, Domain: a.Binding.Domain, Object: fid(23), Digest: fid(24), Length: 123}, Store: a.Binding.Store, Trust: fid(25), Coordinate: a.Binding.Coordinate, NonBody: fid(26), Interpretation: a.Binding.Interpretation, Epoch: 2}
	core := successionHeadCoreBytes(h)
	if _, err := DecodeHeadCore(core); err != nil {
		t.Fatal("independent HEAD core:", err)
	}
	sig := []byte{0x30, 6, 2, 1, 1, 2, 1, 1}
	evidence := successionIDs([]byte{1, 1, 1}, fid(27), fid(28))
	evidence = append(evidence, 0, 8)
	evidence = append(evidence, sig...)
	s := contract.SuccessionSubject{Schema: contract.CanonicalSchema, OperationKind: 1, ApprovalRole: 1, OperationID: fid(30), AdmissionID: fid(32), RequestCoreDigest: fid(33), RequestIdentityDigest: fid(31), IdentityPlanDigest: fid(34), BeforeControlDigest: fid(35), AfterControlDigest: fid(36), BeforeAccessRoot: fid(37), AfterAccessRoot: fid(38), PreservedStateDigest: fid(39), CoverageDigest: fid(40), ReplacementPlanDigest: fid(41), SuccessorEvidenceDigest: contract.Hash(successionBlob([]byte("ENKV/CRYPTO/v2/successor-evidence-v1\x00"), evidence)), ReceiptDeltaDigest: fid(42), HeadCoreDigest: contract.Hash(core), ConditionalPlanDigest: contract.Hash(successionConditionalBytes(h, contract.Hash(core), uint32(len(core)))), IdentityPlanLength: 162, HeadCoreLength: uint32(len(core)), ReplacementCount: 1, SuccessorEvidenceCount: 1, ChangeMask: 1}
	if _, err := contract.DecodeSuccessionSubject(successionSubjectBytes(s)); err != nil {
		t.Fatal("independent succession subject:", err)
	}
	if _, err := contract.DecodePublicSigningBinding(successionAuthorizerBytes(a)); err != nil {
		t.Fatal("independent authorizer:", err)
	}
	b := successionBlob([]byte{'E', 'N', 'K', 'V', 4, 0, 11}, core)
	b = successionBlob(b, sig)
	b = successionBlob(b, nil)
	b = append(b, 2)
	b = successionBlob(b, successionSubjectBytes(s))
	b = successionBlob(b, successionAuthorizerBytes(a))
	b = successionBlob(b, evidence)
	b = successionBlob(b, sig)
	b = append(b, 1, contract.NormalSigningRole)
	b = successionIDs(b, fid(28))
	b = binary.BigEndian.AppendUint64(b, 2)
	return successionBlob(b, sig), h, s, a
}

// full_only: false
func TestSuccessionHeadDecodesIndependentWire(t *testing.T) {
	wire, core, subject, authorizer := successionWireFixture(t)
	h, err := DecodeHead(wire)
	if err != nil {
		t.Fatal("valid stored succession refused:", err)
	}
	got, err := EncodeHead(h)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("stored succession differs from independent bytes", err)
	}
	if h.AuthKind != SuccessionAuth || h.Core != core || h.Succession == nil || h.Succession.Subject != subject ||
		!reflect.DeepEqual(h.Succession.Authorizer, authorizer) || h.Genesis != nil || h.Subject != (contract.LifecycleSubject{}) {
		t.Fatal("decoded succession fields differ")
	}
	clear(wire)
	owned, err := EncodeHead(h)
	if err != nil || !bytes.Equal(owned, got) {
		t.Fatal("decoded succession borrowed its input", err)
	}
}

func successionHeadFixture(t testing.TB) Head {
	t.Helper()
	wire, _, _, _ := successionWireFixture(t)
	h, err := DecodeHead(wire)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func successionHeadBindings(t testing.TB, h *Head) {
	t.Helper()
	core := successionHeadCoreBytes(h.Core)
	s := &h.Succession.Subject
	s.HeadCoreDigest, s.HeadCoreLength = contract.Hash(core), uint32(len(core))
	s.ConditionalPlanDigest = contract.Hash(successionConditionalBytes(h.Core, s.HeadCoreDigest, s.HeadCoreLength))
	digest, err := contract.SuccessorEvidenceDigest(h.Succession.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	s.SuccessorEvidenceDigest = digest
	h.Succession.Acceptances = nil
	for _, row := range h.Succession.Evidence {
		if row.EvidenceKind != contract.SuccessorSignerEvidence {
			continue
		}
		role := uint8(contract.NormalSigningRole)
		if row.TargetRole == contract.SuccessorRecoverySigner {
			role = contract.RecoverySigningRole
		}
		h.Succession.Acceptances = append(h.Succession.Acceptances, SelectionAcceptanceProof{Role: role,
			BindingDigest: row.Trust.SigningBindingDigest, Epoch: 2, Signature: bytes.Clone(h.K1)})
	}
}

func successionHeadCase(t testing.TB, operation, mask, approval uint8, family contract.Family) Head {
	t.Helper()
	h := successionHeadFixture(t)
	h.K3 = bytes.Clone(h.K1)
	h.Core.PreviousToken.Family = family
	a := &h.Succession.Authorizer
	a.Role, a.Provider = approval, family
	if family == contract.GCP {
		h.Core.PreviousToken.Value = "42"
		a.KeySelector = "projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
	}
	s := &h.Succession.Subject
	s.OperationKind, s.ChangeMask, s.ApprovalRole = operation, mask, approval
	// This synthetic fixture fixes Authority as its material source whenever
	// its requested change includes a KEK; pure signing cases have no source.
	if mask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 {
		s.MaterialSourceRole = contract.SuccessionMaterialAuthority
	}
	if operation != 1 {
		s.ReceiptDeltaCount = 1
	}
	h.Succession.Evidence = nil
	for role := uint8(1); role <= 4; role++ {
		if mask&(1<<(role-1)) == 0 {
			continue
		}
		row := contract.SuccessorEvidenceRow{TargetRole: role}
		if role == 1 || role == 3 {
			row.EvidenceKind = 1
			row.Trust = contract.SuccessorTrustEvidence{SuccessorSignerFields: contract.SuccessorSignerFields{ProbeAttemptID: fid(50 + role), SigningBindingDigest: fid(60 + role)}, Signature: bytes.Clone(h.K1)}
		} else {
			kind := uint8(1)
			if role == 4 {
				kind = 2
			}
			row.EvidenceKind = 2
			row.KEK = contract.QualifiedSuccessorRow{ProbeID: fid(50 + role), QualifiedBindingFields: contract.QualifiedBindingFields{SubjectKind: kind, SubjectID: fid(60 + role), BindingID: fid(70 + role), PublicBindingDigest: fid(80 + role), Provider: family, Qualified: 1}}
		}
		h.Succession.Evidence = append(h.Succession.Evidence, row)
	}
	s.ReplacementCount, s.SuccessorEvidenceCount = uint16(len(h.Succession.Evidence)), uint8(len(h.Succession.Evidence))
	successionHeadBindings(t, &h)
	return h
}

// full_only: false
func TestSuccessionHeadAllRolesAndProviders(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, choice := range [][2]uint8{{1, 1}, {1, 2}, {1, 3}, {3, 4}, {3, 8}, {3, 12}} {
			for _, approval := range []uint8{1, 2} {
				t.Run(fmt.Sprintf("provider%d-operation%d-mask%d-approval%d", family, choice[0], choice[1], approval), func(t *testing.T) {
					h := successionHeadCase(t, choice[0], choice[1], approval, family)
					wire, err := EncodeHead(h)
					if err != nil {
						t.Fatal(err)
					}
					got, err := DecodeHead(wire)
					if err != nil || !reflect.DeepEqual(got, h) {
						t.Fatal("stored succession changed fields", err)
					}
					if len(wire) > 3340 {
						t.Fatal("succession HEAD exceeds its schema bound")
					}
				})
			}
		}
	}
}

// full_only: false
func TestSuccessionHeadRefusesUnequalPublicRelations(t *testing.T) {
	for name, change := range map[string]func(*Head){
		"absent proof":              func(h *Head) { h.Succession = nil },
		"stray genesis":             func(h *Head) { h.Genesis = &GenesisProof{} },
		"stray lifecycle":           func(h *Head) { h.Subject.Operation = fid(99) },
		"retained phase":            func(h *Head) { h.AuthKind = 3 },
		"unknown kind":              func(h *Head) { h.AuthKind = 255 },
		"head digest":               func(h *Head) { h.Succession.Subject.HeadCoreDigest = fid(99) },
		"head length":               func(h *Head) { h.Succession.Subject.HeadCoreLength++ },
		"conditional digest":        func(h *Head) { h.Succession.Subject.ConditionalPlanDigest = fid(99) },
		"evidence digest":           func(h *Head) { h.Succession.Subject.SuccessorEvidenceDigest = fid(99) },
		"evidence count":            func(h *Head) { h.Succession.Subject.SuccessorEvidenceCount = 2 },
		"replacement count":         func(h *Head) { h.Succession.Subject.ReplacementCount = 2 },
		"role mask":                 func(h *Head) { h.Succession.Subject.ChangeMask = 2 },
		"empty evidence":            func(h *Head) { h.Succession.Evidence = nil },
		"extra evidence":            func(h *Head) { h.Succession.Evidence = append(h.Succession.Evidence, h.Succession.Evidence[0]) },
		"evidence kind":             func(h *Head) { h.Succession.Evidence[0].EvidenceKind = 2 },
		"probe proof":               func(h *Head) { h.Succession.Evidence[0].Trust.Signature = []byte{1} },
		"authorizer role":           func(h *Head) { h.Succession.Authorizer.Role = 2; h.K3 = bytes.Clone(h.K1) },
		"authorizer provider":       func(h *Head) { h.Succession.Authorizer.Provider = contract.GCP },
		"authorizer domain":         func(h *Head) { h.Succession.Authorizer.Binding.Domain = fid(99) },
		"authorizer store":          func(h *Head) { h.Succession.Authorizer.Binding.Store = fid(99) },
		"authorizer coordinate":     func(h *Head) { h.Succession.Authorizer.Binding.Coordinate = fid(99) },
		"authorizer interpretation": func(h *Head) { h.Succession.Authorizer.Binding.Interpretation = fid(99) },
		"authorizer key":            func(h *Head) { h.Succession.Authorizer.SPKI = []byte{1} },
		"recovery proof":            func(h *Head) { h.K3 = []byte{1} },
		"authority proof":           func(h *Head) { h.AuthorizationSignature = nil },
		"normal binding proof":      func(h *Head) { h.K1 = nil },
		"missing acceptance":        func(h *Head) { h.Succession.Acceptances = nil },
		"duplicate acceptance": func(h *Head) {
			h.Succession.Acceptances = append(h.Succession.Acceptances, h.Succession.Acceptances[0])
		},
		"acceptance role":    func(h *Head) { h.Succession.Acceptances[0].Role = contract.RecoverySigningRole },
		"acceptance binding": func(h *Head) { h.Succession.Acceptances[0].BindingDigest = fid(99) },
		"acceptance epoch":   func(h *Head) { h.Succession.Acceptances[0].Epoch = 0 },
		"acceptance DER":     func(h *Head) { h.Succession.Acceptances[0].Signature = []byte{1} },
	} {
		t.Run(name, func(t *testing.T) {
			h := successionHeadFixture(t)
			change(&h)
			if _, err := EncodeHead(h); err == nil {
				t.Fatal("invalid succession encoded")
			}
		})
	}
	for _, choice := range [][3]uint8{{1, 1, 2}, {3, 4, 1}, {3, 8, 1}} {
		h := successionHeadCase(t, choice[0], choice[1], choice[2], contract.AWS)
		h.K3 = nil
		if _, err := EncodeHead(h); err == nil {
			t.Fatal("recovery-required succession omitted K3")
		}
	}
	h := successionHeadCase(t, 1, 2, 1, contract.AWS)
	h.Succession.Evidence[0].KEK.Provider = contract.GCP
	successionHeadBindings(t, &h)
	if _, err := EncodeHead(h); err == nil {
		t.Fatal("provider-mismatched KEK evidence encoded")
	}
	h = successionHeadFixture(t)
	h.Succession.Evidence[0].TargetRole = 3
	successionHeadBindings(t, &h)
	if _, err := EncodeHead(h); err == nil {
		t.Fatal("self-consistent evidence digest hid wrong target role")
	}
	h = successionHeadFixture(t)
	recovery := h.Succession.Evidence[0]
	recovery.TargetRole = contract.SuccessorRecoverySigner
	recovery.Trust.ProbeAttemptID, recovery.Trust.SigningBindingDigest = fid(82), fid(83)
	h.Succession.Evidence = append(h.Succession.Evidence, recovery)
	h.Succession.Subject.ChangeMask = 1 | 4
	h.Succession.Subject.ReplacementCount, h.Succession.Subject.SuccessorEvidenceCount = 2, 2
	successionHeadBindings(t, &h)
	if len(h.Succession.Acceptances) != 2 {
		t.Fatal("two-row refusal fixture omitted a signer")
	}
	if _, err := EncodeHead(h); err == nil {
		t.Fatal("two acceptance rows authorized an unsupported succession mask")
	}
	lifecycle := headFixture(t)
	lifecycle.Succession = successionHeadFixture(t).Succession
	if _, err := EncodeHead(lifecycle); err == nil {
		t.Fatal("lifecycle ignored stray succession proof")
	}
}

// full_only: false
func TestSuccessionHeadRefusesMalformedStoredFraming(t *testing.T) {
	wire, _, _, _ := successionWireFixture(t)
	for n := 0; n < len(wire); n++ {
		if _, err := DecodeHead(wire[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	if _, err := DecodeHead(append(bytes.Clone(wire), 0)); err == nil {
		t.Fatal("accepted suffix")
	}
	if _, err := DecodeHead(make([]byte, contract.MaxHeadLength+1)); err == nil {
		t.Fatal("accepted oversized HEAD")
	}
	// The independent fixture has one 8-byte signature: count:u8 followed
	// by Role:u8, Digest:32, Epoch:u64 and B(signature).
	const acceptanceSuffix = 1 + 1 + 32 + 8 + 4 + 8
	badCount := bytes.Clone(wire)
	badCount[len(badCount)-acceptanceSuffix] = 3
	if _, err := DecodeHead(badCount); err == nil {
		t.Fatal("accepted oversized acceptance count")
	}
	badSignature := bytes.Clone(wire)
	binary.BigEndian.PutUint32(badSignature[len(badSignature)-12:], contract.MaxSignature+1)
	if _, err := DecodeHead(badSignature); err == nil {
		t.Fatal("accepted oversized acceptance signature")
	}
	offset := 7
	for i, limit := range []uint32{contract.SuccessorHeadCoreMaxLength, 72, 72, 553, contract.PublicSigningBindingMaxLength, 281, 72} {
		if i == 3 {
			offset++
		}
		length := int(binary.BigEndian.Uint32(wire[offset:]))
		bad := bytes.Clone(wire)
		binary.BigEndian.PutUint32(bad[offset:], limit+1)
		if _, err := DecodeHead(bad); err == nil {
			t.Fatalf("accepted oversized blob %d", i)
		}
		offset += 4 + length
	}
}

// full_only: false
func TestSuccessionAcceptanceMaximumWireSuffix(t *testing.T) {
	wire, _, _, _ := successionWireFixture(t)
	const smallSuffix = 1 + 1 + 32 + 8 + 4 + 8
	prefix := bytes.Clone(wire[:len(wire)-smallSuffix])
	// DER sequence with two positive 256-bit integers, each with its sign byte.
	signature := []byte{0x30, 0x46, 0x02, 0x21, 0}
	signature = append(signature, bytes.Repeat([]byte{0x80}, 32)...)
	signature = append(signature, 0x02, 0x21, 0)
	signature = append(signature, bytes.Repeat([]byte{0x80}, 32)...)
	row := successionIDs([]byte{contract.NormalSigningRole}, fid(28))
	row = binary.BigEndian.AppendUint64(row, 2)
	row = successionBlob(row, signature)
	if len(signature) != 72 || len(row) != 117 {
		t.Fatal("independent acceptance bound differs", len(signature), len(row))
	}
	one := append(append(bytes.Clone(prefix), 1), row...)
	decoded, err := DecodeHead(one)
	if err != nil {
		t.Fatal("maximum single acceptance refused", err)
	}
	if encoded, err := EncodeHead(decoded); err != nil || !bytes.Equal(encoded, one) {
		t.Fatal("maximum acceptance bytes changed", err)
	}
	second := bytes.Clone(row)
	second[0] = contract.RecoverySigningRole
	suffix := append(append([]byte{2}, row...), second...)
	if len(suffix) != 235 {
		t.Fatal("two-row bounded suffix differs", len(suffix))
	}
	// No approved operation changes both signing roles. The format bound must
	// not authorize that operation merely because its two rows fit the suffix.
	if _, err := DecodeHead(append(bytes.Clone(prefix), suffix...)); err == nil {
		t.Fatal("two bounded rows authorized an unsupported operation")
	}
}

// full_only: false
func TestSuccessionHeadRefusesRetiredKind(t *testing.T) {
	for _, approval := range []uint8{1, 2} {
		h := successionHeadCase(t, 3, 4, approval, contract.GCP)
		wire, err := EncodeHead(h)
		if err != nil {
			t.Fatal("supported recovery signer HEAD refused", err)
		}
		if _, err := DecodeHead(wire); err != nil {
			t.Fatal("supported recovery signer HEAD did not decode", err)
		}
		subject := successionSubjectBytes(h.Succession.Subject)
		offset := bytes.Index(wire, subject)
		if offset < 0 || bytes.Count(wire, subject) != 1 {
			t.Fatal("HEAD lacks its one independent subject image")
		}
		// Preserve the full framing and DER signatures; only the retired
		// subject operation byte differs from the supported recovery proof.
		wire[offset+len("ENKV/SUCCESSION/v9\x00")+2] = 2
		if _, err := DecodeHead(wire); err == nil {
			t.Errorf("approval %d: retired HEAD proof kind decoded", approval)
		}
		h.Succession.Subject.OperationKind = 2
		if _, err := EncodeHead(h); err == nil {
			t.Errorf("approval %d: retired HEAD proof kind encoded", approval)
		}
	}
}
