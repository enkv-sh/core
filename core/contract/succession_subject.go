package contract

import "bytes"

const (
	successionSubjectPrefix              = "ENKV/SUCCESSION/v9\x00"
	SuccessionSubjectWireLength          = len(successionSubjectPrefix) + 4 + 16*32 + 3*4 + 2 + 4
	SuccessionAuthorizationPlanMaxLength = 1 + 4 + PublicSigningBindingMaxLength + SuccessionSubjectWireLength
)

// These values name the fixed admitted material route. They do not grant
// decryption power or assert that a private call occurred.
const (
	SuccessionMaterialNone      uint8 = 0
	SuccessionMaterialAuthority uint8 = 1
	SuccessionMaterialRecovery  uint8 = 2
)

func successionMaterialRoleValid(operation, mask, role uint8) bool {
	if role > SuccessionMaterialRecovery {
		return false
	}
	if mask&(SuccessionChangeAuthorityKEK|SuccessionChangeRecoveryKEK) != 0 {
		return role != SuccessionMaterialNone
	}
	// Authority may nominate an unchanged encryption binding while changing its
	// signer. Its declared fixed route remains in the request without custody.
	return role == SuccessionMaterialNone || operation == SuccessionReplaceAuthority && mask == SuccessionChangeNormalSigner
}

// SuccessionSubject fixes the public assertions signed by current K2 or K3.
// Core admits the authorizer and checks the complete selected-state relations.
type SuccessionSubject struct {
	Schema        uint16
	OperationKind uint8
	ApprovalRole  uint8
	OperationID   ID

	AdmissionID             ID
	RequestCoreDigest       ID
	RequestIdentityDigest   ID
	IdentityPlanDigest      ID
	BeforeControlDigest     ID
	AfterControlDigest      ID
	BeforeAccessRoot        ID
	AfterAccessRoot         ID
	PreservedStateDigest    ID
	CoverageDigest          ID
	ReplacementPlanDigest   ID
	SuccessorEvidenceDigest ID
	ReceiptDeltaDigest      ID
	HeadCoreDigest          ID
	ConditionalPlanDigest   ID
	IdentityPlanLength      uint32
	HeadCoreLength          uint32
	CoverageCount           uint32
	ReplacementCount        uint16
	SuccessorEvidenceCount  uint8
	ReceiptDeltaCount       uint8
	ChangeMask              uint8
	MaterialSourceRole      uint8
}

func successionSubjectFieldsValid(s SuccessionSubject) bool {
	if s.Schema != CanonicalSchema || (s.ApprovalRole != NormalSigningRole && s.ApprovalRole != RecoverySigningRole) ||
		!publicIDsValid(s.OperationID, s.AdmissionID, s.RequestCoreDigest, s.IdentityPlanDigest,
			s.BeforeControlDigest, s.AfterControlDigest, s.BeforeAccessRoot, s.AfterAccessRoot, s.PreservedStateDigest,
			s.CoverageDigest, s.ReplacementPlanDigest, s.SuccessorEvidenceDigest, s.ReceiptDeltaDigest) ||
		cryptoIdentityDescriptorError(DescriptorVector{Length: uint64(s.IdentityPlanLength)}) != nil ||
		s.HeadCoreLength < SuccessorHeadCoreMinLength || s.HeadCoreLength > SuccessorHeadCoreMaxLength || s.CoverageCount > AccessMaterialLimit {
		return false
	}
	if !successionMaterialRoleValid(s.OperationKind, s.ChangeMask, s.MaterialSourceRole) {
		return false
	}
	roles, count, err := successionRoles(s.OperationKind, s.ChangeMask)
	if err != nil || s.ReplacementCount != uint16(count) || s.SuccessorEvidenceCount != uint8(count) {
		return false
	}
	receipts := uint8(0)
	if s.OperationKind != SuccessionReplaceAuthority {
		receipts = 1
	}
	if s.ReceiptDeltaCount != receipts {
		return false
	}
	for _, role := range roles[:count] {
		if role == SuccessorAuthorityKEK || role == SuccessorRecoveryKEK {
			return true
		}
	}
	return s.CoverageCount == 0
}

func SuccessionSubjectLength(s SuccessionSubject) (int, error) {
	if !successionSubjectFieldsValid(s) || s.RequestIdentityDigest.IsZero() || s.HeadCoreDigest.IsZero() || s.ConditionalPlanDigest.IsZero() {
		return 0, ErrSubject
	}
	return SuccessionSubjectWireLength, nil
}

func writeSuccessionSubject(w *cryptoWriter, s SuccessionSubject) {
	w.raw([]byte(successionSubjectPrefix))
	w.u16(s.Schema)
	w.u8(s.OperationKind)
	w.u8(s.ApprovalRole)
	for _, id := range []ID{s.OperationID, s.AdmissionID, s.RequestCoreDigest, s.RequestIdentityDigest, s.IdentityPlanDigest,
		s.BeforeControlDigest, s.AfterControlDigest, s.BeforeAccessRoot, s.AfterAccessRoot, s.PreservedStateDigest,
		s.CoverageDigest, s.ReplacementPlanDigest, s.SuccessorEvidenceDigest, s.ReceiptDeltaDigest, s.HeadCoreDigest, s.ConditionalPlanDigest} {
		w.id(id)
	}
	w.u32(s.IdentityPlanLength)
	w.u32(s.HeadCoreLength)
	w.u32(s.CoverageCount)
	w.u16(s.ReplacementCount)
	w.u8(s.SuccessorEvidenceCount)
	w.u8(s.ReceiptDeltaCount)
	w.u8(s.ChangeMask)
	w.u8(s.MaterialSourceRole)
}

func readSuccessionSubject(r *cryptoReader) SuccessionSubject {
	if !bytes.Equal(r.take(len(successionSubjectPrefix)), []byte(successionSubjectPrefix)) {
		r.err = ErrSubject
		return SuccessionSubject{}
	}
	return SuccessionSubject{
		Schema: r.u16(), OperationKind: r.u8(), ApprovalRole: r.u8(),
		OperationID: r.id(), AdmissionID: r.id(), RequestCoreDigest: r.id(), RequestIdentityDigest: r.id(), IdentityPlanDigest: r.id(),
		BeforeControlDigest: r.id(), AfterControlDigest: r.id(), BeforeAccessRoot: r.id(), AfterAccessRoot: r.id(), PreservedStateDigest: r.id(),
		CoverageDigest: r.id(), ReplacementPlanDigest: r.id(), SuccessorEvidenceDigest: r.id(), ReceiptDeltaDigest: r.id(),
		HeadCoreDigest: r.id(), ConditionalPlanDigest: r.id(), IdentityPlanLength: r.u32(), HeadCoreLength: r.u32(),
		CoverageCount: r.u32(), ReplacementCount: r.u16(), SuccessorEvidenceCount: r.u8(), ReceiptDeltaCount: r.u8(), ChangeMask: r.u8(), MaterialSourceRole: r.u8(),
	}
}

func EncodeSuccessionSubject(s SuccessionSubject) ([]byte, error) {
	n, err := SuccessionSubjectLength(s)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeSuccessionSubject(&w, s)
	return w.b, nil
}

func DecodeSuccessionSubject(b []byte) (SuccessionSubject, error) {
	if len(b) != SuccessionSubjectWireLength {
		return SuccessionSubject{}, ErrSubject
	}
	r := cryptoReader{b: b}
	s := readSuccessionSubject(&r)
	if err := r.end(); err != nil {
		return SuccessionSubject{}, err
	}
	if _, err := SuccessionSubjectLength(s); err != nil {
		return SuccessionSubject{}, err
	}
	return s, nil
}

func SuccessionSubjectDigest(s SuccessionSubject) (ID, error) {
	if _, err := SuccessionSubjectLength(s); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeSuccessionSubject(&w, s)
	return w.result(0).Digest, nil
}

func NewK2SuccessionRequest(s SuccessionSubject) (SignRequest, error) {
	if s.ApprovalRole != NormalSigningRole {
		return SignRequest{}, ErrSubject
	}
	digest, err := SuccessionSubjectDigest(s)
	if err != nil {
		return SignRequest{}, err
	}
	return SignRequest{purpose: K2SuccessionPurpose, digest: digest}, nil
}

func NewK3SuccessionRequest(s SuccessionSubject) (SignRequest, error) {
	if s.ApprovalRole != RecoverySigningRole {
		return SignRequest{}, ErrSubject
	}
	digest, err := SuccessionSubjectDigest(s)
	if err != nil {
		return SignRequest{}, err
	}
	return SignRequest{purpose: K3SuccessionPurpose, digest: digest}, nil
}

// SuccessionAuthorizationSubject requires zero RequestIdentityDigest,
// HeadCoreDigest and ConditionalPlanDigest. The fixed material role and all
// other fields remain exact. The final identity is filled only after this
// typed plan enters the graph, so no hash fixed point is introduced.
// This hash-only plan cannot be used as a signing subject.
type SuccessionAuthorizationSubject SuccessionSubject

// SuccessionAuthorizationPlan commits the exact prior authorizer and prepared
// subject. Core independently admits that authorizer before using this plan.
type SuccessionAuthorizationPlan struct {
	Subject    SuccessionAuthorizationSubject
	Authorizer PublicSigningBinding
}

func SuccessionAuthorizationPlanLength(v SuccessionAuthorizationPlan) (int, error) {
	s := SuccessionSubject(v.Subject)
	n, err := PublicSigningBindingLength(v.Authorizer)
	if err != nil {
		return 0, err
	}
	if !successionSubjectFieldsValid(s) || !s.RequestIdentityDigest.IsZero() || !s.HeadCoreDigest.IsZero() || !s.ConditionalPlanDigest.IsZero() || v.Authorizer.Role != s.ApprovalRole {
		return 0, ErrSubject
	}
	return 1 + 4 + n + SuccessionSubjectWireLength, nil
}
func writeSuccessionAuthorizationPlan(w *cryptoWriter, v SuccessionAuthorizationPlan) {
	w.u8(v.Subject.ApprovalRole)
	writePublicSigningBindingBlob(w, v.Authorizer)
	writeSuccessionSubject(w, SuccessionSubject(v.Subject))
}
func EncodeSuccessionAuthorizationPlan(v SuccessionAuthorizationPlan) ([]byte, error) {
	n, err := SuccessionAuthorizationPlanLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeSuccessionAuthorizationPlan(&w, v)
	return w.b, nil
}
func SuccessionAuthorizationPlanDigest(v SuccessionAuthorizationPlan) (ID, error) {
	if _, err := SuccessionAuthorizationPlanLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeSuccessionAuthorizationPlan(&w, v)
	return w.result(0).Digest, nil
}
