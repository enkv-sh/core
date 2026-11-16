package contract

import (
	"bytes"
)

const (
	successionRequestPrefix         = cryptoPurposePrefix + "succession-request-core-v2\x00"
	successionRequestFixedLength    = len(successionRequestPrefix) + 2 + 4 + 12*32 + 4*4
	successionIdentityMaxLength     = identityBaseLength + identityPageLength*MaxChildPages
	SuccessionRequestCoreMaxLength  = successionRequestFixedLength + 5 + maxTokenValue + 2*controlCoreMaxLength + SuccessionReplacementPlanCoreMaxLength + successionIdentityMaxLength
	successionSigningBindingMinimum = publicSigningBindingFixedLength + 1 + 91
	successionControlMinimum        = controlCoreFixedLength + successionSigningBindingMinimum + kmsBindingFixedLength + 1
	successionSingleRequestMinimum  = successionRequestFixedLength + 6 + 2*successionControlMinimum + successionReplacementFixedLength + 9 + 2*successionSigningBindingMinimum + identityBaseLength
	successionPairRequestMinimum    = successionSingleRequestMinimum + 9 + 2*(kmsBindingFixedLength+1)
)

type SuccessionRequestFields struct {
	Schema                                                                              uint16
	OperationKind, ApprovalRole, ChangeMask, MaterialSourceRole                         uint8
	DomainID, StoreID, CoordinateID, NonBodyID, TrustInterpretationID                   ID
	CompatibilityID, CryptoSupportID, AdmissionID                                       ID
	OperationID, PredecessorHeadRevisionID, PredecessorFullHEADDigest, BeforeAccessRoot ID
}

// SuccessionRequestCore fixes the complete request before probes and access
// preparation. Structural success does not admit its claimed predecessor.
type SuccessionRequestCore struct {
	SuccessionRequestFields
	Token                               Token
	BeforeControl, ProposedAfterControl ControlCore
	ReplacementPlan                     SuccessionReplacementPlanCore
	IdentityPlan                        IdentityPlan
}

func (v SuccessionRequestFields) ids() []ID {
	return []ID{v.DomainID, v.StoreID, v.CoordinateID, v.NonBodyID, v.TrustInterpretationID,
		v.CompatibilityID, v.CryptoSupportID, v.AdmissionID,
		v.OperationID, v.PredecessorHeadRevisionID, v.PredecessorFullHEADDigest, v.BeforeAccessRoot}
}

func successionControlBindings(v ControlCore) []ID {
	ids := []ID{v.NormalSigning.BindingID, v.AuthorityKMSBinding.BindingID}
	if v.Recovery != nil {
		ids = append(ids, v.Recovery.Signing.BindingID, v.Recovery.KMS.BindingID)
	}
	return ids
}

func successionControlPairValid(v ControlCore) bool {
	ids := successionControlBindings(v)
	for i, id := range ids {
		for _, prior := range ids[:i] {
			if id == prior {
				return false
			}
		}
	}
	return v.Recovery == nil || v.Recovery.RoleID != v.AuthorityRecipientID &&
		v.NormalSigning.Fingerprint != v.Recovery.Signing.Fingerprint && IndependentKMSBindings(v.AuthorityKMSBinding, v.Recovery.KMS)
}

func successionSigningChange(before, after PublicSigningBinding) bool {
	if before.BindingID == after.BindingID {
		return false
	}
	return before.KeySelector != after.KeySelector && !bytes.Equal(before.SPKI, after.SPKI) && before.Fingerprint != after.Fingerprint &&
		IncarnationCounterStep(before.Binding.ControlIncarnationID, before.Binding.Epoch, after.Binding.ControlIncarnationID, after.Binding.Epoch) && before.Schema == after.Schema &&
		before.Role == after.Role && before.Provider == after.Provider && before.SigningProfile == after.SigningProfile &&
		before.Binding.Domain == after.Binding.Domain && before.Binding.Store == after.Binding.Store &&
		before.Binding.Coordinate == after.Binding.Coordinate && before.Binding.Trust == after.Binding.Trust && before.Binding.Interpretation == after.Binding.Interpretation
}

func successionKMSChange(before, after KMSBinding) bool {
	return before.KeySelector != after.KeySelector && !bytes.Equal(before.SPKI, after.SPKI) && before.Fingerprint != after.Fingerprint &&
		IncarnationCounterStep(before.BindingIncarnationID, before.BindingSerial, after.BindingIncarnationID, after.BindingSerial)
}

func (v SuccessionRequestCore) controlError() error {
	b, a := v.BeforeControl, v.ProposedAfterControl
	if !successionMaterialRoleValid(v.OperationKind, v.ChangeMask, v.MaterialSourceRole) || v.MaterialSourceRole == SuccessionMaterialRecovery && b.Recovery == nil {
		return ErrRecord
	}
	bf, af := b.CurrentControlFields, a.CurrentControlFields
	bf.AccessGeneration, af.AccessGeneration = 0, 0
	bf.AccessIncarnationID, af.AccessIncarnationID = ID{}, ID{}
	if bf != af || bf.DomainID != v.DomainID || bf.Provider != v.Token.Family || bf.StoreID != v.StoreID ||
		bf.CoordinateID != v.CoordinateID || bf.NonBodyID != v.NonBodyID || bf.TrustInterpretationID != v.TrustInterpretationID ||
		bf.CompatibilityID != v.CompatibilityID || bf.CryptoSupportID != v.CryptoSupportID ||
		!IncarnationCounterStep(b.AccessIncarnationID, b.AccessGeneration, a.AccessIncarnationID, a.AccessGeneration) || (b.Recovery == nil) != (a.Recovery == nil) ||
		!successionControlPairValid(b) || !successionControlPairValid(a) {
		return ErrRecord
	}
	if b.Recovery == nil {
		if v.OperationKind != SuccessionReplaceAuthority || v.ApprovalRole != NormalSigningRole {
			return ErrRecord
		}
	} else if b.Recovery.RoleID != a.Recovery.RoleID {
		return ErrRecord
	}
	if v.ChangeMask&SuccessionChangeNormalSigner == 0 && !successionSigningEqual(b.NormalSigning, a.NormalSigning) ||
		v.ChangeMask&SuccessionChangeAuthorityKEK == 0 && !successionKMSEqual(b.AuthorityKMSBinding, a.AuthorityKMSBinding) ||
		b.Recovery != nil && (v.ChangeMask&SuccessionChangeRecoverySigner == 0 && !successionSigningEqual(b.Recovery.Signing, a.Recovery.Signing) ||
			v.ChangeMask&SuccessionChangeRecoveryKEK == 0 && !successionKMSEqual(b.Recovery.KMS, a.Recovery.KMS)) {
		return ErrRecord
	}
	p := v.ReplacementPlan
	if p.Schema != v.Schema || p.DomainID != v.DomainID || p.OperationKind != v.OperationKind || p.ChangeMask != v.ChangeMask {
		return ErrRecord
	}
	beforeIDs := successionControlBindings(b)
	for _, row := range p.Rows {
		var beforeSigning, afterSigning PublicSigningBinding
		var beforeKMS, afterKMS KMSBinding
		switch row.TargetRole {
		case SuccessorNormalSigner:
			beforeSigning, afterSigning = b.NormalSigning, a.NormalSigning
		case SuccessorAuthorityKEK:
			beforeKMS, afterKMS = b.AuthorityKMSBinding, a.AuthorityKMSBinding
		case SuccessorRecoverySigner:
			if b.Recovery == nil {
				return ErrRecord
			}
			beforeSigning, afterSigning = b.Recovery.Signing, a.Recovery.Signing
		case SuccessorRecoveryKEK:
			if b.Recovery == nil {
				return ErrRecord
			}
			beforeKMS, afterKMS = b.Recovery.KMS, a.Recovery.KMS
		default:
			return ErrRecord
		}
		var next ID
		if row.TargetRole == SuccessorNormalSigner || row.TargetRole == SuccessorRecoverySigner {
			if !successionSigningEqual(row.BeforeSigning, beforeSigning) || !successionSigningEqual(row.AfterSigning, afterSigning) ||
				!successionSigningChange(beforeSigning, afterSigning) {
				return ErrRecord
			}
			next = afterSigning.BindingID
		} else {
			if !successionKMSEqual(row.BeforeKMS, beforeKMS) || !successionKMSEqual(row.AfterKMS, afterKMS) ||
				!successionKMSChange(beforeKMS, afterKMS) {
				return ErrRecord
			}
			next = afterKMS.BindingID
		}
		for _, old := range beforeIDs {
			if old == next {
				return ErrRecord
			}
		}
	}
	return nil
}

type successionRequestLengths struct{ before, after, replacement, identity, total int }

func (v SuccessionRequestCore) lengths() (successionRequestLengths, error) {
	var sizes successionRequestLengths
	if len(v.Token.Value) > maxTokenValue || len(v.IdentityPlan.Pages) > MaxChildPages || len(v.IdentityPlan.Rows) > CryptoMaxValueEntries {
		return sizes, ErrRecordCapacity
	}
	if v.Schema != CanonicalSchema || (v.ApprovalRole != NormalSigningRole && v.ApprovalRole != RecoverySigningRole) || !publicIDsValid(v.ids()...) ||
		!v.Token.Valid() || len(v.IdentityPlan.Rows) != 0 || v.IdentityPlan.Operation != v.OperationID {
		return sizes, ErrRecord
	}
	var err error
	if sizes.before, err = ControlCoreLength(v.BeforeControl); err != nil {
		return sizes, err
	}
	if sizes.after, err = ControlCoreLength(v.ProposedAfterControl); err != nil {
		return sizes, err
	}
	if sizes.replacement, err = SuccessionReplacementPlanCoreLength(v.ReplacementPlan); err != nil {
		return sizes, err
	}
	if sizes.identity, err = identityPlanSize(v.IdentityPlan); err != nil {
		return sizes, err
	}
	if err = v.controlError(); err != nil {
		return sizes, err
	}
	sizes.total = successionRequestFixedLength + 5 + len(v.Token.Value) + sizes.before + sizes.after + sizes.replacement + sizes.identity
	if sizes.total > SuccessionRequestCoreMaxLength || sizes.total > 32<<10 {
		return sizes, ErrRecordCapacity
	}
	return sizes, nil
}

func writeSuccessionRequestCore(w *cryptoWriter, v SuccessionRequestCore, sizes successionRequestLengths) {
	w.raw([]byte(successionRequestPrefix))
	w.u16(v.Schema)
	w.u8(v.OperationKind)
	w.u8(v.ApprovalRole)
	w.u8(v.ChangeMask)
	w.u8(v.MaterialSourceRole)
	for _, id := range v.ids() {
		w.id(id)
	}
	writeToken(w, v.Token)
	w.u32(uint32(sizes.before))
	writeControlCore(w, currentControlInputOf(v.BeforeControl.CurrentControl), kmsBindingInput{value: v.BeforeControl.AuthorityKMSBinding})
	w.u32(uint32(sizes.after))
	writeControlCore(w, currentControlInputOf(v.ProposedAfterControl.CurrentControl), kmsBindingInput{value: v.ProposedAfterControl.AuthorityKMSBinding})
	w.u32(uint32(sizes.replacement))
	writeSuccessionReplacementPlanCore(w, v.ReplacementPlan)
	w.u32(uint32(sizes.identity))
	writeIdentityPlan(w, v.IdentityPlan)
}

func SuccessionRequestCoreLength(v SuccessionRequestCore) (int, error) {
	sizes, err := v.lengths()
	return sizes.total, err
}
func EncodeSuccessionRequestCore(v SuccessionRequestCore) ([]byte, error) {
	sizes, err := v.lengths()
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, sizes.total)}
	writeSuccessionRequestCore(&w, v, sizes)
	return w.b, nil
}
func SuccessionRequestDescriptor(v SuccessionRequestCore) (DescriptorVector, error) {
	sizes, err := v.lengths()
	if err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeSuccessionRequestCore(&w, v, sizes)
	return w.result(len(v.ReplacementPlan.Rows)), nil
}

func successionRequestDescriptorError(d DescriptorVector) error {
	if d.Count > 2 || d.Length > uint64(SuccessionRequestCoreMaxLength) {
		return ErrRecordCapacity
	}
	if d.Digest.IsZero() {
		return ErrRecord
	}
	if d.Count == 1 && d.Length >= uint64(successionSingleRequestMinimum) || d.Count == 2 && d.Length >= uint64(successionPairRequestMinimum) {
		return nil
	}
	return ErrRecord
}
