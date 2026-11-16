package contract

import "bytes"

const selectionAcceptancePrefix = "ENKV/SELECTION-ACCEPTANCE/v1\x00"

// SelectionAcceptance binds one changed current signer to the complete final
// successor selection. The caller supplies the canonical encoded HeadCore.
type SelectionAcceptance struct {
	HeadCore      []byte
	CurrentAccess CurrentAccessSection
	AccessRoot    ID
	Succession    SuccessionSubject
	Authorizer    PublicSigningBinding
	Evidence      []SuccessorEvidenceRow
	Accepting     PublicSigningBinding
	Role          uint8
	Epoch         uint64
}

func EncodeSelectionAcceptance(v SelectionAcceptance) ([]byte, error) {
	if len(v.HeadCore) == 0 || len(v.HeadCore) > MaxHeadLength ||
		v.Succession.HeadCoreLength != uint32(len(v.HeadCore)) || v.Succession.HeadCoreDigest != Hash(v.HeadCore) ||
		v.AccessRoot.IsZero() || v.AccessRoot != v.CurrentAccess.AccessRoot || v.AccessRoot != v.Succession.AfterAccessRoot ||
		v.Role != NormalSigningRole && v.Role != RecoverySigningRole || v.Accepting.Role != v.Role ||
		v.Epoch == 0 || v.Accepting.Binding.Epoch != v.Epoch || v.Authorizer.Role != v.Succession.ApprovalRole {
		return nil, ErrRecord
	}
	selected := v.CurrentAccess.Core.NormalSigning
	target := SuccessorNormalSigner
	if v.Role == RecoverySigningRole {
		if v.CurrentAccess.Core.Recovery == nil {
			return nil, ErrRecord
		}
		selected = v.CurrentAccess.Core.Recovery.Signing
		target = SuccessorRecoverySigner
	}
	accepting, err := EncodePublicSigningBinding(v.Accepting)
	if err != nil {
		return nil, err
	}
	selectedBody, err := EncodePublicSigningBinding(selected)
	if err != nil || !bytes.Equal(accepting, selectedBody) {
		return nil, ErrRecord
	}
	digest, err := SigningBindingDigest(v.Accepting)
	if err != nil {
		return nil, err
	}
	found := false
	for _, row := range v.Evidence {
		if row.TargetRole != target {
			continue
		}
		if row.EvidenceKind != SuccessorSignerEvidence || row.Trust.SigningBindingDigest != digest || found {
			return nil, ErrRecord
		}
		found = true
	}
	if !found {
		return nil, ErrRecord
	}
	access, err := EncodeCurrentAccessSection(v.CurrentAccess)
	if err != nil {
		return nil, err
	}
	subject, err := EncodeSuccessionSubject(v.Succession)
	if err != nil {
		return nil, err
	}
	authorizer, err := EncodePublicSigningBinding(v.Authorizer)
	if err != nil {
		return nil, err
	}
	evidence, err := EncodeSuccessorEvidenceVector(v.Evidence)
	if err != nil {
		return nil, err
	}
	evidenceDigest, err := SuccessorEvidenceDigest(v.Evidence)
	if err != nil || evidenceDigest != v.Succession.SuccessorEvidenceDigest {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, len(selectionAcceptancePrefix)+6*4+len(v.HeadCore)+len(access)+len(subject)+len(authorizer)+len(evidence)+len(accepting)+41)}
	w.raw([]byte(selectionAcceptancePrefix))
	w.blob(v.HeadCore)
	w.blob(access)
	w.id(v.AccessRoot)
	w.blob(subject)
	w.blob(authorizer)
	w.blob(evidence)
	w.blob(accepting)
	w.u8(v.Role)
	w.u64(v.Epoch)
	return w.b, nil
}

func NewSelectionAcceptanceRequest(v SelectionAcceptance) (SignRequest, error) {
	body, err := EncodeSelectionAcceptance(v)
	if err != nil {
		return SignRequest{}, err
	}
	return SignRequest{purpose: SelectionAcceptancePurpose, digest: Hash(body)}, nil
}
