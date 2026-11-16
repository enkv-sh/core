package format

import "enkv.sh/core/contract"

// SuccessionProof carries the public assertions for a current-authorizer
// succession. Structural decoding does not admit the predecessor authorizer.
type SuccessionProof struct {
	Subject     contract.SuccessionSubject
	Authorizer  contract.PublicSigningBinding
	Evidence    []contract.SuccessorEvidenceRow
	Acceptances []SelectionAcceptanceProof
}

// SelectionAcceptanceProof is the successor signer's signature over the final
// selected HEAD core and current-access section. Core verifies its signature.
type SelectionAcceptanceProof struct {
	Role          uint8
	BindingDigest ID
	Epoch         uint64
	Signature     []byte
}

// HeadPlan requires exactly the Root.Digest hole. It cannot encode stored HEAD.
type HeadPlan HeadCore

func EncodeHeadPlan(plan HeadPlan) ([]byte, error) {
	p := HeadCore(plan)
	if p.Form != SuccessorHead || !headCoreFieldsValid(p) {
		return nil, ErrFormat
	}
	root, err := contract.AppendRootRefDigestPlan(nil, contract.RootRefDigestPlan(p.Root), Version)
	if err != nil {
		return nil, ErrFormat
	}
	return encodeHeadCoreFields(p, root)
}

// ConditionalRequestPlan requires exactly the HeadCore digest hole and a
// matching predecessor condition. It cannot encode an executable condition.
type ConditionalRequestPlan ConditionalPlan

func EncodeConditionalRequestPlan(plan ConditionalRequestPlan) ([]byte, error) {
	p := ConditionalPlan(plan)
	if !p.HeadCore.IsZero() || p.Condition.IsAbsent() || !conditionalPlanFieldsValid(p) {
		return nil, ErrFormat
	}
	return encodeConditionalPlanFields(p)
}

func successionHeadRelations(p Head, core []byte) bool {
	if p.Core.Form != SuccessorHead || p.Succession == nil || p.Genesis != nil || p.Subject != (contract.LifecycleSubject{}) ||
		(len(p.K3) != 0 && !signatureValid(p.K3)) {
		return false
	}
	s, a := p.Succession.Subject, p.Succession.Authorizer
	if _, err := contract.SuccessionSubjectLength(s); err != nil {
		return false
	}
	if _, err := contract.PublicSigningBindingLength(a); err != nil {
		return false
	}
	if s.HeadCoreDigest != contract.Hash(core) || s.HeadCoreLength != uint32(len(core)) ||
		a.Role != s.ApprovalRole || a.Provider != p.Core.PreviousToken.Family ||
		a.Binding.Domain != p.Core.Domain || a.Binding.Store != p.Core.Store ||
		a.Binding.Coordinate != p.Core.Coordinate || a.Binding.Interpretation != p.Core.Interpretation ||
		(s.OperationKind != contract.SuccessionReplaceAuthority || s.ApprovalRole == contract.RecoverySigningRole) && len(p.K3) == 0 {
		return false
	}
	rows := p.Succession.Evidence
	digest, err := contract.SuccessorEvidenceDigest(rows)
	if err != nil || digest != s.SuccessorEvidenceDigest || len(rows) != int(s.SuccessorEvidenceCount) {
		return false
	}
	var mask uint8
	for _, row := range rows {
		mask |= 1 << (row.TargetRole - 1)
		if row.EvidenceKind == contract.SuccessorKEKEvidence && row.KEK.Provider != a.Provider {
			return false
		}
	}
	if mask != s.ChangeMask {
		return false
	}
	acceptance := 0
	for _, row := range rows {
		if row.EvidenceKind != contract.SuccessorSignerEvidence {
			continue
		}
		if acceptance >= len(p.Succession.Acceptances) {
			return false
		}
		proof := p.Succession.Acceptances[acceptance]
		role := contract.NormalSigningRole
		if row.TargetRole == contract.SuccessorRecoverySigner {
			role = contract.RecoverySigningRole
		}
		if proof.Role != role || proof.BindingDigest != row.Trust.SigningBindingDigest || proof.Epoch == 0 || !signatureValid(proof.Signature) {
			return false
		}
		acceptance++
	}
	if acceptance != len(p.Succession.Acceptances) || acceptance > 2 {
		return false
	}
	condition, err := contract.MatchHeadCondition(p.Core.PreviousToken)
	if err != nil {
		return false
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: p.Core.PreviousToken.Family, Store: p.Core.Store,
		Coordinate: p.Core.Coordinate, NonBody: p.Core.NonBody, Condition: condition,
		HeadCore: s.HeadCoreDigest, HeadCoreLength: s.HeadCoreLength})
	return err == nil && s.ConditionalPlanDigest == contract.Hash(plan)
}
