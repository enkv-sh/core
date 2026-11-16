package core

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// AdmittedSuccession is issued by the enclosing private admission boundary
// after it admits the complete request and each exact required capability.
type AdmittedSuccession struct {
	observation *operationObservation
	session     *StateSession
	goal        *admittedAuthorityGoal
	request     contract.SuccessionRequestCore
	plan        transitionPlan
	descriptor  contract.DescriptorVector
	context     contract.ApplyContext
	source      contract.BindingTableRow
	probe       contract.SuccessorKEKProbeCore
	crypto      contract.Crypto
	instance    contract.ID
	deadline    time.Time
	used        bool
}

// SuccessionSigners supplies only the explicitly requested private routes.
// Each proof is checked against its exact independently admitted public binding.
type SuccessionSigners struct {
	Authorizer        contract.Trust
	NormalSuccessor   contract.QualifyingTrust
	RecoverySuccessor contract.QualifyingTrust
}

type successionPreparation struct {
	request                      contract.DescriptorVector
	qualified, claimed, readback bool
	frozen, requiresCrypto       bool
	basis                        *qualifiedCurrentBasis
	selectionAdmission           *openAdmission
}

func signerOnlyRecovery(q contract.SuccessionRequestCore) bool {
	return q.OperationKind == contract.SuccessionReplaceAuthority &&
		q.ChangeMask == contract.SuccessionChangeNormalSigner &&
		q.ApprovalRole == contract.RecoverySigningRole
}

func successionRolePlan(before, after contract.ControlCore, operation, mask uint8) contract.SuccessionReplacementPlanCore {
	p := contract.SuccessionReplacementPlanCore{SuccessionReplacementPlanFields: contract.SuccessionReplacementPlanFields{Schema: contract.CanonicalSchema, DomainID: before.DomainID, OperationKind: operation, ChangeMask: mask}}
	if mask&contract.SuccessionChangeNormalSigner != 0 {
		p.Rows = append(p.Rows, contract.SuccessionReplacementRow{TargetRole: contract.SuccessorNormalSigner, BeforeSigning: before.NormalSigning, AfterSigning: after.NormalSigning})
	}
	if mask&contract.SuccessionChangeAuthorityKEK != 0 {
		p.Rows = append(p.Rows, contract.SuccessionReplacementRow{TargetRole: contract.SuccessorAuthorityKEK, BeforeKMS: before.AuthorityKMSBinding, AfterKMS: after.AuthorityKMSBinding})
	}
	if mask&contract.SuccessionChangeRecoverySigner != 0 && before.Recovery != nil && after.Recovery != nil {
		p.Rows = append(p.Rows, contract.SuccessionReplacementRow{TargetRole: contract.SuccessorRecoverySigner, BeforeSigning: before.Recovery.Signing, AfterSigning: after.Recovery.Signing})
	}
	if mask&contract.SuccessionChangeRecoveryKEK != 0 && before.Recovery != nil && after.Recovery != nil {
		p.Rows = append(p.Rows, contract.SuccessionReplacementRow{TargetRole: contract.SuccessorRecoveryKEK, BeforeKMS: before.Recovery.KMS, AfterKMS: after.Recovery.KMS})
	}
	return p
}

func (c *Candidate) successionBasisReady(before *StateSession, request contract.DescriptorVector) bool {
	return c != nil && before != nil && c.session == before && c.succession != nil && c.succession.request == request &&
		c.succession.qualified && c.succession.frozen && (!c.succession.requiresCrypto || c.succession.claimed) && c.succession.readback && c.head.AuthKind == format.SuccessionAuth
}

func (c *Candidate) successionSelectionReady() bool {
	if c == nil || c.succession == nil || c.succession.selectionAdmission == nil || c.succession.basis == nil || !c.successionBasisReady(c.session, c.succession.request) {
		return false
	}
	a := c.succession.selectionAdmission
	b := c.succession.basis
	before := c.session.admission
	if a.domain != before.domain || a.store != before.store || a.recipient != before.recipient || a.composition != before.composition || a.current == nil ||
		!bytes.Equal(a.current.control, b.control) || !bytes.Equal(a.current.selection, b.selection) || len(a.current.enrollment) != len(b.enrollment) {
		return false
	}
	for i, row := range b.enrollment {
		other := a.current.enrollment[i]
		if row.id != other.id || row.status != other.status || row.name != other.name {
			return false
		}

	}
	return true
}

func currentControlOf(s *StateSession) contract.ControlCore {
	return contract.ControlCore{CurrentControl: s.root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *s.authority().CurrentBinding}
}

func sameControl(a, b contract.ControlCore) bool {
	x, err := contract.EncodeControlCore(a)
	if err != nil {
		return false
	}
	y, err := contract.EncodeControlCore(b)
	return err == nil && bytes.Equal(x, y)
}

func (s *StateSession) successionRequestValid(ctx context.Context, q contract.SuccessionRequestCore, p transitionPlan) error {
	if s == nil || s.prepared || !s.admission.valid(s.store) || s.authority() == nil || q.DomainID != s.admission.domain || q.StoreID != s.admission.store.Identity ||
		q.CoordinateID != s.admission.store.Coordinate || q.NonBodyID != s.admission.store.NonBody || !s.successionActorMatches(q) ||
		q.TrustInterpretationID != contract.TrustInterpretationID() || q.CompatibilityID != contract.CompatibilityID() || q.CryptoSupportID != contract.CryptoSupportID() ||
		q.PredecessorHeadRevisionID != s.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(s.body) || q.Token != s.token || q.BeforeAccessRoot != s.root.CurrentAccess.AccessRoot ||
		!sameControl(q.BeforeControl, currentControlOf(s)) {
		return contract.ErrRecord
	}
	if _, err := contract.SuccessionRequestDescriptor(q); err != nil {
		return err
	}
	want, err := contract.EncodeIdentityPlan(identityPlan(&Comparison{session: s}, p))
	if err != nil {
		return err
	}
	actual, err := contract.EncodeIdentityPlan(q.IdentityPlan)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, actual) || q.OperationID != p.operation || len(q.IdentityPlan.Rows) != 0 {
		return contract.ErrRecord
	}
	used, err := s.closureIDsMode(ctx, signerOnlyRecovery(q))
	if err != nil {
		return err
	}
	add := func(id contract.ID) bool {
		if id.IsZero() || used[id] {
			return false
		}
		used[id] = true
		return true
	}
	for _, row := range q.ReplacementPlan.Rows {
		id := row.AfterKMS.BindingID
		if row.TargetRole == 1 || row.TargetRole == 3 {
			id = row.AfterSigning.BindingID
		}
		if !add(id) {
			return contract.ErrRecord
		}
	}
	for _, id := range []contract.ID{p.operation, p.transition, p.snapshot, p.revision} {
		if !add(id) {
			return contract.ErrRecord
		}
	}
	for _, page := range q.IdentityPlan.Pages {
		if !add(page.Object) {
			return contract.ErrRecord
		}
	}
	for _, id := range p.pages {
		if !id.IsZero() {
			return contract.ErrRecord
		}
	}
	if len(p.values) != 0 || len(p.incarnations) != 0 {
		return contract.ErrRecord
	}
	for i, page := range s.recipients {
		required := false
		if q.ChangeMask&contract.SuccessionChangeAuthorityKEK != 0 && page != nil {
			for _, row := range page.Slots {
				required = required || row != nil && row.RecipientID == s.admission.recipient
			}
		}
		if required == p.recipientPages[i].IsZero() {
			return contract.ErrRecord
		}
	}
	for i, page := range s.access {
		if (q.ChangeMask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 && page != nil) == p.accessPages[i].IsZero() {
			return contract.ErrRecord
		}
	}
	var required [contract.MaxChildPages]bool
	if !signerOnlyRecovery(q) {
		snapshotIndexes, err := s.generatedSnapshotPageIndexes()
		if err != nil {
			return err
		}
		for _, i := range snapshotIndexes {
			required[i] = true
		}
	}
	if q.OperationKind != contract.SuccessionReplaceAuthority {
		indexes, err := s.mutationReceiptPageIndexes(ctx)
		if err != nil {
			return err
		}
		for _, i := range indexes {
			required[i] = true
		}
	}
	for i, id := range p.supportPages {
		if required[i] == id.IsZero() {
			return contract.ErrRecord
		}
	}
	return nil
}
