package core

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type installedReplacementActor struct {
	session                               *StateSession
	owner                                 *installedReplacement
	ctx                                   context.Context
	deadline                              time.Time
	target                                ReplacementTarget
	goal                                  RoleReplacementGoal
	admission, recipient, operation       contract.ID
	revision, head, access, requestDigest contract.ID
	root                                  format.Ref
	token                                 contract.Token
	after                                 contract.ControlCore
	mask                                  uint8
	intent                                contract.RecipientReplacementIntent
	source                                contract.BindingTableRow
	plan                                  transitionPlan
	planDescriptor                        contract.DescriptorVector
	ids                                   map[contract.ID]bool
}

func (a *installedReplacementActor) live(s *StateSession) bool {
	if a == nil || s == nil || a.session != s || a.ctx == nil || a.ctx.Err() != nil || !validPrivateDeadline(a.deadline) || a.owner == nil ||
		a.revision != s.head.Core.Revision || a.head != contract.Hash(s.body) || a.root != s.head.Core.Root || a.token != s.token || a.access != s.root.CurrentAccess.AccessRoot || !s.admission.valid(s.store) {
		return false
	}
	a.owner.mu.Lock()
	defer a.owner.mu.Unlock()
	return !a.owner.closed && a.owner.used && a.owner.target == a.target && a.owner.goal == a.goal && a.owner.recipient == a.recipient
}
func (a *installedReplacementActor) matches(s *StateSession, q contract.SuccessionRequestCore) bool {
	if !a.live(s) || a.target == ReplacementTargetRecipient || q.AdmissionID != a.admission || q.ApprovalRole != a.goal.ApprovalRole || q.ChangeMask != a.mask || q.MaterialSourceRole != replacementMaterialRole(a.goal.MaterialSource) || !sameControl(q.ProposedAfterControl, a.after) ||
		a.target == ReplacementTargetAuthority && q.OperationKind != contract.SuccessionReplaceAuthority || a.target == ReplacementTargetRecovery && q.OperationKind != contract.SuccessionReplaceRecoveryBasis ||
		!a.operation.IsZero() && q.OperationID != a.operation {
		return false
	}
	if !a.planDescriptor.Digest.IsZero() {
		descriptor, err := contract.IdentityPlanDescriptor(q.IdentityPlan)
		if err != nil || descriptor != a.planDescriptor {
			return false
		}
	}
	return true
}
func (a *installedReplacementActor) matchesRecipient(s *StateSession, intent contract.RecipientReplacementIntent) bool {
	if !a.live(s) || a.target != ReplacementTargetRecipient || a.goal.ApprovalRole != contract.NormalSigningRole || a.goal.MaterialSource != ReplacementMaterialAuthority || a.recipient != intent.RecipientID {
		return false
	}
	x, err := contract.EncodeRecipientReplacementIntent(a.intent)
	if err != nil {
		return false
	}
	y, err := contract.EncodeRecipientReplacementIntent(intent)
	return err == nil && bytes.Equal(x, y)
}
func (s *StateSession) successionActorMatches(q contract.SuccessionRequestCore) bool {
	if s == nil {
		return false
	}
	if s.installedReplacement != nil {
		return s.installedReplacement.matches(s, q)
	}
	if signerOnlyRecovery(q) {
		return false
	}
	return true
}
func (a *installedReplacementActor) pinPlan(s *StateSession, p transitionPlan) error {
	descriptor, err := contract.IdentityPlanDescriptor(identityPlan(&Comparison{session: s}, p))
	if err != nil {
		return err
	}
	a.operation, a.plan, a.planDescriptor = p.operation, p, descriptor
	return nil
}

func replacementMaterialRole(source ReplacementMaterialSource) uint8 {
	switch source {
	case ReplacementMaterialAuthority:
		return contract.SuccessionMaterialAuthority
	case ReplacementMaterialRecovery:
		return contract.SuccessionMaterialRecovery
	default:
		return contract.SuccessionMaterialNone
	}
}
