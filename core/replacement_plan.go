package core

import (
	"context"
	"crypto/rand"
	"io"
	"slices"

	"enkv.sh/core/contract"
)

func (s *StateSession) planRecipientReplacement(ctx context.Context, intent contract.RecipientReplacementIntent) (transitionPlan, bool) {
	p := transitionPlan{}
	if err := s.replacementIntentValid(ctx, intent); err != nil {
		return p, false
	}
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return p, false
	}
	used[intent.Successor.BindingID] = true
	if actor := s.installedReplacement; actor != nil {
		for id := range actor.ids {
			used[id] = true
		}
	}
	entropy := s.admission.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	next := func() (contract.ID, bool) {
		var id contract.ID
		_, err := io.ReadFull(entropy, id[:])
		if err != nil || id.IsZero() || used[id] {
			return contract.ID{}, false
		}
		used[id] = true
		if actor := s.installedReplacement; actor != nil {
			actor.ids[id] = true
		}
		return id, true
	}
	for _, out := range []*contract.ID{&p.operation, &p.transition, &p.snapshot, &p.revision} {
		id, ok := next()
		if !ok {
			return transitionPlan{}, false
		}
		*out = id
	}
	for index, page := range s.recipients {
		if page == nil {
			continue
		}
		for _, r := range page.Slots {
			if r != nil && r.RecipientID == intent.RecipientID {
				id, ok := next()
				if !ok {
					return transitionPlan{}, false
				}
				p.recipientPages[index] = id
			}
		}
	}
	for index, page := range s.access {
		if page == nil {
			continue
		}
		required := false
		for _, record := range page.Records {
			required = required || slices.ContainsFunc(record.Wraps, func(w contract.WrapRow) bool { return w.SubjectKind == 1 && w.SubjectID == intent.RecipientID })
		}
		if required {
			id, ok := next()
			if !ok {
				return transitionPlan{}, false
			}
			p.accessPages[index] = id
		}
	}
	indexes, err := s.mutationReceiptPageIndexes(ctx)
	if err != nil {
		return transitionPlan{}, false
	}
	for _, index := range indexes {
		id, ok := next()
		if !ok {
			return transitionPlan{}, false
		}
		p.supportPages[index] = id
	}
	return p, true
}

func (s *StateSession) planSuccession(ctx context.Context, after contract.ControlCore, operation, approval, mask uint8, admission contract.ID, materialSourceRole uint8) (contract.SuccessionRequestCore, transitionPlan, bool) {
	var p transitionPlan
	var q contract.SuccessionRequestCore
	if s == nil || s.prepared || !s.admission.valid(s.store) || admission.IsZero() || s.authority() == nil {
		return q, p, false
	}
	before := currentControlOf(s)
	var used map[contract.ID]bool
	var err error
	if operation == contract.SuccessionReplaceAuthority && mask == contract.SuccessionChangeNormalSigner && approval == contract.RecoverySigningRole {
		used, err = s.closureIDsMode(ctx, true)
	} else {
		used, err = s.closureIDsMode(ctx, false)
	}
	if err != nil {
		return q, p, false
	}
	q = contract.SuccessionRequestCore{SuccessionRequestFields: contract.SuccessionRequestFields{Schema: contract.CanonicalSchema, OperationKind: operation, ApprovalRole: approval, ChangeMask: mask, MaterialSourceRole: materialSourceRole,
		DomainID: s.admission.domain, StoreID: s.admission.store.Identity, CoordinateID: s.admission.store.Coordinate, NonBodyID: s.admission.store.NonBody,
		TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
		AdmissionID: admission, PredecessorHeadRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body), BeforeAccessRoot: s.root.CurrentAccess.AccessRoot},
		Token: s.token, BeforeControl: before, ProposedAfterControl: after, ReplacementPlan: successionRolePlan(before, after, operation, mask)}
	for _, row := range q.ReplacementPlan.Rows {
		id := row.AfterKMS.BindingID
		if row.TargetRole == 1 || row.TargetRole == 3 {
			id = row.AfterSigning.BindingID
		}
		if id.IsZero() || used[id] {
			return contract.SuccessionRequestCore{}, transitionPlan{}, false
		}
		used[id] = true
	}
	if actor := s.installedReplacement; actor != nil {
		for id := range actor.ids {
			used[id] = true
		}
	}
	entropy := s.admission.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	next := func(out *contract.ID) bool {
		_, err := io.ReadFull(entropy, out[:])
		if err != nil || out.IsZero() || used[*out] {
			return false
		}
		used[*out] = true
		if actor := s.installedReplacement; actor != nil {
			actor.ids[*out] = true
		}
		return true
	}
	for _, out := range []*contract.ID{&p.operation, &p.transition, &p.snapshot, &p.revision} {
		if !next(out) {
			return contract.SuccessionRequestCore{}, transitionPlan{}, false
		}
	}
	if mask&2 != 0 {
		for i, page := range s.recipients {
			if page != nil {
				for _, row := range page.Slots {
					if row != nil && row.RecipientID == s.admission.recipient && !next(&p.recipientPages[i]) {
						return contract.SuccessionRequestCore{}, transitionPlan{}, false
					}
				}
			}
		}
	}
	if mask&(2|8) != 0 {
		for i, page := range s.access {
			if page != nil && !next(&p.accessPages[i]) {
				return contract.SuccessionRequestCore{}, transitionPlan{}, false
			}
		}
	}
	if operation != 1 {
		indexes, err := s.mutationReceiptPageIndexes(ctx)
		if err != nil {
			return contract.SuccessionRequestCore{}, transitionPlan{}, false
		}
		for _, index := range indexes {
			if !next(&p.supportPages[index]) {
				return contract.SuccessionRequestCore{}, transitionPlan{}, false
			}
		}
	}
	if !signerOnlyRecovery(q) {
		indexes, err := s.generatedSnapshotPageIndexes()
		if err != nil {
			return contract.SuccessionRequestCore{}, transitionPlan{}, false
		}
		for _, index := range indexes {
			if p.supportPages[index].IsZero() && !next(&p.supportPages[index]) {
				return contract.SuccessionRequestCore{}, transitionPlan{}, false
			}
		}
	}
	q.OperationID = p.operation
	q.IdentityPlan = identityPlan(&Comparison{session: s}, p)
	err = s.successionRequestValid(ctx, q, p)
	return q, p, err == nil
}
