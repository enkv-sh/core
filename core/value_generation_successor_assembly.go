package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) beginGeneratedSuccessor(plan transitionPlan) (StateSession, *Candidate, contract.IdentityPlan) {
	next := *s
	next.cache, next.accessLocations, next.valueReaders = nil, nil, nil
	next.root.Snapshot, next.root.Transition = plan.snapshot, plan.transition
	identity := contract.IdentityPlan{Operation: plan.operation, Transition: plan.transition,
		Snapshot: plan.snapshot, Revision: plan.revision}
	return next, &Candidate{session: s}, identity
}

func (s *StateSession) installGeneratedSuccessorSupport(ctx context.Context, next *StateSession, packed [][]contract.SupportRecord, pageIDs []contract.ID, candidate *Candidate, identity *contract.IdentityPlan) error {
	return s.installGeneratedSuccessorSupportWithBundles(ctx, next, packed, pageIDs, candidate, identity, nil)
}
func (s *StateSession) installGeneratedSuccessorSupportWithBundles(ctx context.Context, next *StateSession, packed [][]contract.SupportRecord, pageIDs []contract.ID, candidate *Candidate, identity *contract.IdentityPlan, bundles []contract.GeneratorPlanBundle) error {
	var materialized generatedRequiredSupportMaterialization
	var err error
	if s.fragmentFacts != nil || s.root.OutputConfiguration.SliceCount != 0 {
		materialized, err = s.materializeGeneratedSupportPages(ctx, packed, pageIDs)
	} else {
		materialized, err = materializeGeneratedRequiredSupport(s.root.Domain, packed, pageIDs)
	}
	if err != nil {
		return err
	}
	next.root.RequiredSupport, next.support = materialized.references, materialized.views
	next.root.RequiredSupportRecordCount, next.root.Generated.Fragments = materialized.recordCount, materialized.fragments
	next.clearSelectedSupportFacts()
	candidate.objects = append(candidate.objects, materialized.objects...)
	identity.Pages = append(identity.Pages, materialized.identityPages...)
	return s.installAdministrativeIndexWithBundles(ctx, next, candidate, bundles)
}

func (s *StateSession) encodeGeneratedSuccessorRoot(next *StateSession, candidate *Candidate,
	revision contract.ID) (format.HeadCore, error) {
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		return format.HeadCore{}, err
	}
	rootRef, err := format.Reference(format.RootKind, s.root.Domain, next.root.Snapshot, 0, rootBody)
	if err != nil {
		return format.HeadCore{}, err
	}
	candidate.objects = append(candidate.objects, objectImage{ref: rootRef, body: rootBody})
	head := s.successorCore(transitionPlan{revision: revision})
	head.Root = rootRef
	return head, nil
}

func (s *StateSession) finalizeGeneratedSuccessor(ctx context.Context, next *StateSession, candidate *Candidate,
	head format.HeadCore, subject contract.GeneratorAuthoritySubject) error {
	candidate.head = format.Head{Core: head, AuthKind: format.GeneratorAuth, Generator: &subject,
		K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = candidate.head
	if err := s.generatedAutomaticCandidatePreserved(next); err != nil {
		return err
	}
	return next.validateGeneratedSelection(ctx, nil)
}
