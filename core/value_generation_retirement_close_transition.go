package core

import (
	"bytes"
	"context"
	"fmt"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) generatedRetirementClosePlan(ctx context.Context, attemptID contract.ID,
	admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || attemptID.IsZero() || !s.generatedContextValid(admitted) {
		return nil, fmt.Errorf("retirement close context: %w", contract.ErrRecord)
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, fmt.Errorf("select retirement close: %w", err)
	}
	closure, err := g.generatedRetirementAcknowledgement(ctx, attemptID, s.head.Core.Revision)
	if err != nil {
		return nil, fmt.Errorf("derive retirement close: %w", err)
	}
	bundle, err := g.retainedGraph(closure.attempt.record.OperationID)
	if err != nil {
		return nil, fmt.Errorf("select retirement graph: %w", err)
	}
	target, err := g.retirementAttemptTarget(ctx, bundle, closure.attempt.record)
	if err != nil {
		return nil, fmt.Errorf("select retirement target: %w", err)
	}
	closure.rows, _, _, _, err = s.generatedRetirementReceiptSupport(ctx, g, attemptID, closure.rows, s.head.Core.Revision, nil)
	if err != nil {
		return nil, fmt.Errorf("plan retirement receipt: %w", err)
	}
	groups, err := generatedReservationGroupsForState(s, closure.rows, closure.locations, g.bundles)
	if err != nil {
		return nil, fmt.Errorf("group retirement close: %w", err)
	}
	accessPages, err := generatedLifecycleAccessPageCount(generatedLifecycleAccessRows(s.accessRecords(), append(closure.materials, closure.material)...))
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, generatedNonSupportChildCount(s.root, accessPages), fragments)
	if err != nil {
		return nil, err
	}
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, len(packed), accessPages)
	if err != nil {
		return nil, err
	}
	return &generatedLifecyclePlan{kind: generatedLifecycleRetirementClose, context: admitted, owner: closure.duty.DutyID,
		target: target.ResourceDigest, evidence: contract.Hash(g.attempts[attemptID].result), requestIdentity: request,
		predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token,
		identity: identity, result: bytes.Clone(g.attempts[attemptID].result), source: observationSource{ParentID: closure.attempt.record.OperationID, AttemptID: closure.attempt.record.AttemptID}}, nil
}

// generatedRetirementCloseChange holds the operation's derived successor data.
// It does not grant preparation, signing, persistence or selection rights.
type generatedRetirementCloseChange struct {
	selected                   *generatedSelection
	closure                    generatedRetirementClose
	access                     []contract.AccessRecord
	successes, failures, order contract.GeneratorDescriptor
}

func (s *StateSession) deriveGeneratedRetirementClose(ctx context.Context, plan *generatedLifecyclePlan, detail *changeObservation) (*generatedReservation, error) {
	change, err := s.deriveGeneratedRetirementCloseChange(ctx, plan, detail)
	if err != nil {
		return nil, err
	}
	next, candidate, identity := s.beginGeneratedSuccessor(plan.identity)
	if err := s.materializeGeneratedRetirementClose(ctx, &next, plan, change, candidate, &identity); err != nil {
		return nil, err
	}
	return s.finishGeneratedRetirementClose(ctx, &next, plan, change, candidate, identity)
}

// Derivation reads selected work and receipt evidence before checking the exact
// plan's access and support fit. The packed fit pages are not materialized.
func (s *StateSession) deriveGeneratedRetirementCloseChange(ctx context.Context, plan *generatedLifecyclePlan, detail *changeObservation) (*generatedRetirementCloseChange, error) {
	if plan == nil || plan.kind != generatedLifecycleRetirementClose || len(plan.result) == 0 || contract.Hash(plan.result) != plan.evidence {
		return nil, fmt.Errorf("retirement close plan body: %w", contract.ErrRecord)
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	var attemptID contract.ID
	for id, attempt := range g.attempts {
		if attempt.record.OwnerID == plan.owner && bytes.Equal(attempt.result, plan.result) {
			if !attemptID.IsZero() {
				return nil, contract.ErrRecord
			}
			attemptID = id
		}
	}
	if attemptID.IsZero() {
		return nil, fmt.Errorf("retirement close attempt: %w", contract.ErrRecord)
	}
	closure, err := g.generatedRetirementAcknowledgement(ctx, attemptID, plan.identity.revision)
	if err != nil {
		return nil, fmt.Errorf("retirement close acknowledgement: %w", err)
	}
	if closure.duty.DutyID != plan.owner {
		return nil, fmt.Errorf("retirement close acknowledgement: %w", contract.ErrRecord)
	}
	bundle, err := g.retainedGraph(closure.attempt.record.OperationID)
	if err != nil {
		return nil, err
	}
	target, err := g.retirementAttemptTarget(ctx, bundle, closure.attempt.record)
	if err != nil {
		return nil, fmt.Errorf("retirement close target: %w", err)
	}
	if target.ResourceDigest != plan.target || !bytes.Equal(g.attempts[attemptID].result, plan.result) {
		return nil, fmt.Errorf("retirement close target: %w", contract.ErrRecord)
	}
	access := generatedLifecycleAccessRows(s.accessRecords(), append(closure.materials, closure.material)...)
	accessPages, err := generatedLifecycleAccessPageCount(access)
	if err != nil {
		return nil, err
	}
	var successes, failures, order contract.GeneratorDescriptor
	closure.rows, successes, failures, order, err = s.generatedRetirementReceiptSupport(ctx, g, attemptID, closure.rows, plan.identity.revision, detail)
	if err != nil {
		return nil, fmt.Errorf("derive retirement receipt: %w", err)
	}
	rows, err := rebindSnapshotSliceRecords(closure.rows, s.root.Domain, s.adminIndex.SliceSnapshot, plan.identity.snapshot)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsForState(s, rows, closure.locations, g.bundles)
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, generatedNonSupportChildCount(s.root, accessPages), fragments)
	if err != nil {
		return nil, fmt.Errorf("retirement close packed plan: %w", err)
	}
	if err := s.generatedLifecyclePlanValid(ctx, plan, len(packed), accessPages); err != nil {
		return nil, fmt.Errorf("retirement close packed plan: %w", err)
	}

	return &generatedRetirementCloseChange{selected: g, closure: closure, access: access,
		successes: successes, failures: failures, order: order}, nil
}

// Materialization changes only the local successor. Retiring metadata copies
// its page and entry; unchanged ciphertext and unrelated entries stay borrowed.
// Access and support get new containers. Support materialization reads exact
// predecessor fragments and invalidates the successor's selected support facts.
func (s *StateSession) materializeGeneratedRetirementClose(ctx context.Context, next *StateSession,
	plan *generatedLifecyclePlan, change *generatedRetirementCloseChange,
	candidate *Candidate, identity *contract.IdentityPlan) error {
	next.root.Generated.Slices = change.closure.slices
	next.root.Generated.ActiveOwner, next.root.Generated.ActivePhase, next.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	next.root.Generated.SuccessWindow, next.root.Generated.FailureWindow, next.root.Generated.ReceiptOrder = change.successes, change.failures, change.order
	if !change.closure.nonfinal {
		if err := next.clearGeneratedRetiringPointer(ctx, change.closure.duty.DutyID, plan, candidate, identity); err != nil {
			return fmt.Errorf("retirement close pointer: %w", err)
		}
	}
	if err := next.packGeneratedLifecycleAccess(change.access, plan.identity, candidate, identity); err != nil {
		return fmt.Errorf("retirement close access: %w", err)
	}
	if err := s.installGeneratedLifecycleSupport(ctx, next, change.closure.rows, change.closure.locations, change.selected.bundles, plan, candidate, identity); err != nil {
		return fmt.Errorf("retirement close support: %w", err)
	}
	return nil
}

// Final validation rebuilds the successor's material index, checks relations,
// encodes its root and subject, and checks authority before returning local work.
func (s *StateSession) finishGeneratedRetirementClose(ctx context.Context, next *StateSession,
	plan *generatedLifecyclePlan, change *generatedRetirementCloseChange,
	candidate *Candidate, identity contract.IdentityPlan) (*generatedReservation, error) {
	next.recountChildren()
	if !next.indexSelectedMaterials() || !validAggregate(next.root) {
		return nil, fmt.Errorf("validate retirement-close successor: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("validate retirement-close successor: %w", err)
	}
	head, err := s.encodeGeneratedSuccessorRoot(next, candidate, identity.Revision)
	if err != nil {
		return nil, fmt.Errorf("encode retirement close root: %w", err)
	}
	subject, err := s.generatedRetirementCloseSubject(ctx, next, change.selected, plan, change.closure, identity, head)
	if err != nil {
		return nil, fmt.Errorf("retirement close subject: %w", err)
	}
	if err := s.finalizeGeneratedSuccessor(ctx, next, candidate, head, subject); err != nil {
		return nil, fmt.Errorf("validate retirement-close authority: %w", err)
	}
	return &generatedReservation{state: next, candidate: candidate}, nil
}

func (s *StateSession) generatedRetirementCloseSubject(ctx context.Context, next *StateSession, before *generatedSelection, plan *generatedLifecyclePlan,
	closure generatedRetirementClose, identity contract.IdentityPlan,
	head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	bundle, err := before.retainedGraph(closure.attempt.record.OperationID)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: closure.release.OriginalResultID,
		ResultBodyDigest: plan.evidence, ResultLength: closure.release.ObjectLength}
	evidence, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{reference})
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: plan.requestIdentity, ObservedHEADDigest: plan.predecessorDigest,
		ConditionDigest: plan.context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityRetireClose,
		BeforePhase: 1, AfterPhase: 2, Evidence: contract.GeneratorDescriptor(evidence)}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	x := closure.attempt.expected.Template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityRetireClose,
		DomainID: s.root.Domain, OperationID: plan.identity.operation, RequestIdentityDigest: plan.requestIdentity,
		PlanGraphID: bundle.UsePlan.PlanGraphID, UsePlanDigest: usePlan, PhaseID: phaseID,
		PreviousHEADDigest: plan.predecessorDigest, PreviousRevisionID: plan.predecessorRevision,
		ConditionDigest: plan.context.OriginalConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: closure.duty.DutyID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: x.ResultID, ResultDigest: plan.evidence, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID,
		ResultContractID: x.ResultContractID, Intent: bundle.Request.Declaration, CapacityReservation: closure.duty.CapacityReservation,
		BeforePhase: 1, AfterPhase: 2, ResultVector: contract.GeneratorDescriptor(evidence)}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		return subject, fmt.Errorf("retirement identity: %w", err)
	}
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, generatedEntryUnion(s, next))
	if err != nil {
		return subject, fmt.Errorf("retirement value entries: %w", err)
	}
	membership := s.generatedUnchangedEntryUnion()
	for i := range membership {
		membership[i].After.EntryDigest = contract.ID{}
	}
	subject.RequiredAuthoritySet = generatedMembershipAuthority(membership)
	subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membership)
	if err != nil {
		return subject, fmt.Errorf("retirement membership: %w", err)
	}
	beforeWork, err := s.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	afterWork, err := next.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	subject.BeforeWork, err = s.workSupportDescriptor(beforeWork)
	if err != nil {
		return subject, err
	}
	subject.AfterWork, err = next.workSupportDescriptor(afterWork)
	if err != nil {
		return subject, err
	}
	headBody, err := format.EncodeHeadCore(head)
	if err != nil {
		return subject, err
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head, headBody))
	if err != nil {
		return subject, err
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(headBody), uint32(len(headBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(conditionalBody), uint32(len(conditionalBody))
	_, err = contract.NewGeneratorRequest(subject)
	return subject, err
}
