package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedInboxReleaseClosure struct {
	released  generatedReleasedAttempt
	bundle    contract.GeneratorPlanBundle
	rows      []contract.SupportRecord
	locations []contract.GeneratorSliceLocation
	bundles   []contract.GeneratorPlanBundle
	slices    contract.GeneratorDescriptor
}

func (s *StateSession) generatedInboxReleasePlan(ctx context.Context, inboxID contract.ID,
	admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || ctx == nil || inboxID.IsZero() || !s.generatedContextValid(admitted) {
		return nil, fmt.Errorf("admit inbox release: %w", contract.ErrRecord)
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	clean, err := g.generatedInboxReleaseClosure(inboxID)
	if err != nil {
		return nil, fmt.Errorf("derive clean inbox release: %w", err)
	}
	unknown, err := g.generatedInboxReleaseUnknownClosure(inboxID)
	if err != nil {
		return nil, fmt.Errorf("derive unknown inbox release: %w", err)
	}
	cleanPlan, err := s.generatedInboxReleaseClosurePlan(ctx, clean, generatedLifecycleInboxRelease, admitted)
	if err != nil {
		return nil, err
	}
	unknownPlan, err := s.generatedInboxReleaseClosurePlan(ctx, unknown, generatedLifecycleInboxReleaseUnknown, admitted)
	if err != nil {
		return nil, err
	}
	// Qualify both possible selected closures before the physical object can
	// disappear. A provider outcome cannot repair missing release provenance.
	if _, err := s.deriveGeneratedInboxRelease(ctx, cleanPlan); err != nil {
		return nil, fmt.Errorf("qualify clean inbox release before delete: %w", err)
	}
	if _, err := s.deriveGeneratedInboxReleaseUnknown(ctx, unknownPlan); err != nil {
		return nil, fmt.Errorf("qualify unknown inbox release before delete: %w", err)
	}
	effectContext, cancel := context.WithDeadline(ctx, time.Unix(0, int64(admitted.Expiry)))
	defer cancel()
	switch s.deleteGeneratedInbox(effectContext, inboxID) {
	case generatedInboxDeleteClean:
		return cleanPlan, nil
	case generatedInboxDeleteUnknown:
		return unknownPlan, nil
	case generatedInboxDeleteInvalidObject:
		return nil, selectedReadFailure(failure(IntegrityFailure, ImmutableConflict))
	case generatedInboxDeleteExpired:
		return nil, fmt.Errorf("inbox release deadline: %w", contract.ErrRecord)
	default:
		return nil, fmt.Errorf("pending inbox release: %w", contract.ErrRecord)
	}
}

func (s *StateSession) generatedInboxReleaseClosurePlan(ctx context.Context, closure generatedInboxReleaseClosure,
	kind generatedLifecycleKind, admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	groups, err := generatedReservationGroupsForState(s, closure.rows, closure.locations, closure.bundles)
	if err != nil {
		return nil, fmt.Errorf("group inbox release rows: %w", err)
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(s.root, len(s.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return nil, fmt.Errorf("pack inbox release rows: %w", err)
	}
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, len(packed), 0)
	if err != nil {
		return nil, fmt.Errorf("inbox-release fresh identity: %w", err)
	}
	r := closure.released.release
	return &generatedLifecyclePlan{kind: kind, context: admitted, owner: r.InboxID,
		target: r.OriginalResultID, evidence: r.SelectedHandoffDigest, requestIdentity: request,
		predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision,
		predecessorToken: s.token, identity: identity,
		source: observationSource{ParentID: closure.released.attempt.OperationID, AttemptID: closure.released.attempt.AttemptID}}, nil
}

func (g *generatedSelection) generatedInboxReleaseUnknownClosure(inboxID contract.ID) (generatedInboxReleaseClosure, error) {
	var out generatedInboxReleaseClosure
	if g == nil || inboxID.IsZero() {
		return out, contract.ErrRecord
	}
	for _, released := range g.releases {
		if released.release.InboxID != inboxID {
			continue
		}
		if !out.released.release.InboxID.IsZero() ||
			(released.release.State != contract.GeneratedReleasePending && released.release.State != contract.GeneratedReleaseUnknown) {
			return out, contract.ErrRecord
		}
		out.released = released
	}
	if out.released.release.InboxID.IsZero() {
		return out, contract.ErrRecord
	}
	var err error
	out.bundle, err = g.retainedGraph(out.released.attempt.OperationID)
	if err != nil {
		return out, err
	}
	out.bundles = slices.Clone(g.bundles)
	out.locations, err = g.session.resolveSelectedGeneratedSlices()
	if err != nil {
		return out, err
	}
	out.slices = g.image.root.Generated.Slices
	out.released.release.State = contract.GeneratedReleaseUnknown
	releaseBody, err := contract.EncodePendingInboxReleaseRecord(out.released.release)
	if err != nil {
		return out, err
	}
	for _, row := range g.image.supportRecords() {
		if row.Kind == contract.PendingInboxReleaseSupportKind && row.RecordID == inboxID {
			row.Body = releaseBody
		}
		out.rows = append(out.rows, row)
	}
	return out, nil
}

func (g *generatedSelection) generatedInboxReleaseClosure(inboxID contract.ID) (generatedInboxReleaseClosure, error) {
	var out generatedInboxReleaseClosure
	if g == nil || g.session == nil || inboxID.IsZero() || g.session.adminIndex.SliceSnapshot.IsZero() {
		return out, contract.ErrRecord
	}
	for _, released := range g.releases {
		if released.release.InboxID != inboxID {
			continue
		}
		if !out.released.release.InboxID.IsZero() {
			return out, contract.ErrRecord
		}
		out.released = released
	}
	if out.released.release.InboxID.IsZero() {
		return out, contract.ErrRecord
	}
	var err error
	out.bundle, err = g.retainedGraph(out.released.attempt.OperationID)
	if err != nil {
		return out, err
	}
	rows := make([]contract.SupportRecord, 0, len(g.records))
	for _, row := range g.image.supportRecords() {
		remove := row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == out.released.attempt.AttemptID ||
			row.Kind == contract.PendingInboxReleaseSupportKind && row.RecordID == inboxID
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, inspectErr := contract.InspectGeneratorVectorCarrier(row.Body)
			if inspectErr != nil {
				return out, inspectErr
			}
			remove = remove || carrier.VectorKind == contract.GeneratorVectorSlices ||
				carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == out.released.attempt.AttemptID
		}
		if !remove {
			rows = append(rows, row)
		}
	}

	needed := make(map[contract.ID]bool)
	if g.parent != nil {
		needed[g.parent.OperationID] = true
	}
	remainingInboxes := make(map[contract.ID]contract.ID)
	for _, row := range rows {
		switch row.Kind {
		case contract.GeneratedAttemptSupportKind:
			a, inspectErr := contract.InspectGeneratedAttemptRecord(row.Body)
			if inspectErr != nil {
				return out, inspectErr
			}
			remainingInboxes[a.InboxID] = a.OperationID
			needed[a.OperationID] = true
			var progress [][]byte
			if a.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				if a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
					return out, contract.ErrRecord
				}
			} else {
				progress, inspectErr = g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorProgress, a.Progress)
				if inspectErr != nil {
					return out, inspectErr
				}
			}
			for _, body := range progress {
				p, inspectErr := contract.InspectGeneratorProgress(body)
				if inspectErr != nil {
					return out, inspectErr
				}
				found := false
				for _, bundle := range g.bundles {
					if _, _, present := generatedTemplate(bundle, p.AttemptID); present {
						if found {
							return out, contract.ErrRecord
						}
						needed[bundle.Header.OperationID], found = true, true
					}
				}
				if !found {
					return out, contract.ErrRecord
				}
			}
		case contract.GeneratedDutySupportKind:
			d, inspectErr := contract.InspectGeneratedDutyRecord(row.Body)
			if inspectErr != nil {
				return out, inspectErr
			}
			needed[d.OriginalOperationID] = true
		case contract.GeneratedHazardSupportKind:
			h, inspectErr := contract.InspectGeneratedHazardRecord(row.Body)
			if inspectErr != nil {
				return out, inspectErr
			}
			needed[h.OriginalOperationID] = true
		}
	}
	for _, row := range rows {
		if row.Kind != contract.PendingInboxReleaseSupportKind {
			continue
		}
		r, inspectErr := contract.InspectPendingInboxReleaseRecord(row.Body)
		if inspectErr != nil || remainingInboxes[r.InboxID].IsZero() {
			return out, contract.ErrRecord
		}
		needed[remainingInboxes[r.InboxID]] = true
	}
	for _, bundle := range g.bundles {
		if needed[bundle.Header.OperationID] {
			out.bundles = append(out.bundles, bundle)
		}
	}
	locations, err := g.session.resolveSelectedGeneratedSlices()
	if err != nil {
		return out, err
	}
	usedBlobs := make(map[contract.ID]bool)
	for _, location := range locations {
		keep := true
		if location.ContentKind == contract.GeneratorContentGraph {
			bundle, inspectErr := g.content.graph(location.ContentID)
			if inspectErr != nil {
				return out, inspectErr
			}
			keep = needed[bundle.Header.OperationID]
		}
		if keep {
			out.locations = append(out.locations, location)
			usedBlobs[location.BlobID] = true
		}
	}
	receiptIndex, err := g.session.receiptIndexID()
	if err != nil {
		return out, err
	}
	if !receiptIndex.IsZero() {
		usedBlobs[receiptIndex] = true
	}
	fragmentFacts, err := g.session.selectedFragmentFactsByRecord()
	if err != nil {
		return out, err
	}
	filtered := rows[:0]
	for _, row := range rows {
		if row.Kind == contract.GeneratedFragmentSupportKind {
			var blob contract.ID
			if row.Body == nil {
				fact, ok := fragmentFacts[row.RecordID]
				if !ok {
					return out, contract.ErrRecord
				}
				blob = fact.blob
			} else {
				fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
				if inspectErr != nil {
					return out, inspectErr
				}
				blob = fragment.BlobID
			}
			if !usedBlobs[blob] {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	rows = filtered
	out.locations, err = generatedUniqueLocations(out.locations)
	if err != nil {
		return out, err
	}
	var sliceBodies [][]byte
	for _, location := range out.locations {
		body, encodeErr := contract.EncodeGeneratorSliceLocation(location)
		if encodeErr != nil {
			return out, encodeErr
		}
		sliceBodies = append(sliceBodies, body)
	}
	out.slices, filtered, err = generatedCarrierRows(g.image.root.Domain, contract.GeneratorSnapshotOwner,
		g.session.adminIndex.SliceSnapshot, contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		return out, err
	}
	out.rows = append(rows, filtered...)
	slices.SortFunc(out.rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	return out, nil
}

func (s *StateSession) deriveGeneratedInboxRelease(ctx context.Context, plan *generatedLifecyclePlan) (*generatedReservation, error) {
	if plan == nil || plan.kind != generatedLifecycleInboxRelease || plan.owner.IsZero() || plan.target.IsZero() || plan.evidence.IsZero() {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	// The closure is still selected-source backing. The support installer
	// performs the one old-snapshot -> successor-snapshot carrier rebind.
	closure, err := g.generatedInboxReleaseClosure(plan.owner)
	if err != nil || closure.released.release.OriginalResultID != plan.target ||
		closure.released.release.SelectedHandoffDigest != plan.evidence {
		return nil, fmt.Errorf("inbox-release exact source (closure=%v): %w", err, contract.ErrRecord)
	}
	groups, err := generatedReservationGroupsForState(s, closure.rows, closure.locations, closure.bundles)
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(s.root, len(s.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return nil, fmt.Errorf("inbox-release identity packing: %w", err)
	}
	if err := s.generatedLifecyclePlanValid(ctx, plan, len(packed), 0); err != nil {
		return nil, fmt.Errorf("inbox-release identity packing: %w", err)
	}
	next, candidate, identity := s.beginGeneratedSuccessor(plan.identity)
	next.root.Generated.Slices = closure.slices
	if err := s.installGeneratedLifecycleSupport(ctx, &next, closure.rows, closure.locations, closure.bundles,
		plan, candidate, &identity); err != nil {
		return nil, err
	}
	next.recountChildren()
	if !next.indexSelectedMaterials() {
		return nil, fmt.Errorf("index inbox-release successor: %w", contract.ErrRecord)
	}
	if !validAggregate(next.root) {
		return nil, fmt.Errorf("aggregate inbox-release successor: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("relate inbox-release successor: %w", err)
	}
	head, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
	if err != nil {
		return nil, err
	}
	subject, err := s.generatedInboxReleaseSubject(ctx, &next, g, plan, closure, identity, head)
	if err != nil {
		return nil, fmt.Errorf("inbox-release authority subject: %w", err)
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, fmt.Errorf("validate inbox-release authority: %w", err)
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) deriveGeneratedInboxReleaseUnknown(ctx context.Context, plan *generatedLifecyclePlan) (*generatedReservation, error) {
	if plan == nil || plan.kind != generatedLifecycleInboxReleaseUnknown || plan.owner.IsZero() || plan.target.IsZero() || plan.evidence.IsZero() {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	closure, err := g.generatedInboxReleaseUnknownClosure(plan.owner)
	if err != nil || closure.released.release.OriginalResultID != plan.target ||
		closure.released.release.SelectedHandoffDigest != plan.evidence {
		return nil, contract.ErrRecord
	}
	rows, err := rebindSnapshotSliceRecords(closure.rows, s.root.Domain, s.adminIndex.SliceSnapshot, plan.identity.snapshot)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsForState(s, rows, closure.locations, closure.bundles)
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(s.root, len(s.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return nil, err
	}
	if err := s.generatedLifecyclePlanValid(ctx, plan, len(packed), 0); err != nil {
		return nil, err
	}
	next, candidate, identity := s.beginGeneratedSuccessor(plan.identity)
	next.root.Generated.Slices = closure.slices
	if err := s.installGeneratedLifecycleSupport(ctx, &next, closure.rows, closure.locations, closure.bundles,
		plan, candidate, &identity); err != nil {
		return nil, err
	}
	next.recountChildren()
	if !next.indexSelectedMaterials() || !validAggregate(next.root) {
		return nil, fmt.Errorf("validate unknown inbox-release successor: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("validate unknown inbox-release successor: %w", err)
	}
	head, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
	if err != nil {
		return nil, err
	}
	subject, err := s.generatedInboxReleaseSubject(ctx, &next, g, plan, closure, identity, head)
	if err != nil {
		return nil, err
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, fmt.Errorf("validate unknown inbox-release authority: %w", err)
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedInboxReleaseSubject(ctx context.Context, next *StateSession, before *generatedSelection, plan *generatedLifecyclePlan,
	closure generatedInboxReleaseClosure, identity contract.IdentityPlan, head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	usePlan, err := contract.GeneratorUsePlanDigest(closure.bundle.UsePlan)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	r := closure.released.release
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: r.OriginalResultID,
		ResultBodyDigest: r.SelectedHandoffDigest, ResultLength: r.ObjectLength}
	evidence, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{reference})
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: plan.requestIdentity, ObservedHEADDigest: plan.predecessorDigest,
		ConditionDigest: plan.context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityInboxRelease,
		BeforePhase: 1, AfterPhase: 2, Evidence: contract.GeneratorDescriptor(evidence)}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	x := closure.released.template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityInboxRelease,
		DomainID: s.root.Domain, OperationID: plan.identity.operation, RequestIdentityDigest: plan.requestIdentity,
		PlanGraphID: closure.bundle.UsePlan.PlanGraphID, UsePlanDigest: usePlan, PhaseID: phaseID,
		PreviousHEADDigest: plan.predecessorDigest, PreviousRevisionID: plan.predecessorRevision,
		ConditionDigest: plan.context.OriginalConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: r.InboxID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: r.OriginalResultID, ResultDigest: r.SelectedHandoffDigest, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID,
		ResultContractID: x.ResultContractID, Intent: closure.bundle.Request.Declaration, CapacityReservation: r.CapacityReservation,
		BeforePhase: 1, AfterPhase: 2, ResultVector: contract.GeneratorDescriptor(evidence)}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		return subject, err
	}
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, s.generatedUnchangedEntryUnion())
	if err != nil {
		return subject, err
	}
	membership := s.generatedUnchangedEntryUnion()
	for i := range membership {
		membership[i].After.EntryDigest = contract.ID{}
	}
	subject.RequiredAuthoritySet = generatedMembershipAuthority(membership)
	subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membership)
	if err != nil {
		return subject, err
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

func (s *selectedGeneratedProof) validGeneratedInboxReleaseSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	if g == nil || subject.Purpose != contract.GeneratorAuthorityInboxRelease || subject.BeforePhase != 1 || subject.AfterPhase != 2 ||
		subject.BeforeAccessDigest != subject.AfterAccessDigest || subject.AfterAccessDigest != s.root.CurrentAccess.AccessRoot ||
		subject.ResultDigest.IsZero() || !subject.CapacityReservation.Valid() {
		return false
	}
	var retained *generatedReleasedAttempt
	for _, released := range g.releases {
		if released.release.InboxID != subject.OwnerID && released.attempt.AttemptID != subject.AttemptID {
			continue
		}
		retainedAttempt := released
		if retained != nil || released.release.InboxID != subject.OwnerID || released.attempt.AttemptID != subject.AttemptID ||
			released.release.OriginalResultID != subject.ResultID || released.release.SelectedHandoffDigest != subject.ResultDigest ||
			released.release.CapacityReservation != subject.CapacityReservation || released.release.State != contract.GeneratedReleaseUnknown ||
			released.template.LineageID != subject.LineageID || released.template.PredecessorAttemptID != subject.PredecessorAttemptID ||
			released.template.ConfigContractID != subject.ConfigContractID || released.template.DescriptorID != subject.DescriptorID ||
			released.template.ResultContractID != subject.ResultContractID {
			return false
		}
		retained = &retainedAttempt
	}
	if retained == nil {
		if _, present := g.records[generatedRecordKey{kind: contract.GeneratedAttemptSupportKind, id: subject.AttemptID}]; present {
			return false
		}
	} else {
		bundle, err := g.retainedGraph(retained.attempt.OperationID)
		if err != nil || bundle.Request.Declaration != subject.Intent || bundle.UsePlan.PlanGraphID != subject.PlanGraphID {
			return false
		}
		usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
		if err != nil || usePlan != subject.UsePlanDigest {
			return false
		}
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest,
		TransitionKind: subject.Purpose, BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: subject.ResultVector})
	if err != nil || phase != subject.PhaseID || subject.ResultVector.Count != 1 {
		return false
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: s.root.Snapshot,
		Transition: s.root.Transition, Revision: s.head.Core.Revision}
	for _, ref := range s.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil || descriptor != subject.IdentityPlan {
		return false
	}
	entryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, s.generatedUnchangedEntryUnion())
	if err != nil || entryUnion != subject.ValueEntryUnion {
		return false
	}
	membership := s.generatedUnchangedEntryUnion()
	for i := range membership {
		membership[i].After.EntryDigest = contract.ID{}
	}
	planned, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membership)
	return err == nil && planned == subject.MembershipChanges && generatedMembershipAuthority(membership) == subject.RequiredAuthoritySet
}
