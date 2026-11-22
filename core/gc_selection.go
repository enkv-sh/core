package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type gcPhaseResult struct {
	state                  *StateSession
	result                 Result
	write                  contract.WriteResult
	confirmed, notSelected bool
}

func gcInitialProgress(plan contract.GCPlan) (contract.GCProgress, error) {
	var p contract.GCProgress
	var err error
	p.PlanDigest, err = contract.GCPlanDigest(plan)
	if err != nil {
		return p, err
	}
	p.TargetsDescriptor, err = contract.GCTargetsDescriptor(plan.Targets)
	if err != nil {
		return p, err
	}
	p.RequestIdentity, err = contract.GCPlanRequestIdentity(plan)
	if err != nil {
		return p, err
	}
	p.ObservationDigest, err = contract.GCPlanObservationDigest(plan)
	if err != nil {
		return p, err
	}
	p.Ordinal = 1
	p.RemainingCount = uint16(len(plan.Targets))
	p.Targets = make([]contract.GCTargetProgress, len(plan.Targets))
	for i := range p.Targets {
		p.Targets[i].Disposition = contract.GCTargetPending
	}
	if !p.Valid() {
		return p, contract.ErrRecord
	}
	return p, nil
}

func gcFreshPhaseIdentities(ids transitionPlan, operation contract.ID, targets []contract.GCTarget) bool {
	forbidden := map[contract.ID]bool{operation: true}
	for _, target := range targets {
		forbidden[target.Object.ObjectID] = true
	}
	for _, id := range []contract.ID{ids.operation, ids.transition, ids.snapshot, ids.revision} {
		if id.IsZero() || forbidden[id] {
			return false
		}
	}
	for _, id := range ids.supportPages {
		if !id.IsZero() && forbidden[id] {
			return false
		}
	}
	return true
}

func (s *StateSession) prepareGCPhase(ctx context.Context, plan contract.GCPlan, admission contract.ID, phase contract.GCPhase, after *contract.GCProgress) (*Candidate, Result) {
	if s == nil || ctx == nil || !s.admission.valid(s.store) || !plan.Valid() || len(plan.Targets) == 0 || admission.IsZero() || plan.DomainID != s.root.Domain || plan.StoreDescriptorDigest != administrativeStoreDescriptorDigest(s.admission.store) {
		return nil, refused(AdmissionInvalid)
	}
	var before *contract.GCProgress
	if phase == contract.GCSelect {
		if !s.root.ActiveGC.IsZero() || !s.root.Generated.ActiveOwner.IsZero() || plan.PredecessorToken != s.token || plan.FullHEADDigest != contract.Hash(s.body) || plan.HeadRevisionID != s.head.Core.Revision {
			return nil, refused(InvalidRelation)
		}
		used, err := s.closureIDsMode(ctx, false)
		if err != nil {
			return nil, installedApplyPreparationFailure(err)
		}
		if used[plan.OperationID] {
			return nil, refused(InvalidRelation)
		}
	} else {
		original, p, err := s.selectedGCPlan(plan.OperationID)
		if err != nil {
			return nil, refused(InvalidRelation)
		}
		digest, err := contract.GCPlanDigest(plan)
		if err != nil || digest != p.PlanDigest {
			return nil, refused(InvalidRelation)
		}
		originalDigest, err := contract.GCPlanDigest(original)
		if err != nil || digest != originalDigest {
			return nil, refused(InvalidRelation)
		}
		before = &p
		if phase == contract.GCReacquire {
			if !s.root.ActiveGC.IsZero() || !s.root.Generated.ActiveOwner.IsZero() {
				return nil, refused(InvalidRelation)
			}
		} else if s.root.ActiveGC != plan.OperationID {
			return nil, refused(InvalidRelation)
		}
	}
	if err := validateGCProgressTransition(before, after, phase); err != nil {
		return nil, refused(InvalidRelation)
	}
	ids, _, err := s.freshGeneratedLifecyclePlan(ctx, contract.MaxChildPages, 0)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	if !gcFreshPhaseIdentities(ids, plan.OperationID, plan.Targets) {
		return nil, refused(InvalidRelation)
	}
	next := s.successorState()
	next.root.RequiredSupport = slices.Clone(s.root.RequiredSupport)
	next.support = slices.Clone(s.support)
	next.root.Snapshot, next.root.Transition = ids.snapshot, ids.transition
	next.root.ActiveGC = plan.OperationID
	if phase == contract.GCClose {
		next.root.ActiveGC = contract.ID{}
	}
	c := &Candidate{session: s}
	if phase == contract.GCSelect || phase == contract.GCClose && after == nil {
		if err := s.rewriteGCPlans(&next, c, ids, plan, phase == contract.GCClose); err != nil {
			return nil, installedApplyPreparationFailure(err)
		}
	}
	if err := s.installGCAdministrativeIndex(ctx, &next, c, plan.OperationID, after); err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	if err := s.bindEndWorkSupportFacts(&next, c.objects); err != nil {
		return nil, refused(InvalidRelation)
	}
	beforeCurrent, err := s.gcPreservedCurrent(ctx, plan.OperationID)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	afterCurrent, err := next.gcPreservedCurrent(ctx, plan.OperationID)
	if err != nil || beforeCurrent != afterCurrent {
		return nil, refused(InvalidRelation)
	}
	next.recountChildren()
	root, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, refused(CapacityExceeded)
	}
	ref, err := format.Reference(format.RootKind, s.root.Domain, ids.snapshot, 0, root)
	if err != nil {
		return nil, refused(InvalidReference)
	}
	c.objects = append(c.objects, objectImage{ref: ref, body: root})
	head := s.successorCore(ids)
	head.Root = ref
	core, err := format.EncodeHeadCore(head)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	condition, err := format.EncodeConditionalPlan(conditional(head, core))
	if err != nil {
		return nil, refused(InvalidProof)
	}
	planDigest, err := contract.GCPlanDigest(plan)
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	request, err := contract.GCPlanRequestIdentity(plan)
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	q := contract.GCSubject{DomainID: s.root.Domain, OperationID: plan.OperationID, AdmissionID: admission, RequestIdentity: request, Phase: phase, PredecessorRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body), PredecessorToken: s.token, BeforeOwners: s.root.GCPlans, AfterOwners: next.root.GCPlans, PlanDigest: planDigest, PreservedCurrentDigest: afterCurrent.Digest, PreservedCurrentLength: afterCurrent.Length, HeadCoreDigest: contract.Hash(core), HeadCoreLength: uint32(len(core)), ConditionalPlanDigest: contract.Hash(condition)}
	if before != nil {
		q.BeforeProgressDigest, err = contract.GCProgressDigest(*before)
		if err != nil {
			return nil, refused(InvalidRelation)
		}
	}
	if after != nil {
		q.AfterProgressDigest, err = contract.GCProgressDigest(*after)
		if err != nil {
			return nil, refused(InvalidRelation)
		}
	}
	c.head = format.Head{Core: head, AuthKind: format.GCAuth, GC: &q, K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = c.head
	if !selectedGCSelection(c.head, next.selectedImage()) {
		return nil, refused(InvalidProof)
	}
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	for _, object := range c.objects {
		if used[object.ref.Object] || object.ref.Object == admission {
			return nil, refused(InvalidRelation)
		}
		for _, target := range plan.Targets {
			if object.ref.Object == target.Object.ObjectID {
				return nil, refused(InvalidRelation)
			}
		}
	}
	return c, Result{}
}

// Only GC-only pages are repacked. Mixed pages retain their physical identity
// and sparse selected ordinals when complete close removes the named row.
func (s *StateSession) rewriteGCPlans(next *StateSession, c *Candidate, ids transitionPlan, plan contract.GCPlan, remove bool) error {
	var groups []format.RequiredSupportGroup
	var refs []format.Ref
	var views []format.RequiredSupportPageView
	for i, page := range s.support {
		pure := len(page.Records) != 0 && !slices.ContainsFunc(page.Records, func(r contract.SupportRecordView) bool { return r.Kind != contract.GCPlanSupportKind })
		if pure && !remove {
			for _, row := range page.Records {
				groups = append(groups, format.RequiredSupportGroup{Class: format.GCPlanSupport, Owner: row.RecordID, Records: []contract.SupportRecord{contract.SupportRecord(row)}})
			}
			continue
		}
		if remove {
			page.Records = slices.DeleteFunc(slices.Clone(page.Records), func(r contract.SupportRecordView) bool {
				return r.Kind == contract.GCPlanSupportKind && r.RecordID == plan.OperationID
			})
			if len(page.Records) == 0 {
				continue
			}
		}
		refs = append(refs, s.root.RequiredSupport[i])
		views = append(views, page)
	}
	if !remove {
		body, err := contract.EncodeGCPlan(plan)
		if err != nil {
			return err
		}
		groups = append(groups, format.RequiredSupportGroup{Class: format.GCPlanSupport, Owner: plan.OperationID, Records: []contract.SupportRecord{{Kind: contract.GCPlanSupportKind, RecordID: plan.OperationID, Body: body}}})
		other := s.root.ChildCount - uint32(len(s.root.RequiredSupport)) + uint32(len(refs))
		pages, err := format.PackRequiredSupportRows(s.root.Domain, groups, other)
		if err != nil {
			return contract.ErrRecordCapacity
		}
		used := map[uint16]bool{}
		for _, ref := range refs {
			used[ref.Index] = true
		}
		for _, rows := range pages {
			index := uint16(0)
			for used[index] && index < contract.MaxChildPages {
				index++
			}
			if index >= contract.MaxChildPages {
				return contract.ErrRecordCapacity
			}
			used[index] = true
			page := format.RequiredSupportPage{Domain: s.root.Domain, Object: ids.supportPages[index], Index: index, Records: rows}
			body, err := format.EncodeRequiredSupportPage(page)
			if err != nil {
				return err
			}
			ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, index, body)
			if err != nil {
				return err
			}
			view, err := format.InspectRequiredSupportPage(body)
			if err != nil {
				return err
			}
			refs = append(refs, ref)
			views = append(views, view)
			c.objects = append(c.objects, objectImage{ref: ref, body: body})
		}
	}
	order := make([]int, len(refs))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int { return int(refs[a].Index) - int(refs[b].Index) })
	next.root.RequiredSupport = nil
	next.support = nil
	next.root.RequiredSupportRecordCount = 0
	for _, i := range order {
		next.root.RequiredSupport = append(next.root.RequiredSupport, refs[i])
		next.support = append(next.support, views[i])
		next.root.RequiredSupportRecordCount += uint32(len(views[i].Records))
	}
	return nil
}

func gcCandidateReady(s *StateSession, c *Candidate) bool {
	return s != nil && c != nil && c.session == s && !c.used && c.head.AuthKind == format.GCAuth && c.head.GC != nil && c.firstSend == nil && c.generated == nil && c.publication == nil && c.succession == nil && c.producer == nil && len(c.body) != 0
}

// This selector deliberately has no retransmission loop. Its candidate owns
// one fixed predecessor and one signed physical HEAD image.
func (s *StateSession) selectGCCandidate(ctx context.Context, c *Candidate) gcPhaseResult {
	out := gcPhaseResult{state: s, result: refused(AdmissionInvalid)}
	if ctx == nil || !gcCandidateReady(s, c) || !s.admission.valid(s.store) {
		return out
	}
	if result := s.persistSelectedGrantPages(ctx); result.Outcome != 0 {
		out.result, out.notSelected = result, true
		return out
	}
	c.used = true
	c.objects = nil
	w, _ := gcNormalizeWriteResult(s.storeCompareAndSwap(ctx, s.admission.store.HeadKey, s.token, bytes.Clone(c.body)))
	out.write = w
	if w.Status == contract.WritePrecondition {
		out.result = s.observed(Contention)
		out.result.Reason = StalePrecondition
		out.result.RequestedRevision = c.head.Core.Revision
		return out
	}
	if w.NotSent || w.Status == contract.WriteRefused {
		out.notSelected = w.NotSent
		out.result = refusedStoreWrite(w)
		out.result.RequestedRevision = c.head.Core.Revision
		return out
	}
	if w.Status != contract.WriteAcknowledged && w.Status != contract.WriteUnknown && w.Status != contract.WriteConflict || w.Status == contract.WriteAcknowledged && w.Reason != contract.ReasonNone || w.Status == contract.WriteUnknown && w.Reason != contract.ReasonTransport && w.Reason != contract.ReasonMalformed && w.Reason != contract.ReasonAccess && w.Reason != contract.ReasonConstruction {
		out.state = nil
		out.result = selectionStopped(c.head.Core.Revision, true, contract.ReasonMalformed)
		return out
	}
	episode := &storeEpisode{}
	if w.Status == contract.WriteUnknown && w.Reason == contract.ReasonTransport {
		episode.startFailure(ctx, s.admission.expires)
	}
	if !episode.beginStage(headObservationLimit()) {
		out.result = selectionStopped(c.head.Core.Revision, true, contract.ReasonLimit)
		return out
	}
	observation := context.WithValue(ctx, storeEpisodeKey{}, episode)
	callCtx, cancel := episode.callContext(observation)
	current, result, _ := s.observeSelection(callCtx, s, w.Status == contract.WriteUnknown && w.Reason == contract.ReasonTransport, false)
	cancel()
	result.RequestedRevision = c.head.Core.Revision
	if current != nil && candidateMatches(current, c) && bytes.Equal(current.body, c.body) {
		out.state = current
		out.result = result
		out.confirmed = true
		return out
	}
	out.state = nil
	result.CommitMayHaveOccurred = true
	out.result = result
	if result.Outcome == IntegrityFailure || result.Outcome == RootLossUnsupported || result.Outcome == AdmissionRefused {
		return out
	}
	out.result.Outcome = UnresolvedCommit
	if out.result.Reason == NoReason {
		out.result.Reason = WriteUncertain
	}
	return out
}
