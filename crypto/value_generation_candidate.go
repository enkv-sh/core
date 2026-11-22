package crypto

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedCandidateEntry struct {
	Slot  uint16
	Entry contract.ValueEntry
}

// Core has already checked the selected closure, authority purpose and initial
// request projection. Crypto checks the actual custody and candidate bodies;
// this private binding is neither store authentication nor permission to send.
type generatedCandidate struct {
	retainedCensus                        *generatedFinalRetainedCensus
	ActiveOwner, ActivePhase, ActiveGraph contract.ID
	Subject                               contract.GeneratorAuthoritySubject
	PublicState                           contract.PublicState
	CurrentAccess                         contract.CurrentAccessCore
	AccessRecords                         []contract.AccessRecord
	SupportRecords                        []contract.SupportRecord
	Entries                               []generatedCandidateEntry
	HeadCore, GrantWraps                  []byte
	Conditional                           []byte
	SourceProtections                     []byte
	LiveSourceUses                        []contract.GeneratorSourceUse
	Registry                              *contract.GeneratedCandidateRegistryInput
}

type generatedCandidateFacts struct {
	facts           contract.CryptoGeneratedFreezeRequest
	authorityDigest contract.ID
}

func (r *Runtime) bindGeneratedCandidate(ctx context.Context, id contract.ID, candidate generatedCandidate) contract.CryptoResultCode {
	return r.bindGeneratedCandidateOwned(ctx, id, candidate, nil)
}

func (r *Runtime) bindGeneratedCandidateOwned(ctx context.Context, id contract.ID, candidate generatedCandidate, expected *generatedAdmission) contract.CryptoResultCode {
	if r == nil || ctx == nil {
		return contract.CryptoInvalidAdmission
	}
	callerDone := ctx.Done()
	r.mu.Lock()
	a := r.generated
	if r.closed || a == nil || a.id != id || a.terminal || expected != nil && a != expected {
		r.mu.Unlock()
		return contract.CryptoInvalidAdmission
	}
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		return code
	}
	if a.busy || a.stage != contract.CryptoFreeze || a.candidate != nil {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		return contract.CryptoAlreadyUsed
	}
	a.busy = true
	a.work.Add(1)
	r.mu.Unlock()
	defer a.work.Done()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	facts, ok := a.inspectCandidate(candidate, callerDone)
	r.mu.Lock()
	defer r.mu.Unlock()
	a.busy = false
	code := sessionCancellationObserved(callerDone, a.session)
	if code == contract.CryptoSuccess && !ok {
		code = contract.CryptoInvalidAdmission
	}
	if code != contract.CryptoSuccess {
		a.terminal = true
		a.cancel()
		return code
	}
	a.candidate = &facts
	// Candidate facts replace the predecessor witness after its last check.
	a.purpose.output = nil
	return contract.CryptoSuccess
}

func (a *generatedAdmission) inspectCandidate(c generatedCandidate, callerDone <-chan struct{}) (generatedCandidateFacts, bool) {
	c.retainedCensus = &generatedFinalRetainedCensus{callerDone: callerDone}
	var out generatedCandidateFacts
	s := c.Subject
	authority, err := contract.GeneratorAuthorityDigest(s)
	if err != nil || s.DomainID != a.request.Context.DomainID || s.OperationID != a.graph.Header.OperationID ||
		s.PlanGraphID != a.graph.UsePlan.PlanGraphID || s.UsePlanDigest != a.request.UsePlanDigest ||
		s.PreviousHEADDigest != a.request.Context.PredecessorHEADDigest || s.ConditionDigest != a.request.Context.OriginalConditionDigest ||
		s.BeforeAccessDigest != a.request.Context.CurrentAccessRoot || s.AfterAccessDigest != c.PublicState.AccessRoot ||
		c.PublicState.Domain != a.request.Context.DomainID {
		return out, false
	}
	beforeRoot, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil || s.BeforeRootDigest != beforeRoot.Digest {
		return out, false
	}
	head, err := format.DecodeHeadCore(c.HeadCore)
	if err != nil || head.Form != format.SuccessorHead || head.Domain != s.DomainID || head.PreviousDigest != s.PreviousHEADDigest ||
		head.PreviousRevision != s.PreviousRevisionID || head.Root.Digest != s.AfterRootDigest ||
		head.Store != a.control.StoreID || head.Trust != a.control.NormalSigning.Binding.Trust || head.Coordinate != a.control.CoordinateID ||
		head.NonBody != a.control.NonBodyID || head.Interpretation != a.control.NormalSigning.Binding.Interpretation || head.Epoch != a.control.NormalSigning.Binding.Epoch ||
		contract.Hash(c.HeadCore) != s.HeadCoreDigest || len(c.HeadCore) != int(s.HeadCoreLength) {
		return out, false
	}
	condition, err := format.DecodeConditionalPlan(c.Conditional)
	if err != nil || condition.Family != a.control.Provider || condition.Store != head.Store || condition.Coordinate != head.Coordinate ||
		condition.NonBody != head.NonBody || condition.HeadCore != s.HeadCoreDigest || condition.HeadCoreLength != s.HeadCoreLength ||
		contract.Hash(c.Conditional) != s.ConditionalPlanDigest || len(c.Conditional) != int(s.ConditionalLength) {
		return out, false
	}
	token, ok := condition.Condition.Token()
	conditionDigest, err := contract.CryptoConditionDigest(condition.Condition)
	if !ok || err != nil || token != head.PreviousToken || conditionDigest != s.ConditionDigest {
		return out, false
	}
	if !a.candidateControlMatches(c.CurrentAccess.CurrentControl, c.PublicState.AccessRoot) {
		return out, false
	}
	root, err := contract.AccessRoot(c.CurrentAccess)
	if err != nil || root != c.PublicState.AccessRoot {
		return out, false
	}
	public, err := contract.PublicStateDescriptor(c.PublicState)
	if err != nil || !a.candidateEntriesMatch(c) {
		return out, false
	}
	access, err := contract.AccessRecordsDescriptor(s.DomainID, c.AccessRecords)
	if err != nil || access != c.CurrentAccess.AccessRecordsDescriptor || !a.candidateAutomaticAccessMatches(c) {
		return out, false
	}
	for _, row := range c.AccessRecords {
		if !a.accessBindingsValid(row) {
			return out, false
		}
	}
	support, err := contract.RequiredSupportDescriptor(s.DomainID, c.SupportRecords)
	checkpoint := a.purpose.final != nil && s.Purpose == contract.GeneratorAuthorityFinalPreparation
	if err != nil || support != c.PublicState.RequiredSupport || !a.candidateMaterialMatches(c) || !a.candidateActiveMatches(c) ||
		!checkpoint && (!a.candidateFinalCanonicalsMatch(c) || !a.candidateTerminalUncertain(c)) || !a.candidateDeleteReservationMatches(c) ||
		!a.purpose.output.CandidateMatches(a.graph.Header.OperationID, a.graph.ValueEntryPlans, a.purpose.final != nil && !a.purpose.final.nonselecting && !checkpoint, c.SupportRecords) {
		return out, false
	}
	if !a.candidateRegistryMatches(c, head) {
		return out, false
	}
	var phase *contract.GeneratorPhaseIdentity
	var phaseID contract.ID
	switch {
	case a.purpose.reservation != nil:
		phase, phaseID = a.purpose.reservation.phase, a.purpose.reservation.phaseID
	case a.purpose.adoption != nil:
		phase, phaseID = &a.purpose.adoption.phase, a.purpose.adoption.phaseID
	case a.purpose.final != nil:
		phase, phaseID = &a.purpose.final.phase, a.purpose.final.phaseID
		if checkpoint {
			preparedPhase, ok := a.checkpointCandidatePhase(c, head.Root.Object)
			if !ok {
				return out, false
			}
			phase, phaseID = &preparedPhase, s.PhaseID
		}
	case a.purpose.producer != nil:
		phase, phaseID = a.purpose.producer.phase, a.purpose.producer.phaseID
	default:
		return out, false
	}
	var snapshot, revision contract.ID
	if a.purpose.reservation != nil && phase == nil || a.purpose.producer != nil && phase == nil {
		parent := a.request.Parent
		if a.purpose.reservation != nil {
			parent = contract.GeneratedParentRecord(a.request.ParentPlan)
		}
		phase, err := contract.GeneratorInitialPhaseID(a.graph.Header.RequestCoreDigest)
		if err != nil || s.PhaseID != phase || s.Purpose != contract.GeneratorAuthorityReservation || s.BeforePhase != 0 || s.AfterPhase != 1 ||
			s.OwnerID != a.graph.Header.OperationID || s.Intent != a.graph.Request.Declaration || s.CapacityReservation != parent.Capacity ||
			s.PreviousRevisionID != a.graph.Request.PredecessorRevisionID {
			return out, false
		}
		snapshot, err = contract.GeneratorInitialSnapshotID(a.graph.Header.RequestCoreDigest)
		if err != nil {
			return out, false
		}
		revision, err = contract.GeneratorInitialRevisionID(a.graph.Header.RequestCoreDigest)
		if err != nil {
			return out, false
		}
	} else {
		if phase == nil || s.PhaseID != phaseID || s.Purpose != phase.TransitionKind || s.BeforePhase != phase.BeforePhase || s.AfterPhase != phase.AfterPhase ||
			s.RequestIdentityDigest != phase.RequestIdentityDigest || a.purpose.adoption != nil && !a.candidateResultMatches(c) {
			return out, false
		}
		snapshot, err = contract.GeneratorPhaseSnapshotID(phaseID)
		if err != nil {
			return out, false
		}
		revision, err = contract.GeneratorPhaseRevisionID(phaseID)
		if err != nil {
			return out, false
		}
	}
	if a.purpose.producer != nil && (s.RequestIdentityDigest != a.request.Parent.RequestIdentityDigest || !a.candidateProducerMatches(c)) {
		return out, false
	}
	if snapshot != head.Root.Object || revision != head.Revision || !a.candidateProtectionsMatch(c, head.Root.Object) {
		return out, false
	}
	var validated []contract.GeneratorResultReference
	if a.purpose.adoption != nil {
		validated = a.purpose.adoption.validated
	} else if a.purpose.final != nil {
		validated = a.purpose.final.validated
	}
	results, err := contract.GeneratorResultReferencesDescriptor(validated)
	if err != nil {
		return out, false
	}
	uses, err := contract.CryptoGeneratedKeyUseDescriptor(a.keyUses)
	if err != nil {
		return out, false
	}
	out.authorityDigest = authority
	out.facts = contract.CryptoGeneratedFreezeRequest{OperationRef: a.operation, Context: a.request.Context, PhaseID: s.PhaseID,
		RequestIdentityDigest: s.RequestIdentityDigest, CandidatePublicStateDescriptor: public, CandidateAccess: access, CandidateSupport: support,
		HeadCoreDigest: s.HeadCoreDigest, ConditionDigest: s.ConditionDigest, ActualResults: results, KeyUses: uses}
	return out, true
}

func (a *generatedAdmission) candidateDeleteReservationMatches(c generatedCandidate) bool {
	reservation := a.purpose.reservation
	if reservation == nil || reservation.phase == nil {
		return true
	}
	s := c.Subject
	if s.Purpose != contract.GeneratorAuthorityRetireReserve && s.Purpose != contract.GeneratorAuthorityCleanupReserve ||
		s.OwnerID.IsZero() || s.ResultDigest != (contract.ID{}) || !s.PredecessorAttemptID.IsZero() || s.ResultVector != reservation.phase.Evidence {
		return false
	}
	var template contract.GeneratorAttemptTemplate
	for _, lineage := range a.graph.Lineages {
		for _, candidate := range lineage.Templates[:lineage.TemplateCount] {
			if candidate.AttemptID == s.AttemptID {
				if !template.AttemptID.IsZero() || lineage.Purpose != contract.GeneratorLineageRetirement && lineage.Purpose != contract.GeneratorLineageCleanup {
					return false
				}
				template = candidate
			}
		}
	}
	if template.Action != contract.GeneratorActionDelete || template.Branch != contract.GeneratorBranchInitial || template.LineageID != s.LineageID || template.ResultID != s.ResultID ||
		template.DescriptorID != s.DescriptorID || template.ConfigContractID != s.ConfigContractID || template.ResultContractID != s.ResultContractID ||
		s.OwnerID.IsZero() {
		return false
	}
	var attempt contract.GeneratedAttemptRecord
	var duty contract.GeneratedDutyRecord
	var source contract.GeneratedDeleteSource
	for _, row := range c.SupportRecords {
		var err error
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == template.AttemptID {
			attempt, err = contract.InspectGeneratedAttemptRecord(row.Body)
		} else if row.Kind == contract.GeneratedDutySupportKind && row.RecordID == template.DutyID {
			source, err = contract.InspectGeneratedDeleteSource(row)
			duty = source.Duty
		} else if row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == s.OwnerID {
			source, err = contract.InspectGeneratedDeleteSource(row)
		}
		if err != nil {
			return false
		}
	}
	if source.Record.Kind == contract.GeneratedHazardSupportKind {
		return s.Purpose == contract.GeneratorAuthorityCleanupReserve && source.SourceID == s.OwnerID &&
			source.OwnerID == template.DutyID && source.CapacityReservation == s.CapacityReservation &&
			attempt.AttemptID == template.AttemptID && attempt.OwnerID == source.OwnerID && attempt.OperationID == a.graph.Header.OperationID &&
			attempt.State == contract.GeneratedEffectTransmitted && attempt.Stage == contract.GeneratedStageRetainedResult && a.deleteTargetSourceMatches(source, template)
	}
	if source.SourceID != s.OwnerID || template.DutyID != s.OwnerID || attempt.AttemptID != template.AttemptID || attempt.OwnerID != duty.DutyID || attempt.OperationID != a.graph.Header.OperationID ||
		attempt.State != contract.GeneratedEffectTransmitted || attempt.Stage != contract.GeneratedStageRetainedResult ||
		duty.DutyID != template.DutyID || duty.CapacityReservation != s.CapacityReservation || duty.ResourceID != template.ResourceIncarnationID ||
		duty.DescriptorID != template.DescriptorID || duty.ConfigContractID != template.ConfigContractID || duty.ExecutorID != template.ExecutorID ||
		duty.CredentialRouteID != template.CredentialRouteID || duty.ResourceContractID != template.ResourceContractID ||
		duty.LifecycleMode != template.LifecycleMode || duty.CompletionClass != template.CompletionClass || !a.deleteTargetDutyMatches(duty, template) {
		return false
	}
	return duty.Kind == contract.GeneratedDutyRetirement && duty.Status == contract.GeneratedEffectTransmitted &&
		s.Purpose == contract.GeneratorAuthorityRetireReserve ||
		duty.Kind == contract.GeneratedDutyUnselectedCleanup && duty.Status == contract.GeneratedEffectSucceeded &&
			s.Purpose == contract.GeneratorAuthorityCleanupReserve
}

// The first selecting Final keeps its Parent only to execute the accepted
// automatic Deletes. Every ordinary Final entry/source/access check still runs.
func (a *generatedAdmission) firstAutomaticSelection(c generatedCandidate) bool {
	return a.purpose.final != nil && !a.purpose.final.nonselecting && a.selectionPhase == nil &&
		c.Subject.Purpose == contract.GeneratorAuthorityFinal && c.ActiveOwner == a.graph.Header.OperationID &&
		len(contract.GeneratedAutomaticRetirementIndices(a.graph)) != 0
}

func (a *generatedAdmission) candidateFinalCanonicalsMatch(c generatedCandidate) bool {
	if a.firstAutomaticSelection(c) {
		// Parent retention does not extend its ended CREATE input lifetime.
		// Current values and independent Duty/Hazard consumers remain visible.
		c.ActiveOwner, c.ActivePhase, c.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	}
	return a.candidateCanonicalsMatch(c)
}

func (a *generatedAdmission) candidateAutomaticSelectionMatches(c generatedCandidate) bool {
	final := a.purpose.final
	if !a.firstAutomaticSelection(c) || a.purpose.output == nil || a.beforeAccessRecords == nil ||
		len(final.validated) != len(final.results) || len(final.resultBodies) != len(final.results) ||
		c.ActiveGraph != a.graph.UsePlan.PlanGraphID || c.ActivePhase != final.phaseID {
		return false
	}
	type key struct {
		kind uint8
		id   contract.ID
	}
	selected := func(k key) contract.SupportRecord {
		at, found := slices.BinarySearchFunc(c.SupportRecords, k, func(row contract.SupportRecord, want key) int {
			if row.Kind != want.kind {
				return int(row.Kind) - int(want.kind)
			}
			return bytes.Compare(row.RecordID[:], want.id[:])
		})
		if !found {
			return contract.SupportRecord{}
		}
		return c.SupportRecords[at]
	}
	parent, err := contract.InspectGeneratedParentRecord(selected(key{contract.GeneratedParentSupportKind, a.graph.Header.OperationID}).Body)
	if err != nil || parent != a.request.Parent {
		return false
	}
	phase, err := contract.InspectGeneratedPhaseRecord(selected(key{contract.GeneratedPhaseSupportKind, parent.OperationID}).Body)
	indices := contract.GeneratedAutomaticRetirementIndices(a.graph)
	first := a.graph.Lineages[indices[0]].Templates[0]
	if err != nil || phase.DomainID != parent.DomainID || phase.OperationID != parent.OperationID || phase.OwnerID != parent.OperationID ||
		phase.PlanGraphID != parent.PlanGraphID || phase.UsePlanDigest != parent.UsePlanDigest || phase.PhaseID != final.phaseID || phase.SelectionPhaseID != final.phaseID ||
		phase.Phase != final.phase.AfterPhase || phase.LineageIndex != indices[0] || phase.FrontierAttemptID != first.AttemptID || phase.Branch != 0 ||
		phase.Stage != contract.GeneratedStageRetainedResult || phase.NoEffectUsed != 0 || phase.ResidueUsed != 0 || !phase.AcceptedResultID.IsZero() || !phase.ResultDigest.IsZero() ||
		!phase.FinalPreparationID.IsZero() || phase.Proofs != contract.EmptyGeneratorVector(contract.GeneratorVectorProofs) {
		return false
	}
	changed, ok := a.candidateAutomaticChangedSubjects(c)
	if !ok || changed != phase.ChangedSubjects {
		return false
	}
	access, ok := a.candidateAutomaticChangedAccess(c)
	if !ok || access != phase.ChangedAccess {
		return false
	}
	head, err := format.DecodeHeadCore(c.HeadCore)
	if err != nil || !generatedCandidateContentMatches(c.SupportRecords, parent.DomainID, head.Root.Object, contract.GeneratorContentGraph, parent.PlanGraphID, a.graphBody, nil, true) ||
		!generatedCandidateContentMatches(c.SupportRecords, parent.DomainID, head.Root.Object, contract.GeneratorContentDeclaration, parent.OperationID,
			contract.DigestLength{Digest: contract.Hash(final.plan.declaration), Length: uint64(len(final.plan.declaration))}, final.plan.declaration, true) {
		return false
	}
	before := func(k key) contract.SupportRecordDigest {
		at, found := slices.BinarySearchFunc(a.purpose.output.Rows.Facts, k, func(row contract.SupportRecordDigest, want key) int {
			if row.Kind() != want.kind {
				return int(row.Kind()) - int(want.kind)
			}
			id := row.RecordID()
			return bytes.Compare(id[:], want.id[:])
		})
		if !found {
			return contract.SupportRecordDigest{}
		}
		return a.purpose.output.Rows.Facts[at]
	}
	templates := make(map[contract.ID]contract.GeneratorAttemptTemplate)
	lineages := make(map[contract.ID]bool)
	for _, lineage := range a.graph.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			lineages[lineage.LineageID] = true
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				templates[x.AttemptID] = x
			}
		}
	}
	entered := make(map[contract.ID]contract.GeneratedAttemptRecord)
	for _, fact := range a.purpose.output.Rows.Facts {
		k := key{fact.Kind(), fact.RecordID()}
		_, attempt := templates[k.id]
		if k.kind != contract.GeneratedAttemptSupportKind || !attempt {
			continue
		}
		row := selected(k)
		actual, err := contract.InspectSupportRecordDigest(parent.DomainID, row)
		x := templates[k.id]
		record, e := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || actual != fact || e != nil || !generatedUncertainAttemptMatches(record, x, parent.DomainID, parent.OperationID) || record.Stage != contract.GeneratedStageTerminal {
			return false
		}
		entered[k.id] = record
		for _, vector := range []struct {
			kind       contract.GeneratorVectorKind
			descriptor contract.GeneratorDescriptor
		}{
			{contract.GeneratorVectorFacts, record.Facts}, {contract.GeneratorVectorProgress, record.Progress}, {contract.GeneratorVectorHistory, record.History}, {contract.GeneratorVectorSupport, record.Support},
		} {
			if err := contract.InspectGeneratorSelectedVector(parent.DomainID, row.Kind, row.RecordID, vector.kind, vector.descriptor, c.SupportRecords, func(_ uint32, _ []byte) error { return nil }); err != nil {
				return false
			}
		}
	}
	if len(entered) == 0 {
		return false
	}
	for _, row := range c.SupportRecords {
		k := key{row.Kind, row.RecordID}
		switch k.kind {
		case contract.GeneratedAttemptSupportKind:
			record, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return false
			}
			if record.OperationID == parent.OperationID && entered[k.id].AttemptID.IsZero() {
				return false
			}
		case contract.GeneratedLineageSupportKind:
			if lineages[k.id] {
				fact, err := contract.InspectSupportRecordDigest(parent.DomainID, row)
				if err != nil || before(k) != fact {
					return false
				}
			}
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil || carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == parent.OperationID && carrier.VectorKind == contract.GeneratorVectorConsumers {
				return false
			}
		case contract.MutationReceiptSupportKind:
			receipt, err := contract.InspectCompactMutationReceipt(row.Body)
			if err != nil || receipt.OperationID == parent.OperationID {
				return false
			}
		}
	}
	for _, fact := range a.purpose.output.Rows.Facts {
		k := key{fact.Kind(), fact.RecordID()}
		if k.kind == contract.GeneratedLineageSupportKind && lineages[k.id] {
			actual, err := contract.InspectSupportRecordDigest(parent.DomainID, selected(k))
			if err != nil || actual != fact {
				return false
			}
		}
	}
	for i, result := range final.results {
		x := result.Expected.Template
		at, qualified := slices.BinarySearchFunc(final.validated, x.ResultID, func(reference contract.GeneratorResultReference, id contract.ID) int {
			return bytes.Compare(reference.ResultID[:], id[:])
		})
		if !qualified {
			return false
		}
		reference := final.validated[at]
		row := selected(key{contract.GeneratedResultSupportKind, x.ResultID})
		fact, err := contract.InspectSupportRecordDigest(parent.DomainID, row)
		if err != nil || fact != before(key{row.Kind, row.RecordID}) || entered[x.AttemptID].AttemptID.IsZero() || !bytes.Equal(row.Body, final.resultBodies[i]) || uint32(len(row.Body)) != reference.ResultLength || contract.Hash(row.Body) != reference.ResultBodyDigest {
			return false
		}
	}
	var sets [5][]contract.SupportRecord
	owners := make(map[contract.ID]bool)
	hazards := make(map[contract.ID]bool)
	results := make(map[contract.ID]bool)
	inboxes := make(map[contract.ID]bool)
	for id, record := range entered {
		x := templates[id]
		owners[record.OwnerID], hazards[x.HazardID], results[record.ResultID], inboxes[record.InboxID] = true, true, true, true
		owner := selected(key{contract.GeneratedDutySupportKind, record.OwnerID})
		if len(owner.Body) == 0 {
			// A prior uncertain CREATE can already be owned by its exact
			// retained Hazard. Its record and carriers remain pinned below.
			hazardRow := selected(key{contract.GeneratedHazardSupportKind, x.HazardID})
			hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
			if err != nil || hazard.OriginalOperationID != record.OperationID || hazard.OriginalAttemptID != record.AttemptID ||
				hazard.OwnerID != record.OwnerID || hazard.ResourceID != record.ResourceID ||
				record.State != contract.GeneratedEffectClosedWithResidue && record.State != contract.GeneratedEffectFailedTerminal {
				return false
			}
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(owner.Body)
		if err != nil || duty.Kind != contract.GeneratedDutyCreate || duty.DomainID != record.DomainID || duty.OriginalOperationID != record.OperationID || duty.OriginalAttemptID != id ||
			duty.OwnerID != record.OwnerID || duty.ResourceID != record.ResourceID || duty.DescriptorID != record.DescriptorID || duty.ConfigContractID != record.ConfigContractID || duty.ExecutorID != record.ExecutorID ||
			duty.CredentialRouteID != record.CredentialRouteID || duty.ResourceContractID != record.ResourceContractID || duty.ResultContractID != record.ResultContractID || duty.LifecycleMode != record.LifecycleMode || duty.CompletionClass != record.CompletionClass ||
			duty.Status != record.State || duty.CapacityReservation != parent.Capacity || duty.Progress != record.Progress || duty.History != record.History || duty.Support != record.Support || !a.automaticOriginalConsumersMatch(c, owner, duty.Consumers, x) {
			return false
		}
	}
	for _, row := range c.SupportRecords {
		if row.Kind == contract.GeneratedHazardSupportKind && hazards[row.RecordID] {
			fact, err := contract.InspectSupportRecordDigest(parent.DomainID, row)
			if err != nil || fact != before(key{row.Kind, row.RecordID}) {
				return false
			}
		}
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return false
		}
		immutable := carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == parent.OperationID && carrier.VectorKind != contract.GeneratorVectorConsumers ||
			carrier.OwnerKind == contract.GeneratedAttemptSupportKind && !entered[carrier.OwnerID].AttemptID.IsZero() ||
			carrier.OwnerKind == contract.GeneratedDutySupportKind && owners[carrier.OwnerID] && carrier.VectorKind != contract.GeneratorVectorConsumers ||
			carrier.OwnerKind == contract.GeneratedHazardSupportKind && hazards[carrier.OwnerID]
		if immutable {
			fact, err := contract.InspectSupportRecordDigest(parent.DomainID, row)
			if err != nil || fact != before(key{row.Kind, row.RecordID}) {
				return false
			}
		}
	}
	for _, fact := range a.purpose.output.Rows.Facts {
		if fact.Kind() == contract.GeneratedHazardSupportKind && hazards[fact.RecordID()] {
			row := selected(key{fact.Kind(), fact.RecordID()})
			got, err := contract.InspectSupportRecordDigest(parent.DomainID, row)
			if err != nil || got != fact {
				return false
			}
		}
	}
	for _, index := range indices {
		x := a.graph.Lineages[index].Templates[0]
		owners[x.DutyID] = true
		if !a.candidateAutomaticDutyMatches(c, a.graph.Lineages[index], selected(key{contract.GeneratedDutySupportKind, x.DutyID})) {
			return false
		}
	}
	for _, row := range c.SupportRecords {
		switch row.Kind {
		case contract.GeneratedResultSupportKind:
			if results[row.RecordID] {
				sets[0] = append(sets[0], row)
			}
		case contract.GeneratedAttemptSupportKind:
			if !entered[row.RecordID].AttemptID.IsZero() {
				sets[1] = append(sets[1], row)
			}
		case contract.GeneratedDutySupportKind:
			if owners[row.RecordID] {
				sets[2] = append(sets[2], row)
			}
		case contract.GeneratedHazardSupportKind:
			if hazards[row.RecordID] {
				sets[3] = append(sets[3], row)
			}
		case contract.PendingInboxReleaseSupportKind:
			if inboxes[row.RecordID] {
				sets[4] = append(sets[4], row)
			}
		}
	}
	for i, want := range []contract.GeneratorDescriptor{phase.AcceptedResults, phase.Attempts, phase.Duties, phase.Hazards, phase.PendingReleases} {
		slices.SortFunc(sets[i], func(x, y contract.SupportRecord) int { return bytes.Compare(x.RecordID[:], y.RecordID[:]) })
		got, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorRecordSetKind(i+1), parent.DomainID, sets[i])
		if err != nil || got != want {
			return false
		}
	}
	return true
}

func (a *generatedAdmission) automaticOriginalConsumersMatch(c generatedCandidate, owner contract.SupportRecord, descriptor contract.GeneratorDescriptor, x contract.GeneratorAttemptTemplate) bool {
	var use contract.GeneratorResultUse
	for _, row := range a.graph.ResultUses {
		if row.AttemptID == x.AttemptID {
			use = row
		}
	}
	context, err := contract.GeneratorResultUseDigest(use)
	if err != nil || descriptor.Count != 2 {
		return false
	}
	var seen [2]bool
	err = contract.InspectGeneratorSelectedVector(a.graph.Header.DomainID, owner.Kind, owner.RecordID, contract.GeneratorVectorConsumers, descriptor, c.SupportRecords, func(_ uint32, body []byte) error {
		row, err := contract.InspectGeneratorConsumer(body)
		if err != nil || row.SubjectKind != contract.GeneratorConsumerOriginalResult || row.SubjectID != x.ResultID || row.OwnerID != x.DutyID || row.MaterialID != a.request.MaterialID || row.ContextDigest != context || row.Purpose < contract.GeneratorConsumerDeriveSelectedResult || row.Purpose > contract.GeneratorConsumerAdoptLateOriginalResult {
			return contract.ErrRecord
		}
		at := row.Purpose - contract.GeneratorConsumerDeriveSelectedResult
		if seen[at] {
			return contract.ErrRecord
		}
		seen[at] = true
		return nil
	})
	return err == nil && seen[0] && seen[1]
}

func (a *generatedAdmission) candidateAutomaticDutyMatches(c generatedCandidate, lineage contract.GeneratorLineageTemplate, row contract.SupportRecord) bool {
	x := lineage.Templates[0]
	d, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || row.RecordID != x.DutyID || d.DomainID != a.graph.Header.DomainID || d.DutyID != x.DutyID || d.OwnerID != x.DutyID || d.Kind != contract.GeneratedDutyRetirement ||
		d.ResourceID != x.ResourceIncarnationID || d.DescriptorID != x.DescriptorID || d.ConfigContractID != x.ConfigContractID || d.ExecutorID != x.ExecutorID || d.CredentialRouteID != x.CredentialRouteID ||
		d.ResourceContractID != x.ResourceContractID || d.ResultContractID != x.ResultContractID || d.LifecycleMode != x.LifecycleMode || d.CompletionClass != x.CompletionClass || d.Status != contract.GeneratedEffectNotStarted || d.Step != 1 ||
		d.CapacityReservation != a.request.Parent.Capacity || d.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || d.History != contract.EmptyGeneratorVector(contract.GeneratorVectorHistory) ||
		d.Consumers != contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers) || d.Target.Count != 1 {
		return false
	}
	var prior contract.ValueEntryView
	found := false
	for i, entry := range a.purpose.output.EntriesBefore {
		if entry.Name == lineage.Name {
			prior, err = contract.InspectValueEntry(a.purpose.output.EntryBodies[i])
			found = err == nil
			break
		}
	}
	if !found || prior.ValueSource != contract.Generated || prior.Incarnation != lineage.EntryIncarnationID || prior.Generated.Epoch != lineage.Epoch {
		return false
	}
	m := prior.Generated
	if d.Support != m.RequiredSupport || x.ResourceContractID != m.ResourceContractID {
		return false
	}
	var originalContract contract.ID
	for _, evidenceRow := range c.SupportRecords {
		if evidenceRow.Kind == contract.GeneratedCreateEvidenceSupportKind && evidenceRow.RecordID == m.CreateResultID {
			evidence, err := contract.InspectGeneratedCreateEvidence(evidenceRow.Body)
			if err != nil {
				return false
			}
			descriptor, err := contract.GeneratedCreateEvidenceDescriptor(contract.GeneratedCreateEvidence(evidence))
			if err != nil || descriptor != m.CreateEvidence {
				return false
			}
			core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
			if err != nil {
				return false
			}
			originalContract = core.ResultContractID
		}
	}
	if originalContract.IsZero() {
		return false
	}
	if m.ResourceIncarnationID != d.ResourceID || m.ConfigContractID != d.ConfigContractID || m.ResourceContractID != d.ResourceContractID || m.LifecycleMode != d.LifecycleMode || m.OriginOperationID != d.OriginalOperationID || m.OriginAttemptID != d.OriginalAttemptID || m.CompletionClass != d.CompletionClass {
		return false
	}
	err = contract.InspectGeneratorSelectedVector(d.DomainID, row.Kind, row.RecordID, contract.GeneratorVectorTargets, d.Target, c.SupportRecords, func(_ uint32, body []byte) error {
		target, e := contract.InspectGeneratorTarget(body)
		if e != nil || target.Name != lineage.Name || target.IncarnationID != prior.Incarnation || target.Epoch != m.Epoch || target.ResourceID != m.ResourceIncarnationID || target.LifecycleMode != m.LifecycleMode || target.ResourceDigest != m.ResourceDigest || target.ConfigContractID != m.ConfigContractID || target.ResourceContractID != m.ResourceContractID || target.OriginalOperationID != m.OriginOperationID || target.OriginalAttemptID != m.OriginAttemptID || target.CompletionClass != m.CompletionClass || target.ResultContractID != originalContract {
			return contract.ErrRecord
		}
		return nil
	})
	return err == nil
}

func (a *generatedAdmission) candidateAutomaticChangedAccess(c generatedCandidate) (contract.GeneratorDescriptor, bool) {
	var changes []contract.AccessChangeRow
	for _, row := range c.AccessRecords {
		at, present := slices.BinarySearchFunc(a.beforeAccessRecords, row, func(old, want contract.AccessRecord) int {
			if old.MaterialKind != want.MaterialKind {
				return int(old.MaterialKind) - int(want.MaterialKind)
			}
			return bytes.Compare(old.MaterialID[:], want.MaterialID[:])
		})
		if present {
			old := a.beforeAccessRecords[at]
			x, err := contract.AccessRecordDigest(old)
			if err != nil {
				return contract.GeneratorDescriptor{}, false
			}
			y, err := contract.AccessRecordDigest(row)
			if err != nil {
				return contract.GeneratorDescriptor{}, false
			}
			if x != y {
				changes = append(changes, contract.AccessChangeRow{Before: old, After: row})
			}
		}
	}
	d, err := contract.AccessChangeDescriptor(c.PublicState.Domain, changes)
	return d, err == nil
}

func (a *generatedAdmission) candidateAutomaticChangedSubjects(c generatedCandidate) (contract.GeneratorDescriptor, bool) {
	output := a.purpose.output
	if output == nil || len(output.EntriesBefore) != len(output.EntryBodies) {
		return contract.GeneratorDescriptor{}, false
	}
	type previous struct {
		view       contract.ValueEntryView
		membership contract.MembershipRow
	}
	old := make(map[string]previous, len(output.EntriesBefore))
	for i, row := range output.EntriesBefore {
		view, err := contract.InspectValueEntry(output.EntryBodies[i])
		if err != nil {
			return contract.GeneratorDescriptor{}, false
		}
		old[row.Name] = previous{view, row}
	}
	current := make(map[string]generatedCandidateEntry, len(c.Entries))
	for _, row := range c.Entries {
		current[row.Entry.Name] = row
	}
	configuration, err := output.ConfigurationAfter(a.graph.Header.OperationID, a.graph.ValueEntryPlans)
	if err != nil {
		return contract.GeneratorDescriptor{}, false
	}
	outputChanges, err := contract.OutputConfigurationChangedSubjects(output.Before, configuration)
	if err != nil {
		return contract.GeneratorDescriptor{}, false
	}
	capacity := 2*(len(output.EntriesBefore)+len(c.Entries)) + len(outputChanges)
	for _, row := range output.EntriesBefore {
		capacity += len(row.Recipients)
	}
	for _, row := range c.Entries {
		capacity += len(row.Entry.Recipients)
	}
	if a.registry != nil {
		capacity += len(a.registry.desired)
	}
	changes := make([]contract.ChangedSubjectIdentity, 0, capacity)
	appendIdentity := func(kind, change uint8, primary, secondary contract.ID) bool {
		id, err := contract.ChangedSubjectIdentityID(c.PublicState.Domain, kind, primary, secondary)
		if err != nil {
			return false
		}
		changes = append(changes, contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: id})
		return true
	}
	names := make([]string, 0, len(old)+len(current))
	for name := range old {
		names = append(names, name)
	}
	for name := range current {
		if _, present := old[name]; !present {
			names = append(names, name)
		}
	}
	for _, name := range names {
		prior, was := old[name]
		next, present := current[name]
		entry := next.Entry
		digest := contract.ID{}
		if present {
			var err error
			digest, err = contract.PublicValueEntryDigest(c.PublicState.Domain, next.Slot, entry)
			if err != nil {
				return contract.GeneratorDescriptor{}, false
			}
		}
		switch {
		case !was:
			if !appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, entry.Incarnation, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		case !present:
			if !appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, prior.view.Incarnation, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		case prior.view.Incarnation != entry.Incarnation:
			if !appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, prior.view.Incarnation, contract.ID{}) || !appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, entry.Incarnation, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		case prior.membership.EntryDigest != digest:
			if !appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, entry.Incarnation, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		}
		for _, id := range prior.membership.Recipients {
			if !present || prior.view.Incarnation != entry.Incarnation || !slices.Contains(entry.Recipients, id) {
				if !appendIdentity(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, prior.view.Incarnation, id) {
					return contract.GeneratorDescriptor{}, false
				}
			}
		}
		for _, id := range entry.Recipients {
			if !was || prior.view.Incarnation != entry.Incarnation || !slices.Contains(prior.membership.Recipients, id) {
				if !appendIdentity(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, entry.Incarnation, id) {
					return contract.GeneratorDescriptor{}, false
				}
			}
		}
		beforeGenerated, afterGenerated := was && prior.view.ValueSource == contract.Generated, present && entry.ValueSource == contract.Generated
		switch {
		case beforeGenerated && (!afterGenerated || prior.view.Generated.GenerationID != entry.Generated.GenerationID):
			if !appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, prior.view.Generated.GenerationID, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
			if afterGenerated && !appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, entry.Generated.GenerationID, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		case !beforeGenerated && afterGenerated:
			if !appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, entry.Generated.GenerationID, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		case beforeGenerated && afterGenerated && prior.membership.EntryDigest != digest:
			if !appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectUpdated, entry.Generated.GenerationID, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		}
	}
	if a.registry != nil {
		for _, next := range a.registry.desired {
			at := slices.IndexFunc(a.registry.current, func(old contract.RecipientRecord) bool { return old.RecipientID == next.RecipientID })
			if at >= 0 && sameApplyRecipient(a.registry.current[at], next) {
				continue
			}
			change := uint8(contract.ChangedSubjectAdded)
			if at >= 0 {
				change = contract.ChangedSubjectUpdated
			}
			if !appendIdentity(contract.ChangedSubjectRecipient, change, next.RecipientID, contract.ID{}) {
				return contract.GeneratorDescriptor{}, false
			}
		}
	}
	changes = append(changes, outputChanges...)
	d, err := contract.ChangedSubjectDescriptor(changes)
	return d, err == nil
}

// A result-free final can close only a fully represented uncertain create
// path. This check keeps the empty entry batch from becoming an admission
// shortcut when Core and Crypto do not share a caller.
func (a *generatedAdmission) candidateTerminalUncertain(c generatedCandidate) bool {
	final := a.purpose.final
	if final == nil || generatedCurrentOnlyDeletePlan(a.graph) {
		return true
	}
	if a.firstAutomaticSelection(c) {
		return a.candidateAutomaticSelectionMatches(c)
	}
	if len(final.validated) != len(final.results) || len(final.resultBodies) != len(final.results) {
		return false
	}
	templates := make(map[contract.ID]contract.GeneratorAttemptTemplate)
	resultAttempts := make(map[contract.ID]contract.ID)
	inboxAttempts := make(map[contract.ID]contract.ID)
	for _, lineage := range a.graph.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				templates[x.AttemptID] = x
				resultAttempts[x.ResultID] = x.AttemptID
				inboxAttempts[x.InboxID] = x.AttemptID
			}
		}
	}
	results := make(map[contract.ID]contract.GeneratedResultRecord)
	bodies := make(map[contract.ID][]byte)
	for i, admitted := range final.results {
		x := admitted.Expected.Template
		result, err := contract.DecodeGeneratedResultRecord(final.resultBodies[i])
		if err != nil || templates[x.AttemptID] != x || !results[x.AttemptID].Core.AttemptID.IsZero() {
			return false
		}
		results[x.AttemptID], bodies[x.AttemptID] = result, final.resultBodies[i]
	}
	localFailures := make(map[contract.ID]contract.GeneratedAttemptRecord)
	localReleases := make(map[contract.ID]contract.GeneratedAttemptRecord)
	localInboxes := make(map[contract.ID]contract.ID)
	for _, row := range final.checkpointSupport {
		if row.Kind != contract.GeneratedAttemptSupportKind {
			continue
		}
		record, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || !a.finalLocalCheckpointAttempt(record) {
			return false
		}
		if record.State == contract.GeneratedEffectFailedTerminal {
			localFailures[record.AttemptID] = record
		} else {
			localReleases[record.AttemptID] = record
			localInboxes[record.InboxID] = record.AttemptID
		}
	}
	selected := make(map[contract.ID]bool)
	for _, entry := range final.entryPreparations {
		if entry.prepared && entry.result >= 0 && entry.result < len(final.results) {
			selected[final.results[entry.result].Expected.Template.AttemptID] = true
		}
	}
	required := make(map[contract.ID]bool)
	for id, result := range results {
		if result.Disposition() == contract.GeneratorDispositionOwnedUnusableCreate ||
			result.Disposition() == contract.GeneratorDispositionCompleteCreate && !selected[id] && localReleases[id].AttemptID.IsZero() {
			required[id] = true
		}
	}
	if a.purpose.output == nil {
		return false
	}
	predecessors := make(map[contract.ID]contract.SupportRecordDigest)
	for _, fact := range a.purpose.output.Rows.Facts {
		if fact.Kind() == contract.GeneratedAttemptSupportKind {
			if _, active := templates[fact.RecordID()]; active {
				predecessors[fact.RecordID()] = fact
				if _, returned := results[fact.RecordID()]; !returned && localFailures[fact.RecordID()].AttemptID.IsZero() {
					required[fact.RecordID()] = true
				}
			}
		} else if fact.Kind() == contract.GeneratedResultSupportKind {
			if id, active := resultAttempts[fact.RecordID()]; active &&
				(uint32(len(bodies[id])) != fact.BodyLength() || contract.Hash(bodies[id]) != fact.BodyDigest()) {
				return false
			}
		}
	}
	attempts := make(map[contract.ID]contract.GeneratedAttemptRecord)
	attemptBodies := make(map[contract.ID][]byte)
	retainedResults := make(map[contract.ID]bool)
	owners := make(map[contract.ID]contract.SupportRecord)
	releaseMappings := make(map[contract.ID]bool)
	releaseRows := make(map[contract.ID]bool)
	for _, row := range c.SupportRecords {
		switch row.Kind {
		case contract.GeneratedParentSupportKind:
			parent, err := contract.InspectGeneratedParentRecord(row.Body)
			if err != nil || parent.OperationID == a.graph.Header.OperationID {
				return false
			}
		case contract.GeneratedPhaseSupportKind:
			phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
			if err != nil || phase.OperationID == a.graph.Header.OperationID {
				return false
			}
		case contract.GeneratedLineageSupportKind:
			lineage, err := contract.InspectGeneratedLineageRecord(row.Body)
			if err != nil || lineage.OperationID == a.graph.Header.OperationID {
				return false
			}
		case contract.GeneratedResultSupportKind:
			if id := resultAttempts[row.RecordID]; !localFailures[id].AttemptID.IsZero() || !localReleases[id].AttemptID.IsZero() {
				return false
			}
			result, err := contract.InspectGeneratedResultRecord(row.Body)
			if id := resultAttempts[result.Core.ResultID]; !localFailures[id].AttemptID.IsZero() || !localReleases[id].AttemptID.IsZero() {
				return false
			}
			if err != nil || result.Core.OperationID == a.graph.Header.OperationID && !bytes.Equal(row.Body, bodies[result.Core.AttemptID]) {
				return false
			}
			if result.Core.OperationID == a.graph.Header.OperationID {
				retainedResults[result.Core.AttemptID] = true
			}
		case contract.GeneratedAttemptSupportKind:
			if !localFailures[row.RecordID].AttemptID.IsZero() {
				return false
			}
			record, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return false
			}
			if record.OperationID != a.graph.Header.OperationID {
				continue
			}
			if !localFailures[record.AttemptID].AttemptID.IsZero() {
				return false
			}
			if original := localReleases[record.AttemptID]; !original.AttemptID.IsZero() {
				mapping := original
				mapping.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
				mapping.History = contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
				if row.RecordID != record.AttemptID || record != mapping || releaseMappings[record.AttemptID] || !a.terminalLocalSupportMatches(c, mapping) {
					return false
				}
				releaseMappings[record.AttemptID] = true
				continue
			}
			x, ok := templates[record.AttemptID]
			if !ok || !generatedUncertainAttemptMatches(record, x, a.graph.Header.DomainID, a.graph.Header.OperationID) ||
				record.Stage != contract.GeneratedStageTerminal || !attempts[record.AttemptID].AttemptID.IsZero() {
				return false
			}
			attempts[record.AttemptID] = record
			attemptBodies[record.AttemptID] = row.Body
		case contract.PendingInboxReleaseSupportKind:
			release, err := contract.InspectPendingInboxReleaseRecord(row.Body)
			if err != nil || row.RecordID != release.InboxID {
				return false
			}
			for _, failed := range localFailures {
				if release.InboxID == failed.InboxID || release.OriginalResultID == failed.ResultID {
					return false
				}
			}
			id := localInboxes[release.InboxID]
			if resultID := resultAttempts[release.OriginalResultID]; !localReleases[resultID].AttemptID.IsZero() && resultID != id {
				return false
			}
			if !id.IsZero() {
				original := localReleases[id]
				duty, present := generatedFinalCheckpointDuty(final.checkpointSupport, original.OwnerID)
				revision, err := contract.GeneratorPhaseRevisionID(final.phaseID)
				if !present || err != nil || releaseRows[id] {
					return false
				}
				want := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: original.DomainID, InboxID: original.InboxID,
					OriginalResultID: original.ResultID, SelectedHandoffDigest: contract.Hash(bodies[id]), HandoffRevisionID: revision,
					ObjectLength: uint32(len(bodies[id])), CapacityReservation: duty.CapacityReservation, State: contract.GeneratedReleasePending}
				if release != want {
					return false
				}
				releaseRows[id] = true
			} else if !resultAttempts[release.OriginalResultID].IsZero() || !inboxAttempts[release.InboxID].IsZero() {
				fact, err := contract.InspectSupportRecordDigest(a.graph.Header.DomainID, row)
				if err != nil || !slices.Contains(a.purpose.output.Rows.Facts, fact) {
					return false
				}
			}
		case contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind:
			source, err := contract.InspectGeneratedDeleteSource(row)
			if err != nil {
				return false
			}
			if source.OriginalOperationID == a.graph.Header.OperationID {
				if !final.nonselecting && row.Kind == contract.GeneratedDutySupportKind && source.Duty.Kind == contract.GeneratedDutyUnselectedCleanup &&
					selected[source.OriginalAttemptID] && source.ResourceID == templates[source.OriginalAttemptID].ResourceIncarnationID {
					return false
				}
				if _, exists := owners[source.OriginalAttemptID]; exists {
					return false
				}
				owners[source.OriginalAttemptID] = row
			}
		}
	}
	for id := range localReleases {
		if !releaseMappings[id] || !releaseRows[id] {
			return false
		}
	}
	for id := range required {
		if attempts[id].AttemptID.IsZero() {
			return false
		}
		if _, returned := results[id]; returned && !retainedResults[id] {
			return false
		}
		if fact, pinned := predecessors[id]; pinned &&
			(uint32(len(attemptBodies[id])) != fact.BodyLength() || contract.Hash(attemptBodies[id]) != fact.BodyDigest()) {
			return false
		}
	}
	if len(required) != 0 && (!slices.ContainsFunc(c.SupportRecords, func(row contract.SupportRecord) bool {
		return row.Kind == contract.OperationMaterialSupportKind && row.RecordID == a.request.MaterialID
	}) || !slices.ContainsFunc(c.AccessRecords, func(row contract.AccessRecord) bool {
		return row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == a.request.MaterialID
	})) {
		return false
	}
	entered := make(map[contract.ID]bool)
	for id := range results {
		entered[id] = true
	}
	for id := range localFailures {
		entered[id] = true
	}
	for id, record := range attempts {
		entered[id] = true
		result, returned := results[id]
		row, owned := owners[id]
		if !returned {
			hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
			if !owned || row.Kind != contract.GeneratedHazardSupportKind || err != nil ||
				record.State != contract.GeneratedEffectClosedWithResidue ||
				record.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) ||
				record.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) ||
				record.Support != contract.EmptyGeneratorVector(contract.GeneratorVectorSupport) ||
				!generatedUncertainHazardMatches(hazard, record, templates[id]) || !a.terminalOriginalConsumerMatches(c, row, hazard.Consumers, templates[id]) ||
				!a.terminalResultlessHistoryMatches(c, hazard, record, templates, results, bodies, attempts) {
				return false
			}
			continue
		}
		if record.RequestDigest != result.Core.RequestDigest || record.ResultID != result.Core.ResultID || !owned {
			return false
		}
		source, err := contract.InspectGeneratedDeleteSource(row)
		if err != nil || !a.terminalOriginalConsumerMatches(c, row, source.Consumers, templates[id]) || record.State == contract.GeneratedEffectSucceeded &&
			(result.Disposition() != contract.GeneratorDispositionCompleteCreate || row.Kind != contract.GeneratedDutySupportKind ||
				source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup || source.Duty.Status != contract.GeneratedEffectSucceeded) ||
			record.State != contract.GeneratedEffectSucceeded && (row.Kind != contract.GeneratedHazardSupportKind || source.Hazard.Fenced != 1) {
			return false
		}
		head, err := format.DecodeHeadCore(c.HeadCore)
		if err != nil {
			return false
		}
		if _, err := contract.InspectGeneratedSelectedCreateAncestry(a.graph.Header.DomainID, head.Root.Object, c.SupportRecords, source); err != nil {
			return false
		}
	}
	for id := range owners {
		if attempts[id].AttemptID.IsZero() {
			return false
		}
	}
	unfulfilled, lineages := false, 0
	for _, lineage := range a.graph.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		lineages++
		var frontier contract.GeneratorAttemptTemplate
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			if entered[x.AttemptID] && (frontier.AttemptID.IsZero() || x.Branch > frontier.Branch) {
				frontier = x
			}
		}
		if frontier.AttemptID.IsZero() {
			return false
		}
		fulfilled := results[frontier.AttemptID].Disposition() == contract.GeneratorDispositionCompleteCreate &&
			(attempts[frontier.AttemptID].AttemptID.IsZero() || attempts[frontier.AttemptID].State == contract.GeneratedEffectSucceeded)
		if !final.nonselecting {
			selected := false
			for _, entry := range final.entryPreparations {
				selected = selected || entry.prepared && final.results[entry.result].Expected.Template.AttemptID == frontier.AttemptID
			}
			if !fulfilled || !selected {
				return false
			}
		} else if fulfilled && attempts[frontier.AttemptID].AttemptID.IsZero() && !releaseMappings[frontier.AttemptID] {
			return false
		}
		unfulfilled = unfulfilled || !fulfilled
		for x := frontier; ; {
			if !entered[x.AttemptID] {
				return false
			}
			delete(entered, x.AttemptID)
			if x.PredecessorAttemptID.IsZero() {
				break
			}
			previous, ok := templates[x.PredecessorAttemptID]
			if !ok || previous.LineageID != lineage.LineageID {
				return false
			}
			guard := uint8(contract.GeneratorGuardResidue)
			if attempts[previous.AttemptID].State != contract.GeneratedEffectClosedWithResidue {
				if results[previous.AttemptID].SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect {
					return false
				}
				guard = contract.GeneratorGuardQualifiedNoEffect
			}
			branch, present, err := previous.SuccessorBranch(guard)
			if err != nil || !present || branch != x.Branch {
				return false
			}
			x = previous
		}
	}
	return lineages != 0 && len(entered) == 0 && (!final.nonselecting || unfulfilled)
}

func (a *generatedAdmission) terminalLocalSupportMatches(c generatedCandidate, record contract.GeneratedAttemptRecord) bool {
	if a.purpose.output == nil {
		return false
	}
	for _, row := range c.SupportRecords {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return false
		}
		if carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == record.OperationID &&
			carrier.VectorKind == contract.GeneratorVectorSupport && carrier.Vector == record.Support {
			fact, err := contract.InspectSupportRecordDigest(record.DomainID, row)
			if err != nil || !slices.Contains(a.purpose.output.Rows.Facts, fact) {
				return false
			}
		}
	}
	return contract.InspectGeneratorSelectedVector(record.DomainID, contract.GeneratedParentSupportKind, record.OperationID,
		contract.GeneratorVectorSupport, record.Support, c.SupportRecords, func(_ uint32, _ []byte) error { return nil }) == nil
}

func (a *generatedAdmission) terminalResultlessHistoryMatches(c generatedCandidate, hazard contract.GeneratedHazardRecord,
	attempt contract.GeneratedAttemptRecord, templates map[contract.ID]contract.GeneratorAttemptTemplate,
	results map[contract.ID]contract.GeneratedResultRecord, bodies map[contract.ID][]byte, attempts map[contract.ID]contract.GeneratedAttemptRecord) bool {
	var path []contract.GeneratorAttemptTemplate
	for x := templates[attempt.AttemptID]; ; {
		path = append(path, x)
		if x.PredecessorAttemptID.IsZero() {
			break
		}
		previous, ok := templates[x.PredecessorAttemptID]
		if !ok || previous.LineageID != x.LineageID || len(path) >= contract.GeneratorMaxEnteredCreateAttempts {
			return false
		}
		x = previous
	}
	if hazard.History.Count != uint32(len(path)) || attempt.History != hazard.History {
		return false
	}
	for _, owner := range []struct {
		kind uint8
		id   contract.ID
	}{{contract.GeneratedHazardSupportKind, hazard.HazardID}, {contract.GeneratedAttemptSupportKind, attempt.AttemptID}} {
		err := contract.InspectGeneratorSelectedVector(a.graph.Header.DomainID, owner.kind, owner.id,
			contract.GeneratorVectorHistory, hazard.History, c.SupportRecords, func(index uint32, body []byte) error {
				history, err := contract.InspectGeneratorHistory(body)
				x := path[len(path)-int(index)-1]
				if err != nil || history.PredecessorAttemptID != x.AttemptID || history.OwnerID != x.DutyID {
					return contract.ErrRecord
				}
				want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: x.AttemptID, OwnerID: x.DutyID,
					Outcome: contract.GeneratedEffectClosedWithResidue}
				if returned, ok := results[x.AttemptID]; ok {
					if returned.SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect {
						return contract.ErrRecord
					}
					want.Outcome, want.ResultID, want.ResultDigest = contract.GeneratedEffectConfirmedNoEffect, x.ResultID, contract.Hash(bodies[x.AttemptID])
				} else if record := attempts[x.AttemptID]; record.AttemptID.IsZero() || record.State != contract.GeneratedEffectClosedWithResidue {
					return contract.ErrRecord
				}
				if int(index)+1 < len(path) {
					next := path[len(path)-int(index)-2]
					want.Edge = contract.GeneratorGuardResidue
					if want.Outcome == contract.GeneratedEffectConfirmedNoEffect {
						want.Edge = contract.GeneratorGuardQualifiedNoEffect
					}
					branch, present, err := x.SuccessorBranch(want.Edge)
					if err != nil || !present || branch != next.Branch {
						return contract.ErrRecord
					}
					want.NextAttemptID = next.AttemptID
				}
				if history != want {
					return contract.ErrRecord
				}
				return nil
			})
		if err != nil {
			return false
		}
	}
	return true
}

func (a *generatedAdmission) terminalOriginalConsumerMatches(c generatedCandidate, owner contract.SupportRecord, consumers contract.GeneratorDescriptor, x contract.GeneratorAttemptTemplate) bool {
	var use contract.GeneratorResultUse
	for _, candidate := range a.graph.ResultUses {
		if candidate.AttemptID == x.AttemptID {
			use = candidate
		}
	}
	context, err := contract.GeneratorResultUseDigest(use)
	if err != nil {
		return false
	}
	found := false
	err = contract.InspectGeneratorSelectedVector(a.graph.Header.DomainID, owner.Kind, owner.RecordID,
		contract.GeneratorVectorConsumers, consumers, c.SupportRecords, func(_ uint32, body []byte) error {
			consumer, err := contract.InspectGeneratorConsumer(body)
			if err != nil {
				return err
			}
			if consumer.SubjectKind == contract.GeneratorConsumerOriginalResult {
				if found || consumer.SubjectID != x.ResultID || consumer.OwnerID != owner.RecordID ||
					consumer.MaterialID != a.material.Core.OperationMaterialID || consumer.ContextDigest != context ||
					consumer.Purpose != contract.GeneratorConsumerAdoptLateOriginalResult {
					return contract.ErrRecord
				}
				found = true
			}
			return nil
		})
	return err == nil && found
}

func generatedUncertainAttemptMatches(a contract.GeneratedAttemptRecord, x contract.GeneratorAttemptTemplate, domain, operation contract.ID) bool {
	template, err := contract.GeneratorTemplateID(x)
	return err == nil && a.DomainID == domain && a.OperationID == operation && a.LineageID == x.LineageID &&
		a.AttemptID == x.AttemptID && a.TemplateDigest == template && a.PredecessorAttemptID == x.PredecessorAttemptID &&
		a.OwnerID == x.DutyID && a.ResourceID == x.ResourceIncarnationID && a.TransmissionID == x.TransmissionID &&
		a.ResultID == x.ResultID && a.InboxID == x.InboxID && a.DescriptorID == x.DescriptorID && a.ConfigContractID == x.ConfigContractID &&
		a.ExecutorID == x.ExecutorID && a.CredentialRouteID == x.CredentialRouteID && a.ResourceContractID == x.ResourceContractID &&
		a.ResultContractID == x.ResultContractID && a.LifecycleMode == x.LifecycleMode && a.CompletionClass == x.CompletionClass
}

func generatedUncertainHazardMatches(h contract.GeneratedHazardRecord, a contract.GeneratedAttemptRecord, x contract.GeneratorAttemptTemplate) bool {
	return h.HazardID == x.HazardID && h.DomainID == a.DomainID && h.OriginalOperationID == a.OperationID &&
		h.OriginalAttemptID == a.AttemptID && h.OwnerID == a.OwnerID && h.ResourceID == a.ResourceID &&
		h.DescriptorID == a.DescriptorID && h.ConfigContractID == a.ConfigContractID && h.ExecutorID == a.ExecutorID &&
		h.CredentialRouteID == a.CredentialRouteID && h.ResourceContractID == a.ResourceContractID &&
		h.ResultContractID == a.ResultContractID && h.Exposure == contract.GeneratedExposurePossibleLive &&
		h.CompletionClass == a.CompletionClass && h.Fenced == 1 && h.Eligibility == 0 &&
		h.OriginalResults == contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults) &&
		h.Target == contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) && h.History == a.History &&
		h.Support == contract.EmptyGeneratorVector(contract.GeneratorVectorSupport)
}

func (a *generatedAdmission) candidateActiveMatches(c generatedCandidate) bool {
	if c.ActiveOwner.IsZero() {
		return c.ActivePhase.IsZero() && c.ActiveGraph.IsZero()
	}
	if c.ActivePhase.IsZero() || c.ActiveGraph.IsZero() {
		return false
	}
	var parent contract.GeneratedParentRecord
	var phase contract.GeneratedPhaseRecord
	for _, row := range c.SupportRecords {
		var err error
		if row.Kind == contract.GeneratedParentSupportKind && row.RecordID == c.ActiveOwner {
			parent, err = contract.InspectGeneratedParentRecord(row.Body)
		} else if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == c.ActiveOwner {
			phase, err = contract.InspectGeneratedPhaseRecord(row.Body)
		}
		if err != nil {
			return false
		}
	}
	return parent.DomainID == c.Subject.DomainID && parent.OperationID == c.ActiveOwner && parent.PlanGraphID == c.ActiveGraph &&
		phase.DomainID == parent.DomainID && phase.OperationID == c.ActiveOwner && phase.OwnerID == c.ActiveOwner &&
		phase.PlanGraphID == c.ActiveGraph && phase.UsePlanDigest == parent.UsePlanDigest && phase.PhaseID == c.ActivePhase &&
		(c.ActiveOwner != a.graph.Header.OperationID || c.ActiveGraph == a.graph.UsePlan.PlanGraphID && c.ActivePhase == c.Subject.PhaseID && phase.Phase == c.Subject.AfterPhase)
}

func (a *generatedAdmission) candidateControlMatches(current contract.CurrentControl, root contract.ID) bool {
	expected := a.control
	if root != a.request.Context.CurrentAccessRoot {
		if !contract.IncarnationCounterStep(expected.AccessIncarnationID, expected.AccessGeneration, current.AccessIncarnationID, current.AccessGeneration) {
			return false
		}
		expected.AccessGeneration = current.AccessGeneration
		expected.AccessIncarnationID = current.AccessIncarnationID
	}
	actual := contract.ControlCore{CurrentControl: current, AuthorityKMSBinding: a.control.AuthorityKMSBinding}
	x, err := contract.EncodeControlCore(expected)
	if err != nil {
		return false
	}
	y, err := contract.EncodeControlCore(actual)
	return err == nil && bytes.Equal(x, y)
}

func (a *generatedAdmission) candidateEntriesMatch(c generatedCandidate) bool {
	expected := a.before.Rows
	if a.purpose.final != nil && c.Subject.Purpose != contract.GeneratorAuthorityFinalPreparation {
		var ok bool
		expected, ok = a.preparedPublicStateRows(c)
		if !ok {
			return false
		}
	}
	if len(c.Entries) != len(c.PublicState.Rows) || !slices.Equal(c.PublicState.Rows, expected) {
		return false
	}
	for i, row := range c.PublicState.Rows {
		candidateEntry := c.Entries[i]
		digest, err := contract.PublicValueEntryDigest(c.PublicState.Domain, candidateEntry.Slot, candidateEntry.Entry)
		if err != nil || candidateEntry.Slot != row.Slot || candidateEntry.Entry.Name != row.Name || digest != row.EntryDigest {
			return false
		}
	}
	return true
}

func (a *generatedAdmission) candidateMaterialMatches(c generatedCandidate) bool {
	material, parent, access := false, false, false
	for _, row := range c.SupportRecords {
		switch {
		case row.Kind == contract.OperationMaterialSupportKind && row.RecordID == a.request.MaterialID:
			v, err := contract.InspectOperationMaterialRecord(row.Body)
			if err != nil || v != a.material {
				return false
			}
			material = true
		case row.Kind == contract.GeneratedParentSupportKind && row.RecordID == a.graph.Header.OperationID:
			v, err := contract.InspectGeneratedParentRecord(row.Body)
			want := a.request.Parent
			if a.purpose.reservation != nil {
				want = contract.GeneratedParentRecord(a.request.ParentPlan)
				want.RequestIdentityDigest = c.Subject.RequestIdentityDigest
			}
			if err != nil || v != want {
				return false
			}
			parent = true
		}
	}
	for _, row := range c.AccessRecords {
		if row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == a.request.MaterialID {
			if !sameAccessRecord(a.access, row) {
				return false
			}
			access = true
		}
	}
	return material && parent && access || a.purpose.final != nil && !parent && (material == access)
}

func (a *generatedAdmission) candidateResultMatches(c generatedCandidate) bool {
	if a.purpose.adoption != nil && a.purpose.adoption.localFailure != nil {
		return a.candidateLocalFailureMatches(c)
	}
	adoption := a.purpose.adoption
	if adoption == nil || len(adoption.validated) != 1 || len(adoption.results) != 1 {
		return false
	}
	ref, expected := adoption.validated[0], adoption.results[0].Expected
	s := c.Subject
	if s.LineageID != expected.Template.LineageID || s.AttemptID != expected.Template.AttemptID ||
		s.ResultID != ref.ResultID || s.ResultDigest != ref.ResultBodyDigest || s.DescriptorID != expected.Template.DescriptorID ||
		s.ConfigContractID != expected.Template.ConfigContractID || s.ResultContractID != expected.Template.ResultContractID {
		return false
	}
	for _, row := range c.SupportRecords {
		if row.Kind == contract.GeneratedResultSupportKind && row.RecordID == ref.ResultID {
			return len(row.Body) == int(ref.ResultLength) && contract.Hash(row.Body) == ref.ResultBodyDigest
		}
	}
	return false
}

func (a *generatedAdmission) candidateProtectionsMatch(c generatedCandidate, snapshot contract.ID) bool {
	plan := a.purpose.plan()
	if plan == nil || !generatedSourceSubset(c.LiveSourceUses, plan.liveSources) || a.purpose.final == nil && !slices.Equal(c.LiveSourceUses, plan.liveSources) ||
		c.ActiveOwner == a.graph.Header.OperationID && a.selectionPhase == nil && !a.firstAutomaticSelection(c) && !slices.Equal(c.LiveSourceUses, a.graph.SourceUses) {
		return false
	}
	var protection contract.DigestLength
	if len(c.LiveSourceUses) == 0 {
		if len(c.SourceProtections) != 0 {
			return false
		}
	} else {
		protection = contract.DigestLength{Digest: contract.Hash(c.SourceProtections), Length: uint64(len(c.SourceProtections))}
		view, err := contract.InspectGeneratedSourceProtections(a.material, c.SourceProtections)
		if err != nil || view.Count() != len(c.LiveSourceUses) {
			return false
		}
		if a.purpose.reservation != nil {
			if protection != plan.protection {
				return false
			}
		} else {
			before, err := contract.InspectGeneratedSourceProtections(a.material, plan.protections)
			if err != nil {
				return false
			}
			for i := 0; i < view.Count(); i++ {
				row, err := view.Row(i)
				if err != nil || row.SourceID != c.LiveSourceUses[i].SourceID {
					return false
				}
				found := false
				for j := 0; j < before.Count(); j++ {
					original, err := before.Row(j)
					if err != nil {
						return false
					}
					if row.SourceID != original.SourceID {
						continue
					}
					found = row.OriginalSourceCoreDigest == original.OriginalSourceCoreDigest && row.OriginalEnvelopeDigest == original.OriginalEnvelopeDigest &&
						row.Transfer.Core == original.Transfer.Core && row.Transfer.Nonce == original.Transfer.Nonce && bytes.Equal(row.Transfer.Ciphertext, original.Transfer.Ciphertext)
					break
				}
				if !found {
					return false
				}
			}
		}
	}
	want := contract.GeneratorLogicalSlice{Schema: 1, ContentKind: contract.GeneratorContentConfiguration, ContentID: a.request.MaterialID,
		Length: uint32(protection.Length), Digest: protection.Digest}
	found := 0
	var descriptor contract.GeneratorDescriptor
	var slicesRows [][]byte
	for _, row := range c.SupportRecords {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return false
		}
		if carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.OwnerID != snapshot || carrier.VectorKind != contract.GeneratorVectorSlices {
			continue
		}
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil || id != row.RecordID || carrier.DomainID != a.request.Context.DomainID || uint64(carrier.Vector.Count) > uint64(len(c.SupportRecords)) {
			return false
		}
		if slicesRows == nil {
			descriptor, slicesRows = carrier.Vector, make([][]byte, carrier.Vector.Count)
		}
		if carrier.Vector != descriptor || int(carrier.Ordinal) >= len(slicesRows) || slicesRows[carrier.Ordinal] != nil {
			return false
		}
		slicesRows[carrier.Ordinal] = carrier.Row
		location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			return false
		}
		if location.ContentKind == want.ContentKind && location.ContentID == want.ContentID {
			if location.Logical() != want {
				return false
			}
			found++
		}
	}
	if slicesRows != nil {
		actual, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, slicesRows)
		if err != nil || actual != descriptor {
			return false
		}
	}
	return len(c.LiveSourceUses) == 0 && found == 0 || len(c.LiveSourceUses) != 0 && found == 1
}

func generatedSourceSubset(rows, admitted []contract.GeneratorSourceUse) bool {
	if len(rows) > len(admitted) {
		return false
	}
	index := 0
	for _, row := range admitted {
		if index < len(rows) && rows[index] == row {
			index++
		}
	}
	return index == len(rows)
}

func (r *Runtime) retireGenerated() {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.generated
	r.mu.Unlock()
	if a != nil {
		r.retireSession(a.session)
	}
}
