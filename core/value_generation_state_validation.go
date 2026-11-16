package core

import (
	"context"
	"maps"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A claimed reservation has already validated this immutable selected image.
// Parallel original preparation may read it without rebuilding the session's
// cache from several goroutines.
func (s *StateSession) cachedGeneratedSelectionValid() bool {
	if s == nil || s.generatedWork == nil || s.generatedWork.session != s || s.generatedWork.selection == nil {
		return false
	}
	root, ok := s.generatedSelectionRoot()
	return ok && s.generatedWork.root == root
}

// HEAD supplies authority over the before-state checks. Cold verification
// reconstructs the entire selected after-state without fetching old roots or
// restoring a producer's first-send permission.
func (s *StateSession) validateGeneratedSelection(ctx context.Context, reused *generatedSelection) error {
	if s == nil {
		return contract.ErrRecord
	}
	image, err := s.completeSelectedImage(ctx)
	if err != nil {
		return err
	}
	_, ok := selectedGeneratedPreflight(s.head, image)
	if !ok {
		return contract.ErrRecord
	}
	g := reused
	if g == nil {
		g, err = s.selectedGeneratedWork(ctx)
		if err != nil {
			return err
		}
	} else if g.session != s || g.content == nil {
		return contract.ErrRecord
	}
	proof := selectedGeneratedProof{selectedImage: image, head: s.head, validated: &generatedImageValidation{facts: g}}
	if err := proof.validateGeneratedSelection(ctx); err != nil {
		return err
	}
	root, ok := s.generatedSelectionRoot()
	if !ok {
		return contract.ErrRecord
	}
	s.generatedGraphs = maps.Clone(g.content.graphs)
	s.generatedWork = &validatedGeneratedSelection{session: s, root: root, selection: g}
	return nil
}
func selectedGeneratedPreflight(head format.Head, image *selectedImage) (contract.GeneratorAuthoritySubject, bool) {
	if image == nil || head.AuthKind != format.GeneratorAuth || head.Generator == nil {
		return contract.GeneratorAuthoritySubject{}, false
	}
	subject := *head.Generator
	if _, err := contract.NewGeneratorRequest(subject); err != nil || subject.DomainID != image.root.Domain || subject.AfterRootDigest != head.Core.Root.Digest || subject.AfterAccessDigest != image.root.CurrentAccess.AccessRoot || subject.PreviousHEADDigest != head.Core.PreviousDigest || subject.PreviousRevisionID != head.Core.PreviousRevision {
		return subject, false
	}
	work, err := selectedWorkSupportRecords(image)
	if err != nil {
		return subject, false
	}
	descriptor, err := image.workSupportDescriptor(work)
	return subject, err == nil && descriptor == subject.AfterWork
}
func (p *selectedGeneratedProof) validateGeneratedSelection(ctx context.Context) error {
	if p == nil || p.selectedImage == nil || p.validated == nil || p.validated.facts == nil {
		return contract.ErrRecord
	}
	s := p
	g := p.validated.facts
	subject, ok := selectedGeneratedPreflight(p.head, p.selectedImage)
	if !ok {
		return contract.ErrRecord
	}
	if !newGeneratedCoverageValidation(g).consume(p.generatedCoverageRecords()) {
		return contract.ErrRecord
	}
	var err error
	if (subject.Purpose == contract.GeneratorAuthorityRetireClose || subject.Purpose == contract.GeneratorAuthorityRecord) && s.validGeneratedAutomaticCloseSelection(ctx, g, subject) {
		return nil
	}
	if subject.Purpose == contract.GeneratorAuthorityResidue && g.parent == nil && g.phase == nil {
		if !s.validGeneratedRetirementResidueSelection(g, subject) {
			return contract.ErrRecord
		}
		return nil
	}
	if subject.Purpose == contract.GeneratorAuthorityRecord && g.parent == nil && g.phase == nil {
		if g.generatedOrdinaryCleanupAmbiguityOwner(subject.OwnerID) {
			return s.validateGeneratedOrdinaryCleanupAmbiguitySelection(ctx, g, subject)
		}
		if !s.validGeneratedRetirementAmbiguitySelection(g, subject, false) {
			return contract.ErrRecord
		}
		return nil
	}
	if subject.Purpose == contract.GeneratorAuthorityReflection && g.parent == nil && g.phase == nil {
		if !s.validGeneratedReflectionSelection(g, subject) {
			return contract.ErrRecord
		}
		return nil
	}
	if subject.Purpose == contract.GeneratorAuthorityCleanupClose && g.parent == nil && g.phase == nil {
		if !s.validGeneratedCleanupCloseSelection(g, subject) {
			return contract.ErrRecord
		}
		return nil
	}
	if subject.Purpose == contract.GeneratorAuthorityRetireClose && g.parent == nil && g.phase == nil {
		if !s.validGeneratedRetirementCloseSelection(g, subject) {
			return contract.ErrRecord
		}
		return nil
	}
	if subject.Purpose == contract.GeneratorAuthorityInboxRelease {
		if !s.validGeneratedInboxReleaseSelection(g, subject) {
			return contract.ErrRecord
		}
		return nil
	}
	if subject.Purpose == contract.GeneratorAuthorityFinal {
		return s.validateGeneratedFinalSelection(ctx, g, subject)
	}
	if subject.Purpose == contract.GeneratorAuthorityFinalPreparation {
		return s.validateGeneratedFinalPreparationSelection(ctx, g, subject)
	}
	if subject.Purpose == contract.GeneratorAuthorityRetireReserve || subject.Purpose == contract.GeneratorAuthorityCleanupReserve {
		return s.validateGeneratedDeleteReservationSelection(ctx, g, subject)
	}
	if g.parent == nil || g.phase == nil || subject.OwnerID != g.parent.OperationID ||
		subject.OperationID != g.parent.OperationID || subject.RequestIdentityDigest != g.parent.RequestIdentityDigest ||
		subject.PlanGraphID != g.parent.PlanGraphID || subject.UsePlanDigest != g.parent.UsePlanDigest || subject.PhaseID != g.phase.PhaseID ||
		subject.AfterPhase != g.phase.Phase || subject.Intent != g.parent.Declaration || subject.CapacityReservation != g.parent.Capacity {
		return contract.ErrRecord
	}
	if subject.BeforePhase == 0 {
		if subject.Purpose != contract.GeneratorAuthorityReservation || subject.AfterPhase != 1 {
			return contract.ErrRecord
		}
		initial, err := s.generatedInitialIdentity(g)
		if err != nil || initial.RequestIdentityDigest != subject.RequestIdentityDigest || initial.Plan != subject.IdentityPlan {
			return contract.ErrRecord
		}
	} else if subject.Purpose != contract.GeneratorAuthorityReservation && subject.Purpose != contract.GeneratorAuthorityRecord && subject.Purpose != contract.GeneratorAuthorityNoEffectBranch &&
		subject.Purpose != contract.GeneratorAuthorityResidue && subject.Purpose != contract.GeneratorAuthorityFailedTerminal {
		return contract.ErrRecord
	}
	var declaration []byte
	if g.content.fragmentFacts != nil {
		declaration, err = g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	} else {
		declaration, err = g.content.read(contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	}
	if err != nil {
		return err
	}
	planned, err := s.generatedMembershipPlan(g.bundles[0], declaration)
	if err != nil || subject.RequiredAuthoritySet != generatedMembershipAuthority(planned) {
		return contract.ErrRecord
	}
	membership, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, planned)
	if err != nil || membership != subject.MembershipChanges {
		return contract.ErrRecord
	}
	entryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, s.generatedUnchangedEntryUnion())
	if err != nil || entryUnion != subject.ValueEntryUnion {
		return contract.ErrRecord
	}
	if subject.BeforePhase != 0 {
		if subject.Purpose == contract.GeneratorAuthorityReservation {
			if !s.validGeneratedSuccessorReservationSelection(g, subject) {
				return contract.ErrRecord
			}
			return nil
		}
		if subject.Purpose == contract.GeneratorAuthorityResidue {
			if !s.validGeneratedCreateResidueSelection(g, subject) {
				return contract.ErrRecord
			}
			return nil
		}
		if !s.validGeneratedRecordSelection(g, subject) {
			return contract.ErrRecord
		}
		return nil
	}
	results, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil || subject.ResultVector != contract.GeneratorDescriptor(results) || !subject.LineageID.IsZero() || !subject.AttemptID.IsZero() ||
		!subject.PredecessorAttemptID.IsZero() || !subject.ResultID.IsZero() || !subject.ResultDigest.IsZero() || !subject.ConfigContractID.IsZero() ||
		!subject.DescriptorID.IsZero() || !subject.ResultContractID.IsZero() {
		return contract.ErrRecord
	}
	return nil
}

func (s *selectedGeneratedProof) validGeneratedCreateResidueSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	a, ok := g.attempts[subject.AttemptID]
	if !ok || len(a.result) != 0 || a.record.State != contract.GeneratedEffectClosedWithResidue ||
		a.record.Stage != contract.GeneratedStageTerminal || subject.BeforeAccessDigest != subject.AfterAccessDigest || !subject.ResultDigest.IsZero() {
		return false
	}
	x := a.expected.Template
	if subject.LineageID != x.LineageID || subject.PredecessorAttemptID != x.PredecessorAttemptID || subject.ResultID != x.ResultID ||
		subject.ConfigContractID != x.ConfigContractID || subject.DescriptorID != x.DescriptorID || subject.ResultContractID != x.ResultContractID {
		return false
	}
	hazardRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: x.HazardID}]
	if !ok {
		return false
	}
	hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
	if err != nil || hazard.OriginalOperationID != a.record.OperationID || hazard.OriginalAttemptID != a.record.AttemptID ||
		hazard.OwnerID != a.record.OwnerID || hazard.Fenced != 1 {
		return false
	}
	if !g.phase.AcceptedResultID.IsZero() || !g.phase.ResultDigest.IsZero() || g.phase.OperationID != a.record.OperationID {
		return false
	}
	branch, successor, err := contract.GeneratorSuccessorBranch(x.Branch, contract.GeneratorGuardResidue)
	if err != nil {
		return false
	}
	if successor {
		if int(g.phase.LineageIndex) >= len(g.bundles[0].Lineages) {
			return false
		}
		lineage := g.bundles[0].Lineages[g.phase.LineageIndex]
		if lineage.LineageID != a.record.LineageID || branch >= lineage.TemplateCount ||
			g.phase.FrontierAttemptID != lineage.Templates[branch].AttemptID || g.phase.Branch != branch ||
			g.phase.Stage != contract.GeneratedStageRetainedResult || g.phase.ResidueUsed != 1 ||
			g.phase.NoEffectUsed != boolByte(branch >= contract.GeneratorBranchNoEffectThenResidue) {
			return false
		}
	} else if index, next, present := generatedNextOriginalAfter(g, a.record.LineageID); present {
		pending, entered := g.attempts[next.AttemptID]
		if !entered || !pending.awaitingResult() ||
			g.phase.LineageIndex != index || g.phase.FrontierAttemptID != next.AttemptID || g.phase.Branch != contract.GeneratorBranchInitial ||
			g.phase.Stage != contract.GeneratedStageRetainedResult || g.phase.NoEffectUsed != 0 || g.phase.ResidueUsed != 0 {
			return false
		}
	} else if g.phase.FrontierAttemptID != a.record.AttemptID || g.phase.Branch != x.Branch ||
		g.phase.Stage != contract.GeneratedStageTerminal || g.phase.ResidueUsed != 1 {
		return false
	}
	evidence, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseHazards, s.root.Domain, []contract.SupportRecord{hazardRow})
	if err != nil {
		return false
	}
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil || subject.ResultVector != contract.GeneratorDescriptor(empty) {
		return false
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest, TransitionKind: subject.Purpose,
		BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: evidence})
	if err != nil || phase != subject.PhaseID {
		return false
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil || snapshot != s.root.Snapshot {
		return false
	}
	transition, err := contract.GeneratorPhaseTransitionID(phase)
	if err != nil || transition != s.root.Transition {
		return false
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil || revision != s.head.Core.Revision {
		return false
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: snapshot, Transition: transition, Revision: revision}
	for _, ref := range s.root.RequiredSupport {
		position := slices.Index(s.root.RequiredSupport, ref)
		if position >= 0 && position < len(s.support) {
			rows := make([]contract.SupportRecord, len(s.support[position].Records))
			for i, row := range s.support[position].Records {
				rows[i] = contract.SupportRecord(row)
			}
			if retained, ok := s.retainedOutputPage(rows); ok && retained.ref == ref {
				identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				continue
			}
		}
		id, err := contract.GeneratorPhasePageID(phase, contract.RequiredSupportKind, ref.Index)
		if err != nil || id != ref.Object {
			return false
		}
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	return err == nil && descriptor == subject.IdentityPlan
}

func (s *selectedGeneratedProof) validateGeneratedFinalSelection(ctx context.Context, g *generatedSelection, subject contract.GeneratorAuthoritySubject) error {
	enclosed := generatedSelectionAnchored(g) && g.phase.SelectionPhaseID == subject.PhaseID && g.phase.PhaseID == subject.PhaseID &&
		g.phase.Phase == subject.AfterPhase && g.parent.OperationID == subject.OperationID && g.parent.RequestIdentityDigest == subject.RequestIdentityDigest &&
		len(contract.GeneratedAutomaticRetirementIndices(g.bundles[0])) != 0
	if g == nil || (!enclosed && (g.parent != nil || g.phase != nil || !s.root.Generated.ActiveOwner.IsZero() ||
		!s.root.Generated.ActivePhase.IsZero() || !s.root.Generated.ActiveGraph.IsZero())) ||
		subject.OwnerID != subject.OperationID || subject.BeforePhase == 0 ||
		!subject.LineageID.IsZero() || !subject.AttemptID.IsZero() || !subject.PredecessorAttemptID.IsZero() ||
		!subject.ResultID.IsZero() || !subject.ResultDigest.IsZero() || !subject.ConfigContractID.IsZero() ||
		!subject.DescriptorID.IsZero() || !subject.ResultContractID.IsZero() {
		return contract.ErrRecord
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest,
		TransitionKind: subject.Purpose, BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase,
		Evidence: subject.ResultVector})
	if err != nil || phase != subject.PhaseID {
		return contract.ErrRecord
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil || snapshot != s.root.Snapshot {
		return contract.ErrRecord
	}
	transition, err := contract.GeneratorPhaseTransitionID(phase)
	if err != nil || transition != s.root.Transition {
		return contract.ErrRecord
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil || revision != s.head.Core.Revision {
		return contract.ErrRecord
	}
	plan := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: snapshot, Transition: transition, Revision: revision}
	for _, ref := range s.root.Recipients {
		if ref != nil {
			id, e := contract.GeneratorPhasePageID(phase, contract.RecipientKind, ref.Index)
			if e == nil && id == ref.Object {
				plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
			}
		}
	}
	for i, ref := range s.root.ValueEntryPages {
		if ref != nil {
			plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: uint16(i), Object: ref.Object})
		}
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	for _, ref := range s.root.RequiredSupport {
		position := slices.Index(s.root.RequiredSupport, ref)
		if position >= 0 && position < len(s.support) {
			rows := make([]contract.SupportRecord, len(s.support[position].Records))
			for i, row := range s.support[position].Records {
				rows[i] = contract.SupportRecord(row)
			}
			if retained, ok := s.retainedOutputPage(rows); ok && retained.ref == ref {
				plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				continue
			}
		}
		id, err := contract.GeneratorPhasePageID(phase, contract.RequiredSupportKind, ref.Index)
		if err != nil || id != ref.Object {
			return contract.ErrRecord
		}
		plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	slices.SortFunc(plan.Pages, func(a, b contract.IdentityPage) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return int(a.Index) - int(b.Index)
	})
	d, err := contract.GeneratorAuthorityIdentityDescriptor(plan)
	if err != nil || d != subject.IdentityPlan {
		return contract.ErrRecord
	}
	selected := make(map[contract.ID]bool)
	for _, entry := range s.root.Names {
		valueEntry := s.valueEntry(entry.Slot)
		if valueEntry != nil && valueEntry.ValueSource == contract.Generated && valueEntry.Generated.OriginOperationID == subject.OperationID {
			selected[valueEntry.Generated.CreateResultID] = true
		}
	}
	if len(selected) > 0 {
		if uint32(len(selected)) > subject.ResultVector.Count {
			return contract.ErrRecord
		}
		if enclosed {
			return nil
		}
		return s.validateGeneratedFinalReceipt(ctx, subject, true)
	}
	entryUnionRows := s.generatedUnchangedEntryUnion()
	actualEntryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, entryUnionRows)
	if err != nil || actualEntryUnion != subject.ValueEntryUnion {
		return contract.ErrRecord
	}
	for i := range entryUnionRows {
		entryUnionRows[i].After.EntryDigest = contract.ID{}
	}
	membership, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, entryUnionRows)
	if err != nil || membership != subject.MembershipChanges {
		return contract.ErrRecord
	}
	if subject.ResultVector.Count > 0 {
		return s.validateGeneratedFinalReceipt(ctx, subject, false)
	}
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err == nil && subject.ResultVector == contract.GeneratorDescriptor(empty) {
		return s.validateGeneratedFinalReceipt(ctx, subject, false)
	}
	return contract.ErrRecord
}

func (s *selectedGeneratedProof) validateGeneratedFinalReceipt(ctx context.Context, subject contract.GeneratorAuthoritySubject, selected bool) error {
	var ownHazards uint32
	for _, row := range s.supportRecords() {
		if row.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil || hazard.DomainID != s.root.Domain || hazard.HazardID != row.RecordID {
			return contract.ErrRecord
		}
		if hazard.OriginalOperationID == subject.OperationID {
			ownHazards++
		}
	}
	validReceipt := func(receipt contract.CompactMutationReceipt) bool {
		if receipt.RequestIdentityDigest != subject.RequestIdentityDigest || receipt.RequestedRevisionID != s.head.Core.Revision {
			return false
		}
		domainWarnings, _, err := contract.DecodeReceiptWarningBits(receipt.OperationKind, receipt.WarningBits)
		if subject.ResultVector.Count == 0 {
			empty, emptyErr := contract.GeneratorResultReferencesDescriptor(nil)
			counts := receipt.SummaryCounts
			failures := counts[contract.ReceiptSummaryFailureCount]
			if emptyErr != nil || subject.ResultVector != contract.GeneratorDescriptor(empty) || selected ||
				receipt.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || receipt.ObservedRevisionID != subject.PreviousRevisionID ||
				receipt.AcknowledgedCount != 0 || receipt.ConfirmedCount != 0 || receipt.UnknownCount != ownHazards {
				return false
			}
			if ownHazards == 0 {
				if failures == 0 || counts[contract.ReceiptEffectCount] != failures {
					return false
				}
			} else if uint64(counts[contract.ReceiptEffectCount]) != uint64(failures)+uint64(ownHazards)+uint64(counts[contract.ReceiptNoEffectPredecessorCount]) {
				return false
			}
		}
		return err == nil && domainWarnings == s.root.WarningBits &&
			(receipt.ChangedSubjects.Count != 0 || !selected) &&
			receipt.SummaryCounts[contract.ReceiptEffectCount] >= subject.ResultVector.Count &&
			selected == (receipt.CanonicalOutcome == contract.ReceiptCanonicalSelected) &&
			receipt.SummaryCounts[contract.ReceiptHazardCount] == ownHazards &&
			(ownHazards == 0 || receipt.WarningBits&contract.ReceiptWarningPossibleLive != 0)
	}
	windows, err := s.receiptWindows(ctx)
	if err != nil {
		return err
	}
	for _, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, receipt := range rows {
			if receipt.OperationID == subject.OperationID {
				if !validReceipt(receipt) {
					return contract.ErrRecord
				}
				return nil
			}
		}
	}
	return contract.ErrRecord
}

func (s *selectedGeneratedProof) validGeneratedRecordSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	a, ok := g.attempts[subject.AttemptID]
	failed := subject.Purpose == contract.GeneratorAuthorityFailedTerminal
	if !ok || !failed && len(a.result) == 0 || failed && !generatedLocalFailureAttempt(a) || !s.validGeneratedRecordFrontier(g, a, subject) || subject.BeforeAccessDigest != subject.AfterAccessDigest {
		return false
	}
	x := a.expected.Template
	if subject.LineageID != x.LineageID || subject.PredecessorAttemptID != x.PredecessorAttemptID || subject.ResultID != x.ResultID ||
		subject.ConfigContractID != x.ConfigContractID || subject.DescriptorID != x.DescriptorID || subject.ResultContractID != x.ResultContractID || !failed && contract.Hash(a.result) != subject.ResultDigest || failed && !subject.ResultDigest.IsZero() {
		return false
	}
	var references []contract.GeneratorResultReference
	evidence := contract.GeneratorDescriptor{Digest: subject.ResultDigest, Length: uint64(len(a.result)), Count: 1}
	if failed {
		body, err := contract.EncodeGeneratedAttemptRecord(a.record)
		if err != nil || len(body) != 760 {
			return false
		}
		evidence = contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: uint64(len(body)), Count: 1}
	} else {
		references = []contract.GeneratorResultReference{{Schema: 1, ResultID: subject.ResultID, ResultBodyDigest: subject.ResultDigest, ResultLength: uint32(len(a.result))}}
	}
	results, err := contract.GeneratorResultReferencesDescriptor(references)
	if err != nil || contract.GeneratorDescriptor(results) != subject.ResultVector {
		return false
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest, TransitionKind: subject.Purpose,
		BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase,
		Evidence: evidence})
	if err != nil || phase != subject.PhaseID {
		return false
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil || snapshot != s.root.Snapshot {
		return false
	}
	transition, err := contract.GeneratorPhaseTransitionID(phase)
	if err != nil || transition != s.root.Transition {
		return false
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil || revision != s.head.Core.Revision {
		return false
	}
	plan := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: snapshot, Transition: transition, Revision: revision}
	for _, ref := range s.root.RequiredSupport {
		position := slices.Index(s.root.RequiredSupport, ref)
		if position >= 0 && position < len(s.support) {
			rows := make([]contract.SupportRecord, len(s.support[position].Records))
			for i, row := range s.support[position].Records {
				rows[i] = contract.SupportRecord(row)
			}
			if retained, ok := s.retainedOutputPage(rows); ok && retained.ref == ref {
				plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				continue
			}
		}
		id, err := contract.GeneratorPhasePageID(phase, contract.RequiredSupportKind, ref.Index)
		if err != nil || id != ref.Object {
			return false
		}
		plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	d, err := contract.GeneratorAuthorityIdentityDescriptor(plan)
	return err == nil && d == subject.IdentityPlan
}

func (s *selectedGeneratedProof) validGeneratedRecordFrontier(g *generatedSelection, recorded generatedAttempt, subject contract.GeneratorAuthoritySubject) bool {
	if subject.Purpose == contract.GeneratorAuthorityFailedTerminal {
		if !generatedLocalFailureAttempt(recorded) || !g.phase.AcceptedResultID.IsZero() || !g.phase.ResultDigest.IsZero() ||
			g.phase.Branch != contract.GeneratorBranchInitial || g.phase.NoEffectUsed != 0 || g.phase.ResidueUsed != 0 {
			return false
		}
		index, next, ok := generatedNextOriginalAfter(g, recorded.record.LineageID)
		if !ok {
			return g.phase.FrontierAttemptID == recorded.record.AttemptID && g.phase.Stage == contract.GeneratedStageTerminal
		}
		return g.phase.LineageIndex == index && g.phase.FrontierAttemptID == next.AttemptID && g.phase.Stage == contract.GeneratedStageRetainedResult
	}
	terminal := g.phase.AcceptedResultID == subject.ResultID && g.phase.ResultDigest == subject.ResultDigest &&
		g.phase.FrontierAttemptID == subject.AttemptID && g.phase.Stage == contract.GeneratedStageTerminal
	if recorded.expected.Template.Action == contract.GeneratorActionDelete {
		return subject.Purpose == contract.GeneratorAuthorityRecord && terminal
	}
	result, err := contract.InspectGeneratedResultRecord(recorded.result)
	if err != nil || result.SafeFacts.Disposition < contract.GeneratorDispositionCompleteCreate || result.SafeFacts.Disposition > contract.GeneratorDispositionConfirmedNoEffect {
		return false
	}
	if result.SafeFacts.Disposition == contract.GeneratorDispositionConfirmedNoEffect {
		if subject.Purpose != contract.GeneratorAuthorityNoEffectBranch {
			return false
		}
		next, _, ok := generatedNextNoEffect(g, recorded.expected.Template)
		if ok {
			residue := uint8(0)
			if next.Branch >= contract.GeneratorBranchResidue {
				residue = 1
			}
			return g.phase.AcceptedResultID.IsZero() && g.phase.ResultDigest.IsZero() && g.phase.Stage == contract.GeneratedStageRetainedResult &&
				g.phase.LineageIndex < uint16(len(g.bundles[0].Lineages)) &&
				g.bundles[0].Lineages[g.phase.LineageIndex].LineageID == recorded.record.LineageID &&
				g.phase.Branch == next.Branch && g.phase.NoEffectUsed == 1 && g.phase.ResidueUsed == residue &&
				g.phase.FrontierAttemptID == next.AttemptID
		}
	} else if subject.Purpose != contract.GeneratorAuthorityRecord {
		return false
	}
	index, next, ok := generatedNextOriginalAfter(g, recorded.record.LineageID)
	if !ok {
		return terminal
	}
	return g.phase.AcceptedResultID.IsZero() && g.phase.ResultDigest.IsZero() && g.phase.Stage == contract.GeneratedStageRetainedResult &&
		g.phase.LineageIndex == index && g.phase.Branch == contract.GeneratorBranchInitial && g.phase.NoEffectUsed == 0 && g.phase.ResidueUsed == 0 &&
		g.phase.FrontierAttemptID == next.AttemptID
}

func (s *selectedGeneratedProof) generatedInitialIdentity(g *generatedSelection) (format.GeneratorInitialIdentity, error) {
	parent := contract.GeneratedParentPlan(*g.parent)
	parent.RequestIdentityDigest = contract.ID{}
	planned, err := contract.AppendGeneratedParentSupportPlan(nil, parent)
	if err != nil {
		return format.GeneratorInitialIdentity{}, err
	}
	root := s.root
	root.RequiredSupport = slices.Clone(root.RequiredSupport)
	root.AdministrativeIndexShards = slices.Clone(root.AdministrativeIndexShards)
	pages := make([]format.RequiredSupportPage, len(s.support))
	var opaque []format.GeneratorInitialOpaqueFragmentPage
	if s.fragmentFacts != nil {
		selectedRoot, ok := s.generatedSelectionRoot()
		if !ok || s.generatedSlicesRoot != selectedRoot || len(s.supportFacts) != len(s.support) {
			return format.GeneratorInitialIdentity{}, contract.ErrRecord
		}
		opaque = make([]format.GeneratorInitialOpaqueFragmentPage, len(s.support))
	}
	for i, page := range s.support {
		p := format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: make([]contract.SupportRecord, len(page.Records))}
		if opaque != nil && len(page.Records) != 0 && page.Records[0].Kind == contract.GeneratedFragmentSupportKind {
			facts := s.supportFacts[i]
			if facts.ref != root.RequiredSupport[i] || len(facts.rows) != len(page.Records) || len(facts.rows) != len(facts.ordinals) {
				return format.GeneratorInitialIdentity{}, contract.ErrRecord
			}
			for j, row := range page.Records {
				if row.Kind != contract.GeneratedFragmentSupportKind || row.RecordID != facts.rows[j].RecordID() || row.Body != nil {
					return format.GeneratorInitialIdentity{}, contract.ErrRecord
				}
			}
			p.Records = nil
			opaque[i] = format.GeneratorInitialOpaqueFragmentPage{Ref: facts.ref, Rows: slices.Clone(facts.rows)}
			pages[i] = p
			continue
		}
		parentPage := false
		for j, row := range page.Records {
			p.Records[j] = contract.SupportRecord(row)
			if row.Kind == contract.GeneratedParentSupportKind && row.RecordID == parent.OperationID {
				parentPage = true
				p.Records[j].Body = planned[contract.SupportRecordOverhead:]
			}
		}
		if parentPage {
			body, err := format.EncodeRequiredSupportParentPlan(p, parent)
			if err != nil {
				return format.GeneratorInitialIdentity{}, err
			}
			root.RequiredSupport[i].Digest = contract.Hash(body)
		}
		pages[i] = p
	}
	projectedIndex := s.adminIndex
	projectedIndex.Pages = slices.Clone(s.adminIndex.Pages)
	if len(projectedIndex.Pages) != len(root.RequiredSupport) {
		return format.GeneratorInitialIdentity{}, contract.ErrRecord
	}
	for i := range projectedIndex.Pages {
		projectedIndex.Pages[i].Ref = root.RequiredSupport[i]
	}
	projectedIndexPages, err := format.EncodeAdministrativeIndexPages(projectedIndex)
	if err != nil || len(projectedIndexPages) != 1+len(root.AdministrativeIndexShards) {
		return format.GeneratorInitialIdentity{}, contract.ErrRecord
	}
	root.ChildEncodedBytes = s.root.ChildEncodedBytes - uint64(s.root.AdministrativeIndex.Length) + uint64(projectedIndexPages[0].Ref.Length)
	root.AdministrativeIndex = projectedIndexPages[0].Ref
	for i, shard := range projectedIndexPages[1:] {
		root.ChildEncodedBytes += uint64(shard.Ref.Length) - uint64(root.AdministrativeIndexShards[i].Length)
		root.AdministrativeIndexShards[i] = shard.Ref
	}
	var access []format.AccessPage
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		if s.access[ref.Index] == nil {
			return format.GeneratorInitialIdentity{}, contract.ErrRecord
		}
		access = append(access, *s.access[ref.Index])
	}
	material, err := contract.InspectOperationMaterialRecord(g.records[generatedRecordKey{contract.OperationMaterialSupportKind, parent.MaterialID}].Body)
	if err != nil {
		return format.GeneratorInitialIdentity{}, err
	}
	head := s.head.Core
	head.Root.Digest = contract.ID{}
	body, err := format.EncodeHeadPlan(format.HeadPlan(head))
	if err != nil {
		return format.GeneratorInitialIdentity{}, err
	}
	var retainedSupport []format.Ref
	selectedPages := pages[:0]
	selectedOpaque := opaque[:0]
	for i, page := range pages {
		if retained, ok := s.retainedOutputPage(page.Records); ok && retained.ref == root.RequiredSupport[i] {
			retainedSupport = append(retainedSupport, retained.ref)
			continue
		}
		selectedPages = append(selectedPages, page)
		if opaque != nil {
			selectedOpaque = append(selectedOpaque, opaque[i])
		}
	}
	plan := format.GeneratorInitialReservationPlan{Request: g.bundles[0].Request, Parent: parent, Material: material, Snapshot: root, Head: format.HeadPlan(head),
		Conditional: format.ConditionalRequestPlan{Family: head.PreviousToken.Family, Store: head.Store, Coordinate: head.Coordinate, NonBody: head.NonBody,
			Condition: matchedCondition(head.PreviousToken), HeadCoreLength: uint32(len(body))}, SupportPages: selectedPages, RetainedSupport: retainedSupport, OpaqueFragmentPages: selectedOpaque, AccessPages: access,
		Administrative: projectedIndex}
	filled, err := format.FillGeneratorInitialReservation(plan)
	if err != nil || filled.Head != s.head.Core {
		return format.GeneratorInitialIdentity{}, contract.ErrRecord
	}
	return filled.Identity, nil
}

func (s *StateSession) generatedUnchangedEntryUnion() []contract.UnionRow {
	if s == nil {
		return nil
	}
	return (&selectedGeneratedProof{selectedImage: s.selectedImage(), head: s.head}).generatedUnchangedEntryUnion()
}
func (s *selectedGeneratedProof) generatedUnchangedEntryUnion() []contract.UnionRow {
	rows := make([]contract.UnionRow, len(s.root.Names))
	for i, entry := range s.root.Names {
		row := membership(s.root.Domain, entry.Slot, s.valueEntry(entry.Slot))
		rows[i] = contract.UnionRow{Name: entry.Name, BeforePresent: true, AfterPresent: true, Before: row.Side(), After: row.Side()}
	}
	return rows
}

func generatedMembershipAuthority(rows []contract.UnionRow) uint8 {
	mask := uint8(contract.GeneratorAuthorityNormal)
	for _, row := range rows {
		for _, id := range row.After.Recipients {
			if !row.BeforePresent || row.Before.Incarnation != row.After.Incarnation || !slices.Contains(row.Before.Recipients, id) {
				mask |= contract.GeneratorAuthorityGrant
			}
		}
		for _, id := range row.Before.Recipients {
			if !row.AfterPresent || row.Before.Incarnation != row.After.Incarnation || !slices.Contains(row.After.Recipients, id) {
				mask |= contract.GeneratorAuthorityExclusion
			}
		}
	}
	return mask
}
