package core

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A nonnil projection identifies the support-only Apply reservation, including
// an empty future application. Complete successors already own physical pages.
type receiptApplicationProjection struct {
	entries []contract.GeneratedEntryMetadata
	pages   uint32
}

type installedApplyReceipt struct {
	before   contract.MutationReceiptWindows
	subjects contract.GeneratorDescriptor
	bind     func(context.Context, contract.CryptoApplyReceiptAdmission) error
	identity contract.ID
	receipt  []byte
	after    contract.MutationReceiptWindows
}

// Merge accepted generated and output support into the receipt layout while
// retaining unrelated work and its authenticated ownership.
func (s *StateSession) installedApplyReceiptLayout(ctx context.Context, c *Comparison, p transitionPlan) (mutationReceiptLayout, error) {
	layout, err := s.mutationReceiptLayout(ctx)
	if err != nil || c.support == nil && !c.outputChanged {
		return layout, err
	}
	if c.session != s {
		return mutationReceiptLayout{}, contract.ErrRecord
	}
	after, err := generatedNormalSupportRows(c, p)
	if err != nil {
		return mutationReceiptLayout{}, err
	}
	// The receipt encoder performs the snapshot rebind after it authenticates
	// and materializes any predecessor fragments on a changed physical page.
	rows, err := rebindSnapshotSliceRecords(after.Records, s.root.Domain, normalSupportSliceOwner(c, p), s.adminIndex.SliceSnapshot)
	if err != nil {
		return mutationReceiptLayout{}, err
	}
	indexID, err := s.receiptIndexID()
	if err != nil {
		return mutationReceiptLayout{}, err
	}
	indexRecord := contract.ID{}
	if !indexID.IsZero() {
		indexRecord, err = contract.GeneratorFragmentID(indexID, 0)
		if err != nil {
			return mutationReceiptLayout{}, err
		}
	}
	replacements := make(map[generatedRecordKey]contract.SupportRecord)
	for _, row := range rows {
		switch row.Kind {
		case contract.MutationReceiptSupportKind:
			continue
		case contract.OutputConfigurationSliceSupportKind:
			if c.outputChanged {
				continue
			}
		case contract.GeneratedFragmentSupportKind:
			if row.RecordID == indexRecord {
				continue
			}
		}
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		if _, duplicate := replacements[key]; duplicate {
			return mutationReceiptLayout{}, contract.ErrRecord
		}
		replacements[key] = row
	}
	// Only the closed local-evidence transform may remove old non-output
	// rows here. All unrelated predecessor support must still be present.
	localRemovals := make(map[generatedRecordKey]bool)
	if c.support != nil {
		local, err := c.support.LocalEvidenceAfter(c.intent)
		if err != nil {
			return mutationReceiptLayout{}, err
		}
		kept := make(map[generatedRecordKey]bool, len(local.Records))
		for _, row := range local.Records {
			kept[generatedRecordKey{row.Kind, row.RecordID}] = true
		}
		for _, row := range c.support.Records {
			key := generatedRecordKey{row.Kind, row.RecordID}
			if !kept[key] {
				localRemovals[key] = true
			}
		}
	}
	occupied := uint32(0)
	for index, rows := range layout.rows {
		kept := rows[:0]
		for _, row := range rows {
			if c.outputChanged && row.Kind == contract.OutputConfigurationSliceSupportKind {
				layout.changed[index] = true
				continue
			}
			key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
			replacement, present := replacements[key]
			if !present {
				if !localRemovals[key] {
					return mutationReceiptLayout{}, contract.ErrRecord
				}
				layout.changed[index] = true
				continue
			}
			layout.changed[index] = layout.changed[index] || !bytes.Equal(row.Body, replacement.Body)
			row = replacement
			delete(replacements, key)
			kept = append(kept, row)
		}
		layout.rows[index] = kept
		if len(kept) != 0 {
			occupied++
		} else if uint16(index) != layout.receipts && uint16(index) != layout.index {
			layout.changed[index] = false
		}
	}
	var groups []format.RequiredSupportGroup
	if len(replacements) != 0 || c.outputChanged {
		g, err := s.selectedGeneratedWork(ctx)
		if err != nil {
			return mutationReceiptLayout{}, err
		}
		// Replacement keys and group rows must use this layout's predecessor
		// Slice owner. The receipt encoder performs the final Snapshot rebind.
		_, locations, err := normalSupportSlices(s.root.Domain, s.adminIndex.SliceSnapshot, rows)
		if err != nil {
			return mutationReceiptLayout{}, err
		}
		entries, err := prospectiveNormalGeneratedEntryMetadata(c)
		if err != nil {
			return mutationReceiptLayout{}, err
		}
		owners, err := generatedReservationGroupsFromEntries(entries, s, rows, locations, g.bundles)
		if err != nil {
			return mutationReceiptLayout{}, err
		}
		for _, group := range owners {
			var added []contract.SupportRecord
			for _, row := range group.Records {
				key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
				if _, present := replacements[key]; present || c.outputChanged && row.Kind == contract.OutputConfigurationSliceSupportKind {
					added = append(added, row)
					delete(replacements, key)
				}
			}
			if len(added) != 0 {
				group.Records = added
				groups = append(groups, group)
			}
		}
		if len(replacements) != 0 {
			return mutationReceiptLayout{}, contract.ErrRecord
		}
	}
	otherChildren := s.root.ChildCount - uint32(len(s.support)) + occupied + 2
	if otherChildren > contract.MaxChildPages {
		return mutationReceiptLayout{}, contract.ErrRecordCapacity
	}
	packed, err := format.PackRequiredSupportRows(s.root.Domain, groups, otherChildren)
	if err != nil {
		return mutationReceiptLayout{}, err
	}
	next := 0
	for _, rows := range packed {
		for next < len(layout.rows) && (len(layout.rows[next]) != 0 || uint16(next) == layout.receipts || uint16(next) == layout.index) {
			next++
		}
		if next == len(layout.rows) {
			return mutationReceiptLayout{}, contract.ErrRecordCapacity
		}
		layout.rows[next], layout.changed[next] = rows, true
		next++
	}
	return layout, nil
}

func (s *StateSession) installedApplyReceiptPageIndexes(ctx context.Context, c *Comparison, p transitionPlan) ([]uint16, error) {
	layout, err := s.installedApplyReceiptLayout(ctx, c, p)
	if err != nil {
		return nil, err
	}
	var indexes []uint16
	for index, changed := range layout.changed {
		if changed {
			indexes = append(indexes, uint16(index))
		}
	}
	return indexes, nil
}

func (s *StateSession) encodeLifecycleReceiptSupport(ctx context.Context, c *Comparison, p transitionPlan, delta contract.MutationReceiptDeltaPlan, identity contract.ID) (mutationReceiptStorage, error) {
	if c.support == nil && !c.outputChanged {
		return s.encodeMutationReceiptSupport(ctx, p, delta, identity)
	}
	layout, err := s.installedApplyReceiptLayout(ctx, c, p)
	if err != nil {
		return mutationReceiptStorage{}, err
	}
	storage, err := s.encodeMutationReceiptLayout(ctx, p, delta, identity, layout)
	if err == nil {
		if c.outputChanged {
			storage.output = &c.outputAfter.descriptor
		}
		after, supportErr := generatedNormalSupportRows(c, p)
		if supportErr != nil {
			return mutationReceiptStorage{}, supportErr
		}
		directory, _, directoryErr := normalSupportSlices(s.root.Domain, normalSupportSliceOwner(c, p), after.Records)
		if directoryErr != nil {
			return mutationReceiptStorage{}, directoryErr
		}
		storage.generated.Slices = directory
		generatedRefreshClosureCounts(&storage.generated, after.Records)
		storage.generated.GeneratedCurrent = 0
		for _, entry := range c.desiredEntries {
			if entry.ValueSource == contract.Generated {
				storage.generated.GeneratedCurrent++
			}
		}
	}
	return storage, err
}

func (s *StateSession) installedApplyReceiptPlan(c *Comparison, p transitionPlan, access contract.GeneratorDescriptor, request contract.ID) (contract.MutationReceiptDeltaPlan, error) {
	if c.applyReceipt == nil || !c.applyReceipt.subjects.Valid() {
		return contract.MutationReceiptDeltaPlan{}, contract.ErrRecord
	}
	work, err := c.retainedWorkResult(p)
	if err != nil {
		return contract.MutationReceiptDeltaPlan{}, err
	}
	var effects uint64
	if work.hazards.Count != 0 {
		effects = contract.ReceiptWarningPossibleLive
	}
	warningBits, err := contract.EncodeReceiptWarningBits(c.lifecycleOperationKind(), s.root.WarningBits, effects)
	if err != nil {
		return contract.MutationReceiptDeltaPlan{}, err
	}
	row := contract.CompactMutationReceiptPlan{WarningBits: warningBits, Schema: contract.MutationReceiptSchema, OperationKind: c.lifecycleOperationKind(), DomainID: s.root.Domain, OperationID: p.operation,
		PredecessorRevisionID: s.head.Core.Revision, RequestedRevisionID: p.revision, ObservedRevisionID: p.revision, StateResult: contract.ReceiptStateSuccess, EffectSummary: contract.ReceiptEffectNoChange,
		OutputSummary: contract.ReceiptOutputNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical, CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: c.applyReceipt.subjects}
	if row.OperationKind == contract.OperationApplyDeclaration && c.support != nil && len(c.support.Handoffs) != 0 {
		row.StateResult = contract.ReceiptStateRetirementPending
	}
	if c.secretAccess != nil || c.retirement != nil {
		row.EffectSummary = contract.ReceiptEffectNotApplicable
	}
	row.SummaryCounts[contract.ReceiptChangedAccessCount] = access.Count
	row.SummaryCounts[contract.ReceiptDutyCount], row.SummaryCounts[contract.ReceiptHazardCount] = work.duties.Count, work.hazards.Count
	empty := contract.EmptyMutationResultDescriptors()
	row.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: row, RequestCoreDigest: request, ChangedAccess: access, Effects: empty[1], Outputs: empty[2], Duties: work.duties, Hazards: work.hazards})
	return contract.MutationReceiptDeltaPlan{DomainID: s.root.Domain, OperationKind: c.lifecycleOperationKind(), AddedCount: 1, Before: c.applyReceipt.before, NewReceipt: row}, err
}

// This projection reserves receipt/index/admin bytes with the final writers.
// Value/access page counts come from the complete desired set and fixed wrap
// shapes. It constructs no canonical material and grants no mutation authority.
func (s *StateSession) reserveInstalledApplyReceipt(ctx context.Context, c *Comparison, p transitionPlan) error {
	empty := contract.EmptyMutationResultDescriptors()
	request := requestCommitment(s.successorCore(p), contract.LifecycleSubject{IdentityPlan: identityCommitment(c, p), Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: c.desired, Length: c.desiredLength}}})
	delta, err := s.installedApplyReceiptPlan(c, p, empty[0], request)
	if err != nil {
		return err
	}
	storage, err := s.encodeLifecycleReceiptSupport(ctx, c, p, delta, contract.ID{})
	if err != nil {
		return err
	}
	projected := s.successorState()
	projected.root.Snapshot, projected.root.Transition = p.snapshot, p.transition
	if err := projected.installApplyRecipientPages(c, p); err != nil {
		return err
	}
	storage.install(&projected)
	if err := s.bindNormalReceiptSlicePlan(c, &projected, p); err != nil {
		return err
	}
	defer func() { projected.normalReceiptSlices = nil }()
	// The administrative writer sees only the support projection. Charge the
	// separately derived future application/access pages below, without using
	// placeholder value records or invented cryptographic evidence.
	projected.root.ValueEntryPages = [contract.MaxValueEntryPages]*contract.Ref{}
	projected.root.CurrentAccess.Core.AccessPageRefs = nil
	entries, err := prospectiveNormalGeneratedEntryMetadata(c)
	if err != nil {
		return err
	}
	var applicationPages uint32
	var applicationBytes uint64
	for _, occupied := range c.nonemptyPages() {
		if occupied {
			applicationPages++
			applicationBytes += contract.MaxValueEntryPageLength
		}
	}
	accessPages, unchanged, err := normalAccessShape(c, p)
	if err != nil {
		return err
	}
	if unchanged {
		accessPages = len(s.root.CurrentAccess.Core.AccessPageRefs)
	}
	applicationPages += uint32(accessPages)
	applicationBytes += uint64(accessPages) * contract.MaxAccessPageLength
	application := &receiptApplicationProjection{entries: entries, pages: applicationPages}
	planned := make([]plannedPublicationEntry, len(c.desiredEntries))
	for i := range c.intent {
		incarnation := p.incarnations[c.slots[i]]
		if incarnation.IsZero() {
			before := s.valueEntry(c.slots[i])
			if before == nil {
				return contract.ErrRecord
			}
			incarnation = before.Incarnation
		}
		planned[i] = plannedPublicationEntry{incarnation: incarnation}
	}
	if err := s.installAdministrativeIndexInputForApplication(ctx, &projected, &Candidate{session: s}, nil, planned, application, nil, nil, &delta.NewReceipt); err != nil {
		return err
	}
	children := projected.root.ChildCount + applicationPages
	encoded := projected.root.ChildEncodedBytes + applicationBytes
	if children > ordinaryChildPageLimit || encoded > uint64(contract.MaxChildPages)*contract.MaxRequiredSupportPageLength {
		return contract.ErrRecordCapacity
	}
	return nil
}

func installedApplyAccessChanges(before, after []contract.AccessRecord, domain contract.ID) (contract.GeneratorDescriptor, error) {
	var rows []contract.AccessChangeRow
	for _, old := range before {
		at := slices.IndexFunc(after, func(row contract.AccessRecord) bool {
			return row.MaterialKind == old.MaterialKind && row.MaterialID == old.MaterialID
		})
		if at < 0 {
			continue
		}
		left, err := contract.AccessRecordDigest(old)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		right, err := contract.AccessRecordDigest(after[at])
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		if left != right {
			rows = append(rows, contract.AccessChangeRow{Before: old, After: after[at]})
		}
	}
	return contract.AccessChangeDescriptor(domain, rows)
}

func (s *StateSession) receiptSupportPlanDescriptor(storage mutationReceiptStorage, plan contract.CompactMutationReceiptPlan) (contract.DescriptorVector, error) {
	prior := make(map[generatedRecordKey]contract.SupportRecordDigest)
	for _, page := range s.supportFacts {
		for _, fact := range page.rows {
			prior[generatedRecordKey{fact.Kind(), fact.RecordID()}] = fact
		}
	}
	type rowFact struct {
		row  contract.SupportRecord
		fact contract.SupportRecordDigest
	}
	var ordered []rowFact
	for _, page := range storage.pages {
		for _, view := range page.Records {
			row := contract.SupportRecord(view)
			var fact contract.SupportRecordDigest
			if row.Kind == contract.MutationReceiptSupportKind && row.RecordID == plan.OperationID {
			} else if row.Body != nil {
				var err error
				fact, err = contract.InspectSupportRecordDigest(s.root.Domain, row)
				if err != nil {
					return contract.DescriptorVector{}, err
				}
			} else {
				var ok bool
				key := generatedRecordKey{row.Kind, row.RecordID}
				fact, ok = prior[key]
				if !ok {
					return contract.DescriptorVector{}, contract.ErrRecord
				}
				if publicationSupportKind(row.Kind) {
					var err error
					row.Body, err = s.publicationFacts[key].replayBody(fact)
					if err != nil {
						return contract.DescriptorVector{}, err
					}
				}
			}
			ordered = append(ordered, rowFact{row, fact})
		}
	}
	slices.SortFunc(ordered, func(a, b rowFact) int {
		if a.row.Kind != b.row.Kind {
			return int(a.row.Kind) - int(b.row.Kind)
		}
		return bytes.Compare(a.row.RecordID[:], b.row.RecordID[:])
	})
	rows := make([]contract.SupportRecord, len(ordered))
	facts := make([]contract.SupportRecordDigest, len(ordered))
	for i, row := range ordered {
		rows[i], facts[i] = row.row, row.fact
	}
	return contract.RequiredSupportReceiptPlanDescriptor(s.root.Domain, rows, facts, plan)
}

func (s *StateSession) encodeInstalledApply(ctx context.Context, c *Comparison, p transitionPlan) (*Candidate, *StateSession, lifecycleAuthority, Result) {
	fail := func(err error) (*Candidate, *StateSession, lifecycleAuthority, Result) {
		return nil, nil, lifecycleAuthority{}, installedApplyPreparationFailure(err)
	}

	next, err := s.deriveSuccessor(ctx, c, p)
	if err != nil {
		return fail(err)
	}
	access, err := installedApplyAccessChanges(s.accessRecords(), next.accessRecords(), s.root.Domain)
	if err != nil {
		return fail(err)
	}
	request := requestCore(s.successorCore(p), contract.LifecycleSubject{IdentityPlan: identityCommitment(c, p), Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: c.desired, Length: c.desiredLength}}})
	requestDigest, err := contract.RequestDigest(request)
	if err != nil {
		return fail(err)
	}
	delta, err := s.installedApplyReceiptPlan(c, p, access, requestDigest)
	if err != nil {
		return fail(err)
	}
	encoded, result := s.encodeLifecycleReceiptCandidate(ctx, c, next, p, request, delta)
	if encoded == nil {
		return nil, nil, lifecycleAuthority{}, result
	}
	if !c.applyReceipt.identity.IsZero() && c.applyReceipt.identity != encoded.identity {
		return fail(contract.ErrRecord)
	}
	c.applyReceipt.identity, c.applyReceipt.receipt, c.applyReceipt.after = encoded.identity, encoded.receipt, encoded.after
	return encoded.candidate, next, encoded.authority, Result{}
}

func (s *StateSession) bindInstalledApplyReceipt(ctx context.Context, c *Comparison, next *StateSession, p transitionPlan) error {
	if c.applyReceipt == nil || c.applyReceipt.bind == nil || c.operation == nil {
		return contract.ErrRecord
	}
	public, err := next.publicStateProjection()
	if err != nil {
		return err
	}
	descriptor, err := contract.PublicStateDescriptor(public)
	if err != nil {
		return err
	}
	work, err := c.retainedWorkResult(p)
	if err != nil {
		return err
	}
	return c.applyReceipt.bind(ctx, contract.CryptoApplyReceiptAdmission{OperationKind: c.lifecycleOperationKind(), ChangedSubjects: c.applyReceipt.subjects, LiveDuties: work.duties, LiveHazards: work.hazards, Context: c.operation.context, OperationRef: c.operation.operationRef, IdentityPlanDescriptor: c.preparedPlan,
		Delta: contract.MutationReceiptDelta{DomainID: s.root.Domain, OperationKind: c.lifecycleOperationKind(), AddedCount: 1, Before: c.applyReceipt.before, After: c.applyReceipt.after}, AfterSupport: public.RequiredSupport, CandidatePublicState: descriptor})
}

func installedApplyPreparationFailure(err error) Result {
	if result, ok := selectedReadResult(err); ok {
		return result
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	if errors.Is(err, contract.ErrRecordCapacity) {
		return refused(CapacityExceeded)
	}
	if errors.Is(err, contract.ErrRecord) {
		return refused(InvalidRelation)
	}
	return failure(EvidenceUnavailable, NoReason)
}
