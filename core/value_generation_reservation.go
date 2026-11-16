package core

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Inputs come from the fixed private plan and its completed Crypto preparation.
// Construction alone grants neither signing nor first-send permission.
type generatedReservationInput struct {
	graph               contract.GeneratorPlanBundle
	declaration         []byte
	registryImage       []byte
	outputConfiguration []byte
	parent              contract.GeneratedParentPlan
	finished            contract.CryptoGeneratedFinishPlanResult
	requestBindings     []generatedRequestBinding
	intents             generatedCurrentIntentProjection
}

type generatedReservation struct {
	state            *StateSession
	candidate        *Candidate
	identity         format.GeneratorInitialIdentity
	originalAttempts []contract.ID
}

func (s *StateSession) deriveGeneratedReservation(ctx context.Context, input generatedReservationInput) (*generatedReservation, error) {
	if s == nil || !generatedRequestBindingsValid(input.graph, input.requestBindings) || input.parent.RequestIdentityDigest != (contract.ID{}) ||
		contract.ValidateGeneratorEffectGraph(input.graph) != nil || !generatedOperationGraphValid(input.graph) {
		return nil, contract.ErrRecord
	}
	prior, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if prior.parent != nil {
		return nil, contract.ErrRecord
	}
	q, parent := input.graph.Request, input.parent
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil || q.DomainID != s.root.Domain || q.PredecessorRevisionID != s.head.Core.Revision || q.PredecessorHEADDigest != contract.Hash(s.body) || q.ConditionDigest != condition ||
		q.CompatibilityID != s.root.CurrentAccess.Core.CompatibilityID {
		return nil, contract.ErrRecord
	}
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil || contract.ValidateGeneratorDeclarationGraph(declaration, input.graph) != nil {
		return nil, contract.ErrRecord
	}
	graphBody, err := contract.EncodeGeneratorPlanBundle(input.graph)
	if err != nil {
		return nil, err
	}
	if _, err := contract.EncodeCryptoGeneratedFinishPlanResult(input.finished); err != nil {
		return nil, err
	}
	seed, err := contract.DecodeAccessRecord(input.finished.SeedAccess)
	if err != nil || !s.validateMaterialWraps(seed, []contract.ID{s.admission.recipient}) {
		return nil, contract.ErrRecord
	}
	m := input.finished.Material.Core
	if m.DomainID != q.DomainID || m.OperationID != q.OperationID || m.OperationMaterialID != parent.MaterialID || m.UsePlanDigest != parent.UsePlanDigest ||
		m.CryptoSupportID != s.root.CurrentAccess.Core.CryptoSupportID || m.CompatibilityID != q.CompatibilityID {
		return nil, contract.ErrRecord
	}
	request, err := contract.GeneratorRequestCoreDigest(q)
	if err != nil {
		return nil, err
	}
	next := *s
	next.cache, next.accessLocations, next.valueReaders = nil, nil, nil
	deletion, deleteOnly, err := s.generatedDeleteReservationSelection(ctx, input.graph, prior)
	if err != nil {
		return nil, err
	}
	var lineageIndex uint16
	var x contract.GeneratorAttemptTemplate
	var use contract.GeneratorResultUse
	var phaseID, revision contract.ID
	if deleteOnly {
		phaseID, err = contract.GeneratorPhaseID(deletion.phase)
		if err == nil {
			next.root.Snapshot, err = contract.GeneratorPhaseSnapshotID(phaseID)
		}
		if err == nil {
			next.root.Transition, err = contract.GeneratorPhaseTransitionID(phaseID)
		}
		if err == nil {
			revision, err = contract.GeneratorPhaseRevisionID(phaseID)
		}
		lineageIndex, x, use = deletion.lineageIndex, deletion.template, deletion.use
	} else {
		next.root.Snapshot, err = contract.GeneratorInitialSnapshotID(request)
		if err == nil {
			next.root.Transition, err = contract.GeneratorInitialTransitionID(request)
		}
		if err == nil {
			phaseID, err = contract.GeneratorInitialPhaseID(request)
		}
		if err == nil {
			revision, err = contract.GeneratorInitialRevisionID(request)
		}
		var ok bool
		lineageIndex, ok = generatedFirstCreateIndex(input.graph)
		if !ok {
			return nil, contract.ErrRecord
		}
		x = input.graph.Lineages[lineageIndex].Templates[0]
		if x.Action != contract.GeneratorActionCreate || x.Branch != contract.GeneratorBranchInitial {
			return nil, contract.ErrRecord
		}
		_, use, ok = generatedTemplate(input.graph, x.AttemptID)
		if !ok {
			return nil, contract.ErrRecord
		}
	}
	if err != nil {
		return nil, err
	}
	var rows []contract.SupportRecord
	if deleteOnly {
		rows, err = generatedInitialDeleteRows(input, phaseID, deletion, prior)
	} else {
		rows, err = generatedInitialRows(input, declaration, phaseID, lineageIndex, x, use)
	}
	if err != nil {
		return nil, err
	}
	locations, err := s.resolveSelectedGeneratedSlices()
	if err != nil {
		return nil, err
	}
	intentProjection, err := planGeneratedCurrentIntents(ctx, s, prior, locations)
	if err != nil {
		return nil, err
	}
	if !input.intents.predecessor.IsZero() && !input.intents.equal(intentProjection) {
		return nil, contract.ErrRecord
	}
	knownRows := make(map[generatedRecordKey][]byte, len(rows))
	for _, row := range rows {
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		if prior, exists := knownRows[key]; exists && !bytes.Equal(prior, row.Body) {
			return nil, contract.ErrRecord
		}
		knownRows[key] = row.Body
	}
	appendUniqueFragments := func(fragments []contract.SupportRecord) error {
		for _, row := range fragments {
			key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
			if prior, exists := knownRows[key]; exists {
				if !bytes.Equal(prior, row.Body) {
					return contract.ErrRecord
				}
				continue
			}
			knownRows[key] = row.Body
			rows = append(rows, row)
		}
		return nil
	}
	oldRows := s.supportRecords()
	fragmentFacts, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	for _, row := range oldRows {
		if row.Kind == contract.GeneratedFragmentSupportKind {
			var blob contract.ID
			if row.Body == nil {
				fact, ok := fragmentFacts[row.RecordID]
				if !ok || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID {
					return nil, contract.ErrRecord
				}
				blob = fact.blob
			} else {
				fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
				if inspectErr != nil {
					return nil, inspectErr
				}
				blob = fragment.BlobID
			}
			if intentProjection.dropBlobs[blob] {
				continue
			}
		}
		_, carrier, err := snapshotSliceRecord(row, s.root.Domain, s.adminIndex.SliceSnapshot)
		if err != nil {
			return nil, err
		}
		if !carrier {
			if deleteOnly && generatedDeleteReservationReplaces(row, deletion) {
				continue
			}
			key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
			if body, present := knownRows[key]; present {
				if !bytes.Equal(body, row.Body) {
					return nil, contract.ErrRecord
				}
				continue
			}
			knownRows[key] = row.Body
			rows = append(rows, row)
		}
	}
	if intentProjection.changed {
		locations = intentProjection.after
		fragments, emitErr := emitGeneratedCurrentIntents(ctx, prior, intentProjection)
		if emitErr != nil {
			return nil, emitErr
		}
		if err := appendUniqueFragments(fragments); err != nil {
			return nil, err
		}
	}
	// Blob identities are their complete immutable bytes. Semantic slice IDs
	// remain the separately typed declaration, graph, intent and source IDs.
	declBlob, graphBlob := contract.Hash(input.declaration), contract.Hash(graphBody)
	for _, blob := range []struct {
		id   contract.ID
		body []byte
	}{{declBlob, input.declaration}, {graphBlob, graphBody}} {
		fragments, err := generatedFragmentRows(blob.id, blob.body)
		if err != nil {
			return nil, err
		}
		if err := appendUniqueFragments(fragments); err != nil {
			return nil, err
		}
	}
	slicesInDeclaration, err := declaration.Slices()
	if err != nil {
		return nil, err
	}
	for _, slice := range slicesInDeclaration {
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: slice.Logical.ContentKind, ContentID: slice.Logical.ContentID,
			BlobID: declBlob, Offset: uint64(slice.Offset), Length: slice.Logical.Length, Digest: slice.Logical.Digest})
	}
	locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentGraph, ContentID: parent.PlanGraphID,
		BlobID: graphBlob, Length: uint32(len(graphBody)), Digest: contract.Hash(graphBody)})
	if q.Schema == contract.GeneratorPublicRequestCoreSchema || q.Schema == contract.GeneratorApplyRequestCoreSchema {
		if _, err := s.admitGeneratedRegistry(ctx, input.registryImage, q, true); err != nil {
			return nil, err
		}
		blob := contract.Hash(input.registryImage)
		fragments, err := generatedFragmentRows(blob, input.registryImage)
		if err != nil {
			return nil, err
		}
		if err := appendUniqueFragments(fragments); err != nil {
			return nil, err
		}
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentRecipientRegistry, ContentID: q.OperationID, BlobID: blob, Length: uint32(len(input.registryImage)), Digest: blob})
	}
	if q.Schema == contract.GeneratorApplyRequestCoreSchema {
		if _, err := contract.InspectGeneratedOutputConfiguration(input.graph, input.outputConfiguration); err != nil {
			return nil, err
		}
		blob := contract.Hash(input.outputConfiguration)
		fragments, err := generatedFragmentRows(blob, input.outputConfiguration)
		if err != nil {
			return nil, err
		}
		if err := appendUniqueFragments(fragments); err != nil {
			return nil, err
		}
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentOutputConfiguration, ContentID: q.OperationID, BlobID: blob, Length: uint32(len(input.outputConfiguration)), Digest: blob})
	} else if len(input.outputConfiguration) != 0 {
		return nil, contract.ErrRecord
	}
	if len(input.finished.SourceProtections) != 0 {
		body, err := contract.EncodeGeneratedSourceProtections(input.finished.Material, input.finished.SourceProtections)
		if err != nil {
			return nil, err
		}
		blob := contract.Hash(body)
		fragments, err := generatedFragmentRows(blob, body)
		if err != nil {
			return nil, err
		}
		if err := appendUniqueFragments(fragments); err != nil {
			return nil, err
		}
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentConfiguration, ContentID: parent.MaterialID,
			BlobID: blob, Length: uint32(len(body)), Digest: contract.Hash(body)})
	}
	locations, err = generatedUniqueLocations(locations)
	if err != nil {
		return nil, err
	}
	var sliceBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			return nil, err
		}
		sliceBodies = append(sliceBodies, body)
	}
	descriptor, carriers, err := generatedCarrierRows(q.DomainID, contract.GeneratorSnapshotOwner, next.root.Snapshot, contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		return nil, err
	}
	rows = append(rows, carriers...)
	next.root.Generated.Slices = descriptor
	next.root.Generated.ActiveOwner, next.root.Generated.ActivePhase, next.root.Generated.ActiveGraph = q.OperationID, phaseID, parent.PlanGraphID
	createCount := uint32(1)
	if !deleteOnly {
		createCount = 0
		for _, lineage := range input.graph.Lineages {
			if lineage.Purpose == contract.GeneratorLineageCreate {
				createCount++
			}
		}
	}
	for _, change := range []struct {
		count *uint32
		add   uint32
	}{{&next.root.Generated.Attempts, createCount}, {&next.root.Generated.Materials, 1}} {
		if *change.count > math.MaxUint32-change.add {
			return nil, contract.ErrRecordCapacity
		}
		*change.count += change.add
	}
	if !deleteOnly {
		if next.root.Generated.Duties > math.MaxUint32-createCount {
			return nil, contract.ErrRecordCapacity
		}
		next.root.Generated.Duties += createCount
	}
	graphs := []contract.ID{parent.PlanGraphID}
	for _, bundle := range prior.bundles {
		graphs = append(graphs, bundle.UsePlan.PlanGraphID)
	}
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	next.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphs)
	if err != nil {
		return nil, err
	}
	owners := []contract.ID{q.OperationID}
	if !deleteOnly {
		for _, lineage := range input.graph.Lineages {
			if lineage.Purpose == contract.GeneratorLineageCreate {
				owners = append(owners, lineage.Templates[0].DutyID)
			}
		}
	}
	for key := range prior.records {
		if key.kind == contract.GeneratedDutySupportKind || key.kind == contract.GeneratedHazardSupportKind || key.kind == contract.PendingInboxReleaseSupportKind {
			owners = append(owners, key.id)
		}
	}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	next.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, slices.Compact(owners))
	if err != nil {
		return nil, err
	}
	candidate := &Candidate{session: s}
	access := append(s.accessRecords(), seed)
	var accessPages []format.AccessPage
	if deleteOnly {
		accessPages, err = next.packGeneratedAccessWithPageID(access, request, candidate, func(kind contract.Kind, index uint16) (contract.ID, error) {
			return contract.GeneratorPhasePageID(phaseID, kind, index)
		})
	} else {
		accessPages, err = next.packGeneratedAccess(access, request, candidate)
	}
	if err != nil {
		return nil, fmt.Errorf("reservation access pages: %w", err)
	}
	bundles := append(slices.Clone(prior.bundles), input.graph)
	groups, err := generatedReservationGroupsWithSource(&next, s, rows, locations, bundles)
	if err != nil {
		return nil, err
	}
	next.root.RequiredSupport, next.support = nil, nil
	next.recountChildren()
	packed, err := generatedSupportPagesWithParent(q.DomainID, groups, next.root.ChildCount, fragmentFacts, &parent)
	if err != nil {
		return nil, fmt.Errorf("reservation support packing: %w", err)
	}
	pageIDs := make([]contract.ID, len(packed))
	physicalIndexes, err := s.generatedSupportPhysicalIndexes(packed)
	if err != nil {
		return nil, err
	}

	for i := range packed {
		var id contract.ID
		if deleteOnly {
			id, err = contract.GeneratorPhasePageID(phaseID, contract.RequiredSupportKind, physicalIndexes[i])
		} else {
			id, err = contract.GeneratorInitialPageID(request, contract.RequiredSupportKind, physicalIndexes[i])
		}
		if err != nil {
			return nil, fmt.Errorf("reservation support page identity: %w", err)
		}
		pageIDs[i] = id
	}
	materialized, err := s.materializeGeneratedSupportPagesWithParent(ctx, packed, pageIDs, &parent)
	if err != nil {
		return nil, fmt.Errorf("reservation projected support pages: %w", err)
	}
	pages := materialized.pages
	next.root.RequiredSupport, next.root.RequiredSupportRecordCount, next.root.Generated.Fragments =
		materialized.references, materialized.recordCount, materialized.fragments
	projectedIndex, err := s.buildAdministrativeIndex(ctx, next.root, pages, &parent, nil, &next, bundles...)
	if err != nil {
		return nil, fmt.Errorf("reservation administrative ownership: %w", err)
	}
	projectedIndexPages, err := format.EncodeAdministrativeIndexPages(projectedIndex)
	if err != nil {
		return nil, fmt.Errorf("reservation administrative index pages: %w", err)
	}
	next.adminIndex = projectedIndex
	next.root.AdministrativeIndex = projectedIndexPages[0].Ref
	next.root.AdministrativeIndexShards = nil
	for _, shard := range projectedIndexPages[1:] {
		next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
	}
	next.recountChildren()
	if next.root.ChildCount > ordinaryChildPageLimit {
		return nil, contract.ErrRecordCapacity
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, fmt.Errorf("reservation projected root: %w", err)
	}
	head := s.successorCore(transitionPlan{revision: revision})
	head.Root = format.Ref{Kind: format.RootKind, Format: format.Version, Domain: q.DomainID, Object: next.root.Snapshot, Length: uint32(len(rootBody))}
	headBody, err := format.EncodeHeadPlan(format.HeadPlan(head))
	if err != nil {
		return nil, fmt.Errorf("reservation projected HEAD: %w", err)
	}
	plan := format.GeneratorInitialReservationPlan{Request: q, Parent: parent, Material: input.finished.Material, Snapshot: next.root, Head: format.HeadPlan(head),
		Conditional: format.ConditionalRequestPlan{Family: s.token.Family, Store: head.Store, Coordinate: head.Coordinate, NonBody: head.NonBody,
			Condition: matchedCondition(s.token), HeadCoreLength: uint32(len(headBody))}, SupportPages: pages, AccessPages: accessPages,
		Administrative: projectedIndex}
	plan.SupportPages = nil
	for _, page := range pages {
		if retained, ok := s.retainedOutputPage(page.Records); ok {
			plan.RetainedSupport = append(plan.RetainedSupport, retained.ref)
		} else {
			plan.SupportPages = append(plan.SupportPages, page)
		}
	}
	var filled format.GeneratorInitialReservation
	if deleteOnly {
		filled, err = s.fillGeneratedDeleteReservation(plan, deletion.phase)
	} else {
		filled, err = format.FillGeneratorInitialReservation(plan)
	}
	if err != nil {
		return nil, fmt.Errorf("reservation initial identity: %w", err)
	}
	next.root = filled.Snapshot
	next.adminIndex.Pages = slices.Clone(projectedIndex.Pages)
	parentPosition := slices.IndexFunc(next.root.RequiredSupport, func(ref format.Ref) bool { return ref.Index == filled.ParentPage.Index })
	if parentPosition < 0 {
		return nil, contract.ErrRecord
	}
	next.adminIndex.Pages[parentPosition].Ref = next.root.RequiredSupport[parentPosition]
	for _, shard := range filled.AdministrativePages {
		candidate.objects = append(candidate.objects, objectImage{ref: shard.Ref, body: shard.Body})
	}
	pages[parentPosition] = filled.ParentPage
	for i, page := range pages {
		if i == parentPosition {
			body, err := format.EncodeRequiredSupportPage(page)
			if err != nil {
				return nil, err
			}
			view, err := format.InspectRequiredSupportPage(body)
			if err != nil {
				return nil, err
			}
			next.support = append(next.support, view)
			candidate.objects = append(candidate.objects, objectImage{ref: next.root.RequiredSupport[i], body: body})
			continue
		}
		next.support = append(next.support, materialized.views[i])
		for _, object := range materialized.objects {
			if object.ref == next.root.RequiredSupport[i] {
				candidate.objects = append(candidate.objects, object)
				break
			}
		}
	}
	next.clearSelectedSupportFacts()
	if err := s.bindPreservedOutputConfiguration(&next); err != nil {
		return nil, err
	}
	if err := s.bindPreservedPublication(ctx, &next); err != nil {
		return nil, err
	}
	if !next.indexSelectedMaterials() || !validAggregate(next.root) {
		return nil, fmt.Errorf("reservation selected relations: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("reservation selected relations: %w", err)
	}
	// Publication capacity consumes the complete successor support and proofs.
	if err := next.reserveOrdinaryPublicationRewrite(ctx); err != nil {
		return nil, err
	}
	if err := next.reserveFirstEndWork(ctx); err != nil {
		return nil, fmt.Errorf("reservation first end-work capacity: %w", err)
	}
	rootBody, err = format.EncodeRoot(next.root)
	if err != nil {
		return nil, err
	}
	candidate.objects = append(candidate.objects, objectImage{ref: filled.Head.Root, body: rootBody})
	var subject contract.GeneratorAuthoritySubject
	if deleteOnly {
		subject, err = s.generatedDeleteReservationSubject(ctx, &next, input, filled, deletion)
	} else {
		subject, err = s.generatedReservationSubject(ctx, &next, input, filled)
	}
	if err != nil {
		return nil, fmt.Errorf("reservation authority subject: %w", err)
	}
	candidate.head = format.Head{Core: filled.Head, AuthKind: format.GeneratorAuth, Generator: &subject, K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = candidate.head
	reservation := &generatedReservation{state: &next, candidate: candidate, identity: filled.Identity}
	createLineages := make(map[contract.ID]bool)
	for _, lineage := range input.graph.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			createLineages[lineage.LineageID] = true
		}
	}
	for _, binding := range input.requestBindings {
		if createLineages[binding.LineageID] {
			reservation.originalAttempts = append(reservation.originalAttempts, binding.AttemptID)
		}
	}
	return reservation, nil
}

func (s *StateSession) generatedReservationSubject(ctx context.Context, next *StateSession, input generatedReservationInput, filled format.GeneratorInitialReservation) (contract.GeneratorAuthoritySubject, error) {
	parent, q := input.parent, input.graph.Request
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityReservation, RequiredAuthoritySet: contract.GeneratorAuthorityNormal,
		DomainID: q.DomainID, OperationID: q.OperationID, RequestIdentityDigest: filled.Identity.RequestIdentityDigest, PlanGraphID: parent.PlanGraphID,
		UsePlanDigest: parent.UsePlanDigest, PhaseID: next.root.Generated.ActivePhase, PreviousHEADDigest: q.PredecessorHEADDigest,
		PreviousRevisionID: q.PredecessorRevisionID, ConditionDigest: q.ConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: filled.Head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot, OwnerID: q.OperationID,
		Intent: q.Declaration, IdentityPlan: filled.Identity.Plan, CapacityReservation: parent.Capacity, AfterPhase: 1}
	var err error
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(q.DomainID, s.generatedUnchangedEntryUnion())
	if err != nil {
		return subject, err
	}
	planned, err := s.generatedMembershipPlan(input.graph, input.declaration)
	if err != nil {
		return subject, err
	}
	subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(q.DomainID, planned)
	if err != nil {
		return subject, err
	}
	subject.RequiredAuthoritySet = generatedMembershipAuthority(planned)
	before, err := s.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	after, err := next.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	subject.BeforeWork, err = s.workSupportDescriptor(before)
	if err != nil {
		return subject, err
	}
	subject.AfterWork, err = next.workSupportDescriptor(after)
	if err != nil {
		return subject, err
	}
	results, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		return subject, err
	}
	subject.ResultVector = contract.GeneratorDescriptor(results)
	head, err := format.EncodeHeadCore(filled.Head)
	if err != nil {
		return subject, err
	}
	condition, err := format.EncodeConditionalPlan(filled.Conditional)
	if err != nil {
		return subject, err
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(head), uint32(len(head))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(condition), uint32(len(condition))
	_, err = contract.NewGeneratorRequest(subject)
	return subject, err
}

func (s *StateSession) generatedMembershipPlan(graph contract.GeneratorPlanBundle, declaration []byte) ([]contract.UnionRow, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	return (&selectedGeneratedProof{selectedImage: s.selectedImage(), head: s.head}).generatedMembershipPlan(graph, declaration)
}
func (s *selectedGeneratedProof) generatedMembershipPlan(graph contract.GeneratorPlanBundle, declaration []byte) ([]contract.UnionRow, error) {
	view, err := contract.InspectGeneratorDeclaration(declaration)
	if err != nil || view.EntryCount() != len(graph.ValueEntryPlans) {
		return nil, contract.ErrRecord
	}
	rows := make(map[string]contract.UnionRow, len(s.root.Names)+len(graph.ValueEntryPlans))
	for _, entry := range s.root.Names {
		valueEntry := s.valueEntry(entry.Slot)
		if valueEntry == nil {
			return nil, contract.ErrRecord
		}
		rows[entry.Name] = contract.UnionRow{Name: entry.Name, BeforePresent: true, Before: contract.MembershipSide{Slot: entry.Slot, Incarnation: valueEntry.Incarnation,
			EntryDigest: publicEntryDigest(s.root.Domain, entry.Slot, valueEntry), Recipients: valueEntry.Recipients}}
	}
	for i, entryPlan := range graph.ValueEntryPlans {
		entry, _, err := view.Entry(i)
		if err != nil || string(entry.Name) != entryPlan.Name {
			return nil, contract.ErrRecord
		}
		row := rows[entryPlan.Name]
		row.Name, row.AfterPresent = entryPlan.Name, true
		row.After = contract.MembershipSide{Slot: entryPlan.Slot, Incarnation: entryPlan.EntryIncarnationID}
		for offset := 0; offset < len(entry.RecipientIDs); offset += 32 {
			row.After.Recipients = append(row.After.Recipients, contract.ID(entry.RecipientIDs[offset:offset+32]))
		}
		rows[entryPlan.Name] = row
	}
	out := make([]contract.UnionRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b contract.UnionRow) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	return out, nil
}
