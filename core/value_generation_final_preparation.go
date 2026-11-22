package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

func (b *generatedSelectionBuilder) resolveFinalPreparation() error {
	g := b.facts
	if g.parent == nil || g.phase == nil || g.phase.FinalPreparationID.IsZero() {
		return nil
	}
	row, ok := b.claimRecord(contract.GeneratedFinalPreparationSupportKind, g.parent.OperationID)
	if !ok {
		return contract.ErrRecord
	}
	preparation, err := contract.InspectGeneratedFinalPreparationRecord(row.Body)
	if err != nil || preparation.DomainID != g.parent.DomainID || preparation.OperationID != g.parent.OperationID ||
		preparation.Image.ContentID != g.phase.FinalPreparationID || preparation.MaterializationPhase.RequestIdentityDigest != g.parent.RequestIdentityDigest ||
		preparation.MaterializationPhase.AfterPhase != g.phase.Phase || g.phase.Stage != contract.GeneratedStageTerminal {
		return contract.ErrRecord
	}
	body, err := b.content.read(contract.GeneratorContentFinalPreparation, preparation.Image.ContentID, contract.GeneratedFinalPreparationMaxLength)
	if err != nil {
		return err
	}
	if uint32(len(body)) != preparation.Image.Length || contract.Hash(body) != preparation.Image.Digest {
		return contract.ErrRecord
	}
	image, err := contract.DecodeGeneratedFinalPreparationImage(body)
	defer image.Clear()
	phase, phaseErr := contract.GeneratorPhaseID(preparation.MaterializationPhase)
	if err != nil || phaseErr != nil || image.DomainID != preparation.DomainID || image.OperationID != preparation.OperationID ||
		image.MaterializationPhaseID != phase || image.ControlBindingDigest != preparation.ControlBindingDigest {
		return contract.ErrRecord
	}
	checkpoint := preparation.MaterializationPhase
	checkpoint.TransitionKind = contract.GeneratorAuthorityFinalPreparation
	checkpoint.Evidence, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{preparation.Image})
	if err != nil {
		return err
	}
	id, err := contract.GeneratorPhaseID(checkpoint)
	if err != nil || id != g.phase.PhaseID {
		return contract.ErrRecord
	}
	if err := g.image.checkGeneratedGrantSeals(&image); err != nil {
		return err
	}
	g.preparation = &preparation
	return nil
}

func (s *StateSession) generatedFinalPreparationImage(ctx context.Context, g *generatedSelection) (contract.GeneratedFinalPreparationImage, error) {
	return selectedFinalPreparationImage(ctx, g)
}

func selectedFinalPreparationImage(ctx context.Context, g *generatedSelection) (contract.GeneratedFinalPreparationImage, error) {
	if g == nil || g.preparation == nil {
		return contract.GeneratedFinalPreparationImage{}, contract.ErrRecord
	}
	body, err := g.readSelectedSlice(ctx, contract.GeneratorContentFinalPreparation, g.preparation.Image.ContentID, contract.GeneratedFinalPreparationMaxLength)
	if err != nil {
		return contract.GeneratedFinalPreparationImage{}, err
	}
	image, err := contract.DecodeGeneratedFinalPreparationImage(body)
	phase, phaseErr := contract.GeneratorPhaseID(g.preparation.MaterializationPhase)
	if err != nil || phaseErr != nil || contract.Hash(body) != g.preparation.Image.Digest || uint32(len(body)) != g.preparation.Image.Length ||
		image.DomainID != g.preparation.DomainID || image.OperationID != g.preparation.OperationID || image.MaterializationPhaseID != phase ||
		image.ControlBindingDigest != g.preparation.ControlBindingDigest {
		image.Clear()
		return contract.GeneratedFinalPreparationImage{}, contract.ErrRecord
	}
	return image, nil
}

func (s *StateSession) deriveGeneratedFinalPreparation(ctx context.Context, g *generatedSelection, plan *generatedFinalPlan,
	prepared []contract.CryptoGeneratedValueEntryResult, supplied []contract.CryptoPreparedSecret, seals []contract.GeneratedGrantSeal) (*generatedReservation, error) {
	if g == nil || g.parent == nil || g.phase == nil || plan.materialization != nil || !plan.selecting || len(prepared) != len(plan.entryPlans) {
		return nil, contract.ErrRecord
	}
	validated, err := s.validateGeneratedFinalRows(ctx, g, plan, prepared, supplied, false)
	if err != nil {
		return nil, err
	}
	validated.clearOwnedSupplied()
	bindings, err := s.generatedBindings(g)
	if err != nil {
		return nil, err
	}
	digest, err := contract.GeneratedFinalPreparationBindingDigest(currentControlOf(s), bindings)
	if err != nil {
		return nil, err
	}
	image := contract.GeneratedFinalPreparationImage{Schema: contract.GeneratorRecordSchema, DomainID: g.parent.DomainID,
		OperationID: g.parent.OperationID, MaterializationPhaseID: mustGeneratedPhaseID(plan.phase), ControlBindingDigest: digest, Generated: prepared, Supplied: supplied, GrantSeals: seals}
	if len(seals) != 0 {
		image.Schema = contract.GeneratedGrantPreparationSchema
	}
	if err := s.selectedImage().checkGeneratedGrantSeals(&image); err != nil {
		return nil, err
	}
	body, err := contract.EncodeGeneratedFinalPreparationImage(image)
	if err != nil {
		return nil, err
	}
	imageID := contract.Hash(body)
	record := contract.GeneratedFinalPreparationRecord{Schema: contract.GeneratorRecordSchema, DomainID: g.parent.DomainID, OperationID: g.parent.OperationID,
		MaterializationPhase: plan.phase, ControlBindingDigest: digest, Image: contract.GeneratorLogicalSlice{Schema: contract.GeneratorRecordSchema,
			ContentKind: contract.GeneratorContentFinalPreparation, ContentID: imageID, Length: uint32(len(body)), Digest: imageID}}
	recordBody, err := contract.EncodeGeneratedFinalPreparationRecord(record)
	if err != nil {
		return nil, err
	}
	evidence, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{record.Image})
	if err != nil {
		return nil, err
	}
	checkpoint := plan.phase
	checkpoint.TransitionKind, checkpoint.Evidence = contract.GeneratorAuthorityFinalPreparation, evidence
	phaseID, err := contract.GeneratorPhaseID(checkpoint)
	if err != nil {
		return nil, err
	}
	fragments, err := generatedFragmentRows(imageID, body)
	if err != nil {
		return nil, err
	}
	rows := slices.Clone(s.supportRecords())
	locations, err := s.resolveSelectedGeneratedSlices()
	if err != nil {
		return nil, err
	}
	if g.preparation != nil {
		oldImage := g.preparation.Image.ContentID
		var oldBlobs []contract.ID
		locations = slices.DeleteFunc(locations, func(location contract.GeneratorSliceLocation) bool {
			if location.ContentKind == contract.GeneratorContentFinalPreparation && location.ContentID == oldImage {
				oldBlobs = append(oldBlobs, location.BlobID)
				return true
			}
			return false
		})
		fragmentFacts, err := s.selectedFragmentFactsByRecord()
		if err != nil {
			return nil, err
		}
		filtered := rows[:0]
		for _, row := range rows {
			if row.Kind == contract.GeneratedFinalPreparationSupportKind && row.RecordID == g.parent.OperationID {
				continue
			}
			if row.Kind == contract.GeneratedFragmentSupportKind {
				blob, err := generatedSelectedFragmentBlob(row, fragmentFacts)
				if err != nil {
					return nil, err
				}
				if slices.Contains(oldBlobs, blob) && !slices.ContainsFunc(locations, func(location contract.GeneratorSliceLocation) bool { return location.BlobID == blob }) {
					continue
				}
			}
			filtered = append(filtered, row)
		}
		rows = filtered
	}
	rows = append(rows, fragments...)
	rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFinalPreparationSupportKind, RecordID: g.parent.OperationID, Body: recordBody})
	locations = append(locations, contract.GeneratorSliceLocation{Schema: contract.GeneratorRecordSchema, ContentKind: record.Image.ContentKind,
		ContentID: imageID, BlobID: imageID, Length: record.Image.Length, Digest: imageID})
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var sliceBodies [][]byte
	for _, location := range locations {
		encoded, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			return nil, err
		}
		sliceBodies = append(sliceBodies, encoded)
	}
	descriptor, carriers, err := generatedCarrierRows(s.root.Domain, contract.GeneratorSnapshotOwner, s.adminIndex.SliceSnapshot, contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		return nil, err
	}
	rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		return err == nil && carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
	})
	rows = append(rows, carriers...)
	phase := *g.phase
	phase.PhaseID, phase.Phase, phase.FinalPreparationID = phaseID, checkpoint.AfterPhase, imageID
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == contract.GeneratedPhaseSupportKind && rows[i].RecordID == phase.OperationID {
			rows[i].Body = phaseBody
		}
	}
	checkpointPlan := &generatedSuccessorReservationPlan{context: plan.request.Context, phase: checkpoint}
	// The slice descriptor is authenticated by the new root. All selected
	// source rows remain borrowed from the original session without mutation.
	return s.deriveGeneratedPhaseCandidate(ctx, g, checkpointPlan, contract.GeneratorAttemptTemplate{}, phaseID, rows, locations, descriptor)
}

func (s *selectedGeneratedProof) validateGeneratedFinalPreparationSelection(ctx context.Context, g *generatedSelection, subject contract.GeneratorAuthoritySubject) error {
	if g == nil || g.parent == nil || g.phase == nil || g.preparation == nil || subject.Purpose != contract.GeneratorAuthorityFinalPreparation ||
		subject.BeforeAccessDigest != subject.AfterAccessDigest || subject.OperationID != g.parent.OperationID || subject.OwnerID != g.parent.OperationID ||
		subject.PhaseID != g.phase.PhaseID || subject.BeforePhase != g.preparation.MaterializationPhase.BeforePhase || subject.AfterPhase != g.phase.Phase ||
		subject.PreviousHEADDigest != g.preparation.MaterializationPhase.ObservedHEADDigest || subject.ConditionDigest != g.preparation.MaterializationPhase.ConditionDigest {
		return contract.ErrRecord
	}
	phase := g.preparation.MaterializationPhase
	phase.TransitionKind = contract.GeneratorAuthorityFinalPreparation
	var err error
	phase.Evidence, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{g.preparation.Image})
	if err != nil || subject.ResultVector != phase.Evidence {
		return contract.ErrRecord
	}
	id, err := contract.GeneratorPhaseID(phase)
	if err != nil || id != subject.PhaseID {
		return contract.ErrRecord
	}
	union, err := contract.GeneratorAuthorityValueEntriesDescriptor(g.parent.DomainID, s.generatedUnchangedEntryUnion())
	if err != nil || union != subject.ValueEntryUnion {
		return contract.ErrRecord
	}
	if subject.Intent != g.parent.Declaration || subject.RequestIdentityDigest != g.parent.RequestIdentityDigest || subject.PlanGraphID != g.parent.PlanGraphID ||
		subject.UsePlanDigest != g.parent.UsePlanDigest || subject.CapacityReservation != g.parent.Capacity {
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
	membership, err := contract.GeneratorAuthorityMembershipDescriptor(g.parent.DomainID, planned)
	if err != nil || membership != subject.MembershipChanges {
		return contract.ErrRecord
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(id)
	if err != nil || snapshot != s.root.Snapshot {
		return contract.ErrRecord
	}
	transition, err := contract.GeneratorPhaseTransitionID(id)
	if err != nil || transition != s.root.Transition {
		return contract.ErrRecord
	}
	revision, err := contract.GeneratorPhaseRevisionID(id)
	if err != nil || revision != s.head.Core.Revision {
		return contract.ErrRecord
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: snapshot, Transition: transition, Revision: revision}
	for position, ref := range s.root.RequiredSupport {
		if position < len(s.support) {
			rows := make([]contract.SupportRecord, len(s.support[position].Records))
			for i, row := range s.support[position].Records {
				rows[i] = contract.SupportRecord(row)
			}
			if retained, ok := s.retainedOutputPage(rows); ok && retained.ref == ref {
				identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				continue
			}
		}
		page, err := contract.GeneratorPhasePageID(id, contract.RequiredSupportKind, ref.Index)
		if err != nil || page != ref.Object {
			return contract.ErrRecord
		}
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil || descriptor != subject.IdentityPlan {
		return contract.ErrRecord
	}
	return nil
}
