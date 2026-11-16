package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
)

// Fresh allocation must not collide with an accepted future branch, even when
// its result or inbox does not yet exist. Graph inventory does not retain keys.

func (s *StateSession) retainGeneratedIdentities(ctx context.Context, used map[contract.ID]bool) error {
	if used == nil {
		return contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return err
	}
	add := func(ids ...contract.ID) {
		for _, id := range ids {
			if !id.IsZero() {
				used[id] = true
			}
		}
	}
	if g.registry != nil {
		for _, row := range g.registry.Recipients {
			if slices.Contains(g.registry.InitiallyAbsent, row.Recipient.RecipientID) {
				add(row.Recipient.RecipientID, row.Recipient.CurrentBinding.BindingID, row.Recipient.CurrentBinding.BindingIncarnationID)
			}
		}
	}
	if g.parent != nil {
		p := g.parent
		add(p.OperationID, p.MaterialID, p.PlanGraphID, p.RecoveryPolicyID, g.phase.PhaseID)
	}
	for _, bundle := range g.bundles {
		add(bundle.Header.OperationID, bundle.Header.MaterialID, bundle.UsePlan.PlanGraphID,
			bundle.Request.CallerNonce, bundle.Request.PredecessorRevisionID)
		for _, entryPlan := range bundle.ValueEntryPlans {
			add(entryPlan.EntryIncarnationID, entryPlan.PlannedValueSlotID, entryPlan.LineageID)
		}
		for _, lineage := range bundle.Lineages {
			add(lineage.LineageID, lineage.EntryIncarnationID, lineage.ResourceIncarnationID)
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				add(x.AttemptID, x.PredecessorAttemptID, x.ResourceIncarnationID, x.PlannedValueSlotID, x.DutyID, x.HazardID,
					x.TransmissionID, x.ResultID, x.InboxID, x.ConfigContractID, x.ResourceContractID, x.ExecutorID, x.CredentialRouteID,
					x.DescriptorID, x.ResultContractID, x.ResourceDigest, x.TargetSourceID)
				data, commitment, err := contract.GeneratorResultKeyIDs(x.ResultID)
				if err != nil {
					return err
				}
				add(data, commitment)
			}
		}
	}
	addEntry := func(m contract.ValueEntry) error {
		add(m.Incarnation, m.ValueState, m.OriginSnapshot, m.OriginTransition)
		if m.ValueSource == contract.Generated {
			v := m.Generated
			add(v.ConfigContractID, v.ResourceContractID, v.ResourceIncarnationID, v.OriginOperationID, v.OriginAttemptID,
				v.GenerationID, v.ResourceDigest, v.ResourceDigest, v.CreateResultID, v.RetiringDutyID)
		}
		if m.ConfidentialityClass == contract.Secret {
			payload, err := contract.InspectCanonicalPayload(m.ValueBytes)
			if err != nil {
				return err
			}
			add(payload.DataKeyID, payload.CommitmentKeyID)
		}
		return nil
	}
	for _, retained := range g.canonical {
		if err := addEntry(retained.record.Entry); err != nil {
			return err
		}
	}
	for _, entry := range s.root.Names {
		valueEntry := s.valueEntry(entry.Slot)
		if valueEntry == nil {
			return contract.ErrRecord
		}
		if err := addEntry(*valueEntry); err != nil {
			return err
		}
	}
	for key, location := range g.content.locations {
		add(key.id, location.BlobID)
	}
	for materialID, uses := range g.sources {
		row, ok := g.records[generatedRecordKey{contract.OperationMaterialSupportKind, materialID}]
		if !ok {
			return contract.ErrRecord
		}
		material, err := contract.InspectOperationMaterialRecord(row.Body)
		if err != nil {
			return err
		}
		protections, err := contract.InspectGeneratedSourceProtections(material, g.protected[materialID])
		if err != nil {
			return err
		}
		if protections.Count() != len(uses) {
			return contract.ErrRecord
		}
		for i, use := range uses {
			var body []byte
			var err error
			if s.fragmentFacts != nil {
				body, err = g.readSelectedSlice(ctx, contract.GeneratorContentSource, use.SourceID, contract.GeneratorDeclarationEntryMaxLength)
			} else {
				body, err = g.content.read(contract.GeneratorContentSource, use.SourceID, contract.GeneratorDeclarationEntryMaxLength)
			}
			if err != nil {
				return err
			}
			source, err := contract.InspectSealedInputEnvelope(body)
			if err != nil {
				return err
			}
			protection, err := protections.Row(i)
			if err != nil {
				return err
			}
			if protection.SourceID != use.SourceID {
				return contract.ErrRecord
			}
			c := source.Core
			add(c.FileIdentity, c.SourceID, c.DataKeyID,
				source.AuthorityWrap.BindingID, protection.Transfer.Core.EnvelopeID)
		}
	}
	for key, row := range g.records {
		add(key.id)
		switch row.Kind {
		case contract.GeneratedResultSupportKind:
			result, err := contract.InspectGeneratedResultRecord(row.Body)
			if err != nil {
				return err
			}
			add(result.Transfer.Core.EnvelopeID, result.Payload.DataKeyID, result.Payload.CommitmentKeyID)
		case contract.GeneratedDutySupportKind:
			d, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return err
			}
			add(d.OwnerID, d.OriginalOperationID, d.OriginalAttemptID, d.ResourceID, d.ConfigContractID, d.ResourceContractID,
				d.ExecutorID, d.CredentialRouteID, d.DescriptorID, d.ResultContractID)
		case contract.GeneratedHazardSupportKind:
			h, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return err
			}
			add(h.OwnerID, h.OriginalOperationID, h.OriginalAttemptID, h.ResourceID, h.ConfigContractID, h.ResourceContractID,
				h.ExecutorID, h.CredentialRouteID, h.DescriptorID, h.ResultContractID)
		case contract.PendingInboxReleaseSupportKind:
			release, err := contract.InspectPendingInboxReleaseRecord(row.Body)
			if err != nil {
				return err
			}
			add(release.InboxID, release.OriginalResultID, release.HandoffRevisionID)
		case contract.GeneratedCreateEvidenceSupportKind:
			evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
			if err != nil {
				return err
			}
			c, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
			if err != nil {
				return err
			}
			add(c.OperationID, c.MaterialID, c.PlanGraphID, c.AttemptID, c.TransmissionID, c.ResultID,
				c.ExecutorID, c.DescriptorID, c.ConfigContractID, c.ResultContractID)
		}
	}
	for key, vector := range g.vectors.entries {
		if key.kind != contract.GeneratorVectorTargets {
			continue
		}
		for _, body := range vector.rows {
			target, err := contract.InspectGeneratorTarget(body)
			if err != nil {
				return err
			}
			add(target.IncarnationID, target.ResourceID, target.ResourceDigest, target.ResourceDigest, target.ConfigContractID,
				target.ResourceContractID, target.OriginalOperationID, target.OriginalAttemptID, target.ResultContractID)
		}
	}
	return nil
}
