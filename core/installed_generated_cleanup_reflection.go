package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// Original verification uses the actual retained operation and material. A
// detached original has no active parent, declaration, producer or credential.
func (s *StateSession) installedGeneratedVerificationInput(ctx context.Context, work *generatedSelection, plan *generatedLifecyclePlan, q contract.CryptoGeneratedCompareRequest) (contract.GeneratedVerificationInput, error) {
	var input contract.GeneratedVerificationInput
	if work == nil || work.parent != nil || plan == nil || q.Purpose != contract.CryptoGeneratedOriginalVerificationPurpose {
		return input, contract.ErrRecord
	}
	selection, present, err := work.selectGeneratedCleanup(ctx, map[contract.ID][]byte{q.Original.ResultID: plan.result})
	if err != nil {
		return input, err
	}
	if !present || selection.kind != generatedCleanupReflection || selection.attempt.record != q.Original || selection.sourceKey().id != q.OriginalOwnerID {
		return input, contract.ErrRecord
	}
	a := selection.attempt
	input.Owner = work.records[selection.sourceKey()]
	input.Material = a.material
	input.Result = contract.GeneratedResultAdmissionInput{Expected: a.expected, Reference: q.OriginalResult}
	graph, err := work.content.graphForOperation(a.record.OperationID)
	if err != nil {
		return input, err
	}
	input.Session.Graph, err = contract.EncodeGeneratorPlanBundle(graph)
	if err != nil {
		return input, err
	}
	input.Session.BeforePublic, err = s.publicProjection()
	if err != nil {
		return input, err
	}
	input.Session.Output, err = s.generatedOutputTransition(ctx)
	if err != nil {
		return input, err
	}
	input.Session.BeforeReceipts, err = s.receiptWindows(ctx)
	if err != nil {
		return input, err
	}
	input.Session.CurrentRecipients = s.registry()
	for _, ref := range s.root.Recipients {
		if ref != nil {
			input.Session.CurrentRecipientRefs = append(input.Session.CurrentRecipientRefs, *ref)
		}
	}
	seed, present := s.materialAccess(contract.OperationSeedMaterialKind, q.MaterialID)
	if !present {
		return input, contract.ErrRecord
	}
	input.SeedAccess, err = contract.EncodeAccessRecord(seed)
	if err != nil {
		return input, err
	}
	if a.expected.Template.Action == contract.GeneratorActionDelete {
		source, err := contract.InspectGeneratedDeleteSource(input.Owner)
		if err != nil {
			return input, err
		}
		target, err := work.generatedCleanupTarget(source.Record.Kind, source.SourceID, source.Target)
		if err != nil {
			return input, err
		}
		input.Target = &target
	}
	return input, nil
}

func reflectInstalledGeneratedCleanup(ctx context.Context, out PublicApplyResult, s *StateSession, work *generatedSelection, selected generatedCleanupSelection, i ApplyInstallation, deadline time.Time, call *telemetry.Call, checkpoint *generatedSelectionCheckpoint) PublicApplyResult {
	if i.Generated == nil || i.Generated.AdmitVerification == nil {
		return out
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	plan, err := s.generatedReflectionPlan(ctx, selected.attempt.record.ResultID, selected.result, c)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.OperationID, out.RequestIdentity = plan.identity.operation, plan.requestIdentity
	// Complete derivation and capacity admission precede private verification.
	permit, err := s.admitGeneratedLifecyclePlan(ctx, plan)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	q, _, err := s.generatedOriginalVerificationRequest(ctx, plan)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	input, err := s.installedGeneratedVerificationInput(ctx, work, plan, q)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	owner, err := i.Generated.AdmitVerification(ctx, q, currentControlOf(s), input, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	defer owner.Close()
	permit.crypto, permit.instance, permit.verification = owner.Crypto, owner.Crypto.InstanceID(), q
	return selectInstalledGeneratedCleanupLifecycle(ctx, out, s, work, plan, permit, i, call, checkpoint)
}
