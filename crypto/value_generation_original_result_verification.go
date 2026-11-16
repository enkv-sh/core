package crypto

import (
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func (r *Runtime) admitGeneratedVerification(q contract.CryptoGeneratedCompareRequest, input generatedOriginalVerificationAdmissionInput, body []byte, deadline time.Time) error {
	_, err := r.admitGeneratedVerificationOwned(q, input, body, deadline)
	return err
}

func (r *Runtime) admitGeneratedVerificationOwned(q contract.CryptoGeneratedCompareRequest, input generatedOriginalVerificationAdmissionInput, body []byte, deadline time.Time) (*generatedAdmission, error) {
	if input.Result.Reference != q.OriginalResult {
		return nil, ErrAdmission
	}
	graph, err := contract.DecodeGeneratorPlanBundle(input.Session.Graph)
	if err != nil || contract.ValidateGeneratorEffectGraph(graph) != nil {
		return nil, ErrAdmission
	}
	descriptor, err := contract.GeneratorPlanBundleDescriptor(graph)
	use, useErr := contract.GeneratorUsePlanDigest(graph.UsePlan)
	if err != nil || useErr != nil || descriptor != q.PlanGraph || use != q.UsePlanDigest || graph.Header.MaterialID != q.MaterialID ||
		graph.Header.DomainID != q.Context.DomainID || graph.Header.OperationID != q.Original.OperationID {
		return nil, ErrAdmission
	}
	state := &generatedOriginalVerificationState{result: input.Result}
	a, err := r.newGeneratedAdmission(q, input.Session, graph, generatedPurposeState{verification: state}, body, deadline)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			a.clear()
		}
	}()
	if input.Owner.Kind != q.OriginalOwnerKind || input.Owner.RecordID != q.OriginalOwnerID || a.purpose.output == nil {
		return nil, ErrAdmission
	}
	materialBody, err := contract.EncodeOperationMaterialRecord(input.Material)
	if err != nil {
		return nil, ErrAdmission
	}
	materialFact, err := contract.InspectSupportRecordDigest(q.Context.DomainID, contract.SupportRecord{
		Kind: contract.OperationMaterialSupportKind, RecordID: q.MaterialID, Body: materialBody})
	if err != nil || !slices.Contains(a.purpose.output.Rows.Facts, materialFact) {
		return nil, ErrAdmission
	}
	expected := input.Result.Expected
	originalBody, err := contract.EncodeGeneratedAttemptRecord(q.Original)
	if err != nil {
		return nil, ErrAdmission
	}
	originalFact, err := contract.InspectSupportRecordDigest(q.Context.DomainID, contract.SupportRecord{
		Kind: contract.GeneratedAttemptSupportKind, RecordID: q.Original.AttemptID, Body: originalBody})
	if err != nil || !slices.Contains(a.purpose.output.Rows.Facts, originalFact) {
		return nil, ErrAdmission
	}
	fact, err := contract.InspectSupportRecordDigest(q.Context.DomainID, input.Owner)
	if err != nil || !slices.Contains(a.purpose.output.Rows.Facts, fact) {
		return nil, ErrAdmission
	}
	owner, err := contract.InspectGeneratedDeleteSource(input.Owner)
	if err != nil || owner.DomainID != q.Context.DomainID || owner.CompletionClass != q.Original.CompletionClass {
		return nil, ErrAdmission
	}
	if expected.Template.Action == contract.GeneratorActionCreate {
		if input.Owner.Kind != contract.GeneratedHazardSupportKind || owner.Hazard.HazardID != expected.Template.HazardID ||
			owner.OriginalOperationID != q.Original.OperationID || owner.OriginalAttemptID != q.Original.AttemptID || owner.OwnerID != q.Original.OwnerID ||
			owner.Hazard.Fenced != 1 || owner.Hazard.Exposure != contract.GeneratedExposurePossibleLive || q.Original.State != contract.GeneratedEffectClosedWithResidue {
			return nil, ErrAdmission
		}
	} else if owner.OwnerID != q.Original.OwnerID || owner.Target != q.Target ||
		input.Owner.Kind == contract.GeneratedDutySupportKind && owner.Duty.Kind != contract.GeneratedDutyUnselectedCleanup ||
		input.Owner.Kind == contract.GeneratedHazardSupportKind && owner.Hazard.Fenced != 1 {
		return nil, ErrAdmission
	}
	if !a.admitSeed(input.Material, input.SeedAccess) || !a.expectedResultMatches(expected) ||
		!generatedUncertainAttemptMatches(q.Original, expected.Template, graph.Header.DomainID, graph.Header.OperationID) ||
		q.Original.RequestDigest != expected.RequestDigest {
		return nil, ErrAdmission
	}
	if expected.Template.Action == contract.GeneratorActionDelete {
		if input.Target == nil {
			return nil, ErrAdmission
		}
		targetBody, err := contract.EncodeGeneratorTarget(*input.Target)
		if err != nil {
			return nil, ErrAdmission
		}
		target, err := contract.InspectGeneratorTarget(targetBody)
		if err != nil {
			return nil, ErrAdmission
		}
		state.target = target
		descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{targetBody})
		if err != nil || descriptor != q.Target || !a.deleteTargetTemplateMatches(expected.Template) || target.ResourceDigest != expected.TargetResourceDigest {
			return nil, ErrAdmission
		}
	} else if input.Target != nil || q.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) || !expected.TargetResourceDigest.IsZero() {
		return nil, ErrAdmission
	}
	transferred = true
	if err := r.installGeneratedAdmission(a, deadline); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *generatedAdmission) verifyOriginalResult(v contract.CryptoGeneratedVerifyRequest, out *contract.CryptoResponse) contract.CryptoResultCode {
	ref := a.request.OriginalResult
	if v.ExpectedResult != (contract.GeneratorDescriptor{Digest: ref.ResultBodyDigest, Length: uint64(ref.ResultLength), Count: 1}) ||
		len(v.Result) != int(ref.ResultLength) || contract.Hash(v.Result) != ref.ResultBodyDigest {
		return contract.CryptoInvalidAdmission
	}
	result, err := contract.DecodeGeneratedResultRecord(v.Result)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	verification := a.purpose.verification
	if verification == nil {
		return contract.CryptoInvalidAdmission
	}
	plaintext, err := custody.OpenGeneratedResult(verification.result.Expected, a.material, a.seed, result)
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	clear(plaintext[:cap(plaintext)])
	out.Body, err = contract.EncodeGeneratorResultReference(ref)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	return contract.CryptoSuccess
}
