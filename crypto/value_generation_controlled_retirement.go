package crypto

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

type generatedControlledPredecessor struct {
	source             contract.GeneratedDeleteSource
	progress           [][]byte
	SeedAccess, Result []byte
	Expected           contract.GeneratorResultExpectation
	Material           contract.OperationMaterialRecord
}

func (a *generatedAdmission) admitControlledPredecessor(input *contract.GeneratedControlledPredecessor) bool {
	plan := a.purpose.plan()
	if plan == nil {
		return input == nil
	}
	target := a.deleteTarget()
	if input == nil {
		if target == nil {
			// Initial create graphs also pin future cleanup templates, but do
			// not enter those rights. Only an actual create lineage exempts
			// that initial graph, never a standalone delete lacking its target.
			for _, l := range a.graph.Lineages {
				if l.Purpose == contract.GeneratorLineageCreate {
					return true
				}
			}
		}
		for _, l := range a.graph.Lineages {
			if l.Purpose == contract.GeneratorLineageCreate {
				continue
			}
			for _, t := range l.Templates[:l.TemplateCount] {
				if t.Action == contract.GeneratorActionDelete && t.CompletionClass == contract.GeneratedCompletionConfirmed {
					return false
				}
			}
		}
		return true
	}
	source, progress, err := a.controlledSelectedSource(input)
	if err != nil {
		return false
	}
	owned := &generatedControlledPredecessor{source: source, progress: progress}
	owned.source.Record.Body = bytes.Clone(source.Record.Body)
	if len(progress) == 0 {
		if len(input.Result) != 0 || len(input.Graph) != 0 || len(input.SeedAccess) != 0 || input.Expected != (contract.GeneratorResultExpectation{}) || input.Material != (contract.OperationMaterialRecord{}) {
			return false
		}
		plan.controlledPredecessor = owned
		return true
	}
	// One original standalone ACK only. These private input ceilings fit the
	// existing bounded graph/continuation buffers, including all 512 passive
	// entry plans. They do not reduce public limits.
	if len(input.Graph) > contract.GeneratorControlledGraphMaxLength || len(input.Result) > contract.GeneratorControlledResultMaxLength || len(input.SeedAccess) > contract.GeneratorControlledSeedAccessMaxLength {
		return false
	}
	graph, err := a.controlledSelectedGraph(input.BeforeRecords, input.Expected.Plan.PlanGraphID, input.Graph)
	if err != nil {
		return false
	}
	t := input.Expected.Template
	match := false
	for _, lineage := range graph.Lineages {
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			match = match || x == t
		}
	}
	useMatch := false
	for _, u := range graph.ResultUses {
		useMatch = useMatch || u == input.Expected.Use
	}
	if !match || !useMatch || t.Action != contract.GeneratorActionDelete || t.DutyID != source.OwnerID || t.ResourceIncarnationID != source.ResourceID || t.DescriptorID != source.DescriptorID || t.ConfigContractID != source.ConfigContractID ||
		t.CompletionClass != source.CompletionClass || target == nil || input.Expected.TargetResourceDigest != target.ResourceDigest || input.Expected.Plan != graph.UsePlan {
		return false
	}
	p, err := contract.InspectGeneratorProgress(progress[0])
	result := generatedSelectedRecord(input.BeforeRecords, contract.GeneratedResultSupportKind, t.ResultID)
	material := generatedSelectedRecord(input.BeforeRecords, contract.OperationMaterialSupportKind, graph.Header.MaterialID)
	materialBody, materialErr := contract.EncodeOperationMaterialRecord(input.Material)
	if err != nil || p.AttemptID != t.AttemptID || p.ResultID != t.ResultID || p.Evidence.Digest != contract.Hash(input.Result) || p.Evidence.Length != uint64(len(input.Result)) ||
		!bytes.Equal(result.Body, input.Result) || materialErr != nil || !bytes.Equal(material.Body, materialBody) {
		return false
	}
	tmp := *a
	tmp.graph = graph
	tmp.request.MaterialID = graph.Header.MaterialID
	tmp.request.UsePlanDigest = input.Material.Core.UsePlanDigest
	if !tmp.admitSeed(input.Material, input.SeedAccess) {
		return false
	}
	r, err := contract.DecodeGeneratedResultRecord(input.Result)
	if err != nil || contract.ValidateGeneratedResult(input.Expected, input.Material, r) != nil || r.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged {
		return false
	}
	// Graph semantics have been checked against the exact use/material. It is
	// not a later reader and need not be retained with private custody.
	owned.Expected, owned.Material = input.Expected, input.Material
	owned.SeedAccess = bytes.Clone(input.SeedAccess)
	owned.Result = bytes.Clone(input.Result)
	plan.controlledPredecessor = owned
	return true
}

func (a *generatedAdmission) openControlledPredecessor(ctx context.Context, route KeyAccess, out *contract.CryptoResponse) contract.CryptoResultCode {
	plan := a.purpose.plan()
	if plan == nil {
		return contract.CryptoSuccess
	}
	p := plan.controlledPredecessor
	if p == nil || len(p.progress) == 0 {
		return contract.CryptoSuccess
	}
	access, err := contract.DecodeAccessRecord(p.SeedAccess)
	if err != nil {
		return contract.CryptoInvalidAdmission
	}
	tmp := &generatedAdmission{control: a.control, bindings: a.bindings, material: p.Material, access: access}
	defer func() { clear(tmp.seed[:cap(tmp.seed)]) }()
	if code := tmp.openContinuation(ctx, route, out); code != contract.CryptoSuccess {
		return code
	}
	r, err := contract.DecodeGeneratedResultRecord(p.Result)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	plain, err := custody.OpenGeneratedResult(p.Expected, p.Material, tmp.seed, r)
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	clear(plain[:cap(plain)])
	return contract.CryptoSuccess
}

// The fixed response binds resource incarnation, resource digest and scope.
// Only an exact inactive response qualifies; generic refusal is not confirmation.
func controlledRetirementProbeFacts(p *generatedProducerReturnOwner, response []byte) contract.GeneratorSafeFacts {
	x := p.expected.Template
	f := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionDelete, LifecycleMode: x.LifecycleMode,
		ResourceContractID: x.ResourceContractID, Disposition: contract.GeneratorDispositionUnknown, Reason: contract.GeneratorReasonRejected,
		RequestDigest: p.command.RequestDigest, IntentDigest: x.IntentDigest}
	original, err := contract.InspectGeneratorSafeFacts(p.command.OriginalFacts)
	if err != nil {
		return f
	}
	f.Target, f.ResourceData = bytes.Clone(original.Target), bytes.Clone(original.ResourceData)
	if len(response) != 97 || response[0] != 1 && response[0] != 2 || len(p.progress) != 1 {
		return f
	}
	progress, err := contract.InspectGeneratorProgress(p.progress[0])
	if err != nil {
		return f
	}
	var observedResource, observedDigest, observedScope contract.ID
	copy(observedResource[:], response[1:33])
	copy(observedDigest[:], response[33:65])
	copy(observedScope[:], response[65:97])
	if observedResource.IsZero() || observedDigest.IsZero() || observedScope.IsZero() {
		return f
	}
	scope := contract.GeneratorControlledRetirementScope(x.DescriptorID, x.ConfigContractID, x.ResultContractID)
	f.Disposition, f.Reason = contract.GeneratorDispositionScopedUnusability, contract.GeneratorReasonNone
	f.ScopeID, f.PrecedingResultID, f.PrecedingResultBodyDigest = scope, progress.ResultID, progress.Evidence.Digest
	f.ObservedResourceID, f.ObservedResourceDigest, f.ObservedScopeID = observedResource, observedDigest, observedScope
	if observedResource != x.ResourceIncarnationID || observedDigest != p.command.ResourceDigest || observedScope != scope {
		f.Disposition = contract.GeneratorDispositionConflictingBinding
	} else if response[0] == 1 {
		f.Disposition = contract.GeneratorDispositionContinuedUsability
	}
	return f
}
