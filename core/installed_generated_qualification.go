package core

import (
	"bytes"

	"enkv.sh/core/contract"
)

// The selected metadata fixes the Delete contract independently of the current
// installation. A Create result contract is never reused as a Delete contract.
func generatedCleanupResultContract(g *generatedSelection, source contract.GeneratedDeleteSource, target contract.GeneratorTarget) (contract.ID, error) {
	if g == nil || g.image == nil {
		return contract.ID{}, contract.ErrRecord
	}
	selected, present := g.records[generatedRecordKey{source.Record.Kind, source.SourceID}]
	if !present || selected.RecordID != source.Record.RecordID || !bytes.Equal(selected.Body, source.Record.Body) {
		return contract.ID{}, contract.ErrRecord
	}
	actual, err := contract.InspectGeneratedDeleteSource(selected)
	if err != nil {
		return contract.ID{}, err
	}
	source = actual
	actualTarget, err := g.generatedCleanupTarget(source.Record.Kind, source.SourceID, source.Target)
	if err != nil || actualTarget != target {
		return contract.ID{}, contract.ErrRecord
	}
	if source.DomainID != g.image.root.Domain || source.ResourceID != target.ResourceID || source.ConfigContractID != target.ConfigContractID || source.ResourceContractID != target.ResourceContractID || source.CompletionClass != target.CompletionClass || target.ResourceDigest.IsZero() {
		return contract.ID{}, contract.ErrRecord
	}
	matches := func(x contract.GeneratorAttemptTemplate) bool {
		return x.Action == contract.GeneratorActionDelete && x.DutyID == source.OwnerID && x.ResourceIncarnationID == source.ResourceID &&
			x.ConfigContractID == source.ConfigContractID && x.ResourceContractID == source.ResourceContractID &&
			x.ExecutorID == source.ExecutorID && x.CredentialRouteID == source.CredentialRouteID && x.DescriptorID == source.DescriptorID &&
			x.CompletionClass == source.CompletionClass && !x.ResultContractID.IsZero()
	}
	checkOriginal := func(record contract.GeneratedAttemptRecord, x contract.GeneratorAttemptTemplate) (contract.ID, error) {
		if record.OperationID != source.OriginalOperationID || record.AttemptID != source.OriginalAttemptID || record.ResultContractID != source.ResultContractID ||
			x.ResultContractID != source.ResultContractID || x.ResourceDigest != target.ResourceDigest || !matches(x) {
			return contract.ID{}, contract.ErrRecord
		}
		return x.ResultContractID, nil
	}
	if original, present := g.attempts[source.OriginalAttemptID]; present && original.expected.Template.Action == contract.GeneratorActionDelete {
		return checkOriginal(original.record, original.expected.Template)
	}
	if original, present := g.releases[source.OriginalAttemptID]; present && original.template.Action == contract.GeneratorActionDelete {
		return checkOriginal(original.attempt, original.template)
	}
	if source.OriginalOperationID != target.OriginalOperationID || source.OriginalAttemptID != target.OriginalAttemptID || source.ResultContractID != target.ResultContractID {
		return contract.ID{}, contract.ErrRecord
	}
	createResult, err := generatedCreateResultID(source.DomainID, source.OriginalOperationID, source.OriginalAttemptID)
	if err != nil {
		return contract.ID{}, err
	}
	var result contract.ID
	graphPresent := false
	for _, bundle := range g.bundles {
		if bundle.Header.OperationID != target.OriginalOperationID {
			continue
		}
		graphPresent = true
		for _, lineage := range bundle.Lineages {
			if lineage.Purpose != contract.GeneratorLineageCleanup {
				continue
			}
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				if x.DutyID != source.OwnerID || x.ResourceIncarnationID != source.ResourceID {
					continue
				}
				if !matches(x) || x.TargetKind != contract.GeneratorTargetResultResourceSlot || x.TargetSourceID != createResult || !x.ResourceDigest.IsZero() || !result.IsZero() {
					return contract.ID{}, contract.ErrRecord
				}
				result = x.ResultContractID
			}
		}
	}
	if result.IsZero() {
		// Kind-13 historical Create evidence can retain an owned target after
		// its original operational graph has ended. It carries no Delete contract.
		if !graphPresent && source.Record.Kind == contract.GeneratedHazardSupportKind && source.Hazard.Exposure == contract.GeneratedExposureLateEffect {
			_, live := g.attempts[source.OriginalAttemptID]
			_, released := g.releases[source.OriginalAttemptID]
			_, evidence := g.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, createResult}]
			if !live && !released && evidence {
				return contract.ID{}, nil
			}
		}
		return contract.ID{}, contract.ErrRecord
	}
	return result, nil
}

func qualifyGeneratedInvocationResult(i ApplyInstallation, out *PublicApplyResult) {
	if out == nil || out.Generated == nil {
		return
	}
	var resolver func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error)
	if i.Generated != nil {
		resolver = i.Generated.ResolveImplementation
	}
	qualifyGeneratedHazards(resolver, out.Generated.Hazards)
}

// Qualification uses only passive installed metadata and already owned safe
// facts. An absent or changed installation cannot erase selected effect facts.
func qualifyGeneratedHazards(resolver func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error), hazards []GeneratedHazardFact) {
	for at := range hazards {
		h := &hazards[at]
		h.CleanupImplementationQualified = false
		if resolver == nil || h.Target == nil || h.CleanupResultContractID.IsZero() {
			continue
		}
		r := h.Record
		if h.Target.ResourceID != r.ResourceID || h.Target.ConfigContractID != r.ConfigContractID || h.Target.ResourceContractID != r.ResourceContractID || h.Target.CompletionClass != r.CompletionClass {
			continue
		}
		request := GeneratedImplementationRequest{ConfigContractID: r.ConfigContractID, ResourceContractID: r.ResourceContractID, LifecycleMode: contract.GeneratorLifecycleManaged,
			Retained: &GeneratedImplementationIdentity{ExecutorID: r.ExecutorID, CredentialRouteID: r.CredentialRouteID,
				DescriptorID: r.DescriptorID, ResultContractID: h.CleanupResultContractID,
				Action: contract.GeneratorActionDelete, InputEncoding: contract.InputEncodingRaw, CompletionClass: r.CompletionClass, MaxSecret: 0, MaxFacts: contract.GeneratorSafeFactsEnvelopeLength}}
		i := ApplyInstallation{Generated: &GeneratedApplyInstallation{ResolveImplementation: resolver}}
		_, err := resolveGeneratedImplementation(i, request)
		h.CleanupImplementationQualified = err == nil
	}
}
