package core

import (
	"context"
	"crypto/rand"
	"time"

	"enkv.sh/core/contract"
)

// Ordinary cleanup fixes the first eligible owner as a one-target vector.
// The preceding original-result scan covers all retained owners; the vector
// bound does not impose a limit on domain cleanup backlog.
func (s *StateSession) installedGeneratedCleanupPlan(ctx context.Context, i ApplyInstallation, work *generatedSelection, selected generatedCleanupSelection, deadline time.Time) (*generatedPlan, error) {
	if work == nil || work.parent != nil || work.phase != nil || i.Generated == nil || i.Generated.RequestDigest == nil ||
		selected.kind != generatedCleanupDuty && selected.kind != generatedCleanupHazard {
		return nil, contract.ErrRecord
	}
	first, present, err := work.selectGeneratedCleanup(ctx, nil)
	if err != nil {
		return nil, err
	}
	if !present || first.kind != selected.kind || first.sourceKey() != selected.sourceKey() || first.target != selected.target {
		return nil, contract.ErrRecord
	}
	source, err := contract.InspectGeneratedDeleteSource(work.records[selected.sourceKey()])
	if err != nil {
		return nil, err
	}
	target := selected.target
	resultContract, err := generatedCleanupResultContract(work, source, target)
	if err != nil {
		return nil, err
	}
	if resultContract.IsZero() {
		return nil, contract.ErrRecord
	}
	implementation, err := resolveGeneratedImplementation(i, GeneratedImplementationRequest{
		ConfigContractID: source.ConfigContractID, ResourceContractID: source.ResourceContractID, LifecycleMode: contract.GeneratorLifecycleManaged,
		Retained: &GeneratedImplementationIdentity{ExecutorID: source.ExecutorID, CredentialRouteID: source.CredentialRouteID,
			DescriptorID: source.DescriptorID, ResultContractID: resultContract,
			Action: contract.GeneratorActionDelete, InputEncoding: contract.InputEncodingRaw, CompletionClass: source.CompletionClass, MaxFacts: contract.GeneratorSafeFactsEnvelopeLength},
	})
	if err != nil {
		return nil, err
	}
	facts, err := work.createTargetEvidence(ctx, target)
	if err != nil {
		return nil, err
	}
	intent, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, facts.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return nil, err
	}
	requestDigest, err := i.Generated.RequestDigest(ctx, implementation, contract.GeneratorActionDelete, intent, &target)
	if err != nil || requestDigest.IsZero() {
		return nil, contract.ErrRecord
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, err
	}
	var operation, nonce contract.ID
	if _, err := rand.Read(operation[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	registry, err := contract.EncodeGeneratedRecipientRegistryImage(contract.GeneratedRecipientRegistryImage{
		Schema: contract.GeneratedRecipientRegistrySchema, DomainID: s.root.Domain, OperationID: operation,
		OriginalPredecessorSnapshotID: s.root.Snapshot, Recipients: currentApplyRecipients(s.registry()),
	})
	if err != nil {
		return nil, err
	}
	var constructionErr error
	fixed := func(id contract.ID, err error) contract.ID {
		if constructionErr == nil && err != nil {
			constructionErr = err
		}
		return id
	}
	descriptor := func(d contract.GeneratorDescriptor, err error) contract.GeneratorDescriptor {
		if constructionErr == nil && err != nil {
			constructionErr = err
		}
		return d
	}
	policy := contract.GeneratorRecoveryPolicyID()
	graph := contract.GeneratorPlanBundle{Request: contract.GeneratorRequestCore{
		Schema: contract.GeneratorPublicRequestCoreSchema, OperationKind: contract.OperationCleanOwnedFailureResidue,
		DomainID: s.root.Domain, OperationID: operation, PredecessorRevisionID: s.head.Core.Revision,
		PredecessorHEADDigest: contract.Hash(s.body), ConditionDigest: c.OriginalConditionDigest, CallerNonce: nonce,
		CompatibilityID: c.CompatibilityID, RecoveryPolicyID: policy,
	}}
	graph.Request.Registry = descriptor(contract.GeneratedRecipientRegistryDescriptor(registry))
	graph.Header = contract.GeneratorGraphHeader{Schema: contract.GeneratorGraphHeaderSchema, DomainID: s.root.Domain,
		OperationID: operation, MaterialID: fixed(contract.GeneratorMaterialID(s.root.Domain, operation)), RecoveryPolicyID: policy}
	graph.UsePlan = contract.GeneratorUsePlanCore{DomainID: s.root.Domain, OperationID: operation,
		MaterialID: graph.Header.MaterialID, ValueDerivationID: contract.GeneratorValueDerivationID()}
	declaration, plans, err := s.installedGeneratedCurrentDeclaration(work, operation)
	if err != nil {
		return nil, err
	}
	graph.ValueEntryPlans = plans
	declarationBody, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		return nil, err
	}
	graph.Request.Declaration = descriptor(contract.GeneratorDeclarationDescriptor(declaration))
	lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: contract.GeneratorLineageCleanup,
		DomainID: s.root.Domain, OperationID: operation, Name: target.Name, EntryIncarnationID: target.IncarnationID,
		Epoch: target.Epoch, IntentDigest: facts.IntentDigest, ResourceIncarnationID: target.ResourceID, TemplateCount: 1}
	lineage.LineageID = fixed(contract.GeneratorObligationLineageID(s.root.Domain, operation, target.ResourceID, contract.GeneratorLineageCleanup))
	x := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, Action: contract.GeneratorActionDelete,
		LineageID: lineage.LineageID, ResourceIncarnationID: target.ResourceID, DutyID: source.OwnerID, ConfigContractID: source.ConfigContractID,
		ResourceContractID: source.ResourceContractID, ExecutorID: source.ExecutorID, CredentialRouteID: source.CredentialRouteID,
		DescriptorID: source.DescriptorID, ResultContractID: resultContract, IntentDigest: facts.IntentDigest,
		ResourceDigest: target.ResourceDigest, TargetKind: contract.GeneratorTargetResultResourceSlot,
		CompletionClass: source.CompletionClass, RequiredAuthoritySet: 1}
	x.TargetSourceID = fixed(generatedCreateResultID(s.root.Domain, target.OriginalOperationID, target.OriginalAttemptID))
	x.LifecycleMode, x.ResultReaderID = contract.GeneratorLifecycleManaged, contract.GeneratorResultReaderID()
	x.AttemptID = fixed(contract.GeneratorAttemptID(lineage.LineageID, contract.GeneratorBranchInitial))
	completeGeneratedTemplate(&x, s.root.Domain, operation, fixed)
	lineage.Templates[0] = x
	graph.Lineages = []contract.GeneratorLineageTemplate{lineage}
	graph.Header.ValueEntryPlanCount, graph.Header.TemplateCount = uint16(len(plans)), 1
	graph.Header.RequestCoreDigest = fixed(contract.GeneratorRequestCoreDigest(graph.Request))
	join := fixed(contract.GeneratorCompleteJoinID(graph.Header.RequestCoreDigest))
	template := fixed(contract.GeneratorTemplateID(x))
	for _, guard := range []uint8{3, 4} {
		graph.Edges = append(graph.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: template,
			DestinationTemplateID: join, Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1})
	}
	graph.ResultUses = []contract.GeneratorResultUse{{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID,
		InboxID: x.InboxID, ExecutorID: x.ExecutorID, ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID,
		MaterialID: graph.Header.MaterialID, Purpose: 1, MaxFacts: contract.GeneratorSafeFactsEnvelopeLength}}
	graph.UsePlan.SourceUses = descriptor(contract.GeneratorSourceUsesDescriptor(nil))
	graph.UsePlan.ResultUses = descriptor(contract.GeneratorResultUsesDescriptor(graph.ResultUses))
	graph.UsePlan.PlanGraphID = fixed(contract.GeneratorGraphID(graph.Header, plans, graph.Lineages, graph.Edges))
	if constructionErr != nil {
		return nil, constructionErr
	}
	return s.generatedPlanRequest(ctx, generatedPlanInput{graph: graph, declaration: declarationBody, registryImage: registry,
		registry: graph.Request.Registry, recoveryPolicy: policy, context: c,
		requestBindings: []generatedRequestBinding{{LineageID: lineage.LineageID, AttemptID: x.AttemptID, Digest: requestDigest}}})
}
