package core

import (
	"context"
	"crypto/rand"
	"time"

	"enkv.sh/core/contract"
)

// A fresh retirement carries current values unchanged and fixes one selected
// old resource. Local desired declarations supply no part of this graph.
func (s *StateSession) installedGeneratedRetirementPlan(ctx context.Context, i ApplyInstallation, work *generatedSelection, dutyID, nonce contract.ID, deadline time.Time) (*generatedPlan, error) {
	if work == nil || work.parent != nil || i.Generated == nil || i.Generated.RequestDigest == nil {
		return nil, contract.ErrRecord
	}
	row, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}]
	if !present {
		return nil, contract.ErrRecord
	}
	duty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || duty.Kind != contract.GeneratedDutyRetirement {
		return nil, contract.ErrRecord
	}
	target, err := work.retirementTarget(ctx, duty)
	if err != nil {
		return nil, err
	}
	implementation, err := resolveGeneratedImplementation(i, GeneratedImplementationRequest{
		ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID, LifecycleMode: duty.LifecycleMode,
		Retained: &GeneratedImplementationIdentity{ExecutorID: duty.ExecutorID, CredentialRouteID: duty.CredentialRouteID,
			DescriptorID: duty.DescriptorID, ResultContractID: duty.ResultContractID,
			Action: contract.GeneratorActionDelete, InputEncoding: contract.InputEncodingRaw, CompletionClass: duty.CompletionClass, MaxFacts: contract.GeneratorSafeFactsEnvelopeLength},
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
	if err != nil {
		return nil, err
	}
	if requestDigest.IsZero() {
		return nil, contract.ErrRecord
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, err
	}
	var operation contract.ID
	if _, err := rand.Read(operation[:]); err != nil {
		return nil, err
	}
	if nonce.IsZero() {
		return nil, contract.ErrRecord
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
		Schema: contract.GeneratorPublicRequestCoreSchema, OperationKind: contract.OperationRetireGeneratedGeneration,
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
	lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: contract.GeneratorLineageRetirement,
		DomainID: s.root.Domain, OperationID: operation, Name: target.Name, EntryIncarnationID: target.IncarnationID,
		Epoch: target.Epoch, IntentDigest: facts.IntentDigest, ResourceIncarnationID: target.ResourceID, TemplateCount: 1}
	lineage.LineageID = fixed(contract.GeneratorObligationLineageID(s.root.Domain, operation, target.ResourceID, contract.GeneratorLineageRetirement))
	x := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, Action: contract.GeneratorActionDelete,
		LineageID: lineage.LineageID, ResourceIncarnationID: target.ResourceID, DutyID: dutyID, ConfigContractID: duty.ConfigContractID,
		ResourceContractID: duty.ResourceContractID, ExecutorID: duty.ExecutorID, CredentialRouteID: duty.CredentialRouteID,
		DescriptorID: duty.DescriptorID, ResultContractID: duty.ResultContractID, IntentDigest: facts.IntentDigest,
		ResourceDigest: target.ResourceDigest, TargetKind: 2, TargetSourceID: target.ResourceID, CompletionClass: duty.CompletionClass, RequiredAuthoritySet: 1}
	x.LifecycleMode, x.ResultReaderID = duty.LifecycleMode, contract.GeneratorResultReaderID()
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

func (s *StateSession) installedGeneratedCurrentDeclaration(work *generatedSelection, operation contract.ID) (contract.GeneratorDeclaration, []contract.GeneratorValueEntryPlan, error) {
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: s.root.Domain, OperationID: operation}
	plans := make([]contract.GeneratorValueEntryPlan, 0, len(s.root.Names))
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil {
			return declaration, nil, contract.ErrRecord
		}
		decl := contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Name: named.Name, InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Recipients: entry.Recipients}
		plan := contract.GeneratorValueEntryPlan{Schema: contract.GeneratorValueEntryPlanSchema, Name: named.Name, Slot: named.Slot, EntryIncarnationID: entry.Incarnation,
			ValueSource: entry.ValueSource, ConfidentialityClass: entry.ConfidentialityClass, InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding}
		var err error
		plan.IntendedMembership, err = contract.GeneratorIntendedMembershipDescriptor(entry.Recipients)
		if err != nil {
			return declaration, nil, err
		}
		switch {
		case entry.ValueSource == contract.Generated:
			m := entry.Generated
			location, found := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, m.IntentDigest}]
			if !found {
				return declaration, nil, contract.ErrRecord
			}
			decl.Kind = contract.GeneratorDeclarationGeneratedReference
			decl.Payload, err = contract.EncodeGeneratorDeclaredGenerationReference(contract.GeneratorDeclaredGenerationReference{Schema: contract.GeneratorDeclaredReferenceSchema, LifecycleMode: m.SemanticLifecycleMode(),
				Epoch: m.Epoch, RetirementMode: m.RetirementMode, ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID,
				CompletionClass: m.CompletionClass, Intent: location.Logical()})
			plan.Epoch, plan.RetirementMode, plan.IntentDigest, plan.LifecycleMode = m.Epoch, m.RetirementMode, m.IntentDigest, m.SemanticLifecycleMode()
		case entry.ConfidentialityClass == contract.Plain:
			decl.Kind, decl.Payload = contract.GeneratorDeclarationPlain, entry.ValueBytes
		default:
			decl.Kind = contract.GeneratorDeclarationRetained
			decl.Payload, err = contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: named.Slot, Entry: *entry})
		}
		if err != nil {
			return declaration, nil, err
		}
		declaration.Entries = append(declaration.Entries, decl)
		plans = append(plans, plan)
	}
	body, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		return declaration, nil, err
	}
	view, err := contract.InspectGeneratorDeclaration(body)
	if err != nil {
		return declaration, nil, err
	}
	slices, err := view.LogicalSlices()
	if err != nil {
		return declaration, nil, err
	}
	logical := make(map[contract.ID]contract.GeneratorLogicalSlice, len(slices))
	for _, row := range slices {
		logical[row.ContentID] = row
	}
	for at := range plans {
		id := plans[at].IntentDigest
		if id.IsZero() {
			id, err = contract.GeneratorDeclarationEntryID(s.root.Domain, operation, plans[at].Name)
			if err != nil {
				return declaration, nil, err
			}
		}
		plans[at].SourceSlice, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical[id]})
		if err != nil {
			return declaration, nil, err
		}
	}
	return declaration, plans, nil
}
