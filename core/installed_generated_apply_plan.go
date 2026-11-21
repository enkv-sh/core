package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"time"

	"enkv.sh/core/contract"
)

func installedGeneratedContext(s *StateSession, deadline time.Time) (contract.ApplyContext, error) {
	var c contract.ApplyContext
	if s == nil || !validPrivateDeadline(deadline) {
		return c, contract.ErrRecord
	}
	c.OperationClass = contract.CryptoGeneratedClass
	c.DomainID = s.root.Domain
	c.CompatibilityID = s.root.CurrentAccess.Core.CompatibilityID
	c.Expiry = uint64(deadline.UnixNano())
	c.PredecessorHEADDigest = contract.Hash(s.body)
	c.CurrentAccessRoot = s.root.CurrentAccess.AccessRoot
	if _, err := rand.Read(c.AdmissionID[:]); err != nil {
		return c, err
	}
	if _, err := rand.Read(c.SessionID[:]); err != nil {
		return c, err
	}
	ref, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		return c, err
	}
	copy(c.PredecessorRootRef[:], ref)
	c.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	return c, err
}

func installedGeneratedCreates(input []ApplyEntryInput) bool {
	return slices.ContainsFunc(input, func(row ApplyEntryInput) bool {
		return row.ValueSource == contract.Generated && len(row.InputBytes) == 0
	})
}

func resolveGeneratedImplementation(i ApplyInstallation, request GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
	if i.Generated == nil || i.Generated.ResolveImplementation == nil || request.ConfigContractID.IsZero() ||
		request.LifecycleMode != contract.GeneratorLifecycleNone && request.LifecycleMode != contract.GeneratorLifecycleManaged ||
		(request.LifecycleMode == contract.GeneratorLifecycleNone) != request.ResourceContractID.IsZero() {
		return contract.GeneratorImplementation{}, contract.ErrRecord
	}
	row, err := i.Generated.ResolveImplementation(request)
	if err != nil {
		return row, err
	}
	if row.Validate() != nil {
		return row, contract.ErrRecord
	}
	row.CredentialRoute = slices.Clone(row.CredentialRoute)
	if request.Retained != nil && !request.Retained.Matches(row) {
		return row, contract.ErrRecord
	}
	return row, nil
}

func (s *StateSession) installedGeneratedPlan(ctx context.Context, i ApplyInstallation, input []ApplyEntryInput, output *outputApplyInput, deadline time.Time) (*generatedPlan, error) {
	if i.Generated == nil || i.Generated.RequestDigest == nil {
		return nil, contract.ErrRecord
	}
	entries := slices.Clone(input)
	slices.SortFunc(entries, func(a, b ApplyEntryInput) int { return strings.Compare(a.Name, b.Name) })
	var constructionErr error
	fixed := func(id contract.ID, err error) contract.ID {
		if err != nil && constructionErr == nil {
			constructionErr = err
		}
		return id
	}
	descriptor := func(v contract.GeneratorDescriptor, err error) contract.GeneratorDescriptor {
		if err != nil && constructionErr == nil {
			constructionErr = err
		}
		return v
	}
	encode := func(v []byte, err error) []byte {
		if err != nil && constructionErr == nil {
			constructionErr = err
		}
		return v
	}
	var operation, nonce contract.ID
	if _, err := rand.Read(operation[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	image := contract.GeneratedRecipientRegistryImage{Schema: contract.GeneratedRecipientRegistrySchema, DomainID: s.root.Domain, OperationID: operation, OriginalPredecessorSnapshotID: s.root.Snapshot, Recipients: i.DesiredRecipients}
	for _, row := range i.DesiredRecipients {
		if s.recipientRecord(row.Recipient.RecipientID) == nil {
			image.InitiallyAbsent = append(image.InitiallyAbsent, row.Recipient.RecipientID)
		}
	}
	registryBody, err := contract.EncodeGeneratedRecipientRegistryImage(image)
	if err != nil {
		return nil, err
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, err
	}
	// The policy commitment is fixed for this operation; current binding
	// replacement changes neither accepted graph nor accepted proposal.
	policy := contract.GeneratorRecoveryPolicyID()
	g := contract.GeneratorPlanBundle{Request: contract.GeneratorRequestCore{Schema: contract.GeneratorApplyRequestCoreSchema, OperationKind: contract.OperationApplyDeclaration, DomainID: s.root.Domain, OperationID: operation, PredecessorRevisionID: s.head.Core.Revision, PredecessorHEADDigest: contract.Hash(s.body), ConditionDigest: c.OriginalConditionDigest, CallerNonce: nonce, CompatibilityID: c.CompatibilityID, RecoveryPolicyID: policy}}
	g.Request.Registry = descriptor(contract.GeneratedRecipientRegistryDescriptor(registryBody))
	g.Header = contract.GeneratorGraphHeader{Schema: contract.GeneratorGraphHeaderSchema, DomainID: s.root.Domain, OperationID: operation, MaterialID: fixed(contract.GeneratorMaterialID(s.root.Domain, operation)), RecoveryPolicyID: policy}
	g.UsePlan = contract.GeneratorUsePlanCore{DomainID: s.root.Domain, OperationID: operation, MaterialID: g.Header.MaterialID, ValueDerivationID: contract.GeneratorValueDerivationID()}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: s.root.Domain, OperationID: operation}
	before := make(map[string]*contract.ValueEntry, len(s.root.Names))
	slots := make(map[string]uint16, len(s.root.Names))
	var occupied [contract.CryptoMaxValueEntries]bool
	for _, named := range s.root.Names {
		before[named.Name] = s.valueEntry(named.Slot)
		slots[named.Name] = named.Slot
	}
	for _, entry := range entries {
		if old := before[entry.Name]; old != nil {
			occupied[slots[entry.Name]] = true
		}
	}
	var bindings []generatedRequestBinding
	creates := 0
	for _, entry := range entries {
		old := before[entry.Name]
		slot, exists := slots[entry.Name]
		if !exists {
			free := slices.Index(occupied[:], false)
			if free < 0 {
				return nil, contract.ErrRecordCapacity
			}
			slot = uint16(free)
			occupied[free] = true
		}
		incarnation := contract.ID{}
		if old != nil && old.ValueSource == entry.ValueSource {
			incarnation = old.Incarnation
		} else {
			if _, err := rand.Read(incarnation[:]); err != nil {
				return nil, err
			}
		}
		plan := contract.GeneratorValueEntryPlan{Schema: contract.GeneratorValueEntryPlanSchema, Name: entry.Name, Slot: slot, EntryIncarnationID: incarnation, ValueSource: entry.ValueSource, ConfidentialityClass: entry.ConfidentialityClass, InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, IntendedMembership: descriptor(contract.GeneratorIntendedMembershipDescriptor(entry.Recipients))}
		if old == nil || !slices.Equal(old.Recipients, entry.Recipients) {
			plan.ChangeMask |= contract.GeneratorValueChangeMembership
		}
		decl := contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Name: entry.Name, InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Recipients: entry.Recipients}
		switch {
		case entry.ValueSource == contract.Generated:
			if entry.Generated == nil {
				return nil, contract.ErrRecord
			}
			meta := *entry.Generated
			plan.Epoch, plan.RetirementMode, plan.LifecycleMode = meta.Epoch, meta.RetirementMode, meta.LifecycleMode
			plan.IntentDigest = fixed(contract.GeneratorIntentDigest(meta.Intent))
			decl.Kind = contract.GeneratorDeclarationGenerated
			decl.Payload = encode(contract.EncodeGeneratorDeclaredGeneration(meta))
			if old != nil && old.ValueSource == contract.Generated && meta.Epoch == old.Generated.Epoch {
				if old.InputEncoding != entry.InputEncoding {
					return nil, contract.ErrRecord
				}
				if !bytes.Equal(entry.InputBytes, old.ValueBytes) {
					return nil, contract.ErrRecord
				}
				if meta.RetirementMode != old.Generated.RetirementMode {
					plan.ChangeMask |= contract.GeneratorValueChangeRetirement
				}
				break
			}
			plan.ChangeMask |= contract.GeneratorValueChangeContent
			implementation, err := resolveGeneratedImplementation(i, GeneratedImplementationRequest{EntryName: entry.Name, ConfigContractID: meta.ConfigContractID, ResourceContractID: meta.ResourceContractID, LifecycleMode: meta.LifecycleMode})
			if err != nil {
				return nil, err
			}
			if i.Generated.CheckCreateReadiness == nil {
				return nil, contract.ErrRecord
			}
			if err := i.Generated.CheckCreateReadiness(ctx, entry.Name, implementation, meta.Intent); err != nil {
				return nil, err
			}
			lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: contract.GeneratorLineageCreate, DomainID: s.root.Domain, OperationID: operation, Name: entry.Name, EntryIncarnationID: incarnation, Epoch: meta.Epoch, IntentDigest: plan.IntentDigest, TemplateCount: 5}
			local := meta.LifecycleMode == contract.GeneratorLifecycleNone
			maxSecret, maxFacts := uint32(65536), uint32(4096)
			if local {
				lineage.TemplateCount = 1
				maxSecret, maxFacts = contract.CryptoMaxRawValue, contract.GeneratorSafeFactsEnvelopeLength
			}
			lineage.LineageID = fixed(contract.GeneratorLineageID(s.root.Domain, operation, entry.Name, incarnation, meta.Epoch, plan.IntentDigest))
			for branch := range int(lineage.TemplateCount) {
				x := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, Branch: uint8(branch), Action: contract.GeneratorActionCreate, LineageID: lineage.LineageID, ConfigContractID: meta.ConfigContractID, ResourceContractID: meta.ResourceContractID, ExecutorID: implementation.ExecutorID, CredentialRouteID: implementation.CredentialRouteID, DescriptorID: implementation.DescriptorID, IntentDigest: plan.IntentDigest, TargetKind: 1, TargetSourceID: plan.IntentDigest, CompletionClass: meta.CompletionClass, RequiredAuthoritySet: 1}
				x.LifecycleMode, x.ResultReaderID = meta.LifecycleMode, contract.GeneratorResultReaderFor(x.Action, x.CompletionClass, entry.InputEncoding)
				if local {
					x.TargetKind, x.TargetSourceID = 0, contract.ID{}
				}
				x.ResultContractID = fixed(contract.GeneratedResultContractID(implementation, x.Action, x.CompletionClass, maxSecret, maxFacts, entry.InputEncoding))
				x.AttemptID = fixed(contract.GeneratorAttemptID(lineage.LineageID, x.Branch))
				if branch != 0 {
					pre := uint8(0)
					if branch > 2 {
						pre = uint8(branch - 2)
					}
					x.PredecessorAttemptID = fixed(contract.GeneratorAttemptID(lineage.LineageID, pre))
				}
				x.ResourceIncarnationID = fixed(contract.GeneratorResourceID(s.root.Domain, operation, x.AttemptID))
				x.DutyID = fixed(contract.GeneratorDutyID(s.root.Domain, operation, x.AttemptID, 1))
				completeGeneratedTemplate(&x, s.root.Domain, operation, fixed)
				if !local && (branch == 0 || branch == 2) {
					x.NoEffectBudget = 1
				}
				if !local && (branch == 0 || branch == 1) {
					x.ResidueBudget = 1
				}
				lineage.Templates[branch] = x
			}
			g.Lineages = append(g.Lineages, lineage)
			creates++
			plan.LineageID = lineage.LineageID
			plan.PlannedValueSlotID = lineage.Templates[0].PlannedValueSlotID
			digest, err := i.Generated.RequestDigest(ctx, implementation, contract.GeneratorActionCreate, meta.Intent, nil)
			if err != nil || digest.IsZero() {
				return nil, contract.ErrRecord
			}
			bindings = append(bindings, generatedRequestBinding{LineageID: lineage.LineageID, AttemptID: lineage.Templates[0].AttemptID, Digest: digest})
			for _, create := range lineage.Templates[:lineage.TemplateCount] {
				if local {
					continue
				}
				cleanup := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: contract.GeneratorLineageCleanup, DomainID: s.root.Domain, OperationID: operation, Name: entry.Name, EntryIncarnationID: incarnation, Epoch: meta.Epoch, IntentDigest: plan.IntentDigest, ResourceIncarnationID: create.ResourceIncarnationID, TemplateCount: 1}
				cleanup.LineageID = fixed(contract.GeneratorObligationLineageID(s.root.Domain, operation, create.ResourceIncarnationID, 3))
				x := create
				x.Action, x.Branch, x.NoEffectBudget, x.ResidueBudget, x.TargetKind = 2, 0, 0, 0, 3
				x.ResultReaderID = contract.GeneratorResultReaderID()
				x.LineageID, x.TargetSourceID, x.PredecessorAttemptID = cleanup.LineageID, create.ResultID, contract.ID{}
				x.AttemptID = fixed(contract.GeneratorAttemptID(cleanup.LineageID, 0))
				x.ResultContractID = fixed(contract.GeneratedResultContractID(implementation, 2, x.CompletionClass, 0, 4096, contract.InputEncodingRaw))
				completeGeneratedTemplate(&x, s.root.Domain, operation, fixed)
				cleanup.Templates[0] = x
				g.Lineages = append(g.Lineages, cleanup)
			}
		case entry.ConfidentialityClass == contract.Plain:
			decl.Kind, decl.Payload = contract.GeneratorDeclarationPlain, entry.InputBytes
			if old == nil || old.ValueSource != contract.Supplied || old.InputEncoding != entry.InputEncoding || !bytes.Equal(old.ValueBytes, entry.InputBytes) {
				plan.ChangeMask |= contract.GeneratorValueChangeContent
			}
		case entry.Retained != nil:
			if old == nil || old.ValueSource != contract.Supplied || old.ValueState != entry.Retained.Material || old.Incarnation != entry.Retained.Incarnation {
				return nil, contract.ErrRecord
			}
			decl.Kind = contract.GeneratorDeclarationRetained
			decl.Payload = encode(contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: slot, Entry: *old}))
		default:
			source, err := contract.InspectSealedInputEnvelope(entry.InputBytes)
			if err != nil || source.Core.FileIdentity != i.FileIdentity {
				return nil, contract.ErrRecord
			}
			decl.Kind, decl.Payload = contract.GeneratorDeclarationSealed, entry.InputBytes
			plan.ChangeMask |= contract.GeneratorValueChangeContent
			refs := make([]contract.RecipientBindingReference, len(entry.Recipients))
			for j, id := range entry.Recipients {
				r := slices.IndexFunc(i.DesiredRecipients, func(row contract.ApplyRecipientInput) bool { return row.Recipient.RecipientID == id })
				if r < 0 {
					return nil, contract.ErrRecord
				}
				refs[j] = contract.RecipientBindingReference{RecipientID: id, PublicBindingDigest: fixed(contract.PublicBindingDigest(*i.DesiredRecipients[r].Recipient.CurrentBinding))}
			}
			intended := fixed(contract.IntendedRecipientBindingSetDigest(s.root.Domain, s.admission.recipient, refs))
			if intended != source.Core.IntendedRecipientBindingSetDigest {
				if old == nil || old.ValueSource != contract.Supplied || old.ConfidentialityClass != contract.Secret || slices.ContainsFunc(entry.Recipients, func(id contract.ID) bool { return !slices.Contains(old.Recipients, id) }) {
					return nil, &sealedInputBindingError{name: strings.Clone(entry.Name)}
				}
				plan.ChangeMask &^= contract.GeneratorValueChangeContent
			}
		}
		if old != nil && old.ValueSource != entry.ValueSource {
			plan.ChangeMask |= contract.GeneratorValueChangeContent
		}
		declaration.Entries = append(declaration.Entries, decl)
		g.ValueEntryPlans = append(g.ValueEntryPlans, plan)
	}
	// Retirements preserve original semantic target facts while a new obligation
	// freezes the explicitly selected compatible executor and route.
	for _, named := range s.root.Names {
		old := before[named.Name]
		if old.ValueSource != contract.Generated || old.Generated.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			continue
		}
		at := slices.IndexFunc(g.ValueEntryPlans, func(p contract.GeneratorValueEntryPlan) bool { return p.Name == named.Name })
		if at >= 0 && g.ValueEntryPlans[at].ValueSource == contract.Generated && g.ValueEntryPlans[at].ChangeMask&contract.GeneratorValueChangeContent == 0 {
			continue
		}
		meta := old.Generated
		implementation, err := resolveGeneratedImplementation(i, GeneratedImplementationRequest{EntryName: old.Name, ConfigContractID: meta.ConfigContractID, ResourceContractID: meta.ResourceContractID, LifecycleMode: meta.LifecycleMode})
		if err != nil {
			return nil, err
		}
		if _, err := s.installedGeneratedRetirementCompatibility(ctx, i, implementation, meta); err != nil {
			return nil, err
		}
		lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: contract.GeneratorLineageRetirement, DomainID: s.root.Domain, OperationID: operation, Name: old.Name, EntryIncarnationID: old.Incarnation, Epoch: meta.Epoch, IntentDigest: meta.IntentDigest, ResourceIncarnationID: meta.ResourceIncarnationID, TemplateCount: 1}
		lineage.LineageID = fixed(contract.GeneratorObligationLineageID(s.root.Domain, operation, meta.ResourceIncarnationID, 2))
		x := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, Action: 2, LineageID: lineage.LineageID, ConfigContractID: meta.ConfigContractID, ResourceContractID: meta.ResourceContractID, ExecutorID: implementation.ExecutorID, CredentialRouteID: implementation.CredentialRouteID, DescriptorID: implementation.DescriptorID, ResultContractID: fixed(contract.GeneratedResultContractID(implementation, 2, meta.CompletionClass, 0, 4096, contract.InputEncodingRaw)), ResourceIncarnationID: meta.ResourceIncarnationID, IntentDigest: meta.IntentDigest, ResourceDigest: meta.ResourceDigest, TargetKind: 2, TargetSourceID: meta.ResourceIncarnationID, CompletionClass: meta.CompletionClass, RequiredAuthoritySet: 1}
		x.LifecycleMode, x.ResultReaderID = meta.LifecycleMode, contract.GeneratorResultReaderID()
		x.AttemptID = fixed(contract.GeneratorAttemptID(lineage.LineageID, 0))
		x.DutyID = fixed(contract.GeneratorDutyID(s.root.Domain, meta.OriginOperationID, meta.OriginAttemptID, 2))
		completeGeneratedTemplate(&x, s.root.Domain, operation, fixed)
		lineage.Templates[0] = x
		g.Lineages = append(g.Lineages, lineage)
	}
	if creates == 0 {
		return nil, contract.ErrRecord
	}
	registryRows := make([]contract.RecipientRecord, len(i.DesiredRecipients))
	for at, row := range i.DesiredRecipients {
		registryRows[at] = row.Recipient
	}
	transition, err := s.generatedOutputTransitionWithRecipients(ctx, registryRows, entries, output)
	if err != nil {
		return nil, err
	}
	configuration, err := transition.ConfigurationAfter(operation, g.ValueEntryPlans)
	if err != nil {
		return nil, err
	}
	outputImage, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		return nil, err
	}
	g.Request.OutputConfiguration, _, err = contract.SplitOutputConfiguration(s.root.Domain, outputImage)
	if err != nil {
		return nil, err
	}
	declarationBody := encode(contract.EncodeGeneratorDeclaration(declaration))
	view, err := contract.InspectGeneratorDeclaration(declarationBody)
	if err != nil {
		return nil, err
	}
	logicalSlices, err := view.LogicalSlices()
	if err != nil {
		return nil, err
	}
	logical := make(map[contract.ID]contract.GeneratorLogicalSlice, len(logicalSlices))
	for _, slice := range logicalSlices {
		logical[slice.ContentID] = slice
	}
	for at, entry := range declaration.Entries {
		p := &g.ValueEntryPlans[at]
		if !p.LineageID.IsZero() {
			continue
		}
		id := fixed(contract.GeneratorDeclarationEntryID(s.root.Domain, operation, entry.Name))
		if entry.Kind == contract.GeneratorDeclarationGenerated {
			id = p.IntentDigest
		}
		p.SourceSlice = descriptor(contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical[id]}))
		if entry.Kind == contract.GeneratorDeclarationSealed {
			source, err := contract.InspectSealedInputEnvelope(entry.Payload)
			if err != nil {
				return nil, err
			}
			core, err := source.Core.Own()
			if err != nil {
				return nil, err
			}
			use := contract.GeneratorSourceUse{Schema: 1, SourceID: source.Core.SourceID, SealedInputCoreDigest: fixed(contract.SealedInputCoreDigest(core)), EnvelopeDigest: contract.Hash(entry.Payload), SourceSlice: descriptor(contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical[source.Core.SourceID]})), Purpose: 2}
			consumer, err := contract.GeneratorAcceptedSourceConsumer(operation, g.Header.MaterialID, use)
			if err != nil {
				return nil, err
			}
			use.Consumers = descriptor(contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, [][]byte{encode(contract.EncodeGeneratorConsumer(consumer))}))
			g.SourceUses = append(g.SourceUses, use)
		}
	}
	slices.SortFunc(g.Lineages, func(a, b contract.GeneratorLineageTemplate) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}
		return bytes.Compare(a.ResourceIncarnationID[:], b.ResourceIncarnationID[:])
	})
	// Request bindings follow the immutable lineage order, not source input order.
	slices.SortFunc(bindings, func(a, b generatedRequestBinding) int {
		left := slices.IndexFunc(g.Lineages, func(x contract.GeneratorLineageTemplate) bool { return x.LineageID == a.LineageID })
		right := slices.IndexFunc(g.Lineages, func(x contract.GeneratorLineageTemplate) bool { return x.LineageID == b.LineageID })
		return left - right
	})
	slices.SortFunc(g.SourceUses, func(a, b contract.GeneratorSourceUse) int { return bytes.Compare(a.SourceID[:], b.SourceID[:]) })
	g.Request.Declaration = descriptor(contract.GeneratorDeclarationDescriptor(declaration))
	g.Header.ValueEntryPlanCount = uint16(len(g.ValueEntryPlans))
	g.Header.LineageCount = uint16(creates)
	g.Header.RequestCoreDigest = fixed(contract.GeneratorRequestCoreDigest(g.Request))
	join := fixed(contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest))
	for _, lineage := range g.Lineages {
		g.Header.TemplateCount += uint16(lineage.TemplateCount)
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			source := fixed(contract.GeneratorTemplateID(x))
			for guard := uint8(1); guard <= 4; guard++ {
				branch, destination := x.Branch, join
				if guard < 3 {
					if x.Action != 1 || x.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
						continue
					}
					next, present, err := contract.GeneratorSuccessorBranch(x.Branch, guard)
					if err != nil {
						return nil, err
					}
					if !present {
						continue
					}
					branch, destination = next, fixed(contract.GeneratorTemplateID(lineage.Templates[next]))
				}
				n, r := uint8(0), uint8(0)
				if branch == 1 || branch == 3 || branch == 4 {
					n = 1
				}
				if branch >= 2 {
					r = 1
				}
				g.Edges = append(g.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: source, DestinationTemplateID: destination, Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1, NoEffectUsed: n, ResidueUsed: r})
			}
			maxSecret, maxFacts := uint32(65536), uint32(4096)
			if x.Action == 2 {
				maxSecret = 0
			}
			if x.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				maxSecret, maxFacts = contract.CryptoMaxRawValue, contract.GeneratorSafeFactsEnvelopeLength
			}
			g.ResultUses = append(g.ResultUses, contract.GeneratorResultUse{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID, InboxID: x.InboxID, ExecutorID: x.ExecutorID, ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID, MaterialID: g.Header.MaterialID, Purpose: 1, MaxSecret: maxSecret, MaxFacts: maxFacts})
		}
	}
	slices.SortFunc(g.Edges, func(a, b contract.GeneratorEdge) int {
		if order := bytes.Compare(a.SourceTemplateID[:], b.SourceTemplateID[:]); order != 0 {
			return order
		}
		return int(a.Guard) - int(b.Guard)
	})
	slices.SortFunc(g.ResultUses, func(a, b contract.GeneratorResultUse) int { return bytes.Compare(a.AttemptID[:], b.AttemptID[:]) })
	g.UsePlan.SourceUses = descriptor(contract.GeneratorSourceUsesDescriptor(g.SourceUses))
	g.UsePlan.ResultUses = descriptor(contract.GeneratorResultUsesDescriptor(g.ResultUses))
	g.UsePlan.PlanGraphID = fixed(contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges))
	if constructionErr != nil {
		return nil, fmt.Errorf("generated plan construction: %w", constructionErr)
	}
	if err := contract.ValidateGeneratorEffectGraph(g); err != nil {
		return nil, fmt.Errorf("generated effect graph: %w", err)
	}
	if err := contract.ValidateGeneratorDeclarationGraph(view, g); err != nil {
		return nil, fmt.Errorf("generated declaration graph: %w", err)
	}
	return s.generatedPlanRequest(ctx, generatedPlanInput{graph: g, declaration: declarationBody, registryImage: registryBody, outputConfiguration: outputImage, registry: g.Request.Registry, recoveryPolicy: policy, context: c, requestBindings: bindings})
}

func completeGeneratedTemplate(x *contract.GeneratorAttemptTemplate, domain, operation contract.ID, fixed func(contract.ID, error) contract.ID) {
	x.PlannedValueSlotID = fixed(contract.GeneratorValueSlotID(domain, operation, x.AttemptID))
	if x.SemanticLifecycleMode() != contract.GeneratorLifecycleNone {
		x.HazardID = fixed(contract.GeneratorHazardID(domain, x.AttemptID))
	}
	x.TransmissionID = fixed(contract.GeneratorTransmissionID(x.AttemptID, x.Action))
	x.ResultID = fixed(contract.GeneratorResultID(domain, operation, x.AttemptID, x.TransmissionID, x.Action))
	x.InboxID = fixed(contract.GeneratorInboxID(domain, operation, x.AttemptID, x.ResultID))
	x.RequestPlanDigest = fixed(contract.GeneratorRequestPlanDigest(*x))
}

// Normal handoff creates a new obligation from selected current generation
// facts. Each entry keeps its explicit selected implementation and checked compatibility.
func (s *StateSession) installedGeneratedNormalImplementations(ctx context.Context, i ApplyInstallation, c *Comparison) (map[string]contract.GeneratedSupportHandoff, error) {
	rows := make(map[string]contract.GeneratedSupportHandoff)
	for _, named := range s.root.Names {
		old := s.valueEntry(named.Slot)
		if old == nil || old.ValueSource != contract.Generated || old.Generated.LifecycleMode == contract.GeneratorLifecycleNone {
			continue
		}
		desired := slices.IndexFunc(c.desiredEntries, func(row ApplyEntryInput) bool { return row.Name == named.Name })
		if desired >= 0 && c.desiredEntries[desired].ValueSource == contract.Generated {
			continue
		}
		request := GeneratedImplementationRequest{EntryName: old.Name, ConfigContractID: old.Generated.ConfigContractID, ResourceContractID: old.Generated.ResourceContractID, LifecycleMode: old.Generated.LifecycleMode}
		row, err := resolveGeneratedImplementation(i, request)
		if err != nil {
			return nil, err
		}
		handoff, err := s.installedGeneratedRetirementCompatibility(ctx, i, row, old.Generated)
		if err != nil {
			return nil, err
		}
		rows[old.Name] = handoff
	}
	return rows, nil
}
