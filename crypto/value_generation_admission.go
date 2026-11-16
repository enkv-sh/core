package crypto

import (
	"bytes"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func generatedAdmissionBody(r *Runtime, q contract.CryptoGeneratedCompareRequest, input generatedSessionAdmissionInput,
	deadline time.Time) ([]byte, error) {
	if r == nil || input.RouteID.IsZero() || !validDeadline(deadline) || q.Context.Expiry != uint64(deadline.UnixNano()) ||
		(q.Purpose < contract.CryptoGeneratedReservationPurpose || q.Purpose > contract.CryptoGeneratedOriginalVerificationPurpose) ||
		!generatedBindingsValid(input.Control, input.Bindings) || input.Control.Provider != r.family ||
		input.Control.DomainID != q.Context.DomainID || input.Control.CompatibilityID != q.Context.CompatibilityID ||
		input.Control.CryptoSupportID != contract.CryptoSupportID() {
		return nil, ErrAdmission
	}
	body, err := contract.EncodeCryptoGeneratedCompareRequest(q)
	if err != nil {
		return nil, ErrAdmission
	}
	return body, nil
}

func (r *Runtime) newGeneratedAdmission(q contract.CryptoGeneratedCompareRequest, input generatedSessionAdmissionInput,
	graph contract.GeneratorPlanBundle, purpose generatedPurposeState, body []byte, deadline time.Time) (*generatedAdmission, error) {
	if !purpose.valid(q.Purpose) || !generatedBindingsValid(input.Control, input.Bindings) ||
		input.Control.Provider != r.family || input.Control.DomainID != q.Context.DomainID ||
		input.Control.CompatibilityID != q.Context.CompatibilityID || input.Control.CryptoSupportID != contract.CryptoSupportID() {
		return nil, ErrAdmission
	}
	if _, err := contract.PublicStateDescriptor(input.BeforePublic); err != nil || input.BeforePublic.Domain != q.Context.DomainID ||
		input.BeforePublic.AccessRoot != q.Context.CurrentAccessRoot {
		return nil, ErrAdmission
	}
	if input.Output == nil {
		return nil, ErrAdmission
	}
	owner, err := r.generatedInputOwner()
	if err != nil {
		return nil, err
	}
	owned, err := owner.ownOutput(input.BeforePublic, input.Output)
	if err != nil {
		return nil, ErrAdmission
	}
	purpose.output = owned
	controlBody, err := contract.EncodeControlCore(input.Control)
	if err != nil {
		return nil, ErrAdmission
	}
	control, err := contract.DecodeControlCore(controlBody)
	if err != nil {
		return nil, ErrAdmission
	}
	bindingsBody, err := contract.EncodeBindingTable(input.Bindings)
	if err != nil {
		return nil, ErrAdmission
	}
	bindings, err := contract.DecodeBindingTable(bindingsBody)
	if err != nil {
		return nil, ErrAdmission
	}
	bindingDigests := make([]contract.ID, len(bindings))
	for i, binding := range bindings {
		bindingDigests[i], err = contract.PublicBindingDigest(binding.Binding)
		if err != nil {
			return nil, ErrAdmission
		}
	}
	a := &generatedAdmission{request: q, requestDigest: contract.Hash(body), requestLength: len(body), control: control,
		bindings: bindings, bindingDigests: bindingDigests, routeID: input.RouteID, graph: graph,
		stage: contract.CryptoCompare, before: input.BeforePublic, purpose: purpose, registry: input.Registry}
	a.inputOwner = owner
	a.before.Rows = slices.Clone(input.BeforePublic.Rows)
	return a, nil
}

func ownGeneratedTarget(input *contract.GeneratorTarget) (*contract.GeneratorTarget, bool) {
	if input == nil {
		return nil, true
	}
	body, err := contract.EncodeGeneratorTarget(*input)
	if err != nil {
		return nil, false
	}
	target, err := contract.InspectGeneratorTarget(body)
	if err != nil {
		return nil, false
	}
	return &target, true
}

func (r *Runtime) prepareGeneratedPlan(q contract.CryptoGeneratedCompareRequest, sessionInput generatedSessionAdmissionInput,
	planInput generatedPlanAdmissionInput, purpose generatedPurposeState, accepted map[contract.ID]contract.SealedInputCore,
	body []byte, deadline time.Time) (*generatedAdmission, error) {
	reservation := purpose.reservation != nil
	validated, streams, err := r.validateGeneratedPlan(sessionInput.Graph, planInput.Declaration, reservation)
	if err != nil {
		return nil, ErrAdmission
	}
	graph := validated.graph
	if (graph.Request.Schema == contract.GeneratorPublicRequestCoreSchema || graph.Request.Schema == contract.GeneratorApplyRequestCoreSchema) && sessionInput.Registry == nil || graph.Request.Schema == contract.GeneratorRequestCoreSchema && sessionInput.Registry != nil {
		return nil, ErrAdmission
	}
	if reservation && (graph.Request.Schema == contract.GeneratorPublicRequestCoreSchema || graph.Request.Schema == contract.GeneratorApplyRequestCoreSchema) && graph.Request.RecoveryPolicyID != contract.GeneratorRecoveryPolicyID() {
		return nil, ErrAdmission
	}
	if (graph.Request.OperationKind == contract.OperationCleanOwnedFailureResidue ||
		graph.Request.OperationKind == contract.OperationRetireGeneratedGeneration) && !generatedCurrentOnlyDeletePlan(graph) {
		return nil, ErrAdmission
	}
	if len(planInput.Canonical) > contract.CryptoMaxValueEntries || len(planInput.CurrentIntents) > contract.GeneratedCurrentEntryLimit ||
		!generatedSourceSubset(planInput.LiveSourceUses, graph.SourceUses) ||
		reservation && !slices.Equal(planInput.LiveSourceUses, graph.SourceUses) {
		return nil, ErrAdmission
	}
	parent := q.Parent
	if reservation {
		parent = contract.GeneratedParentRecord(q.ParentPlan)
	}
	if !generatedParentMatches(parent, validated) {
		return nil, ErrAdmission
	}
	if reservation {
		purpose.reservation.streams = streams
	}
	a, err := r.newGeneratedAdmission(q, sessionInput, graph, purpose, body, deadline)
	if err != nil {
		return nil, err
	}
	a.graphBody = contract.DigestLength{Digest: contract.Hash(sessionInput.Graph), Length: uint64(len(sessionInput.Graph))}
	if !a.admitAutomaticAccess(sessionInput) {
		a.clear()
		return nil, ErrAdmission
	}
	if a.selectionPhase != nil && (purpose.reservation != nil || purpose.final != nil || len(planInput.LiveSourceUses) != 0 || len(planInput.Canonical) != 0 || len(planInput.CurrentValues) != 0) {
		a.clear()
		return nil, ErrAdmission
	}
	returned := false
	defer func() {
		if !returned {
			a.clear()
		}
	}()
	plan := a.purpose.plan()
	declarationBody := planInput.Declaration
	if a.purpose.producer == nil {
		plan.declaration = bytes.Clone(declarationBody)
		declarationBody = plan.declaration
	}
	declaration, err := contract.InspectGeneratorDeclaration(declarationBody)
	if err != nil {
		return nil, ErrAdmission
	}
	if err := a.purpose.output.ValidateSuccessorRouting(graph, declaration); err != nil {
		return nil, ErrAdmission
	}
	plan.liveSources = slices.Clone(planInput.LiveSourceUses)
	canonicalCount := 0
	currentIntentCount := 0
	for i := 0; i < declaration.EntryCount(); i++ {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			return nil, ErrAdmission
		}
		_, payloadOffset, err := declaration.EntrySpan(i)
		if err != nil {
			return nil, ErrAdmission
		}
		idLength := len(contract.ID{})
		ids := make([]contract.ID, len(entry.RecipientIDs)/idLength)
		for j := range ids {
			ids[j] = contract.ID(entry.RecipientIDs[j*idLength : (j+1)*idLength])
		}
		if reservation && !applyRecipientsAdmitted(ids, a.control.AuthorityRecipientID, a.bindings) {
			return nil, ErrAdmission
		}
		plan.recipients = append(plan.recipients, ids)
		plan.intents = append(plan.intents, contract.GeneratorDescriptor{})
		if a.selectionPhase != nil {
			continue
		}
		if entry.Kind == contract.GeneratorDeclarationGenerated || entry.Kind == contract.GeneratorDeclarationGeneratedReference {
			var meta contract.GeneratorDeclaredGeneration
			var logical contract.GeneratorLogicalSlice
			if entry.Kind == contract.GeneratorDeclarationGeneratedReference {
				ref, err := contract.InspectGeneratorDeclaredGenerationReferenceForEntry(entry.Schema, entry.Payload)
				if err != nil {
					return nil, ErrAdmission
				}
				meta = contract.GeneratorDeclaredGeneration{Schema: ref.Schema, LifecycleMode: ref.LifecycleMode, Epoch: ref.Epoch, RetirementMode: ref.RetirementMode,
					ConfigContractID: ref.ConfigContractID, ResourceContractID: ref.ResourceContractID, CompletionClass: ref.CompletionClass}
				logical = ref.Intent
			} else {
				var err error
				meta, err = contract.InspectGeneratorDeclaredGenerationForEntry(entry.Schema, entry.Payload)
				if err != nil {
					return nil, ErrAdmission
				}
				digest, err := contract.GeneratorIntentDigest(meta.Intent)
				if err != nil {
					return nil, ErrAdmission
				}
				logical = contract.GeneratorLogicalSlice{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: digest,
					Length: uint32(len(meta.Intent)), Digest: contract.Hash(meta.Intent)}
			}
			if graph.ValueEntryPlans[i].ChangeMask&contract.GeneratorValueChangeContent == 0 {
				if currentIntentCount >= len(planInput.CurrentIntents) ||
					!a.currentIntentMatches(planInput.CurrentIntents[currentIntentCount], graph.ValueEntryPlans[i], meta, logical) {
					return nil, ErrAdmission
				}
				currentIntentCount++
			}
			plan.intents[i], err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical})
			if err != nil {
				return nil, ErrAdmission
			}
		}
		if entry.Kind == contract.GeneratorDeclarationRetained {
			present, ok := a.admitCanonical(entry, payloadOffset, planInput.Canonical)
			if !ok {
				return nil, ErrAdmission
			}
			if present {
				canonicalCount++
			}
			continue
		}
		if entry.Kind != contract.GeneratorDeclarationSealed {
			continue
		}
		envelope, err := contract.InspectSealedInputEnvelope(entry.Payload)
		if err != nil {
			return nil, ErrAdmission
		}
		core, err := envelope.Core.Own()
		if err != nil || core.CompatibilityID != q.Context.CompatibilityID || core.CryptoSupportID != a.control.CryptoSupportID {
			return nil, ErrAdmission
		}
		digest := contract.Hash(entry.Payload)
		plan.sources = append(plan.sources, generatedSource{offset: payloadOffset,
			length: uint32(len(entry.Payload)), core: core, envelope: digest})
		if a.purpose.producer != nil && graph.ValueEntryPlans[i].ChangeMask&contract.GeneratorValueChangeContent == 0 &&
			slices.ContainsFunc(plan.liveSources, func(use contract.GeneratorSourceUse) bool { return use.SourceID == core.SourceID }) {
			// Producer admission borrows the declaration. Keep only the exact
			// source needed to recheck current equality before producer use.
			plan.sources[len(plan.sources)-1].buffer = bytes.Clone(entry.Payload)
		}
		if !reservation {
			continue
		}
		admitted, ok := accepted[digest]
		if !ok || admitted != core {
			return nil, ErrAdmission
		}
		refs := make([]contract.RecipientBindingReference, len(ids))
		for j, id := range ids {
			index := applyBindingIndex(a.bindings, id)
			if index < 0 {
				return nil, ErrAdmission
			}
			refs[j] = contract.RecipientBindingReference{RecipientID: id, PublicBindingDigest: a.bindingDigests[index]}
		}
		bindingSet, err := contract.IntendedRecipientBindingSetDigest(q.Context.DomainID, a.control.AuthorityRecipientID, refs)
		if err != nil || bindingSet != core.IntendedRecipientBindingSetDigest && !a.originalSealedCurrentSubset(i) {
			return nil, ErrAdmission
		}
		authority := applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)
		if authority < 0 {
			return nil, ErrAdmission
		}
		wrap, err := custody.SealedInputWrapCore(core, a.bindings[authority])
		if err != nil || !applyWrapMatches(contract.WrapRow(envelope.AuthorityWrap), wrap) {
			return nil, ErrAdmission
		}
	}
	if canonicalCount != len(planInput.Canonical) || currentIntentCount != len(planInput.CurrentIntents) || reservation && len(accepted) != len(plan.sources) ||
		a.selectionPhase == nil && !a.admitCurrentValues(planInput.CurrentValues, declarationBody) {
		return nil, ErrAdmission
	}
	returned = true
	return a, nil
}

func (a *generatedAdmission) admitContinuationCustody(material contract.OperationMaterialRecord, seedAccess, sourceProtections []byte,
	controlled *contract.GeneratedControlledPredecessor) bool {
	plan := a.purpose.plan()
	if plan == nil || !a.admitSeed(material, seedAccess) || !a.admitControlledPredecessor(controlled) {
		return false
	}
	if len(plan.liveSources) == 0 {
		return len(sourceProtections) == 0
	}
	protections, err := contract.InspectGeneratedSourceProtections(a.material, sourceProtections)
	if err != nil || protections.Count() != len(plan.liveSources) {
		return false
	}
	for i := 0; i < protections.Count(); i++ {
		row, err := protections.Row(i)
		if err != nil || !slices.ContainsFunc(plan.liveSources, func(use contract.GeneratorSourceUse) bool { return use.SourceID == row.SourceID }) {
			return false
		}
		index := slices.IndexFunc(plan.sources, func(source generatedSource) bool { return source.core.SourceID == row.SourceID })
		if index < 0 {
			return false
		}
		source := plan.sources[index]
		digest, err := contract.SealedInputCoreDigest(source.core)
		if err != nil || digest != row.OriginalSourceCoreDigest || source.envelope != row.OriginalEnvelopeDigest {
			return false
		}
	}
	plan.protections = bytes.Clone(sourceProtections)
	plan.protection = contract.DigestLength{Digest: contract.Hash(plan.protections), Length: uint64(len(plan.protections))}
	return true
}

func (a *generatedAdmission) resultsValid(results []generatedResultAdmission) bool {
	if len(results) > contract.GeneratorMaxTemplates {
		return false
	}
	for _, result := range results {
		if !a.expectedResultMatches(result.Expected) || result.Reference.ResultID != result.Expected.Use.ResultID {
			return false
		}
		if _, err := contract.EncodeGeneratorResultReference(result.Reference); err != nil {
			return false
		}
	}
	return true
}

func (r *Runtime) installGeneratedAdmission(a *generatedAdmission, deadline time.Time) error {
	installed := false
	defer func() {
		if !installed {
			a.clear()
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	route := r.routes[a.routeID]
	if route == nil || route.Family() != r.family || route.CredentialRoute() != a.routeID || !a.purpose.valid(a.request.Purpose) {
		return ErrAdmission
	}
	var originalDone <-chan struct{}
	if adoption := a.purpose.adoption; adoption != nil && adoption.localFailure != nil {
		guard := adoption.localFailure.guard
		if !guard.live() || deadline.After(guard.deadline) {
			return ErrAdmission
		}
		originalDone = guard.callerDone
	}
	a.session = r.installSession(a.request.Context.AdmissionID, deadline, originalDone, a.clear)
	if a.session == nil {
		return ErrAdmission
	}
	r.generated = a
	installed = true
	return nil
}

// Admission owns these validated bindings and digests for its whole lifetime.
func (a *generatedAdmission) accessBindingsValid(access contract.AccessRecord) bool {
	if len(a.bindings) != len(a.bindingDigests) {
		return false
	}
	if _, err := contract.AccessRecordLength(access); err != nil {
		return false
	}
	for _, wrap := range access.Wraps {
		index := slices.IndexFunc(a.bindings, func(row contract.BindingTableRow) bool {
			return row.SubjectKind == wrap.SubjectKind && row.SubjectID == wrap.SubjectID && row.Binding.BindingID == wrap.BindingID
		})
		if index < 0 || wrap.BindingSerial != a.bindings[index].Binding.BindingSerial || wrap.PublicBindingDigest != a.bindingDigests[index] {
			return false
		}
	}
	return true
}

func sameGeneratedBinding(a, b contract.KMSBinding) bool {
	return a.BindingID == b.BindingID && a.BindingIncarnationID == b.BindingIncarnationID &&
		a.BindingSerial == b.BindingSerial && a.Provider == b.Provider && a.WrapProfile == b.WrapProfile &&
		a.ProtectionClass == b.ProtectionClass && a.KeySelector == b.KeySelector && a.Fingerprint == b.Fingerprint && bytes.Equal(a.SPKI, b.SPKI)
}
