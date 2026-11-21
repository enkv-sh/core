package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedFinalResult struct {
	attempt   generatedAttempt
	reference contract.GeneratorResultReference
}

type generatedFinalPlan struct {
	request contract.CryptoGeneratedCompareRequest
	phase   contract.GeneratorPhaseIdentity
	generatedFinalProjection
	materialization *contract.GeneratedFinalPreparationRecord
	qualifyLegacy   bool
}

type generatedFinalSuppliedEntry struct {
	entry             contract.ValueEntry
	access            *contract.AccessRecord
	currentOnlyReplay bool
}

type generatedFinalWrapIdentity struct {
	subjectKind uint8
	subjectID   contract.ID
	bindingID   contract.ID
	serial      uint64
	digest      contract.ID
}

func generatedFinalBindingIdentity(row contract.BindingTableRow, digest contract.ID) generatedFinalWrapIdentity {
	return generatedFinalWrapIdentity{subjectKind: row.SubjectKind, subjectID: row.SubjectID, bindingID: row.Binding.BindingID,
		serial: row.Binding.BindingSerial, digest: digest}
}

func generatedFinalWrapRowIdentity(row contract.WrapRow) generatedFinalWrapIdentity {
	return generatedFinalWrapIdentity{subjectKind: row.SubjectKind, subjectID: row.SubjectID, bindingID: row.BindingID,
		serial: row.BindingSerial, digest: row.PublicBindingDigest}
}

// generatedFinalRetirement is the immutable handoff from a selected old
// generation to its detached retirement owner. The old target is captured
// before entry selection removes the current slot and access relation.
type generatedFinalRetirement struct {
	template contract.GeneratorAttemptTemplate
	target   contract.GeneratorTarget
	support  contract.GeneratorDescriptor
}

type admittedGeneratedFinal struct {
	observation *operationObservation
	session     *StateSession
	plan        *generatedFinalPlan
	crypto      contract.Crypto
	instance    contract.ID
	deadline    time.Time
	used        bool
}

func (s *StateSession) generatedFinalRequest(ctx context.Context, admitted contract.ApplyContext) (*generatedFinalPlan, error) {
	plan, err := s.generatedFinalRequestWithPreparation(ctx, admitted, true)
	if err != nil || plan.materialization == nil {
		return plan, err
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	replace, err := s.generatedFinalPreparationNeedsReplacement(ctx, g, plan)
	if err != nil {
		plan.clearOwnedInputs()
		return nil, err
	}
	if replace {
		plan.clearOwnedInputs()
		replacement, err := s.generatedFinalRequestWithPreparation(ctx, admitted, false)
		if err != nil {
			return nil, err
		}
		replacement.qualifyLegacy = true
		return replacement, nil
	}
	return plan, nil
}

func (s *StateSession) generatedFinalRequestWithPreparation(ctx context.Context, admitted contract.ApplyContext, reuse bool) (*generatedFinalPlan, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if g.parent == nil || g.phase == nil || g.phase.Phase == ^uint32(0) ||
		g.phase.Stage != contract.GeneratedStageTerminal || !g.phase.SelectionPhaseID.IsZero() {
		return nil, contract.ErrRecord
	}
	if _, _, _, pending := generatedNextOriginal(g); pending {
		return nil, contract.ErrRecord
	}
	bundle, parent := g.bundles[0], *g.parent
	if !generatedOperationGraphValid(bundle) || bundle.Request.OperationKind != contract.OperationApplyDeclaration && bundle.Request.OperationKind != contract.OperationRotateValueEntryValue {
		return nil, contract.ErrRecord
	}
	facts, err := selectedFinalResults(g)
	if err != nil {
		return nil, err
	}
	selecting, evidence := facts.selecting, facts.evidence
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: parent.RequestIdentityDigest,
		ObservedHEADDigest: admitted.PredecessorHEADDigest, ConditionDigest: admitted.OriginalConditionDigest,
		TransitionKind: contract.GeneratorAuthorityFinal, BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1,
		Evidence: contract.GeneratorDescriptor(evidence)}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		return nil, fmt.Errorf("generated final phase: %w", err)
	}
	materialization, err := selectedFinalMaterialization(ctx, s.selectedImage(), g, facts, reuse)
	if err != nil {
		return nil, err
	}
	if materialization != nil {
		phaseID, err = contract.GeneratorPhaseID(materialization.MaterializationPhase)
		if err != nil {
			return nil, err
		}
	}
	if selecting {
		needed := generatedFinalPhaseSteps(bundle, materialization != nil)
		if uint64(g.phase.Phase)+needed > uint64(^uint32(0)) {
			return nil, contract.ErrRecord
		}
	}
	projection, err := selectedFinalProjection(ctx, s.selectedImage(), g, phaseID, facts)
	if err != nil {
		return nil, err
	}
	q := contract.CryptoGeneratedCompareRequest{Context: admitted, Purpose: contract.CryptoGeneratedFinalPreparationPurpose, Parent: parent, PlanGraph: parent.Graph,
		UsePlanDigest: parent.UsePlanDigest, MaterialID: parent.MaterialID, AcceptedSources: parent.SourceUses, IntendedEntryPlans: parent.IntendedEntryPlans}
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		return nil, fmt.Errorf("generated final admission: %w", err)
	}
	if _, err := contract.EncodeCryptoGeneratedCompareRequest(q); err != nil {
		return nil, fmt.Errorf("generated final request: %w", err)
	}
	return &generatedFinalPlan{generatedFinalProjection: projection, request: q, phase: phase, materialization: materialization}, nil
}

func generatedLineageTerminalUncertain(g *generatedSelection, lineage contract.GeneratorLineageTemplate) bool {
	if g == nil || g.phase == nil {
		return false
	}
	var frontier *generatedAttempt
	for _, x := range lineage.Templates[:lineage.TemplateCount] {
		a, entered := g.attempts[x.AttemptID]
		if !entered {
			continue
		}
		attemptCopy := a
		if frontier == nil || attemptCopy.expected.Template.Branch > frontier.expected.Template.Branch {
			frontier = &attemptCopy
		}
	}
	if frontier == nil || frontier.record.State != contract.GeneratedEffectClosedWithResidue ||
		frontier.record.Stage != contract.GeneratedStageTerminal || len(frontier.result) != 0 {
		return false
	}
	hazardRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: frontier.expected.Template.HazardID}]
	if !ok {
		return false
	}
	hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
	if err != nil || hazard.Fenced != 1 || hazard.OriginalAttemptID != frontier.record.AttemptID ||
		hazard.OriginalOperationID != frontier.record.OperationID || hazard.OwnerID != frontier.record.OwnerID {
		return false
	}
	lineageRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedLineageSupportKind, id: lineage.LineageID}]
	if !ok {
		return false
	}
	state, err := contract.InspectGeneratedLineageRecord(lineageRow.Body)
	return err == nil && state.Frontier == frontier.expected.Template.Branch && state.Branch == state.Frontier && state.ResidueUsed == 1
}

// PrepareGeneratedFinal prepares every generated output before one atomic
// final candidate is exposed. The private permit supplies the exact admitted
// Crypto owner; encoded bytes cannot create this authority.
func (s *StateSession) prepareGeneratedFinal(ctx context.Context, permit *admittedGeneratedFinal) (*generatedPreparation, Result) {
	if s == nil || ctx == nil || s.prepared || !s.admission.valid(s.store) || permit == nil || permit.used || permit.session != s || permit.plan == nil ||
		permit.crypto == nil || permit.instance.IsZero() || permit.crypto.InstanceID() != permit.instance || !validPrivateDeadline(permit.deadline) ||
		permit.plan.request.Context.Expiry != uint64(permit.deadline.UnixNano()) {
		return nil, refused(AdmissionInvalid)
	}
	permit.used = true
	if ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	c := permit.plan.request.Context
	c.IntentDescriptor = contract.DescriptorVector{}
	checked, err := s.generatedFinalRequest(ctx, c)
	if result, ok := selectedReadResult(err); ok {
		return nil, result
	}
	if err != nil || !generatedFinalPlansEqual(checked, permit.plan) {
		return nil, refused(AdmissionInvalid)
	}
	bindingWork, bindingErr := s.selectedGeneratedWork(ctx)
	if bindingErr != nil {
		return nil, installedApplyPreparationFailure(bindingErr)
	}
	bindings, err := s.generatedBindings(bindingWork)
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	bindingIdentities := make([]generatedFinalWrapIdentity, len(bindings))
	for i, binding := range bindings {
		digest, digestErr := contract.PublicBindingDigest(binding.Binding)
		if digestErr != nil {
			return nil, refused(InvalidRelation)
		}
		bindingIdentities[i] = generatedFinalBindingIdentity(binding, digest)
	}
	selectedWork, selectErr := s.selectedGeneratedWork(ctx)
	if result, ok := selectedReadResult(selectErr); ok {
		return nil, result
	}
	if selectErr != nil {
		return nil, refused(InvalidRelation)
	}
	var declarationBody []byte
	var readErr error
	if len(s.fragmentFacts) != 0 {
		declarationBody, readErr = selectedWork.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, selectedWork.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	} else {
		declarationBody, readErr = selectedWork.content.read(contract.GeneratorContentDeclaration, selectedWork.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	}
	if result, ok := selectedReadResult(readErr); ok {
		return nil, result
	}
	if readErr != nil {
		return nil, refused(InvalidRelation)
	}
	declaration, inspectErr := contract.InspectGeneratorDeclaration(declarationBody)
	if inspectErr != nil {
		return nil, refused(InvalidRelation)
	}
	var retainedImage contract.GeneratedFinalPreparationImage
	var prepared []contract.CryptoGeneratedValueEntryResult
	var supplied []contract.CryptoPreparedSecret
	if permit.plan.materialization != nil || permit.plan.qualifyLegacy {
		retainedImage, err = s.generatedFinalPreparationImage(ctx, selectedWork)
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		if err != nil || len(retainedImage.Generated) != len(permit.plan.entryPlans) {
			retainedImage.Clear()
			return nil, refused(InvalidRelation)
		}
		defer retainedImage.Clear()
		if permit.plan.materialization != nil {
			prepared, supplied = retainedImage.Generated, retainedImage.Supplied
		}
	}
	currentOpens, err := selectedWork.continuationCurrentOpens(ctx)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	s.prepared = true
	source := generatedExchangeSource(permit.plan.request)
	phaseID := mustGeneratedPhaseID(permit.plan.phase)
	source.PhaseID = phaseID
	p := &generatedPreparation{operation: &cryptoOperation{observation: permit.observation, source: source, adapter: permit.crypto, instance: permit.instance,
		authority: s.admission.recipient, context: permit.plan.request.Context, deadline: permit.deadline,
		bindings: bindings, sourceCount: 1 + currentOpens}}
	if permit.plan.materialization != nil || permit.plan.qualifyLegacy {
		p.operation.sourceCount += uint32(len(retainedImage.Generated) + len(retainedImage.Supplied))
		for _, row := range retainedImage.Generated {
			if current := s.generatedFinalPredecessor(row.Slot, row.Entry.Name); current != nil && current.ConfidentialityClass == contract.Secret && generatedFinalExcludesReader(*current, row.Entry.Recipients) {
				p.operation.sourceCount++
			}
		}
		for _, prepared := range retainedImage.Supplied {
			index := slices.IndexFunc(selectedWork.bundles[0].ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool {
				return row.Name == prepared.Name && row.Slot == prepared.Slot
			})
			if index < 0 {
				return nil, refused(InvalidRelation)
			}
			entry, _, err := declaration.Entry(index)
			if err != nil {
				return nil, refused(InvalidRelation)
			}
			plan := selectedWork.bundles[0].ValueEntryPlans[index]
			membershipOnly := plan.ConfidentialityClass == contract.Secret && plan.ChangeMask&contract.GeneratorValueChangeMembership != 0 && plan.ChangeMask&contract.GeneratorValueChangeContent == 0
			current := s.generatedFinalPredecessor(plan.Slot, plan.Name)
			readers := make([]contract.ID, len(entry.RecipientIDs)/32)
			for i := range readers {
				readers[i] = contract.ID(entry.RecipientIDs[i*32 : (i+1)*32])
			}
			contentExclusion := current != nil && current.ConfidentialityClass == contract.Secret && generatedFinalExcludesReader(*current, readers)
			if membershipOnly || entry.Kind == contract.GeneratorDeclarationRetained || contentExclusion {
				p.operation.sourceCount++
			}
		}
	}
	if permit.plan.qualifyLegacy {
		retainedImage.Clear()
	}
	body, err := contract.EncodeCryptoGeneratedCompareRequest(permit.plan.request)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	if permit.plan.request.Purpose.QualifiesPendingRecipients(len(permit.plan.entryPlans) != 0) {
		p.operation.qualificationCounts = s.generatedQualificationCounts(bindings)
	}
	reply, res := p.exchange(ctx, contract.CryptoCompare, body)
	if res.Outcome != 0 {
		return nil, res
	}
	compared, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	p.operation.operationRef, p.operation.sourceCount = compared.OperationRef, 0
	if permit.plan.materialization == nil {
		for start, batch := 0, uint32(0); start < len(permit.plan.supplied.Rows); batch++ {
			end := len(permit.plan.supplied.Rows)
			for end > start {
				batchPlan := permit.plan.supplied
				batchPlan.Rows = permit.plan.supplied.Rows[start:end]
				identity, encodeErr := contract.EncodeIdentityPlan(batchPlan)
				if encodeErr != nil {
					return nil, refused(AdmissionInvalid)
				}
				var sealedInputs []contract.CryptoSealedInput
				for _, source := range permit.plan.sealedInputs {
					if source.Name >= batchPlan.Rows[0].Name && source.Name <= batchPlan.Rows[len(batchPlan.Rows)-1].Name {
						sealedInputs = append(sealedInputs, source)
					}
				}
				final := uint8(0)
				if end == len(permit.plan.supplied.Rows) {
					final = 1
				}
				body, encodeErr = contract.EncodeCryptoGeneratedSuppliedRequest(contract.CryptoGeneratedSuppliedRequest{OperationRef: compared.OperationRef,
					Context: permit.plan.request.Context, PhaseID: mustGeneratedPhaseID(permit.plan.phase), BatchIndex: batch,
					Final: final, IdentityPlan: identity, SealedInputs: sealedInputs})
				if encodeErr == nil {
					view, inspectErr := contract.InspectCryptoGeneratedSuppliedRequest(body)
					if inspectErr != nil {
						return nil, refused(AdmissionInvalid)
					}
					_, encodeErr = contract.CryptoGeneratedSuppliedResultBound(view)
				}
				if encodeErr == nil {
					break
				}
				if encodeErr != contract.ErrCryptoCapacity {
					return nil, refused(AdmissionInvalid)
				}
				end--
			}
			if end == start {
				return nil, refused(CapacityExceeded)
			}
			p.operation.sourceCount = 0
			p.operation.wrapCounts = make(map[contract.ID]uint32)
			var expectedSecrets []string
			for _, identity := range permit.plan.supplied.Rows[start:end] {
				planIndex := slices.IndexFunc(selectedWork.bundles[0].ValueEntryPlans, func(entryPlan contract.GeneratorValueEntryPlan) bool { return entryPlan.Name == identity.Name })
				if planIndex < 0 {
					return nil, refused(InvalidRelation)
				}
				entry, _, entryErr := declaration.Entry(planIndex)
				if entryErr != nil {
					return nil, refused(InvalidRelation)
				}
				if entry.ConfidentialityClass() != contract.Secret {
					continue
				}
				expectedSecrets = append(expectedSecrets, identity.Name)
				var retainedWraps map[generatedFinalWrapIdentity]bool
				plan := selectedWork.bundles[0].ValueEntryPlans[planIndex]
				membershipOnly := plan.ConfidentialityClass == contract.Secret && plan.ChangeMask&contract.GeneratorValueChangeMembership != 0 && plan.ChangeMask&contract.GeneratorValueChangeContent == 0
				if entry.Kind == contract.GeneratorDeclarationRetained || membershipOnly {
					current := s.valueEntry(plan.Slot)
					if current == nil {
						return nil, refused(InvalidRelation)
					}
					value := current.ValueState
					if entry.Kind == contract.GeneratorDeclarationRetained {
						record, recordErr := contract.DecodeRetainedCanonicalRecord(entry.Payload)
						if recordErr != nil {
							return nil, refused(InvalidRelation)
						}
						value = record.Entry.ValueState
					}
					retainedAccess, ok := s.materialAccess(contract.ValueMaterialKind, value)
					if !ok {
						return nil, refused(InvalidRelation)
					}
					p.operation.sourceCount++
					retainedWraps = make(map[generatedFinalWrapIdentity]bool, len(retainedAccess.Wraps))
					if identity.ValueState == value {
						for _, wrap := range retainedAccess.Wraps {
							retainedWraps[generatedFinalWrapRowIdentity(wrap)] = true
						}
					}
				}
				recipients := make([]contract.ID, len(entry.RecipientIDs)/32)
				for i := range recipients {
					recipients[i] = contract.ID(entry.RecipientIDs[i*32 : (i+1)*32])
				}
				for i, binding := range bindings {
					intended := binding.SubjectKind == contract.RecoveryWrapSubject || slices.Contains(recipients, binding.SubjectID)
					present := retainedWraps[bindingIdentities[i]]
					if intended && !present {
						p.operation.wrapCounts[binding.Binding.BindingID]++
					}
				}
			}
			reply, res = p.exchange(ctx, contract.CryptoPrepare, body)
			if res.Outcome != 0 {
				return nil, res
			}
			view, inspectErr := contract.InspectCryptoGeneratedSuppliedResult(reply.Body)
			if inspectErr != nil || view.BatchIndex != batch || (view.Final == 1) != (end == len(permit.plan.supplied.Rows)) {
				return nil, refused(AdmissionInvalid)
			}
			rows, inspectErr := view.Own()
			if inspectErr != nil || len(rows) != len(expectedSecrets) {
				return nil, refused(AdmissionInvalid)
			}
			for i, row := range rows {
				if row.Name != expectedSecrets[i] {
					return nil, refused(AdmissionInvalid)
				}
			}
			supplied = append(supplied, rows...)
			start = end
		}
		p.operation.sourceCount = 0
		prepared = make([]contract.CryptoGeneratedValueEntryResult, 0, len(permit.plan.entryPlans))
		for start, batch := 0, uint32(0); ; batch++ {
			end := len(permit.plan.entryPlans)
			if start == end {
				if start != 0 {
					break
				}
			} else {
				for end > start {
					final := uint8(0)
					if end == len(permit.plan.entryPlans) {
						final = 1
					}
					request := contract.CryptoGeneratedValueEntriesRequest{OperationRef: compared.OperationRef, Context: permit.plan.request.Context,
						PhaseID: phaseID, BatchIndex: batch, Final: final, Rows: permit.plan.entryPlans[start:end]}
					encoded, encodeErr := contract.EncodeCryptoGeneratedValueEntriesRequest(request)
					if encodeErr == nil {
						view, inspectErr := contract.InspectCryptoGeneratedValueEntriesRequest(encoded)
						if inspectErr != nil {
							return nil, refused(AdmissionInvalid)
						}
						_, boundErr := contract.CryptoGeneratedValueEntriesResultBound(view, s.root.CurrentAccess.Core.Recovery != nil)
						if boundErr == nil {
							body = encoded
							break
						}
						if boundErr != contract.ErrCryptoCapacity {
							return nil, refused(AdmissionInvalid)
						}
					} else if encodeErr != contract.ErrCryptoCapacity {
						return nil, refused(AdmissionInvalid)
					}
					end--
				}
				if end == start {
					return nil, refused(CapacityExceeded)
				}
			}
			final := uint8(0)
			if end == len(permit.plan.entryPlans) {
				final = 1
			}
			if start == len(permit.plan.entryPlans) {
				var encodeErr error
				body, encodeErr = contract.EncodeCryptoGeneratedValueEntriesRequest(contract.CryptoGeneratedValueEntriesRequest{OperationRef: compared.OperationRef,
					Context: permit.plan.request.Context, PhaseID: phaseID, BatchIndex: batch, Final: 1})
				if encodeErr != nil {
					return nil, refused(AdmissionInvalid)
				}
			}
			p.operation.wrapCounts = make(map[contract.ID]uint32)
			for _, entryPlan := range permit.plan.entryPlans[start:end] {
				for _, binding := range bindings {
					if binding.SubjectKind == contract.RecoveryWrapSubject || slices.Contains(entryPlan.Recipients, binding.SubjectID) {
						p.operation.wrapCounts[binding.Binding.BindingID]++
					}
				}
			}
			reply, res = p.exchange(ctx, contract.CryptoPrepare, body)
			if res.Outcome != 0 {
				return nil, res
			}
			view, inspectErr := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
			if inspectErr != nil {
				return nil, refused(AdmissionInvalid)
			}
			entryResults, ownErr := view.Own()
			if ownErr != nil || entryResults.BatchIndex != batch || entryResults.Final != final || len(entryResults.Rows) != end-start {
				return nil, refused(AdmissionInvalid)
			}
			prepared = append(prepared, entryResults.Rows...)
			if final == 1 {
				break
			}
			start = end
		}
	}
	var change *changeObservation
	if permit.observation.enabled() {
		change = &changeObservation{}
	}
	if permit.plan.selecting && len(prepared) != 0 && permit.plan.materialization == nil {
		p.reservation, err = s.deriveGeneratedFinalPreparation(ctx, selectedWork, permit.plan, prepared, supplied)
	} else {
		p.reservation, err = s.deriveGeneratedFinalWithObservation(ctx, permit.plan, prepared, change, supplied)
	}
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	if change != nil {
		change.Source = generatedExchangeSource(permit.plan.request)
		change.Source.Stage, change.Source.PhaseID = observationCandidate, p.reservation.candidate.head.Generator.PhaseID
		change.Candidate = candidateObservationIdentity(p.reservation.candidate)
		permit.observation.offerChange(ctx, *change)
		change = nil
	}
	candidateSource := generatedExchangeSource(permit.plan.request)
	candidateSource.PhaseID = p.reservation.candidate.head.Generator.PhaseID
	p.reservation.candidate.bindObservation(permit.observation, candidateSource)
	p.results = make([]contract.GeneratorResultReference, len(permit.plan.results))
	for i := range permit.plan.results {
		p.results[i] = permit.plan.results[i].reference
	}
	slices.SortFunc(p.results, func(a, b contract.GeneratorResultReference) int {
		return bytes.Compare(a.ResultID[:], b.ResultID[:])
	})
	p.reservation.candidate.generated = &generatedCandidateFacts{reservation: p.reservation}
	p.reservation.candidate.producer = p
	return p, s.observed(ObservedCurrent)
}

func generatedFinalPlansEqual(a, b *generatedFinalPlan) bool {
	if a == nil || b == nil || a.request != b.request || a.phase != b.phase || a.selecting != b.selecting || a.qualifyLegacy != b.qualifyLegacy || len(a.results) != len(b.results) ||
		len(a.entryPlans) != len(b.entryPlans) || !slices.Equal(a.retirements, b.retirements) || !slices.Equal(a.supplied.Rows, b.supplied.Rows) ||
		a.supplied.Operation != b.supplied.Operation || a.supplied.Transition != b.supplied.Transition || a.supplied.Snapshot != b.supplied.Snapshot ||
		a.supplied.Revision != b.supplied.Revision || !slices.EqualFunc(a.sealedInputs, b.sealedInputs, func(x, y contract.CryptoSealedInput) bool {
		return x.Name == y.Name && bytes.Equal(x.EnvelopeBytes, y.EnvelopeBytes)
	}) || !slices.EqualFunc(a.plain, b.plain, func(x, y contract.ValueEntry) bool {
		return x.Name == y.Name && x.Incarnation == y.Incarnation && x.ValueState == y.ValueState && x.OriginSnapshot == y.OriginSnapshot &&
			x.OriginTransition == y.OriginTransition && x.ValueSource == y.ValueSource && x.ConfidentialityClass == y.ConfidentialityClass && slices.Equal(x.Recipients, y.Recipients) && bytes.Equal(x.ValueBytes, y.ValueBytes)
	}) {
		return false
	}
	if (a.materialization == nil) != (b.materialization == nil) || a.materialization != nil && *a.materialization != *b.materialization {
		return false
	}
	for i := range a.results {
		if a.results[i].attempt.expected != b.results[i].attempt.expected || a.results[i].reference != b.results[i].reference ||
			!bytes.Equal(a.results[i].attempt.result, b.results[i].attempt.result) {
			return false
		}
	}
	return slices.EqualFunc(a.entryPlans, b.entryPlans, func(x, y contract.CryptoGeneratedValueEntryPlan) bool {
		return x.Slot == y.Slot && bytes.Equal(x.Result, y.Result) && x.ValueCore == y.ValueCore && x.Generated == y.Generated && slices.Equal(x.Recipients, y.Recipients)
	})
}

func mustGeneratedPhaseID(phase contract.GeneratorPhaseIdentity) contract.ID {
	id, _ := contract.GeneratorPhaseID(phase)
	return id
}

func (s *StateSession) deriveGeneratedFinal(ctx context.Context, plan *generatedFinalPlan,
	prepared []contract.CryptoGeneratedValueEntryResult, suppliedRows ...[]contract.CryptoPreparedSecret) (*generatedReservation, error) {
	return s.deriveGeneratedFinalWithObservation(ctx, plan, prepared, nil, suppliedRows...)
}

func (s *StateSession) deriveGeneratedFinalWithObservation(ctx context.Context, plan *generatedFinalPlan,
	prepared []contract.CryptoGeneratedValueEntryResult, detail *changeObservation, suppliedRows ...[]contract.CryptoPreparedSecret) (*generatedReservation, error) {
	if plan == nil || len(prepared) != len(plan.entryPlans) || len(suppliedRows) > 1 {
		return nil, contract.ErrRecord
	}
	var preparedSupplied []contract.CryptoPreparedSecret
	if len(suppliedRows) == 1 {
		preparedSupplied = suppliedRows[0]
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, fmt.Errorf("generated final selected work: %w", err)
	}
	phaseID, err := contract.GeneratorPhaseID(plan.phase)
	if err != nil {
		return nil, err
	}
	validated, err := s.validateGeneratedFinalRows(ctx, g, plan, prepared, preparedSupplied, false)
	if err != nil {
		return nil, err
	}
	defer validated.clearOwnedSupplied()
	bySlot, suppliedBySlot := validated.generated, validated.supplied
	next := *s
	next.cache, next.accessLocations, next.valueReaders = nil, nil, nil
	next.root.Snapshot, err = contract.GeneratorPhaseSnapshotID(phaseID)
	if err != nil {
		return nil, err
	}
	next.root.Transition, err = contract.GeneratorPhaseTransitionID(phaseID)
	if err != nil {
		return nil, err
	}
	revision, err := contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		return nil, err
	}
	candidate := &Candidate{session: s}
	rows, locations, bundles, sliceDescriptor, err := s.generatedFinalSupport(g, plan, prepared, next.root.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("generated final support: %w", err)
	}
	var unusedValues []contract.ID
	if !plan.selecting {
		rows, unusedValues, err = g.generatedPruneRetainedCanonicals(rows)
		if err != nil {
			return nil, fmt.Errorf("generated final retained values: %w", err)
		}
	}
	if plan.selecting {
		if err := next.installGeneratedRegistry(s, g, phaseID, candidate); err != nil {
			return nil, err
		}
		if err := next.installGeneratedFinalEntries(g, plan, bySlot, suppliedBySlot, rows, phaseID, candidate); err != nil {
			return nil, fmt.Errorf("generated final value entries: %w", err)
		}
		outputEntries, entryErr := generatedDeclarationOutputEntries(validated.declaration)
		if entryErr != nil {
			return nil, entryErr
		}
		registryRows, err := s.generatedEffectiveRecipients(g)
		if err != nil {
			return nil, err
		}
		var outputImage []byte
		if g.bundles[0].Request.Schema == contract.GeneratorApplyRequestCoreSchema {
			outputImage, err = g.readSelectedSlice(ctx, contract.GeneratorContentOutputConfiguration, g.parent.OperationID, contract.MaxOutputConfigurationBytes)
			if err != nil {
				return nil, err
			}
		}
		output, err := s.generatedRequestedOutputTransition(ctx, g.bundles[0], registryRows, outputEntries, outputImage)
		if err != nil {
			return nil, fmt.Errorf("generated final output predecessor: %w", err)
		}
		changed, descriptor, err := output.Rebind(g.bundles[0].Header.OperationID, g.bundles[0].ValueEntryPlans)
		if err != nil {
			return nil, fmt.Errorf("generated final output rebind: %w", err)
		}
		rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
			return row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind
		})
		rows = append(rows, changed.Records...)
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
			if a.Kind != b.Kind {
				return int(a.Kind) - int(b.Kind)
			}
			return bytes.Compare(a.RecordID[:], b.RecordID[:])
		})
		next.root.OutputConfiguration = descriptor
	}
	validated.clearOwnedSupplied()
	retainSeed := generatedRowsContainMaterial(rows, plan.request.MaterialID)
	if !plan.selecting && (!retainSeed || len(unusedValues) != 0) {
		var access []contract.AccessRecord
		for _, row := range next.accessRecords() {
			if (row.MaterialKind != contract.OperationSeedMaterialKind || row.MaterialID != plan.request.MaterialID || retainSeed) &&
				(row.MaterialKind != contract.ValueMaterialKind || !slices.Contains(unusedValues, row.MaterialID)) {
				access = append(access, row)
			}
		}
		if err := next.packGeneratedFinalAccess(access, phaseID, candidate); err != nil {
			return nil, err
		}
	}
	enclosed := plan.selecting && len(contract.GeneratedAutomaticRetirementIndices(g.bundles[0])) != 0
	if enclosed {
		phase := *g.phase
		phase.PhaseID, phase.Phase, phase.SelectionPhaseID = phaseID, plan.phase.AfterPhase, phaseID
		phase.FinalPreparationID = contract.ID{}
		phase.ChangedSubjects, err = generatedChangedSubjects(ctx, s, &next, detail)
		if err == nil {
			phase.ChangedAccess, err = generatedFinalChangedAccess(s, &next)
		}
		if err != nil {
			return nil, err
		}
		index := contract.GeneratedAutomaticRetirementIndices(g.bundles[0])[0]
		phase.LineageIndex, phase.FrontierAttemptID = index, g.bundles[0].Lineages[index].Templates[0].AttemptID
		phase.Stage, phase.Branch, phase.NoEffectUsed, phase.ResidueUsed = contract.GeneratedStageRetainedResult, 0, 0, 0
		phase.AcceptedResultID, phase.ResultDigest = contract.ID{}, contract.ID{}
		rows, err = generatedAutomaticPhaseRows(g, phase, rows)
	} else {
		rows, next.root.Generated.SuccessWindow, next.root.Generated.FailureWindow, next.root.Generated.ReceiptOrder, err =
			s.generatedFinalReceiptSupport(ctx, &next, g, plan, rows, revision, detail)
	}
	if err != nil {
		return nil, fmt.Errorf("generated final receipt or selection anchor: %w", err)
	}
	groups, err := generatedReservationGroupsWithSource(&next, s, rows, locations, bundles)
	if err != nil {
		return nil, fmt.Errorf("generated final support groups: %w", err)
	}
	next.root.RequiredSupport, next.support = nil, nil
	next.recountChildren()
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, fmt.Errorf("generated final fragment facts: %w", err)
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, next.root.ChildCount, fragments)
	if err != nil {
		return nil, fmt.Errorf("generated final pack: %w", err)
	}
	pageIDs := make([]contract.ID, len(packed))
	physicalIndexes, err := s.generatedSupportPhysicalIndexes(packed)
	if err != nil {
		return nil, err
	}

	for i := range pageIDs {
		id, err := contract.GeneratorPhasePageID(phaseID, contract.RequiredSupportKind, physicalIndexes[i])
		if err != nil {
			return nil, err
		}
		pageIDs[i] = id
	}
	var materialized generatedRequiredSupportMaterialization
	if len(s.fragmentFacts) != 0 || s.root.OutputConfiguration.SliceCount != 0 {
		materialized, err = s.materializeGeneratedSupportPages(ctx, packed, pageIDs)
	} else {
		materialized, err = materializeGeneratedRequiredSupport(s.root.Domain, packed, pageIDs)
	}
	if err != nil {
		return nil, fmt.Errorf("generated final materialize: %w", err)
	}
	next.root.RequiredSupport, next.support = materialized.references, materialized.views
	next.root.RequiredSupportRecordCount, next.root.Generated.Fragments = materialized.recordCount, materialized.fragments
	next.clearSelectedSupportFacts()
	candidate.objects = append(candidate.objects, materialized.objects...)
	if enclosed {
		next.root.Generated.ActivePhase = phaseID
	} else {
		next.root.Generated.ActiveOwner, next.root.Generated.ActivePhase, next.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	}
	generatedRefreshClosureCounts(&next.root.Generated, rows)
	var graphs []contract.ID
	for _, bundle := range bundles {
		graphs = append(graphs, bundle.UsePlan.PlanGraphID)
	}
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	next.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, slices.Compact(graphs))
	if err != nil {
		return nil, fmt.Errorf("generated final graph set: %w", err)
	}
	next.root.Generated.Slices = sliceDescriptor
	if err := s.installAdministrativeIndexWithBundles(ctx, &next, candidate, g.bundles); err != nil {
		return nil, fmt.Errorf("generated final administrative index: %w", err)
	}
	// Slice carriers were part of rows before packing and must agree exactly.
	if !next.indexSelectedMaterials() {
		return nil, fmt.Errorf("generated final material index: %w", contract.ErrRecord)
	}
	if _, err := next.selectedGeneratedWork(ctx); err != nil {
		return nil, fmt.Errorf("generated final work closure: %w", err)
	}
	next.recountChildren()
	if !validAggregate(next.root) {
		return nil, fmt.Errorf("generated final aggregate: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("generated final relations: %w", err)
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, fmt.Errorf("generated final root: %w", err)
	}
	rootRef, err := format.Reference(format.RootKind, s.root.Domain, next.root.Snapshot, 0, rootBody)
	if err != nil {
		return nil, fmt.Errorf("generated final root reference: %w", err)
	}
	candidate.objects = append(candidate.objects, objectImage{ref: rootRef, body: rootBody})
	head := s.successorCore(transitionPlan{revision: revision})
	head.Root = rootRef
	subject, err := s.generatedFinalSubject(ctx, &next, g, plan, head, phaseID, revision)
	if err != nil {
		return nil, fmt.Errorf("generated final subject: %w", err)
	}
	candidate.head = format.Head{Core: head, AuthKind: format.GeneratorAuth, Generator: &subject,
		K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = candidate.head
	if err := next.validateGeneratedSelection(ctx, nil); err != nil {
		return nil, fmt.Errorf("generated final selection: %w", err)
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedFinalPredecessor(slot uint16, name string) *contract.ValueEntry {
	return s.selectedImage().generatedFinalPredecessor(slot, name)
}
func (s *selectedImage) generatedFinalPredecessor(slot uint16, name string) *contract.ValueEntry {
	current := s.valueEntry(slot)
	if current == nil || current.Name != name {
		return nil
	}
	return current
}

// The predecessor and intended sets are authenticated independently of the mask.
func generatedFinalExcludesReader(before contract.ValueEntry, intended []contract.ID) bool {
	return slices.ContainsFunc(before.Recipients, func(id contract.ID) bool { return !slices.Contains(intended, id) })
}

func generatedFinalFreshProtection(before, after contract.ValueEntry) bool {
	if !generatedFinalChangedProtection(before, after) {
		return false
	}
	if before.ValueSource == after.ValueSource {
		metadata := before.Generated
		if before.ValueSource == contract.Generated {
			metadata.GenerationID = after.ValueState
		}
		return before.Incarnation == after.Incarnation && after.Generated == metadata
	}
	return true
}

func generatedFinalChangedProtection(before, after contract.ValueEntry) bool {
	if before.ValueState == after.ValueState || before.OriginSnapshot == after.OriginSnapshot || before.OriginTransition == after.OriginTransition {
		return false
	}
	oldPayload, oldErr := contract.InspectCanonicalPayload(before.ValueBytes)
	newPayload, newErr := contract.InspectCanonicalPayload(after.ValueBytes)
	if oldErr != nil || newErr != nil || oldPayload.SemanticCommitment == newPayload.SemanticCommitment ||
		bytes.Equal(oldPayload.Ciphertext, newPayload.Ciphertext) {
		return false
	}
	for _, old := range []contract.ID{oldPayload.DataKeyID, oldPayload.CommitmentKeyID} {
		if newPayload.DataKeyID == old || newPayload.CommitmentKeyID == old {
			return false
		}
	}
	return true
}

// These inputs were cloned by request construction. Result evidence in results
// still borrows the authenticated selection and is never cleared here.
func (p *generatedFinalPlan) clearOwnedInputs() {
	if p != nil {
		p.generatedFinalProjection.clearOwnedInputs()
	}
}
