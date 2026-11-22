package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

type generatedSuppliedPreparation struct {
	plan              int
	identity          contract.IdentityRow
	entryDigest       contract.ID
	canonical         contract.ID
	access            contract.DigestLength
	prepared          bool
	currentOnlyReplay bool
}

func (a *generatedAdmission) prepareSupplied(ctx context.Context, route KeyAccess, view contract.CryptoGeneratedSuppliedRequestView,
	out *contract.CryptoResponse) contract.CryptoResultCode {
	final := a.purpose.final
	if final == nil || generatedCurrentOnlyDeletePlan(a.graph) || final.nonselecting || final.suppliedFinal || view.PhaseID != final.phaseID ||
		view.BatchIndex != final.suppliedBatch {
		return contract.CryptoInvalidAdmission
	}
	if _, err := contract.CryptoGeneratedSuppliedResultBound(view); err != nil {
		if err == contract.ErrCryptoCapacity {
			return contract.CryptoCapacityExceeded
		}
		return contract.CryptoInvalidInput
	}
	request, err := view.Own()
	if err != nil {
		return contract.CryptoInvalidInput
	}
	identity, err := contract.DecodeIdentityPlan(request.IdentityPlan)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(final.phaseID)
	if err != nil {
		return contract.CryptoInvalidAdmission
	}
	transition, err := contract.GeneratorPhaseTransitionID(final.phaseID)
	if err != nil {
		return contract.CryptoInvalidAdmission
	}
	revision, err := contract.GeneratorPhaseRevisionID(final.phaseID)
	if err != nil || identity.Operation != a.graph.Header.OperationID || identity.Snapshot != snapshot ||
		identity.Transition != transition || identity.Revision != revision || len(identity.Pages) != 0 {
		return contract.CryptoInvalidAdmission
	}
	declaration, err := contract.InspectGeneratorDeclaration(final.plan.declaration)
	if err != nil || declaration.EntryCount() != len(a.graph.ValueEntryPlans) {
		return contract.CryptoInvalidAdmission
	}
	var expected []contract.IdentityRow
	for i, plan := range a.graph.ValueEntryPlans {
		prepareSupplied := plan.ValueSource == contract.Supplied && plan.ChangeMask&(contract.GeneratorValueChangeContent|contract.GeneratorValueChangeMembership) != 0
		if !prepareSupplied && !generatedMembershipOnly(plan) {
			continue
		}
		entry, _, err := declaration.Entry(i)
		if err != nil || string(entry.Name) != plan.Name || entry.ValueSource() != plan.ValueSource || entry.ConfidentialityClass() != plan.ConfidentialityClass {
			return contract.CryptoInvalidAdmission
		}
		identity, ok := a.preparedSuppliedIdentity(i, entry)
		if !ok {
			return contract.CryptoInvalidAdmission
		}
		expected = append(expected, identity)
		if entry.Kind != contract.GeneratorDeclarationPlain && entry.Kind != contract.GeneratorDeclarationSealed &&
			entry.Kind != contract.GeneratorDeclarationRetained && !generatedMembershipOnly(plan) {
			return contract.CryptoInvalidAdmission
		}
	}
	start, end := final.suppliedNext, final.suppliedNext+len(identity.Rows)
	if len(expected) != final.suppliedCount || len(identity.Rows) == 0 || end > len(expected) ||
		(request.Final == 1) != (end == len(expected)) || !slices.Equal(identity.Rows, expected[start:end]) {
		return contract.CryptoInvalidAdmission
	}
	var sealed []contract.CryptoSealedInput
	preparedSecrets := 0
	for _, row := range identity.Rows {
		planIndex := slices.IndexFunc(a.graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool { return plan.Name == row.Name })
		if planIndex < 0 {
			return contract.CryptoInvalidAdmission
		}
		entry, _, entryErr := declaration.Entry(planIndex)
		if entryErr != nil {
			return contract.CryptoInvalidAdmission
		}
		if entry.ConfidentialityClass() == contract.Secret {
			preparedSecrets++
		}
		if entry.Kind == contract.GeneratorDeclarationSealed {
			sealed = append(sealed, contract.CryptoSealedInput{Name: row.Name, EnvelopeBytes: entry.Payload})
		}
	}
	if !slices.EqualFunc(request.SealedInputs, sealed, func(x, y contract.CryptoSealedInput) bool {
		return x.Name == y.Name && bytes.Equal(x.EnvelopeBytes, y.EnvelopeBytes)
	}) {
		return contract.CryptoInvalidAdmission
	}
	result := contract.CryptoGeneratedSuppliedResult{BatchIndex: request.BatchIndex, Final: request.Final,
		Rows: make([]contract.CryptoPreparedSecret, 0, preparedSecrets)}
	preparedBatch := make([]generatedSuppliedPreparation, 0, len(identity.Rows))
	for _, row := range identity.Rows {
		planIndex := slices.IndexFunc(a.graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool { return plan.Name == row.Name })
		if planIndex < 0 || !applyRecipientsAdmitted(final.plan.recipients[planIndex], a.control.AuthorityRecipientID, a.bindings) {
			return contract.CryptoInvalidAdmission
		}
		entry, _, err := declaration.Entry(planIndex)
		if err != nil {
			return contract.CryptoInvalidAdmission
		}
		preparation := generatedSuppliedPreparation{plan: planIndex, identity: row}
		var valueEntry contract.ValueEntry
		var accessBody []byte
		if generatedMembershipOnly(a.graph.ValueEntryPlans[planIndex]) {
			var code contract.CryptoResultCode
			valueEntry, accessBody, code = a.prepareMembership(ctx, route, planIndex, out)
			if code != contract.CryptoSuccess {
				return code
			}
			entryBytes, err := contract.EncodeValueEntry(valueEntry)
			if err != nil {
				return contract.CryptoCustodyUnavailable
			}
			result.Rows = append(result.Rows, contract.CryptoPreparedSecret{Name: row.Name, Slot: row.Slot, EntryBytes: entryBytes, AccessRecord: accessBody})
			if entry.Kind == contract.GeneratorDeclarationRetained {
				record, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
				if err != nil {
					return contract.CryptoInvalidAdmission
				}
				preparation.canonical = record.Entry.ValueState
			}
		} else {
			switch entry.Kind {
			case contract.GeneratorDeclarationPlain:
				content, err := contract.InputContentLength(entry.InputEncoding, entry.Payload)
				if err != nil {
					return contract.CryptoInvalidAdmission
				}
				valueEntry = contract.ValueEntry{Name: row.Name, Incarnation: row.Incarnation, ValueState: row.ValueState,
					OriginSnapshot: row.OriginSnapshot, OriginTransition: row.OriginTransition, ValueSource: contract.Supplied,
					ConfidentialityClass: contract.Plain, InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, ContentLength: content, RetainedLength: uint32(len(entry.Payload)), Recipients: slices.Clone(final.plan.recipients[planIndex]), ValueBytes: bytes.Clone(entry.Payload)}
			case contract.GeneratorDeclarationSealed:
				sourceIndex := slices.IndexFunc(final.plan.sources, func(source generatedSource) bool { return source.core.Name == row.Name })
				if sourceIndex < 0 {
					return contract.CryptoInvalidAdmission
				}
				plain, code := a.openTransferredSource(final.plan.sources[sourceIndex], entry.Payload)
				if code != contract.CryptoSuccess {
					if plain != nil {
						clear(plain[:cap(plain)])
					}
					return code
				}
				prepared, coreAccess, code := a.sealFinalValue(ctx, row, contract.Supplied, entry.InputEncoding, entry.OutputEncoding, contract.GeneratedEntryMetadata{}, final.plan.recipients[planIndex], plain, out)
				clear(plain[:cap(plain)])
				if code != contract.CryptoSuccess {
					return code
				}
				valueEntry = prepared
				entryBytes, err := contract.EncodeValueEntry(valueEntry)
				if err != nil {
					return contract.CryptoCustodyUnavailable
				}
				accessBody, err = contract.EncodeAccessRecord(coreAccess)
				if err != nil {
					return contract.CryptoCustodyUnavailable
				}
				result.Rows = append(result.Rows, contract.CryptoPreparedSecret{Name: row.Name, Slot: row.Slot,
					EntryBytes: entryBytes, AccessRecord: accessBody})
			case contract.GeneratorDeclarationGenerated, contract.GeneratorDeclarationGeneratedReference:
				var code contract.CryptoResultCode
				valueEntry, accessBody, code = a.prepareMembership(ctx, route, planIndex, out)
				if code != contract.CryptoSuccess {
					return code
				}
				entryBytes, err := contract.EncodeValueEntry(valueEntry)
				if err != nil {
					return contract.CryptoCustodyUnavailable
				}
				result.Rows = append(result.Rows, contract.CryptoPreparedSecret{Name: row.Name, Slot: row.Slot, EntryBytes: entryBytes, AccessRecord: accessBody})
			case contract.GeneratorDeclarationRetained:
				prepared, retainedPreparation, code := a.prepareRetainedSupplied(ctx, route, planIndex, row, out)
				if code != contract.CryptoSuccess {
					return code
				}
				result.Rows = append(result.Rows, prepared)
				preparedBatch = append(preparedBatch, retainedPreparation)
				continue
			default:
				return contract.CryptoInvalidAdmission
			}
		}
		preparation.entryDigest, err = contract.PublicValueEntryDigest(a.request.Context.DomainID, row.Slot, valueEntry)
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		if accessBody != nil {
			preparation.access = contract.DigestLength{Digest: contract.Hash(accessBody), Length: uint64(len(accessBody))}
		}
		preparation.prepared = true
		preparedBatch = append(preparedBatch, preparation)
	}
	if len(final.entryPreparations) != 0 {
		if err := a.protectSuppliedGrants(result.Rows); err != nil {
			return contract.CryptoCustodyUnavailable
		}
	}
	out.Body, err = contract.EncodeCryptoGeneratedSuppliedResult(result)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	final.supplied = append(final.supplied, preparedBatch...)
	final.suppliedNext = end
	final.suppliedBatch++
	final.suppliedFinal = request.Final == 1
	return contract.CryptoSuccess
}

// A retained row owns its decoded entry, old keys and plaintext until its wire
// result is complete. Keep cleanup in this scope so no prior row's private
// workspace survives into the next source open, including on failure.
func (a *generatedAdmission) prepareRetainedSupplied(ctx context.Context, route KeyAccess, planIndex int, row contract.IdentityRow,
	out *contract.CryptoResponse) (contract.CryptoPreparedSecret, generatedSuppliedPreparation, contract.CryptoResultCode) {
	var prepared contract.CryptoPreparedSecret
	var preparation generatedSuppliedPreparation
	final := a.purpose.final
	sourceIndex := slices.IndexFunc(final.plan.canonicals, func(source generatedCanonicalSource) bool {
		return source.originalSlot == row.Slot && source.core.Name == row.Name
	})
	if sourceIndex < 0 {
		return prepared, preparation, contract.CryptoInvalidAdmission
	}
	source := &final.plan.canonicals[sourceIndex]
	keys, code := a.openCanonicalKeys(ctx, route, source, out)
	defer clear(keys[:cap(keys)])
	if code != contract.CryptoSuccess {
		return prepared, preparation, code
	}
	record, err := contract.DecodeRetainedCanonicalRecord(source.buffer)
	defer clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
	if err != nil || record.Entry.InputEncoding != a.graph.ValueEntryPlans[planIndex].InputEncoding || record.Entry.Incarnation != row.Incarnation {
		return prepared, preparation, contract.CryptoInvalidAdmission
	}
	valueEntry := record.Entry
	valueEntry.OutputEncoding = a.graph.ValueEntryPlans[planIndex].OutputEncoding
	var access contract.AccessRecord
	if a.finalExcludesReader(planIndex) {
		payload, err := contract.InspectCanonicalPayload(record.Entry.ValueBytes)
		if err != nil {
			return prepared, preparation, contract.CryptoStoredAuthenticationFailed
		}
		plain, err := custody.OpenValue(source.core, contract.CanonicalPayload(payload), keys)
		defer clear(plain[:cap(plain)])
		if err != nil {
			return prepared, preparation, contract.CryptoStoredAuthenticationFailed
		}
		valueEntry, access, code = a.sealFinalValue(ctx, row, record.Entry.ValueSource, record.Entry.InputEncoding, a.graph.ValueEntryPlans[planIndex].OutputEncoding, record.Entry.Generated, final.plan.recipients[planIndex], plain, out)
		defer clear(valueEntry.ValueBytes[:cap(valueEntry.ValueBytes)])
		if code != contract.CryptoSuccess {
			return prepared, preparation, code
		}
	} else {
		valueEntry.Recipients = slices.Clone(final.plan.recipients[planIndex])
		selectedWraps := make(map[generatedWrapIdentity]contract.WrapRow, len(source.selectedAccess.Wraps))
		for _, wrap := range source.selectedAccess.Wraps {
			selectedWraps[generatedWrapRowIdentity(wrap)] = wrap
		}
		access = source.selectedAccess
		readers := generatedReaderUnion(valueEntry.Recipients, generatedReaderUnion(source.recipients, source.retained))
		access.Wraps = make([]contract.WrapRow, 0, len(readers)+1)
		for bindingIndex, binding := range a.bindings {
			if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(readers, binding.SubjectID) {
				continue
			}
			if ctx.Err() != nil {
				return prepared, preparation, contract.CryptoCancelled
			}
			identity := generatedBindingIdentity(binding, a.bindingDigests[bindingIndex])
			if wrap, present := selectedWraps[identity]; present {
				access.Wraps = append(access.Wraps, wrap)
				continue
			}
			core, err := custody.ValueWrapCore(source.core, binding)
			if err != nil || core.PublicBindingDigest != a.bindingDigests[bindingIndex] {
				return prepared, preparation, contract.CryptoCustodyUnavailable
			}
			wrap, err := custody.Wrap(core, binding.Binding, keys)
			uses := KeyUses{Completed: 1}
			if err != nil {
				uses = KeyUses{Failed: 1}
			}
			if !appendKeyUses(out, binding, contract.KeyUseMaterialWrap, uses, 1) {
				return prepared, preparation, contract.CryptoResponseUnknown
			}
			if err != nil {
				return prepared, preparation, contract.CryptoCustodyUnavailable
			}
			access.Wraps = append(access.Wraps, wrap)
		}
	}
	entryBytes, err := contract.EncodeValueEntry(valueEntry)
	if err != nil {
		return prepared, preparation, contract.CryptoCustodyUnavailable
	}
	accessBody, err := contract.EncodeAccessRecord(access)
	if err != nil {
		return prepared, preparation, contract.CryptoCustodyUnavailable
	}
	entryDigest, err := contract.PublicValueEntryDigest(a.request.Context.DomainID, row.Slot, valueEntry)
	if err != nil {
		return prepared, preparation, contract.CryptoCustodyUnavailable
	}
	prepared = contract.CryptoPreparedSecret{Name: row.Name, Slot: row.Slot, EntryBytes: entryBytes, AccessRecord: accessBody}
	preparation = generatedSuppliedPreparation{plan: planIndex, identity: row, canonical: record.Entry.ValueState,
		entryDigest: entryDigest, access: contract.DigestLength{Digest: contract.Hash(accessBody), Length: uint64(len(accessBody))}, prepared: true}
	return prepared, preparation, contract.CryptoSuccess
}

func (a *generatedAdmission) sealFinalValue(ctx context.Context, identity contract.IdentityRow, source, inputEncoding, outputEncoding uint8, generated contract.GeneratedEntryMetadata, recipients []contract.ID,
	plain []byte, out *contract.CryptoResponse) (contract.ValueEntry, contract.AccessRecord, contract.CryptoResultCode) {
	content, err := contract.InputContentLength(inputEncoding, plain)
	if err != nil {
		return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoInvalidInput
	}
	core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: a.request.Context.CompatibilityID,
		CryptoSupportID: a.control.CryptoSupportID, DomainID: a.request.Context.DomainID, Name: identity.Name,
		EntryIncarnationID: identity.Incarnation, ValueStateID: identity.ValueState, OriginSnapshotID: identity.OriginSnapshot,
		OriginTransitionID: identity.OriginTransition, DataKeyEpoch: 1, CommitmentKeyEpoch: 1, ContentLength: content, InputEncoding: inputEncoding, RetainedLength: uint32(len(plain)), ValueSource: source}
	if source == contract.Generated {
		generated.GenerationID = identity.ValueState
		var err error
		core.GeneratedBindingDigest, err = contract.GeneratedBindingDigest(generated)
		if err != nil {
			return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoInvalidAdmission
		}
		core.DataKeyID, core.CommitmentKeyID, err = contract.GeneratorValueKeyIDs(identity.ValueState)
		if err != nil {
			return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoInvalidAdmission
		}
	} else {
		_, _ = rand.Read(core.DataKeyID[:])
		_, _ = rand.Read(core.CommitmentKeyID[:])
	}
	if core.DataKeyID.IsZero() || core.CommitmentKeyID.IsZero() || core.DataKeyID == core.CommitmentKeyID {
		return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCustodyUnavailable
	}
	return sealValueForRecipients(ctx, core, generated, outputEncoding, recipients, a.bindings, plain, out)
}
