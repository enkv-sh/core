package crypto

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// Policy support and the retiring-Duty selection are pinned by the private
// parent. Graph, selected result, evidence and mechanical value facts remain
// independently checked by this owner before it creates entry material.
type generatedEntryAdmission struct {
	Slot      uint16
	Generated contract.GeneratedEntryMetadata
}

type generatedEntryPreparation struct {
	generatedEntryAdmission
	plan, result int
	entryDigest  contract.ID
	access       contract.DigestLength
	prepared     bool
}

func (a *generatedAdmission) admitEntries(input []generatedEntryAdmission) bool {
	final := a.purpose.final
	if final == nil {
		return false
	}
	if len(input) == 0 {
		return true
	}
	if len(input) > contract.CryptoMaxValueEntries || len(input) > len(final.results) {
		return false
	}
	references := make([]contract.GeneratorResultReference, len(final.results))
	for i, row := range final.results {
		references[i] = row.Reference
	}
	slices.SortFunc(references, func(a, b contract.GeneratorResultReference) int { return bytes.Compare(a.ResultID[:], b.ResultID[:]) })
	if _, err := contract.GeneratorResultReferencesDescriptor(references); err != nil {
		return false
	}
	required := 0
	for _, plan := range a.graph.ValueEntryPlans {
		if plan.ValueSource == contract.Generated && plan.ChangeMask&contract.GeneratorValueChangeContent != 0 {
			required++
		}
	}
	if len(input) != required {
		return false
	}
	for i, entryAdmission := range input {
		if i > 0 && input[i-1].Slot >= entryAdmission.Slot {
			return false
		}
		planIndex := slices.IndexFunc(a.graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool { return plan.Slot == entryAdmission.Slot })
		resultIndex := slices.IndexFunc(final.results, func(row generatedResultAdmission) bool {
			return row.Reference.ResultID == entryAdmission.Generated.CreateResultID
		})
		if planIndex < 0 || resultIndex < 0 {
			return false
		}
		plan, expected, meta := a.graph.ValueEntryPlans[planIndex], final.results[resultIndex].Expected, entryAdmission.Generated
		if !applyRecipientsAdmitted(final.plan.recipients[planIndex], a.control.AuthorityRecipientID, a.bindings) {
			return false
		}
		if _, err := contract.GeneratedEntryMetadataLength(meta); err != nil {
			return false
		}
		x := expected.Template
		if plan.InputEncoding != expected.InputEncoding || plan.ValueSource != contract.Generated || plan.ChangeMask&contract.GeneratorValueChangeContent == 0 || x.Action != contract.GeneratorActionCreate || plan.LineageID != x.LineageID ||
			meta.Epoch != plan.Epoch || meta.RetirementMode != plan.RetirementMode || meta.IntentDigest != plan.IntentDigest ||
			meta.ConfigContractID != x.ConfigContractID || meta.ResourceContractID != x.ResourceContractID || meta.CompletionClass != x.CompletionClass ||
			meta.ResourceIncarnationID != x.ResourceIncarnationID || meta.OriginOperationID != a.material.Core.OperationID ||
			meta.OriginAttemptID != x.AttemptID || meta.LifecycleMode != x.LifecycleMode {
			return false
		}
		for _, previous := range final.entryPreparations {
			if previous.result == resultIndex {
				return false
			}
		}
		final.entryPreparations = append(final.entryPreparations, generatedEntryPreparation{generatedEntryAdmission: entryAdmission, plan: planIndex, result: resultIndex})
	}
	return true
}

func (a *generatedAdmission) prepareEntries(v contract.CryptoGeneratedValueEntriesRequestView, out *contract.CryptoResponse) contract.CryptoResultCode {
	final := a.purpose.final
	if final == nil || !final.suppliedFinal || final.suppliedNext != final.suppliedCount {
		return contract.CryptoInvalidAdmission
	}
	bound, err := contract.CryptoGeneratedValueEntriesResultBound(v, a.control.Recovery != nil)
	if err != nil {
		if err == contract.ErrCryptoCapacity {
			return contract.CryptoCapacityExceeded
		}
		return contract.CryptoInvalidInput
	}
	count := v.RowCount()
	if v.PhaseID != final.phaseID || v.BatchIndex != final.entryBatch || count > len(final.entryPreparations)-final.entryNext ||
		(v.Final == 1) != (final.entryNext+count == len(final.entryPreparations)) {
		return contract.CryptoInvalidAdmission
	}
	result := contract.CryptoGeneratedValueEntriesResult{BatchIndex: v.BatchIndex, Final: v.Final, Rows: make([]contract.CryptoGeneratedValueEntryResult, 0, count)}
	for i := 0; i < count; i++ {
		view, err := v.Row(i)
		if err != nil {
			return contract.CryptoInvalidInput
		}
		plan, err := view.Own()
		if err != nil {
			return contract.CryptoInvalidInput
		}
		row := &final.entryPreparations[final.entryNext+i]
		graph := a.graph.ValueEntryPlans[row.plan]
		selected := final.results[row.result]
		if plan.ValueCore.InputEncoding != graph.InputEncoding || plan.OutputEncoding != graph.OutputEncoding || row.prepared || plan.Slot != row.Slot || plan.Generated != row.Generated || plan.ValueCore.Name != graph.Name ||
			plan.ValueCore.EntryIncarnationID != graph.EntryIncarnationID || !slices.Equal(plan.Recipients, final.plan.recipients[row.plan]) {
			return contract.CryptoInvalidAdmission
		}
		if !a.entryEvidenceMatches(plan, *row) {
			return contract.CryptoInvalidAdmission
		}
		preparedEntry, code := a.sealEntry(plan, selected, out)
		if code != contract.CryptoSuccess {
			return code
		}
		row.entryDigest, err = contract.PublicValueEntryDigest(a.request.Context.DomainID, preparedEntry.Slot, preparedEntry.Entry)
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		access, err := contract.EncodeAccessRecord(preparedEntry.Access)
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		row.access = contract.DigestLength{Digest: contract.Hash(access), Length: uint64(len(access))}
		row.prepared = true
		result.Rows = append(result.Rows, preparedEntry)
	}
	out.Body, err = contract.EncodeCryptoGeneratedValueEntriesResult(result)
	if err != nil || len(out.Body) != bound+10 {
		return contract.CryptoCustodyUnavailable
	}
	final.entryNext += count
	final.entryBatch++
	if v.Final == 1 {
		a.stage = contract.CryptoFreeze
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) entryEvidenceMatches(plan contract.CryptoGeneratedValueEntryPlan, row generatedEntryPreparation) bool {
	final := a.purpose.final
	if final == nil || row.result < 0 || row.result >= len(final.results) {
		return false
	}
	selected := final.results[row.result]
	if len(plan.Result) != int(selected.Reference.ResultLength) || contract.Hash(plan.Result) != selected.Reference.ResultBodyDigest {
		return false
	}
	result, err := contract.DecodeGeneratedResultRecord(plan.Result)
	if err != nil {
		return false
	}
	core, err := contract.EncodeGeneratedResultCore(result.Core)
	if err != nil {
		return false
	}
	facts, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
	if err != nil {
		return false
	}
	record := contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema, LifecycleMode: selected.Expected.Template.SemanticLifecycleMode(),
		OriginalResultID: selected.Reference.ResultID, CredentialRouteID: selected.Expected.Template.CredentialRouteID, ResultCore: core, SafeFacts: facts,
		Intent: final.plan.intents[row.plan], CompletionClass: selected.Expected.Template.CompletionClass}
	evidence, err := contract.GeneratedCreateEvidenceDescriptor(record)
	return err == nil && evidence == plan.Generated.CreateEvidence
}

func (a *generatedAdmission) sealEntry(plan contract.CryptoGeneratedValueEntryPlan, selected generatedResultAdmission, out *contract.CryptoResponse) (contract.CryptoGeneratedValueEntryResult, contract.CryptoResultCode) {
	var result contract.CryptoGeneratedValueEntryResult
	final := a.purpose.final
	if final == nil {
		return result, contract.CryptoInvalidAdmission
	}
	payload, keys, err := custody.SealGeneratedValuePayload(selected.Expected, a.material, final.materializationPhaseID, selected.Reference, plan, a.seed)
	defer clear(keys[:cap(keys)])
	if err != nil {
		return result, contract.CryptoStoredAuthenticationFailed
	}
	context, err := contract.ValueMaterialContextDigest(plan.ValueCore)
	if err != nil {
		return result, contract.CryptoCustodyUnavailable
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: plan.ValueCore.ValueStateID, MaterialContextDigest: context, PackageCheck: payload.PackageCheck}
	for _, binding := range a.bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(plan.Recipients, binding.SubjectID) {
			continue
		}
		core, err := custody.ValueWrapCore(plan.ValueCore, binding)
		if err != nil {
			return result, contract.CryptoCustodyUnavailable
		}
		wrap, err := custody.Wrap(core, binding.Binding, keys)
		uses := KeyUses{Completed: 1}
		if err != nil {
			uses = KeyUses{Failed: 1}
		}
		if !appendKeyUses(out, binding, contract.KeyUseMaterialWrap, uses, 1) {
			return result, contract.CryptoResponseUnknown
		}
		if err != nil {
			return result, contract.CryptoCustodyUnavailable
		}
		access.Wraps = append(access.Wraps, wrap)
	}
	body, err := contract.EncodeCanonicalPayload(payload)
	if err != nil {
		return result, contract.CryptoCustodyUnavailable
	}
	core := plan.ValueCore
	entry := contract.ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID, OriginSnapshot: core.OriginSnapshotID,
		OriginTransition: core.OriginTransitionID, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, InputEncoding: core.InputEncoding, OutputEncoding: plan.OutputEncoding, ContentLength: core.ContentLength, RetainedLength: core.RetainedLength, Generated: plan.Generated, Recipients: plan.Recipients, ValueBytes: body}
	result = contract.CryptoGeneratedValueEntryResult{Slot: plan.Slot, ResultID: selected.Reference.ResultID, ResultDigest: selected.Reference.ResultBodyDigest,
		ValueCore: core, Entry: entry, Access: access}
	return result, contract.CryptoSuccess
}

func (a *generatedAdmission) preparedPublicStateRows(c generatedCandidate) ([]contract.PublicStateRow, bool) {
	final := a.purpose.final
	if final == nil || !final.suppliedFinal || final.suppliedNext != final.suppliedCount ||
		len(final.supplied) != final.suppliedCount || final.entryNext != len(final.entryPreparations) {
		return nil, false
	}
	if final.nonselecting {
		if len(final.entryPreparations) != 0 || len(final.supplied) != 0 {
			return nil, false
		}
		return slices.Clone(a.before.Rows), true
	}
	rows := make([]contract.PublicStateRow, 0, len(a.graph.ValueEntryPlans))
	var recipients [contract.CryptoMaxValueEntryRecipients]contract.ID
	for index, before := range a.before.Rows {
		at := slices.IndexFunc(a.graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool {
			return plan.Name == before.Name && plan.Slot == before.Slot
		})
		if at < 0 {
			continue
		}
		plan := a.graph.ValueEntryPlans[at]
		if plan.ChangeMask&contract.GeneratorValueChangeContent == 0 {
			if a.purpose.output == nil || index >= len(a.purpose.output.EntryBodies) {
				return nil, false
			}
			view, err := contract.InspectValueEntry(a.purpose.output.EntryBodies[index])
			if err != nil || view.InputEncoding != plan.InputEncoding || string(view.Name) != plan.Name || view.Incarnation != plan.EntryIncarnationID {
				return nil, false
			}
			if view.OutputEncoding != plan.OutputEncoding {
				entry := contract.ValueEntry{Name: string(view.Name), Incarnation: view.Incarnation, ValueState: view.ValueState,
					OriginSnapshot: view.OriginSnapshot, OriginTransition: view.OriginTransition, ValueSource: view.ValueSource,
					ConfidentialityClass: view.ConfidentialityClass, InputEncoding: view.InputEncoding, OutputEncoding: plan.OutputEncoding,
					ContentLength: view.ContentLength, RetainedLength: view.RetainedLength, ValueBytes: view.ValueBytes, Generated: view.Generated,
					Recipients: recipients[:view.RecipientCount()]}
				for i := range entry.Recipients {
					id, ok := view.RecipientID(i)
					if !ok {
						return nil, false
					}
					entry.Recipients[i] = id
				}
				before.EntryDigest, err = contract.PublicValueEntryDigest(a.before.Domain, plan.Slot, entry)
				if err != nil {
					return nil, false
				}
			}
		}
		rows = append(rows, before)
	}
	for _, entryPreparation := range final.entryPreparations {
		if !entryPreparation.prepared {
			return nil, false
		}
		value := contract.PublicStateRow{Name: a.graph.ValueEntryPlans[entryPreparation.plan].Name, Slot: entryPreparation.Slot, EntryDigest: entryPreparation.entryDigest}
		index := slices.IndexFunc(rows, func(row contract.PublicStateRow) bool { return row.Slot == entryPreparation.Slot })
		if index < 0 {
			rows = append(rows, value)
		} else {
			rows[index] = value
		}
		access := slices.IndexFunc(c.AccessRecords, func(row contract.AccessRecord) bool {
			return row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == entryPreparation.Generated.GenerationID
		})
		if access < 0 {
			return nil, false
		}
		body, err := contract.EncodeAccessRecord(c.AccessRecords[access])
		if err != nil || uint64(len(body)) != entryPreparation.access.Length || contract.Hash(body) != entryPreparation.access.Digest {
			return nil, false
		}
	}
	for _, entryPreparation := range final.supplied {
		if !entryPreparation.prepared {
			return nil, false
		}
		plan := a.graph.ValueEntryPlans[entryPreparation.plan]
		value := contract.PublicStateRow{Name: plan.Name, Slot: plan.Slot, EntryDigest: entryPreparation.entryDigest}
		index := slices.IndexFunc(rows, func(row contract.PublicStateRow) bool { return row.Slot == plan.Slot })
		if index < 0 {
			rows = append(rows, value)
		} else {
			rows[index] = value
		}
		if entryPreparation.access == (contract.DigestLength{}) {
			continue
		}
		access := slices.IndexFunc(c.AccessRecords, func(row contract.AccessRecord) bool {
			return row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == entryPreparation.identity.ValueState
		})
		if access < 0 {
			return nil, false
		}
		if !a.suppliedFinalAccessMatches(c, entryPreparation, c.AccessRecords[access]) {
			return nil, false
		}
	}
	slices.SortFunc(rows, func(x, y contract.PublicStateRow) int { return bytes.Compare([]byte(x.Name), []byte(y.Name)) })
	return rows, true
}
