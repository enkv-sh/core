package crypto

import (
	"bytes"
	"context"
	"crypto/subtle"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func (a *generatedAdmission) finalLocalCheckpointAttempt(record contract.GeneratedAttemptRecord) bool {
	final := a.purpose.final
	if final == nil || !final.nonselecting || record.Schema != contract.GeneratedAttemptRecordSchema ||
		record.LifecycleMode != contract.GeneratorLifecycleNone || !record.PredecessorAttemptID.IsZero() ||
		record.RetryUsed != 0 || record.Stage != contract.GeneratedStageTerminal {
		return false
	}
	_, err := contract.GeneratedAttemptRecordLength(record)
	if err != nil {
		return false
	}
	matched := false
	for _, lineage := range a.graph.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate || lineage.TemplateCount != 1 {
			continue
		}
		x := lineage.Templates[0]
		if x.Schema == contract.GeneratorAttemptTemplateSchema && x.LifecycleMode == contract.GeneratorLifecycleNone &&
			x.Action == contract.GeneratorActionCreate && x.Branch == contract.GeneratorBranchInitial &&
			generatedUncertainAttemptMatches(record, x, a.graph.Header.DomainID, a.graph.Header.OperationID) {
			if matched {
				return false
			}
			matched = true
		}
	}
	if !matched {
		return false
	}
	returned := false
	for _, body := range final.resultBodies {
		result, err := contract.InspectGeneratedResultRecord(body)
		if err != nil {
			return false
		}
		if result.Core.ResultID == record.ResultID {
			if returned || !result.MatchesLocalCreateAttempt(record) {
				return false
			}
			returned = true
		}
	}
	if returned {
		return true
	}
	if !generatedLocalTerminalAttempt(record) || a.purpose.output == nil {
		return false
	}
	for _, fact := range a.purpose.output.Rows.Facts {
		if fact.Kind() == contract.GeneratedResultSupportKind && fact.RecordID() == record.ResultID {
			return false
		}
	}
	return true
}

func generatedFinalCheckpointAttempt(rows []contract.SupportRecord, id contract.ID) (contract.GeneratedAttemptRecord, bool) {
	for _, row := range rows {
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == id {
			record, err := contract.InspectGeneratedAttemptRecord(row.Body)
			return record, err == nil && record.AttemptID == id
		}
	}
	return contract.GeneratedAttemptRecord{}, false
}

func generatedFinalCheckpointDuty(rows []contract.SupportRecord, id contract.ID) (contract.GeneratedDutyRecord, bool) {
	for _, row := range rows {
		if row.Kind == contract.GeneratedDutySupportKind && row.RecordID == id {
			record, err := contract.InspectGeneratedDutyRecord(row.Body)
			return record, err == nil && record.DutyID == id
		}
	}
	return contract.GeneratedDutyRecord{}, false
}

func generatedLocalDutyMatches(d contract.GeneratedDutyRecord, a contract.GeneratedAttemptRecord) bool {
	return d.Schema == contract.GeneratedDutyRecordSchema && d.LifecycleMode == contract.GeneratorLifecycleNone &&
		d.DomainID == a.DomainID && d.DutyID == a.OwnerID && d.OwnerID == d.DutyID && d.OriginalOperationID == a.OperationID &&
		d.OriginalAttemptID == a.AttemptID && d.ResourceID == a.ResourceID && d.DescriptorID == a.DescriptorID && d.ConfigContractID == a.ConfigContractID &&
		d.ExecutorID == a.ExecutorID && d.CredentialRouteID == a.CredentialRouteID && d.ResourceContractID == a.ResourceContractID &&
		d.ResultContractID == a.ResultContractID && d.CompletionClass == a.CompletionClass &&
		d.Kind == contract.GeneratedDutyCreate && d.Step == 1 && d.Status == a.State
}

// A selected image is historical data. Reuse additionally requires the exact
// current control and bindings; it does not turn its old context into authority.
func (a *generatedAdmission) admitFinalPreparation(input generatedFinalAdmissionInput) bool {
	final := a.purpose.final
	if final == nil {
		return false
	}
	selected := make(map[contract.SupportRecordDigest]bool)
	selectedPreparation := false
	if a.purpose.output != nil {
		for _, fact := range a.purpose.output.Rows.Facts {
			selected[fact] = true
			if fact.Kind() == contract.GeneratedFinalPreparationSupportKind && fact.RecordID() == a.graph.Header.OperationID {
				selectedPreparation = true
			}
		}
	}
	type rowKey struct {
		kind uint8
		id   contract.ID
	}
	seen := make(map[rowKey]bool)
	localAttempts, localDuties := 0, 0
	for _, row := range input.CheckpointSupport {
		key := rowKey{row.Kind, row.RecordID}
		if final == nil || a.purpose.output == nil || seen[key] {
			return false
		}
		seen[key] = true
		fact, err := contract.InspectSupportRecordDigest(a.request.Context.DomainID, row)
		if err != nil || !selected[fact] {
			return false
		}
		switch row.Kind {
		case contract.GeneratedPhaseSupportKind, contract.GeneratedFinalPreparationSupportKind:
			if row.RecordID != a.graph.Header.OperationID {
				return false
			}
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil || carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.VectorKind != contract.GeneratorVectorSlices {
				return false
			}
		case contract.GeneratedAttemptSupportKind:
			record, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil || row.RecordID != record.AttemptID || !a.finalLocalCheckpointAttempt(record) {
				return false
			}
			localAttempts++
			if localAttempts > contract.GeneratorMaxCreateLineages {
				return false
			}
		case contract.GeneratedDutySupportKind:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			original, present := generatedFinalCheckpointAttempt(input.CheckpointSupport, duty.OriginalAttemptID)
			if err != nil || row.RecordID != duty.DutyID || !present || !a.finalLocalCheckpointAttempt(original) ||
				original.State == contract.GeneratedEffectFailedTerminal || !generatedLocalDutyMatches(duty, original) {
				return false
			}
			localDuties++
			if localDuties > contract.GeneratorMaxCreateLineages {
				return false
			}
		case contract.GeneratedFragmentSupportKind:
		default:
			return false
		}
		row.Body = bytes.Clone(row.Body)
		final.checkpointSupport = append(final.checkpointSupport, row)
	}
	if final.nonselecting {
		for _, result := range final.results {
			x := result.Expected.Template
			if x.LifecycleMode == contract.GeneratorLifecycleNone && !seen[rowKey{contract.GeneratedAttemptSupportKind, x.AttemptID}] {
				return false
			}
		}
	}
	for _, row := range final.checkpointSupport {
		if row.Kind != contract.GeneratedAttemptSupportKind {
			continue
		}
		record, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil {
			return false
		}
		if record.State != contract.GeneratedEffectFailedTerminal {
			duty, present := generatedFinalCheckpointDuty(final.checkpointSupport, record.OwnerID)
			if !present || !generatedLocalDutyMatches(duty, record) {
				return false
			}
		}
	}
	current, err := contract.GeneratedFinalPreparationBindingDigest(a.control, a.bindings)
	if err != nil {
		return false
	}
	if input.Preparation == nil {
		if input.QualifyLegacy || input.PreparationPhase != nil || len(input.PreparedImage) != 0 {
			return false
		}
		if !selectedPreparation {
			return true
		}
		// A binding change has its own replacement authority. Same-binding
		// replacement must qualify the selected image, even if its carrier is omitted.
		for _, row := range final.checkpointSupport {
			if row.Kind == contract.GeneratedFinalPreparationSupportKind && row.RecordID == a.graph.Header.OperationID {
				record, err := contract.InspectGeneratedFinalPreparationRecord(row.Body)
				return err == nil && record.DomainID == a.request.Context.DomainID && record.OperationID == a.graph.Header.OperationID && record.ControlBindingDigest != current
			}
		}
		return false
	}
	if final == nil || final.nonselecting || input.PreparationPhase == nil || a.purpose.output == nil {
		return false
	}
	record, phase := *input.Preparation, *input.PreparationPhase
	encoded, err := contract.EncodeGeneratedFinalPreparationRecord(record)
	if err != nil || record.DomainID != a.request.Context.DomainID || record.OperationID != a.graph.Header.OperationID ||
		record.MaterializationPhase.RequestIdentityDigest != a.request.Parent.RequestIdentityDigest ||
		record.MaterializationPhase.Evidence != final.phase.Evidence || record.MaterializationPhase.AfterPhase != final.phase.BeforePhase ||
		uint64(len(input.PreparedImage)) != uint64(record.Image.Length) || contract.Hash(input.PreparedImage) != record.Image.Digest {
		return false
	}
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil || phase.DomainID != record.DomainID || phase.OperationID != record.OperationID || phase.OwnerID != record.OperationID ||
		phase.PlanGraphID != a.graph.UsePlan.PlanGraphID || phase.UsePlanDigest != a.request.UsePlanDigest ||
		phase.FinalPreparationID != record.Image.ContentID || phase.Phase != final.phase.BeforePhase || phase.Stage != contract.GeneratedStageTerminal {
		return false
	}
	for _, row := range []contract.SupportRecord{
		{Kind: contract.GeneratedFinalPreparationSupportKind, RecordID: record.OperationID, Body: encoded},
		{Kind: contract.GeneratedPhaseSupportKind, RecordID: phase.OperationID, Body: phaseBody},
	} {
		fact, err := contract.InspectSupportRecordDigest(record.DomainID, row)
		if err != nil || !selected[fact] {
			return false
		}
	}
	checkpoint := record.MaterializationPhase
	checkpoint.TransitionKind = contract.GeneratorAuthorityFinalPreparation
	checkpoint.Evidence, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{record.Image})
	if err != nil {
		return false
	}
	checkpointID, err := contract.GeneratorPhaseID(checkpoint)
	if err != nil || checkpointID != phase.PhaseID {
		return false
	}
	if current != record.ControlBindingDigest {
		return false
	}
	materialization, err := contract.GeneratorPhaseID(record.MaterializationPhase)
	if err != nil {
		return false
	}
	image, err := contract.DecodeGeneratedFinalPreparationImage(input.PreparedImage)
	if err != nil {
		return false
	}
	if image.DomainID != record.DomainID || image.OperationID != record.OperationID || image.MaterializationPhaseID != materialization ||
		image.ControlBindingDigest != current || len(image.Generated) != len(final.entryPreparations) {
		image.Clear()
		return false
	}
	if input.QualifyLegacy {
		final.qualificationImage = &image
	} else {
		final.preparedImage = &image
		final.materializationPhaseID = materialization
	}
	return true
}

// Qualification may exempt only exact historical preservation. It cannot make
// that image a prepared Final or alter the active fresh preparation's sources.
func (a *generatedAdmission) qualifyHistoricalPreparation(ctx context.Context, route KeyAccess, out *contract.CryptoResponse) contract.CryptoResultCode {
	final := a.purpose.final
	image := final.qualificationImage
	if image == nil || final.preparedImage != nil || final.entryNext != 0 || len(final.supplied) != 0 {
		return contract.CryptoInvalidAdmission
	}
	final.qualificationImage = nil
	defer image.Clear()
	historical := *final
	historical.materializationPhaseID, historical.preparedImage = image.MaterializationPhaseID, image
	historical.qualifyingLegacy, historical.legacyExclusion = true, false
	historical.entryPreparations = slices.Clone(final.entryPreparations)
	// openCanonicalKeys marks a source opened. Only the copied source structs
	// receive that mark; their immutable source buffers remain borrowed.
	historical.plan.canonicals = slices.Clone(final.plan.canonicals)
	historical.supplied = nil
	defer func() {
		clear(historical.entryPreparations)
		clear(historical.supplied)
		clear(historical.plan.canonicals)
	}()
	for i := range historical.entryPreparations {
		row := &historical.entryPreparations[i]
		selected := historical.results[row.result]
		binding, err := contract.GeneratedBindingDigest(row.Generated)
		identity, identityErr := contract.DeriveGeneratedValueIdentity(selected.Expected.Use.PlannedValueSlotID, image.MaterializationPhaseID, selected.Reference.ResultID, binding)
		if err != nil || identityErr != nil {
			return contract.CryptoInvalidAdmission
		}
		row.Generated.GenerationID = identity.ValueStateID
	}
	qualified := *a
	qualified.purpose.final = &historical
	if code := qualified.openFinalPreparation(ctx, route, out); code != contract.CryptoSuccess {
		return code
	}
	if !historical.legacyExclusion {
		return contract.CryptoInvalidAdmission
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) openFinalPreparation(ctx context.Context, route KeyAccess, out *contract.CryptoResponse) contract.CryptoResultCode {
	final := a.purpose.final
	if final == nil || final.preparedImage == nil || final.entryNext != 0 || len(final.supplied) != 0 {
		return contract.CryptoInvalidAdmission
	}
	for i, image := range final.preparedImage.Generated {
		row := &final.entryPreparations[i]
		graph, selected := a.graph.ValueEntryPlans[row.plan], final.results[row.result]
		plan := contract.CryptoGeneratedValueEntryPlan{Slot: row.Slot, OutputEncoding: graph.OutputEncoding, ValueCore: image.ValueCore, Generated: row.Generated,
			Recipients: final.plan.recipients[row.plan], Result: final.resultBodies[row.result]}
		if image.Slot != row.Slot || image.ResultID != selected.Reference.ResultID || image.ResultDigest != selected.Reference.ResultBodyDigest ||
			image.ValueCore.InputEncoding != graph.InputEncoding || image.Entry.InputEncoding != graph.InputEncoding || image.Entry.OutputEncoding != graph.OutputEncoding ||
			image.ValueCore.Name != graph.Name || image.ValueCore.EntryIncarnationID != graph.EntryIncarnationID ||
			image.Entry.Generated != row.Generated || !slices.Equal(image.Entry.Recipients, plan.Recipients) || !a.entryEvidenceMatches(plan, *row) {
			return contract.CryptoInvalidAdmission
		}
		payload, derived, err := custody.SealGeneratedValuePayload(selected.Expected, a.material, final.materializationPhaseID, selected.Reference, plan, a.seed)
		if err != nil {
			clear(derived[:cap(derived)])
			return contract.CryptoStoredAuthenticationFailed
		}
		payloadBody, err := contract.EncodeCanonicalPayload(payload)
		clear(payload.Ciphertext[:cap(payload.Ciphertext)])
		defer clear(payloadBody[:cap(payloadBody)])
		if err != nil || !bytes.Equal(payloadBody, image.Entry.ValueBytes) {
			clear(derived[:cap(derived)])
			return contract.CryptoStoredAuthenticationFailed
		}
		keys, code := a.openPreparedValue(ctx, route, image.ValueCore, image.Entry, image.Access, plan.Recipients, out)
		if code != contract.CryptoSuccess {
			clear(derived[:cap(derived)])
			return code
		}
		equal := subtle.ConstantTimeCompare(keys, derived) == 1
		if equal && a.finalExcludesReader(row.plan) {
			code = a.preparedContentExclusionMatches(ctx, route, row.plan, image.Entry, keys, out)
			if code != contract.CryptoSuccess {
				clear(keys[:cap(keys)])
				clear(derived[:cap(derived)])
				return code
			}
		}
		clear(keys[:cap(keys)])
		clear(derived[:cap(derived)])
		if !equal {
			return contract.CryptoStoredAuthenticationFailed
		}
		row.entryDigest, err = contract.PublicValueEntryDigest(a.request.Context.DomainID, image.Slot, image.Entry)
		if err != nil {
			return contract.CryptoInvalidAdmission
		}
		body, err := contract.EncodeAccessRecord(image.Access)
		if err != nil {
			return contract.CryptoInvalidAdmission
		}
		row.access, row.prepared = contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}, true
	}
	if code := a.openPreparedSupplied(ctx, route, out); code != contract.CryptoSuccess {
		return code
	}
	final.entryNext = len(final.entryPreparations)
	final.suppliedNext, final.suppliedFinal = final.suppliedCount, true
	return contract.CryptoSuccess
}

func (a *generatedAdmission) openPreparedValue(ctx context.Context, route KeyAccess, core contract.ValueCore, entry contract.ValueEntry,
	access contract.AccessRecord, readers []contract.ID, out *contract.CryptoResponse) ([]byte, contract.CryptoResultCode) {
	expected, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
	if err != nil || expected != core || !a.accessBindingsValid(access) {
		return nil, contract.CryptoInvalidAdmission
	}
	context, err := contract.ValueMaterialContextDigest(core)
	payload, payloadErr := contract.DecodeCanonicalPayload(entry.ValueBytes)
	defer clear(payload.Ciphertext[:cap(payload.Ciphertext)])
	if err != nil || payloadErr != nil || access.MaterialKind != contract.ValueMaterialKind || access.MaterialID != core.ValueStateID ||
		access.MaterialContextDigest != context || access.PackageCheck != payload.PackageCheck {
		return nil, contract.CryptoInvalidAdmission
	}
	count := len(readers)
	if a.control.Recovery != nil {
		count++
	}
	if len(access.Wraps) != count {
		return nil, contract.CryptoInvalidAdmission
	}
	for i, id := range readers {
		if access.Wraps[i].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[i].SubjectID != id {
			return nil, contract.CryptoInvalidAdmission
		}
	}
	if a.control.Recovery != nil {
		wrap := access.Wraps[len(readers)]
		if wrap.SubjectKind != contract.RecoveryWrapSubject || wrap.SubjectID != a.control.Recovery.RoleID {
			return nil, contract.CryptoInvalidAdmission
		}
	}
	keys, code := a.openCurrentValue(ctx, route, contract.ConsumerSelection{Core: core, Access: access}, out)
	if code != contract.CryptoSuccess {
		return nil, code
	}
	check, err := custody.PackageCheck(core, keys)
	if err != nil || check != access.PackageCheck {
		clear(keys[:cap(keys)])
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	plain, err := custody.OpenValue(core, payload, keys)
	clear(plain[:cap(plain)])
	if err != nil {
		clear(keys[:cap(keys)])
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	return keys, contract.CryptoSuccess
}

func (a *generatedAdmission) openPreparedSupplied(ctx context.Context, route KeyAccess, out *contract.CryptoResponse) contract.CryptoResultCode {
	final := a.purpose.final
	declaration, err := contract.InspectGeneratorDeclaration(final.plan.declaration)
	if err != nil {
		return contract.CryptoInvalidAdmission
	}
	used := 0
	for index, plan := range a.graph.ValueEntryPlans {
		if (plan.ValueSource != contract.Supplied || plan.ChangeMask&(contract.GeneratorValueChangeContent|contract.GeneratorValueChangeMembership) == 0) && !generatedMembershipOnly(plan) {
			continue
		}
		input, _, err := declaration.Entry(index)
		if err != nil {
			return contract.CryptoInvalidAdmission
		}
		identity, ok := a.preparedSuppliedIdentity(index, input)
		if !ok {
			return contract.CryptoInvalidAdmission
		}
		state := generatedSuppliedPreparation{plan: index, identity: identity}
		var entry contract.ValueEntry
		if plan.ConfidentialityClass == contract.Plain {
			content, err := contract.InputContentLength(input.InputEncoding, input.Payload)
			if err != nil {
				return contract.CryptoInvalidAdmission
			}
			entry = contract.ValueEntry{Name: identity.Name, Incarnation: identity.Incarnation, ValueState: identity.ValueState,
				OriginSnapshot: identity.OriginSnapshot, OriginTransition: identity.OriginTransition, ValueSource: contract.Supplied,
				ConfidentialityClass: contract.Plain, InputEncoding: input.InputEncoding, OutputEncoding: input.OutputEncoding, ContentLength: content, RetainedLength: uint32(len(input.Payload)), Recipients: final.plan.recipients[index], ValueBytes: input.Payload}
		} else {
			imageIndex := slices.IndexFunc(final.preparedImage.Supplied, func(row contract.CryptoPreparedSecret) bool { return row.Slot == plan.Slot && row.Name == plan.Name })
			if imageIndex < 0 {
				return contract.CryptoInvalidAdmission
			}
			image := final.preparedImage.Supplied[imageIndex]
			used++
			entry, err = contract.DecodeValueEntry(image.EntryBytes)
			defer clear(entry.ValueBytes[:cap(entry.ValueBytes)])
			legacy := false
			if old, ok := a.preparedLegacyIdentity(index, input, entry); ok {
				identity, state.identity, legacy = old, old, true
			}
			if err != nil || entry.Name != identity.Name || entry.Incarnation != identity.Incarnation || entry.ValueState != identity.ValueState ||
				entry.OriginSnapshot != identity.OriginSnapshot || entry.OriginTransition != identity.OriginTransition ||
				entry.InputEncoding != plan.InputEncoding || entry.OutputEncoding != plan.OutputEncoding || entry.ValueSource != plan.ValueSource || entry.ConfidentialityClass != contract.Secret || !slices.Equal(entry.Recipients, final.plan.recipients[index]) {
				return contract.CryptoInvalidAdmission
			}
			core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
			access, accessErr := contract.DecodeAccessRecord(image.AccessRecord)
			for _, wrap := range access.Wraps {
				defer clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
			}
			if err != nil || accessErr != nil {
				return contract.CryptoInvalidAdmission
			}
			readers := slices.Clone(entry.Recipients)
			membershipIndex := -1
			if generatedMembershipOnly(plan) {
				membershipIndex = slices.IndexFunc(final.membership, func(row generatedMembershipSelection) bool { return row.Selection.Slot == plan.Slot })
				if membershipIndex < 0 {
					return contract.CryptoInvalidAdmission
				}
				if !a.finalExcludesReader(index) || legacy {
					readers = generatedReaderUnion(readers, final.membership[membershipIndex].retained)
				}
			} else if input.Kind == contract.GeneratorDeclarationRetained {
				at := slices.IndexFunc(final.plan.canonicals, func(row generatedCanonicalSource) bool {
					return row.originalSlot == plan.Slot && row.core.Name == plan.Name
				})
				if at < 0 {
					return contract.CryptoInvalidAdmission
				}
				if !a.finalExcludesReader(index) || legacy {
					readers = generatedReaderUnion(readers, generatedReaderUnion(final.plan.canonicals[at].recipients, final.plan.canonicals[at].retained))
				}
				// Older selected Content images contain exactly the intended
				// current readers. Qualify that complete relation separately;
				// an arbitrary subset of the canonical union is not a preparation.
				count := len(entry.Recipients)
				if a.control.Recovery != nil {
					count++
				}
				if plan.ChangeMask&contract.GeneratorValueChangeContent != 0 && len(readers) > len(entry.Recipients) && len(access.Wraps) == count {
					readers = entry.Recipients
					state.currentOnlyReplay = true
				}
			}
			keys, code := a.openPreparedValue(ctx, route, core, entry, access, readers, out)
			if code != contract.CryptoSuccess {
				return code
			}
			code = a.preparedSuppliedMatchesSource(ctx, route, index, input, entry, keys, membershipIndex, out)
			clear(keys[:cap(keys)])
			if code != contract.CryptoSuccess {
				return code
			}
			state.access = contract.DigestLength{Digest: contract.Hash(image.AccessRecord), Length: uint64(len(image.AccessRecord))}
			if input.Kind == contract.GeneratorDeclarationRetained {
				record, err := contract.DecodeRetainedCanonicalRecord(input.Payload)
				state.canonical = record.Entry.ValueState
				clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
				if err != nil {
					return contract.CryptoInvalidAdmission
				}
			}
		}
		state.entryDigest, err = contract.PublicValueEntryDigest(a.request.Context.DomainID, plan.Slot, entry)
		if err != nil {
			return contract.CryptoInvalidAdmission
		}
		state.prepared = true
		final.supplied = append(final.supplied, state)
	}
	if used != len(final.preparedImage.Supplied) || len(final.supplied) != final.suppliedCount {
		return contract.CryptoInvalidAdmission
	}
	return contract.CryptoSuccess
}

func preparedPreservesSource(before, after contract.ValueEntry) bool {
	return before.Name == after.Name && before.Incarnation == after.Incarnation && before.ValueState == after.ValueState &&
		before.OriginSnapshot == after.OriginSnapshot && before.OriginTransition == after.OriginTransition &&
		before.ValueSource == after.ValueSource && before.ConfidentialityClass == contract.Secret && after.ConfidentialityClass == contract.Secret &&
		before.Generated == after.Generated && bytes.Equal(before.ValueBytes, after.ValueBytes)
}

func (a *generatedAdmission) preparedLegacyIdentity(index int, input contract.GeneratorDeclarationEntryView, entry contract.ValueEntry) (contract.IdentityRow, bool) {
	final, plan := a.purpose.final, a.graph.ValueEntryPlans[index]
	if !final.qualifyingLegacy || !a.finalExcludesReader(index) {
		return contract.IdentityRow{}, false
	}
	var source contract.ValueEntry
	if generatedMembershipOnly(plan) {
		at := slices.IndexFunc(final.membership, func(row generatedMembershipSelection) bool { return row.Selection.Slot == plan.Slot })
		if at < 0 {
			return contract.IdentityRow{}, false
		}
		source = final.membership[at].Selection.Entry
	} else if input.Kind == contract.GeneratorDeclarationRetained {
		at := slices.IndexFunc(final.plan.canonicals, func(row generatedCanonicalSource) bool {
			return row.originalSlot == plan.Slot && row.core.Name == plan.Name
		})
		if at < 0 {
			return contract.IdentityRow{}, false
		}
		record, err := contract.DecodeRetainedCanonicalRecord(final.plan.canonicals[at].buffer)
		defer clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
		if err != nil {
			return contract.IdentityRow{}, false
		}
		source = record.Entry
	} else {
		return contract.IdentityRow{}, false
	}
	if !preparedPreservesSource(source, entry) {
		return contract.IdentityRow{}, false
	}
	return contract.IdentityRow{Name: source.Name, Slot: plan.Slot, Incarnation: source.Incarnation, ValueState: source.ValueState,
		OriginSnapshot: source.OriginSnapshot, OriginTransition: source.OriginTransition}, true
}

func (a *generatedAdmission) preparedSuppliedIdentity(index int, input contract.GeneratorDeclarationEntryView) (contract.IdentityRow, bool) {
	final, plan := a.purpose.final, a.graph.ValueEntryPlans[index]
	if plan.ConfidentialityClass == contract.Secret && a.finalExcludesReader(index) {
		return a.finalFreshIdentity(index)
	}
	var entry contract.ValueEntry
	switch {
	case generatedMembershipOnly(plan):
		at := slices.IndexFunc(final.membership, func(row generatedMembershipSelection) bool { return row.Selection.Slot == plan.Slot })
		if at < 0 {
			return contract.IdentityRow{}, false
		}
		entry = final.membership[at].Selection.Entry
	case plan.ChangeMask&contract.GeneratorValueChangeContent == 0:
		at := slices.IndexFunc(a.before.Rows, func(row contract.PublicStateRow) bool { return row.Slot == plan.Slot && row.Name == plan.Name })
		if at < 0 || a.purpose.output == nil || at >= len(a.purpose.output.EntryBodies) {
			return contract.IdentityRow{}, false
		}
		var err error
		entry, err = contract.DecodeValueEntry(a.purpose.output.EntryBodies[at])
		defer clear(entry.ValueBytes[:cap(entry.ValueBytes)])
		if err != nil || entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, input.Payload) {
			return contract.IdentityRow{}, false
		}
	case input.Kind == contract.GeneratorDeclarationRetained:
		record, err := contract.DecodeRetainedCanonicalRecord(input.Payload)
		defer clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
		if err != nil || record.OriginalSlot != plan.Slot {
			return contract.IdentityRow{}, false
		}
		entry = record.Entry
	default:
		return a.finalFreshIdentity(index)
	}
	return contract.IdentityRow{Name: entry.Name, Slot: plan.Slot, Incarnation: entry.Incarnation, ValueState: entry.ValueState,
		OriginSnapshot: entry.OriginSnapshot, OriginTransition: entry.OriginTransition}, true
}

func (a *generatedAdmission) preparedSuppliedMatchesSource(ctx context.Context, route KeyAccess, index int, input contract.GeneratorDeclarationEntryView,
	entry contract.ValueEntry, keys []byte, membershipIndex int, out *contract.CryptoResponse) contract.CryptoResultCode {
	final := a.purpose.final
	if membershipIndex >= 0 {
		selected := final.membership[membershipIndex].Selection
		original, code := a.openCurrentValue(ctx, route, selected, out)
		if code != contract.CryptoSuccess {
			return code
		}
		defer clear(original[:cap(original)])
		legacy := final.qualifyingLegacy && a.finalExcludesReader(index) && preparedPreservesSource(selected.Entry, entry)
		if a.finalExcludesReader(index) && !legacy {
			return a.preparedExclusionMatchesSource(selected.Entry, selected.Core, original, entry, keys)
		}
		if !bytes.Equal(selected.Entry.ValueBytes, entry.ValueBytes) || selected.Entry.Generated != entry.Generated {
			return contract.CryptoInvalidAdmission
		}
		if subtle.ConstantTimeCompare(keys, original) != 1 {
			return contract.CryptoStoredAuthenticationFailed
		}
		final.legacyExclusion = final.legacyExclusion || legacy
		return contract.CryptoSuccess
	}
	if input.Kind == contract.GeneratorDeclarationRetained {
		at := slices.IndexFunc(final.plan.canonicals, func(row generatedCanonicalSource) bool {
			return row.originalSlot == a.graph.ValueEntryPlans[index].Slot && row.core.Name == entry.Name
		})
		if at < 0 {
			return contract.CryptoInvalidAdmission
		}
		source := &final.plan.canonicals[at]
		record, err := contract.DecodeRetainedCanonicalRecord(source.buffer)
		defer clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
		if err != nil {
			return contract.CryptoInvalidAdmission
		}
		original, code := a.openCanonicalKeys(ctx, route, source, out)
		if code != contract.CryptoSuccess {
			return code
		}
		defer clear(original[:cap(original)])
		legacy := final.qualifyingLegacy && a.finalExcludesReader(index) && preparedPreservesSource(record.Entry, entry)
		if a.finalExcludesReader(index) && !legacy {
			return a.preparedExclusionMatchesSource(record.Entry, source.core, original, entry, keys)
		}
		if !bytes.Equal(record.Entry.ValueBytes, entry.ValueBytes) || record.Entry.Generated != entry.Generated {
			return contract.CryptoInvalidAdmission
		}
		if subtle.ConstantTimeCompare(keys, original) != 1 {
			return contract.CryptoStoredAuthenticationFailed
		}
		final.legacyExclusion = final.legacyExclusion || legacy
		return contract.CryptoSuccess
	}
	if input.Kind != contract.GeneratorDeclarationSealed {
		return contract.CryptoInvalidAdmission
	}
	at := slices.IndexFunc(final.plan.sources, func(row generatedSource) bool { return row.core.Name == entry.Name })
	if at < 0 {
		return contract.CryptoInvalidAdmission
	}
	plain, code := a.openTransferredSource(final.plan.sources[at], input.Payload)
	if code != contract.CryptoSuccess {
		clear(plain[:cap(plain)])
		return code
	}
	defer clear(plain[:cap(plain)])
	core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
	payload, payloadErr := contract.DecodeCanonicalPayload(entry.ValueBytes)
	defer clear(payload.Ciphertext[:cap(payload.Ciphertext)])
	if err != nil || payloadErr != nil {
		return contract.CryptoInvalidAdmission
	}
	equal, err := custody.EqualValue(core, payload, keys, plain)
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	if !equal {
		return contract.CryptoInvalidAdmission
	}
	if a.finalExcludesReader(index) {
		return a.preparedContentExclusionMatches(ctx, route, index, entry, keys, out)
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) checkpointCandidatePhase(c generatedCandidate, snapshot contract.ID) (contract.GeneratorPhaseIdentity, bool) {
	final := a.purpose.final
	var zero contract.GeneratorPhaseIdentity
	if final == nil || final.preparedImage != nil || final.nonselecting || c.ActiveOwner != a.graph.Header.OperationID ||
		c.ActiveGraph != a.graph.UsePlan.PlanGraphID || c.ActivePhase != c.Subject.PhaseID ||
		c.Subject.OwnerID != c.ActiveOwner || c.Subject.Intent != a.request.Parent.Declaration || c.Subject.CapacityReservation != a.request.Parent.Capacity ||
		c.PublicState.AccessRoot != a.before.AccessRoot || !slices.Equal(c.PublicState.Rows, a.before.Rows) ||
		final.entryNext != len(final.entryPreparations) || final.suppliedNext != final.suppliedCount || !final.suppliedFinal {
		return zero, false
	}
	var preparation contract.GeneratedFinalPreparationRecord
	var phase, prior contract.GeneratedPhaseRecord
	var oldPreparation contract.GeneratedFinalPreparationRecord
	for _, row := range c.SupportRecords {
		var err error
		if row.Kind == contract.GeneratedFinalPreparationSupportKind && row.RecordID == c.ActiveOwner {
			preparation, err = contract.InspectGeneratedFinalPreparationRecord(row.Body)
		} else if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == c.ActiveOwner {
			phase, err = contract.InspectGeneratedPhaseRecord(row.Body)
		}
		if err != nil {
			return zero, false
		}
	}
	for _, row := range final.checkpointSupport {
		var err error
		switch row.Kind {
		case contract.GeneratedPhaseSupportKind:
			prior, err = contract.InspectGeneratedPhaseRecord(row.Body)
		case contract.GeneratedFinalPreparationSupportKind:
			oldPreparation, err = contract.InspectGeneratedFinalPreparationRecord(row.Body)
		}
		if err != nil {
			return zero, false
		}
	}
	bindings, err := contract.GeneratedFinalPreparationBindingDigest(a.control, a.bindings)
	if err != nil || preparation.OperationID != c.ActiveOwner || preparation.DomainID != a.request.Context.DomainID ||
		preparation.MaterializationPhase != final.phase || preparation.ControlBindingDigest != bindings ||
		prior.OperationID != c.ActiveOwner || prior.Phase != final.phase.BeforePhase {
		return zero, false
	}
	checkpoint := final.phase
	checkpoint.TransitionKind = contract.GeneratorAuthorityFinalPreparation
	checkpoint.Evidence, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{preparation.Image})
	if err != nil || c.Subject.ResultVector != checkpoint.Evidence {
		return zero, false
	}
	union := make([]contract.UnionRow, len(a.purpose.output.EntriesBefore))
	for i, row := range a.purpose.output.EntriesBefore {
		union[i] = contract.UnionRow{Name: row.Name, BeforePresent: true, AfterPresent: true, Before: row.Side(), After: row.Side()}
	}
	entryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(preparation.DomainID, union)
	if err != nil || entryUnion != c.Subject.ValueEntryUnion {
		return zero, false
	}
	id, err := contract.GeneratorPhaseID(checkpoint)
	if err != nil || id != c.Subject.PhaseID {
		return zero, false
	}
	want := prior
	want.PhaseID, want.Phase, want.FinalPreparationID = id, checkpoint.AfterPhase, preparation.Image.ContentID
	if phase != want {
		return zero, false
	}
	image, err := contract.ReadGeneratedFinalPreparationImage(preparation.DomainID, snapshot, c.SupportRecords, preparation)
	if err != nil {
		return zero, false
	}
	defer image.Clear()
	if !slices.Equal(image.GrantSeals, a.purpose.final.grantSeals) {
		return zero, false
	}
	opened, openErr := a.openCheckpointGrants(&image)
	clear(opened)
	if openErr != nil || !a.checkpointImageMatches(image) || !a.checkpointSupportMatches(c.SupportRecords, preparation, oldPreparation) {
		return zero, false
	}
	return checkpoint, true
}

func (a *generatedAdmission) checkpointImageMatches(image contract.GeneratedFinalPreparationImage) bool {
	final := a.purpose.final
	if image.MaterializationPhaseID != final.materializationPhaseID || len(image.Generated) != len(final.entryPreparations) {
		return false
	}
	for i, row := range image.Generated {
		prepared := final.entryPreparations[i]
		selected := final.results[prepared.result].Reference
		entry, err := contract.PublicValueEntryDigest(image.DomainID, row.Slot, row.Entry)
		access, accessErr := contract.EncodeAccessRecord(row.Access)
		core, coreErr := contract.ValueCoreForEntry(image.DomainID, a.request.Context.CompatibilityID, row.Entry)
		if err != nil || accessErr != nil || coreErr != nil || core != row.ValueCore || !prepared.prepared || row.Slot != prepared.Slot ||
			row.ResultID != selected.ResultID || row.ResultDigest != selected.ResultBodyDigest || row.Entry.Generated != prepared.Generated ||
			entry != prepared.entryDigest || prepared.access != (contract.DigestLength{Digest: contract.Hash(access), Length: uint64(len(access))}) {
			return false
		}
	}
	secrets := 0
	for _, prepared := range final.supplied {
		if prepared.access == (contract.DigestLength{}) {
			continue
		}
		secrets++
		index := slices.IndexFunc(image.Supplied, func(row contract.CryptoPreparedSecret) bool {
			return row.Slot == prepared.identity.Slot && row.Name == prepared.identity.Name
		})
		if index < 0 {
			return false
		}
		row := image.Supplied[index]
		entry, err := contract.DecodeValueEntry(row.EntryBytes)
		defer clear(entry.ValueBytes[:cap(entry.ValueBytes)])
		if err != nil || entry.Name != prepared.identity.Name {
			return false
		}
		digest, err := contract.PublicValueEntryDigest(image.DomainID, row.Slot, entry)
		if err != nil || !prepared.prepared || digest != prepared.entryDigest ||
			prepared.access != (contract.DigestLength{Digest: contract.Hash(row.AccessRecord), Length: uint64(len(row.AccessRecord))}) {
			return false
		}
	}
	return secrets == len(image.Supplied)
}

// Only independently qualified slice carriers and exclusive old image
// fragments may leave the predecessor. Consumer/history vectors remain exact.
func (a *generatedAdmission) checkpointSupportMatches(rows []contract.SupportRecord, preparation, old contract.GeneratedFinalPreparationRecord) bool {
	beforeLocations, beforeSliceFacts, ok := a.checkpointSlices(a.purpose.final.checkpointSupport)
	if !ok {
		return false
	}
	afterLocations, afterSliceFacts, ok := a.checkpointSlices(rows)
	if !ok {
		return false
	}
	var oldBlobs, newBlobs []contract.ID
	beforeKept := slices.DeleteFunc(slices.Clone(beforeLocations), func(row contract.GeneratorSliceLocation) bool {
		if !old.OperationID.IsZero() && row.Logical() == old.Image {
			oldBlobs = append(oldBlobs, row.BlobID)
			return true
		}
		return false
	})
	afterKept := slices.DeleteFunc(slices.Clone(afterLocations), func(row contract.GeneratorSliceLocation) bool {
		if row.Logical() == preparation.Image {
			newBlobs = append(newBlobs, row.BlobID)
			return true
		}
		return false
	})
	if len(newBlobs) != 1 || !old.OperationID.IsZero() && len(oldBlobs) != 1 || !slices.Equal(beforeKept, afterKept) {
		return false
	}
	allowedBefore := make(map[contract.SupportRecordDigest]bool, len(beforeSliceFacts))
	for _, fact := range beforeSliceFacts {
		allowedBefore[fact] = true
	}
	for _, row := range a.purpose.final.checkpointSupport {
		fact, err := contract.InspectSupportRecordDigest(a.request.Context.DomainID, row)
		if err != nil {
			return false
		}
		switch row.Kind {
		case contract.GeneratedPhaseSupportKind, contract.GeneratedFinalPreparationSupportKind:
			allowedBefore[fact] = true
		case contract.GeneratedFragmentSupportKind:
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil || !slices.Contains(oldBlobs, fragment.BlobID) || slices.ContainsFunc(beforeKept, func(location contract.GeneratorSliceLocation) bool { return location.BlobID == fragment.BlobID }) {
				return false
			}
			allowedBefore[fact] = true
		}
	}
	after := make(map[contract.SupportRecordDigest]bool, len(rows))
	allowedAfter := make(map[contract.SupportRecordDigest]bool, len(afterSliceFacts))
	for _, fact := range afterSliceFacts {
		allowedAfter[fact] = true
	}
	for _, row := range rows {
		fact, err := contract.InspectSupportRecordDigest(a.request.Context.DomainID, row)
		if err != nil {
			return false
		}
		after[fact] = true
		if (row.Kind == contract.GeneratedPhaseSupportKind || row.Kind == contract.GeneratedFinalPreparationSupportKind) && row.RecordID == preparation.OperationID {
			allowedAfter[fact] = true
		} else if row.Kind == contract.GeneratedFragmentSupportKind {
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				return false
			}
			if slices.Contains(newBlobs, fragment.BlobID) {
				allowedAfter[fact] = true
			}
		}
	}
	before := make(map[contract.SupportRecordDigest]bool, len(a.purpose.output.Rows.Facts))
	for _, fact := range a.purpose.output.Rows.Facts {
		before[fact] = true
		if !allowedBefore[fact] && !after[fact] {
			return false
		}
	}
	for fact := range after {
		if !allowedAfter[fact] && !before[fact] {
			return false
		}
	}
	return true
}

func (a *generatedAdmission) checkpointSlices(rows []contract.SupportRecord) ([]contract.GeneratorSliceLocation, []contract.SupportRecordDigest, bool) {
	var owner contract.ID
	var descriptor contract.GeneratorDescriptor
	var bodies [][]byte
	var facts []contract.SupportRecordDigest
	for _, row := range rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return nil, nil, false
		}
		if carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.VectorKind != contract.GeneratorVectorSlices {
			continue
		}
		if owner.IsZero() {
			owner, descriptor = carrier.OwnerID, carrier.Vector
			if uint64(descriptor.Count) > uint64(len(rows)) {
				return nil, nil, false
			}
			bodies = make([][]byte, descriptor.Count)
		}
		if carrier.OwnerID != owner || carrier.Vector != descriptor || int(carrier.Ordinal) >= len(bodies) || bodies[carrier.Ordinal] != nil {
			return nil, nil, false
		}
		bodies[carrier.Ordinal] = carrier.Row
		fact, err := contract.InspectSupportRecordDigest(a.request.Context.DomainID, row)
		if err != nil {
			return nil, nil, false
		}
		facts = append(facts, fact)
	}
	if owner.IsZero() {
		return nil, nil, true
	}
	actual, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, bodies)
	if err != nil || actual != descriptor {
		return nil, nil, false
	}
	locations := make([]contract.GeneratorSliceLocation, 0, len(bodies))
	for _, body := range bodies {
		location, err := contract.InspectGeneratorSliceLocation(body)
		if err != nil {
			return nil, nil, false
		}
		locations = append(locations, location)
	}
	return locations, facts, true
}

// Reopening a fresh image proves semantic continuity against its authenticated
// source, while both private keys and every public protection identity change.
func (a *generatedAdmission) preparedExclusionMatchesSource(before contract.ValueEntry, oldCore contract.ValueCore, oldKeys []byte,
	after contract.ValueEntry, keys []byte) contract.CryptoResultCode {
	if code := a.preparedChangedProtectionMatches(before, oldCore, oldKeys, after, keys); code != contract.CryptoSuccess {
		return code
	}
	metadata := before.Generated
	if before.ValueSource == contract.Generated {
		metadata.GenerationID = after.ValueState
	}
	if after.Generated != metadata || before.Incarnation != after.Incarnation || before.ValueSource != after.ValueSource ||
		before.ValueState == after.ValueState || before.OriginSnapshot == after.OriginSnapshot || before.OriginTransition == after.OriginTransition {
		return contract.CryptoInvalidAdmission
	}
	oldPayload, oldErr := contract.InspectCanonicalPayload(before.ValueBytes)
	payload, payloadErr := contract.InspectCanonicalPayload(after.ValueBytes)
	core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, after)
	if oldErr != nil || payloadErr != nil || err != nil {
		return contract.CryptoInvalidAdmission
	}
	plain, err := custody.OpenValue(oldCore, contract.CanonicalPayload(oldPayload), oldKeys)
	if plain != nil {
		defer clear(plain[:cap(plain)])
	}
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	equal, err := custody.EqualValue(core, contract.CanonicalPayload(payload), keys, plain)
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	if !equal {
		return contract.CryptoInvalidAdmission
	}
	return contract.CryptoSuccess
}

// Changed content proves its own source separately; exclusion also requires
// both new keys to differ from both keys available to the removed reader.
func (a *generatedAdmission) preparedChangedProtectionMatches(before contract.ValueEntry, oldCore contract.ValueCore, oldKeys []byte,
	after contract.ValueEntry, keys []byte) contract.CryptoResultCode {
	if len(oldKeys) != 64 || len(keys) != 64 {
		return contract.CryptoInvalidAdmission
	}
	for _, old := range [][]byte{oldKeys[:32], oldKeys[32:]} {
		for _, current := range [][]byte{keys[:32], keys[32:]} {
			if subtle.ConstantTimeCompare(old, current) == 1 {
				return contract.CryptoInvalidAdmission
			}
		}
	}
	if before.ValueState == after.ValueState || before.OriginSnapshot == after.OriginSnapshot || before.OriginTransition == after.OriginTransition {
		return contract.CryptoInvalidAdmission
	}
	oldPayload, oldErr := contract.InspectCanonicalPayload(before.ValueBytes)
	payload, payloadErr := contract.InspectCanonicalPayload(after.ValueBytes)
	core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, after)
	if oldErr != nil || payloadErr != nil || err != nil || bytes.Equal(oldPayload.Ciphertext, payload.Ciphertext) || oldPayload.SemanticCommitment == payload.SemanticCommitment {
		return contract.CryptoInvalidAdmission
	}
	for _, id := range []contract.ID{oldCore.DataKeyID, oldCore.CommitmentKeyID} {
		if core.DataKeyID == id || core.CommitmentKeyID == id {
			return contract.CryptoInvalidAdmission
		}
	}
	plain, err := custody.OpenValue(oldCore, contract.CanonicalPayload(oldPayload), oldKeys)
	clear(plain[:cap(plain)])
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) preparedContentExclusionMatches(ctx context.Context, route KeyAccess, index int, entry contract.ValueEntry,
	keys []byte, out *contract.CryptoResponse) contract.CryptoResultCode {
	plan := a.purpose.final.plan
	at := slices.IndexFunc(plan.currentValues, func(row contract.ConsumerSelection) bool {
		return row.Slot == a.graph.ValueEntryPlans[index].Slot && row.Entry.Name == entry.Name
	})
	if at < 0 {
		return contract.CryptoInvalidAdmission
	}
	selected := plan.currentValues[at]
	original, code := a.openCurrentValue(ctx, route, selected, out)
	if original != nil {
		defer clear(original[:cap(original)])
	}
	if code != contract.CryptoSuccess {
		return code
	}
	return a.preparedChangedProtectionMatches(selected.Entry, selected.Core, original, entry, keys)
}
