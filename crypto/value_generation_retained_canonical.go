package crypto

import (
	"bytes"
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// Core supplies the selected owner and exact original entry. A current entry
// may omit Owner for reservation or unchanged delete metadata. Retained
// consumption needs a live typed consumer, independently of current access.
type generatedCanonicalSelection = contract.GeneratedCanonicalSelection

type generatedCanonicalSource struct {
	offset, length    uint32
	originalSlot      uint16
	body, entryDigest contract.ID
	core              contract.ValueCore
	recipients        []contract.ID
	retained          []contract.ID
	sourceID          contract.ID
	wrap              contract.WrapRow
	access            contract.DigestLength
	selectedAccess    contract.AccessRecord
	buffer            []byte
	opened            bool
}

type generatedWrapIdentity struct {
	subjectKind uint8
	subjectID   contract.ID
	bindingID   contract.ID
	serial      uint64
	digest      contract.ID
}

func generatedBindingIdentity(row contract.BindingTableRow, digest contract.ID) generatedWrapIdentity {
	return generatedWrapIdentity{subjectKind: row.SubjectKind, subjectID: row.SubjectID, bindingID: row.Binding.BindingID,
		serial: row.Binding.BindingSerial, digest: digest}
}

func generatedWrapRowIdentity(row contract.WrapRow) generatedWrapIdentity {
	return generatedWrapIdentity{subjectKind: row.SubjectKind, subjectID: row.SubjectID, bindingID: row.BindingID,
		serial: row.BindingSerial, digest: row.PublicBindingDigest}
}

// This predicate is used only after the complete graph and declaration validate.
// A closed delete carries current values as membership facts, not value inputs.
func generatedCurrentOnlyDeletePlan(graph contract.GeneratorPlanBundle) bool {
	var purpose contract.GeneratorLineagePurpose
	switch graph.Request.OperationKind {
	case contract.OperationCleanOwnedFailureResidue:
		purpose = contract.GeneratorLineageCleanup
	case contract.OperationRetireGeneratedGeneration:
		purpose = contract.GeneratorLineageRetirement
	default:
		return false
	}
	if len(graph.Lineages) != 1 || graph.Header.LineageCount != 0 || graph.Header.TemplateCount != 1 ||
		graph.Lineages[0].Purpose != purpose || graph.Lineages[0].TemplateCount != 1 ||
		graph.Lineages[0].Templates[0].Action != contract.GeneratorActionDelete || len(graph.SourceUses) != 0 {
		return false
	}
	return !slices.ContainsFunc(graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool {
		return plan.ChangeMask != 0
	})
}

func (a *generatedAdmission) admitCanonical(entry contract.GeneratorDeclarationEntryView, payloadOffset uint32, input []generatedCanonicalSelection) (bool, bool) {
	plan := a.purpose.plan()
	if plan == nil {
		return false, false
	}
	record, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
	if err != nil {
		return false, false
	}
	core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, record.Entry)
	if err != nil {
		return false, false
	}
	entryDigest, err := contract.PublicValueEntryDigest(a.request.Context.DomainID, record.OriginalSlot, record.Entry)
	if err != nil {
		return false, false
	}
	source := generatedCanonicalSource{offset: payloadOffset, length: uint32(len(entry.Payload)),
		originalSlot: record.OriginalSlot, body: contract.Hash(entry.Payload), entryDigest: entryDigest, core: core, recipients: slices.Clone(record.Entry.Recipients)}
	current := slices.Contains(a.before.Rows, contract.PublicStateRow{Slot: record.OriginalSlot, Name: record.Entry.Name, EntryDigest: entryDigest})
	currentOnly := generatedCurrentOnlyDeletePlan(a.graph)
	deleteOperation := a.graph.Request.OperationKind == contract.OperationCleanOwnedFailureResidue ||
		a.graph.Request.OperationKind == contract.OperationRetireGeneratedGeneration
	if deleteOperation && !currentOnly {
		return false, false
	}
	if currentOnly {
		if !current || !bytes.Equal(entry.Name, []byte(record.Entry.Name)) || len(entry.RecipientIDs) != len(record.Entry.Recipients)*len(contract.ID{}) {
			return false, false
		}
		for i, recipient := range record.Entry.Recipients {
			if !bytes.Equal(entry.RecipientIDs[i*len(recipient):(i+1)*len(recipient)], recipient[:]) {
				return false, false
			}
		}
	}
	source.sourceID, err = contract.AdmissionEntryDigest(record)
	if err != nil {
		return false, false
	}
	index := -1
	for i, selected := range input {
		id, err := contract.AdmissionEntryDigest(selected.Record)
		if err != nil {
			return false, false
		}
		if id == source.sourceID {
			if index >= 0 {
				return false, false
			}
			index = i
		}
	}
	if index < 0 {
		if a.purpose.reservation != nil || current {
			return false, false
		}
		plan.canonicals = append(plan.canonicals, source)
		return false, true
	}
	selected := input[index]
	s := selected.Selection
	wrapIndex, _, valid := checkConsumerSelection(s, a.control.Provider)
	if !valid || !generatedCanonicalEntryMatches(selected) || s.Core != core || s.EntryDigest != entryDigest ||
		s.DomainID != a.request.Context.DomainID || s.HEADDigest != a.request.Context.PredecessorHEADDigest || s.AccessRoot != a.request.Context.CurrentAccessRoot ||
		s.Binding.SubjectID != a.control.AuthorityRecipientID || !sameGeneratedBinding(s.Binding.Binding, a.control.AuthorityKMSBinding) ||
		!a.accessBindingsValid(s.Access) {
		return false, false
	}
	root, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil || root != s.Root || a.purpose.reservation != nil && s.HEADRevision != a.graph.Request.PredecessorRevisionID {
		return false, false
	}
	condition, err := contract.MatchHeadCondition(s.HEADToken)
	if err != nil {
		return false, false
	}
	digest, err := contract.CryptoConditionDigest(condition)
	if err != nil || digest != a.request.Context.OriginalConditionDigest {
		return false, false
	}
	if selected.Owner.Kind == 0 {
		if a.purpose.reservation == nil && !currentOnly || !current || !selected.Owner.RecordID.IsZero() || len(selected.Owner.Body) != 0 || len(selected.Consumers) != 0 {
			return false, false
		}
	} else if !generatedCanonicalOwnerMatches(selected) {
		return false, false
	}
	if a.control.Recovery != nil && !slices.ContainsFunc(s.Access.Wraps, func(row contract.WrapRow) bool {
		return row.SubjectKind == contract.RecoveryWrapSubject && row.SubjectID == a.control.Recovery.RoleID
	}) {
		return false, false
	}
	body, err := contract.EncodeAccessRecord(s.Access)
	if err != nil {
		return false, false
	}
	source.access = contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}
	if currentOnly {
		plan.canonicals = append(plan.canonicals, source)
		return true, true
	}
	selectedAccess, err := contract.DecodeAccessRecord(body)
	if err != nil {
		return false, false
	}
	retained, ok := a.predecessorRetainedReaders(core, record.Entry.ValueBytes)
	if !ok {
		return false, false
	}
	readers := generatedReaderUnion(record.Entry.Recipients, retained)
	count := len(readers)
	if a.control.Recovery != nil {
		count++
	}
	if len(selectedAccess.Wraps) != count {
		return false, false
	}
	for i, id := range readers {
		if selectedAccess.Wraps[i].SubjectKind != contract.OrdinaryWrapSubject || selectedAccess.Wraps[i].SubjectID != id {
			return false, false
		}
	}
	source.retained = retained
	source.selectedAccess = selectedAccess
	source.wrap = s.Access.Wraps[wrapIndex]
	source.wrap.RSACiphertext = bytes.Clone(source.wrap.RSACiphertext)
	if a.purpose.reservation == nil && a.purpose.producer == nil {
		source.buffer = entry.Payload[:len(entry.Payload):len(entry.Payload)]
	}
	plan.canonicals = append(plan.canonicals, source)
	return true, true
}

func (a *generatedAdmission) candidateCanonicalsMatch(c generatedCandidate) bool {
	plan := a.purpose.plan()
	if plan == nil || len(plan.canonicals) == 0 && (a.purpose.final == nil || len(a.purpose.final.canonicalAccess) == 0) {
		return true
	}
	readers, ok := a.candidateCanonicalReaders(c)
	if !ok || !a.candidateCanonicalAccessMatches(c, readers) {
		return false
	}

	var supplied []generatedSuppliedPreparation
	if a.purpose.final != nil {
		supplied = a.purpose.final.supplied
	}
	for _, source := range plan.canonicals {
		if a.purpose.final != nil {
			_, pinned := slices.BinarySearchFunc(a.purpose.final.canonicalAccess, source.core.ValueStateID, func(pin generatedCanonicalAccessPin, value contract.ID) int {
				return bytes.Compare(pin.access.MaterialID[:], value[:])
			})
			if pinned {
				// The complete predecessor projection above already checked this
				// material, including ended-only reader removal in actual Final.
				continue
			}
		}
		prepared := slices.IndexFunc(supplied, func(row generatedSuppliedPreparation) bool {
			return row.canonical == source.core.ValueStateID && row.identity.ValueState == source.core.ValueStateID
		})
		live := slices.Contains(c.PublicState.Rows, contract.PublicStateRow{Slot: source.originalSlot, Name: source.core.Name, EntryDigest: source.entryDigest}) ||
			c.ActiveOwner == a.graph.Header.OperationID && c.ActiveGraph == a.graph.UsePlan.PlanGraphID
		expectedAccess := source.access
		if prepared >= 0 {
			row := supplied[prepared]
			live = slices.Contains(c.PublicState.Rows, contract.PublicStateRow{Slot: row.identity.Slot, Name: source.core.Name, EntryDigest: row.entryDigest})
			expectedAccess = row.access
		}
		live = live || len(readers[source.core.ValueStateID]) != 0
		index := slices.IndexFunc(c.AccessRecords, func(row contract.AccessRecord) bool {
			return row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == source.core.ValueStateID
		})
		if !live {
			if index >= 0 {
				return false
			}
			continue
		}
		if index < 0 || expectedAccess == (contract.DigestLength{}) {
			return false
		}
		if a.purpose.final != nil && !a.purpose.final.nonselecting && c.Subject.Purpose == contract.GeneratorAuthorityFinal {
			if prepared >= 0 {
				if !a.suppliedFinalAccessMatches(c, supplied[prepared], c.AccessRecords[index]) {
					return false
				}
			} else if !a.finalValueAccessMatches(c, source.originalSlot, source.core.ValueStateID, c.AccessRecords[index], source.selectedAccess, expectedAccess) {
				return false
			}
		} else {
			body, err := contract.EncodeAccessRecord(c.AccessRecords[index])
			if err != nil || uint64(len(body)) != expectedAccess.Length || contract.Hash(body) != expectedAccess.Digest {
				return false
			}
		}
	}
	return true
}

// Resolve each source and owner once, then group required readers by material.
// The complete historical census is independent of the active declaration size.
func (a *generatedAdmission) candidateCanonicalReaders(c generatedCandidate) (map[contract.ID][]contract.ID, bool) {
	plan := a.purpose.plan()
	if plan == nil || a.purpose.output == nil {
		return nil, false
	}
	facts := make(map[contract.SupportRecordDigest]bool, len(a.purpose.output.Rows.Facts))
	for _, fact := range a.purpose.output.Rows.Facts {
		facts[fact] = true
	}
	declared := make(map[contract.ID]contract.ID, len(plan.canonicals))
	for _, source := range plan.canonicals {
		declared[source.sourceID] = source.body
	}
	type sourceMeaning struct {
		core    contract.ValueCore
		payload contract.ID
		readers []contract.ID
	}
	sources := make(map[contract.ID]sourceMeaning)
	materials := make(map[contract.ID]sourceMeaning)
	for _, row := range c.SupportRecords {
		if row.Kind != contract.RetainedCanonicalSupportKind {
			continue
		}
		fact, err := contract.InspectSupportRecordDigest(c.Subject.DomainID, row)
		if err != nil || !facts[fact] && declared[row.RecordID] != contract.Hash(row.Body) {
			return nil, false
		}
		record, err := contract.DecodeRetainedCanonicalRecord(row.Body)
		if err != nil {
			return nil, false
		}
		core, err := contract.ValueCoreForEntry(c.Subject.DomainID, a.request.Context.CompatibilityID, record.Entry)
		payload := contract.Hash(record.Entry.ValueBytes)
		clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
		if _, duplicate := sources[row.RecordID]; err != nil || duplicate {
			return nil, false
		}
		if prior, present := materials[core.ValueStateID]; present && (prior.core != core || prior.payload != payload) {
			return nil, false
		}
		source := sourceMeaning{core: core, payload: payload, readers: record.Entry.Recipients}
		sources[row.RecordID], materials[core.ValueStateID] = source, source
	}
	if !slices.ContainsFunc(c.SupportRecords, func(row contract.SupportRecord) bool {
		return row.Kind == contract.GeneratedDutySupportKind || row.Kind == contract.GeneratedHazardSupportKind
	}) {
		return nil, len(sources) == 0
	}
	carriers, ok := generatedCandidateCarrierIndex(c.SupportRecords)
	if !ok {
		return nil, false
	}
	used := make(map[contract.ID]bool)
	for _, owner := range c.SupportRecords {
		if owner.Kind != contract.GeneratedDutySupportKind && owner.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		rows, ok := generatedCandidateConsumers(carriers, len(c.SupportRecords), owner, c.Subject.DomainID)
		if !ok {
			return nil, false
		}
		ownerSources := make(map[contract.ID]contract.ID)
		for _, row := range rows {
			if row.SubjectKind != contract.GeneratorConsumerRetainedCanonicalValue {
				continue
			}
			source, present := sources[row.SubjectID]
			context, err := contract.ValueMaterialContextDigest(source.core)
			prior := ownerSources[row.MaterialID]
			if !present || err != nil || row.MaterialID != source.core.ValueStateID || row.ContextDigest != context || row.Purpose != contract.GeneratorConsumerUseRetainedCanonical ||
				!prior.IsZero() && prior != row.SubjectID {
				return nil, false
			}
			ownerSources[row.MaterialID] = row.SubjectID
			used[row.SubjectID] = true
		}
	}
	if len(used) != len(sources) {
		return nil, false
	}
	readers := make(map[contract.ID][]contract.ID)
	for _, source := range sources {
		readers[source.core.ValueStateID] = generatedReaderUnion(readers[source.core.ValueStateID], source.readers)
	}
	return readers, true
}

type generatedCarrierKey struct {
	ownerKind  uint8
	ownerID    contract.ID
	vectorKind contract.GeneratorVectorKind
}

type generatedCandidateCarrier struct {
	recordID contract.ID
	carrier  contract.GeneratorVectorCarrier
}

func generatedCandidateCarrierIndex(support []contract.SupportRecord) (map[generatedCarrierKey][]generatedCandidateCarrier, bool) {
	index := make(map[generatedCarrierKey][]generatedCandidateCarrier)
	for _, row := range support {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return nil, false
		}
		key := generatedCarrierKey{carrier.OwnerKind, carrier.OwnerID, carrier.VectorKind}
		index[key] = append(index[key], generatedCandidateCarrier{row.RecordID, carrier})
	}
	return index, true
}

func generatedCandidateConsumers(carriers map[generatedCarrierKey][]generatedCandidateCarrier, supportCount int, owner contract.SupportRecord, domain contract.ID) ([]contract.GeneratorConsumer, bool) {
	var descriptor contract.GeneratorDescriptor
	switch owner.Kind {
	case contract.GeneratedDutySupportKind:
		row, err := contract.InspectGeneratedDutyRecord(owner.Body)
		if err != nil || row.DomainID != domain || row.DutyID != owner.RecordID {
			return nil, false
		}
		descriptor = row.Consumers
	case contract.GeneratedHazardSupportKind:
		row, err := contract.InspectGeneratedHazardRecord(owner.Body)
		if err != nil || row.DomainID != domain || row.HazardID != owner.RecordID {
			return nil, false
		}
		descriptor = row.Consumers
	default:
		return nil, false
	}
	if !contract.GeneratorVectorShapeValid(contract.GeneratorVectorConsumers, descriptor) || uint64(descriptor.Count) > uint64(supportCount) {
		return nil, false
	}
	bodies := make([][]byte, descriptor.Count)
	consumers := make([]contract.GeneratorConsumer, descriptor.Count)
	key := generatedCarrierKey{owner.Kind, owner.RecordID, contract.GeneratorVectorConsumers}
	for _, row := range carriers[key] {
		carrier := row.carrier
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil || id != row.recordID || carrier.DomainID != domain || carrier.Vector != descriptor || int(carrier.Ordinal) >= len(bodies) || bodies[carrier.Ordinal] != nil {
			return nil, false
		}
		consumer, err := contract.InspectGeneratorConsumer(carrier.Row)
		if err != nil || consumer.OwnerID != owner.RecordID {
			return nil, false
		}
		bodies[carrier.Ordinal], consumers[carrier.Ordinal] = carrier.Row, consumer
	}
	actual, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, bodies)
	return consumers, err == nil && actual == descriptor
}

func (a *generatedAdmission) openCanonicalKeys(ctx context.Context, route KeyAccess, source *generatedCanonicalSource, out *contract.CryptoResponse) ([]byte, contract.CryptoResultCode) {
	if generatedCurrentOnlyDeletePlan(a.graph) || source.opened || contract.Hash(source.buffer) != source.body {
		return nil, contract.CryptoInvalidAdmission
	}
	record, err := contract.DecodeRetainedCanonicalRecord(source.buffer)
	defer clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
	if err != nil || record.OriginalSlot != source.originalSlot {
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, record.Entry)
	if err != nil || core != source.core {
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	payload, err := contract.InspectCanonicalPayload(record.Entry.ValueBytes)
	if err != nil {
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	binding := a.bindings[applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)]
	wrap, err := custody.ValueWrapCore(core, binding)
	if err != nil {
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	keys, code := openMaterialPacket(ctx, route, binding, wrap, source.wrap, contract.CryptoStoredAuthenticationFailed, out)
	if code != contract.CryptoSuccess {
		return nil, code
	}
	plain, err := custody.OpenValue(core, contract.CanonicalPayload(payload), keys)
	clear(plain[:cap(plain)])
	if err != nil {
		clear(keys[:cap(keys)])
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	source.opened = true
	return keys, contract.CryptoSuccess
}

func (a *generatedAdmission) openCanonical(ctx context.Context, route KeyAccess, source *generatedCanonicalSource, out *contract.CryptoResponse) contract.CryptoResultCode {
	keys, code := a.openCanonicalKeys(ctx, route, source, out)
	if keys != nil {
		clear(keys[:cap(keys)])
	}
	return code
}

func (r *Runtime) admitGeneratedConsumer(id, purpose, sinkID, routeID contract.ID, selected generatedCanonicalSelection, sink consumerSink, deadline time.Time) error {
	if r == nil || id.IsZero() || purpose.IsZero() || sinkID.IsZero() || routeID.IsZero() || sink == nil || !validDeadline(deadline) || sink.Identity() != sinkID {
		return ErrAdmission
	}
	index, packet, ok := checkConsumerSelection(selected.Selection, r.family)
	if !ok || !generatedCanonicalEntryMatches(selected) || !generatedCanonicalOwnerMatches(selected) {
		return ErrAdmission
	}
	return r.admitCheckedConsumer(id, purpose, sinkID, routeID, selected.Selection, index, packet, sink, deadline)
}

func generatedCanonicalEntryMatches(v generatedCanonicalSelection) bool {
	if v.Record.OriginalSlot != v.Selection.Slot {
		return false
	}
	if _, err := contract.RetainedCanonicalRecordLength(v.Record); err != nil {
		return false
	}
	original, err := contract.EncodeValueEntry(v.Record.Entry)
	if err != nil {
		return false
	}
	selected, err := contract.EncodeValueEntry(v.Selection.Entry)
	return err == nil && bytes.Equal(original, selected)
}

type generatedCanonicalOwnerFacts struct {
	domain, owner contract.ID
}

func inspectGeneratedCanonicalOwner(v generatedCanonicalSelection) (generatedCanonicalOwnerFacts, bool) {
	var domain, owner contract.ID
	var expected contract.GeneratorDescriptor
	switch v.Owner.Kind {
	case contract.GeneratedDutySupportKind:
		row, err := contract.InspectGeneratedDutyRecord(v.Owner.Body)
		if err != nil {
			return generatedCanonicalOwnerFacts{}, false
		}
		domain, owner, expected = row.DomainID, row.DutyID, row.Consumers
	case contract.GeneratedHazardSupportKind:
		row, err := contract.InspectGeneratedHazardRecord(v.Owner.Body)
		if err != nil {
			return generatedCanonicalOwnerFacts{}, false
		}
		domain, owner, expected = row.DomainID, row.HazardID, row.Consumers
	default:
		return generatedCanonicalOwnerFacts{}, false
	}
	actual, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, v.Consumers)
	if err != nil || actual != expected || owner != v.Owner.RecordID {
		return generatedCanonicalOwnerFacts{}, false
	}
	for _, body := range v.Consumers {
		row, err := contract.InspectGeneratorConsumer(body)
		if err != nil || row.OwnerID != owner {
			return generatedCanonicalOwnerFacts{}, false
		}
	}
	return generatedCanonicalOwnerFacts{domain: domain, owner: owner}, true
}

func (facts generatedCanonicalOwnerFacts) matches(v generatedCanonicalSelection) bool {
	s := v.Selection
	if facts.domain != s.DomainID {
		return false
	}
	context, err := contract.ValueMaterialContextDigest(s.Core)
	if err != nil {
		return false
	}
	sourceID, err := contract.AdmissionEntryDigest(v.Record)
	if err != nil {
		return false
	}
	found := false
	for _, body := range v.Consumers {
		row, err := contract.InspectGeneratorConsumer(body)
		if err != nil || row.OwnerID != facts.owner {
			return false
		}
		if row.SubjectKind != contract.GeneratorConsumerRetainedCanonicalValue || row.SubjectID != sourceID && row.SubjectID != s.Core.ValueStateID {
			continue
		}
		if row.Purpose != contract.GeneratorConsumerUseRetainedCanonical || row.MaterialID != s.Core.ValueStateID || row.ContextDigest != context {
			return false
		}
		found = true
	}
	return found
}

func generatedCanonicalOwnerMatches(v generatedCanonicalSelection) bool {
	// Reinspect every occurrence's actual owner and vector bytes. The input is
	// borrowed only for this synchronous call; no row or header is retained.
	facts, ok := inspectGeneratedCanonicalOwner(v)
	return ok && facts.matches(v)
}
