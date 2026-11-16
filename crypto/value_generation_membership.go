package crypto

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// The private parent authenticates current material and any retained canonical
// row. A public selection alone cannot install these facts or grant a reader.
type generatedMembershipSelection struct {
	Selection contract.ConsumerSelection
	retained  []contract.ID
}

func generatedMembershipOnly(plan contract.GeneratorValueEntryPlan) bool {
	return plan.ConfidentialityClass == contract.Secret && plan.ChangeMask&contract.GeneratorValueChangeMembership != 0 && plan.ChangeMask&contract.GeneratorValueChangeContent == 0
}

func (a *generatedAdmission) admitMembership(input []generatedMembershipSelection, intents []contract.GeneratedCurrentIntentSelection) bool {
	final := a.purpose.final
	if final == nil || len(input) > contract.CryptoMaxValueEntries {
		return false
	}
	required := 0
	if !final.nonselecting {
		for _, plan := range a.graph.ValueEntryPlans {
			if generatedMembershipOnly(plan) {
				required++
			}
		}
	}
	if len(input) != required {
		return false
	}
	for i, row := range input {
		s := row.Selection
		if i > 0 && input[i-1].Selection.Slot >= s.Slot {
			return false
		}
		planIndex := slices.IndexFunc(a.graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool { return plan.Slot == s.Slot })
		beforeIndex := slices.IndexFunc(a.before.Rows, func(row contract.PublicStateRow) bool { return row.Slot == s.Slot })
		if planIndex < 0 || beforeIndex < 0 || !generatedMembershipOnly(a.graph.ValueEntryPlans[planIndex]) || a.purpose.output == nil || beforeIndex >= len(a.purpose.output.EntryBodies) {
			return false
		}
		plan := a.graph.ValueEntryPlans[planIndex]
		if _, _, ok := checkConsumerSelection(s, a.control.Provider); !ok {
			return false
		}
		c := a.request.Context
		root, err := contract.DecodeRef(c.PredecessorRootRef[:], contract.CanonicalSchema)
		if err != nil || s.Root != root || s.DomainID != c.DomainID || s.HEADDigest != c.PredecessorHEADDigest || s.AccessRoot != c.CurrentAccessRoot ||
			s.Binding.SubjectID != a.control.AuthorityRecipientID || !sameGeneratedBinding(s.Binding.Binding, a.control.AuthorityKMSBinding) || !a.accessBindingsValid(s.Access) {
			return false
		}
		condition, err := contract.MatchHeadCondition(s.HEADToken)
		if err != nil {
			return false
		}
		digest, err := contract.CryptoConditionDigest(condition)
		if err != nil || digest != c.OriginalConditionDigest || a.before.Rows[beforeIndex] != (contract.PublicStateRow{Slot: s.Slot, Name: s.Entry.Name, EntryDigest: s.EntryDigest}) ||
			s.Entry.InputEncoding != plan.InputEncoding || s.Entry.Name != plan.Name || s.Entry.Incarnation != plan.EntryIncarnationID || s.Entry.ValueSource != plan.ValueSource {
			return false
		}
		// The owned output transition is the sole retained current payload image.
		view, err := contract.InspectValueEntry(a.purpose.output.EntryBodies[beforeIndex])
		if err != nil {
			return false
		}
		entry := contract.ValueEntry{Name: string(view.Name), Incarnation: view.Incarnation, ValueState: view.ValueState,
			OriginSnapshot: view.OriginSnapshot, OriginTransition: view.OriginTransition, ValueSource: view.ValueSource,
			ConfidentialityClass: view.ConfidentialityClass, InputEncoding: view.InputEncoding, OutputEncoding: view.OutputEncoding, ContentLength: view.ContentLength, RetainedLength: view.RetainedLength, Generated: view.Generated, ValueBytes: view.ValueBytes}
		for j := 0; j < view.RecipientCount(); j++ {
			id, ok := view.RecipientID(j)
			if !ok {
				return false
			}
			entry.Recipients = append(entry.Recipients, id)
		}
		if plan.ValueSource == contract.Generated {
			intentIndex := slices.IndexFunc(intents, func(row contract.GeneratedCurrentIntentSelection) bool { return row.Row.Slot == s.Slot })
			if intentIndex < 0 {
				return false
			}
			intent := intents[intentIndex]
			if intent.Root != s.Root || intent.HEADRevision != s.HEADRevision || intent.HEADToken != s.HEADToken || intent.Generated != entry.Generated || intent.Incarnation != entry.Incarnation {
				return false
			}
		}
		payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
		if err != nil {
			return false
		}
		s.Entry, s.Payload = entry, contract.CanonicalPayload(payload)
		s.Binding = a.bindings[applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)]
		retained, ok := a.predecessorRetainedReaders(s.Core, s.Entry.ValueBytes)
		if !ok {
			return false
		}
		readers := generatedReaderUnion(entry.Recipients, retained)
		expectedWraps := len(readers)
		if a.control.Recovery != nil {
			expectedWraps++
		}
		if len(s.Access.Wraps) != expectedWraps {
			return false
		}
		for j, id := range readers {
			if s.Access.Wraps[j].SubjectKind != contract.OrdinaryWrapSubject || s.Access.Wraps[j].SubjectID != id {
				return false
			}
		}
		if a.control.Recovery != nil {
			w := s.Access.Wraps[len(readers)]
			if w.SubjectKind != contract.RecoveryWrapSubject || w.SubjectID != a.control.Recovery.RoleID {
				return false
			}
		}
		s.Access.Wraps = slices.Clone(s.Access.Wraps)
		for j := range s.Access.Wraps {
			s.Access.Wraps[j].RSACiphertext = bytes.Clone(s.Access.Wraps[j].RSACiphertext)
		}
		final.membership = append(final.membership, generatedMembershipSelection{Selection: s, retained: retained})
	}
	return true
}

func (a *generatedAdmission) prepareMembership(ctx context.Context, route KeyAccess, planIndex int, out *contract.CryptoResponse) (contract.ValueEntry, []byte, contract.CryptoResultCode) {
	final := a.purpose.final
	plan := a.graph.ValueEntryPlans[planIndex]
	index := slices.IndexFunc(final.membership, func(row generatedMembershipSelection) bool { return row.Selection.Slot == plan.Slot })
	if index < 0 || !generatedMembershipOnly(plan) {
		return contract.ValueEntry{}, nil, contract.CryptoInvalidAdmission
	}
	selected := final.membership[index]
	s := selected.Selection
	authority := a.bindings[applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)]
	wrapCore, err := custody.ValueWrapCore(s.Core, authority)
	if err != nil {
		return contract.ValueEntry{}, nil, contract.CryptoInvalidAdmission
	}
	wrapIndex := slices.IndexFunc(s.Access.Wraps, func(w contract.WrapRow) bool {
		return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == a.control.AuthorityRecipientID
	})
	if wrapIndex < 0 {
		return contract.ValueEntry{}, nil, contract.CryptoInvalidAdmission
	}
	keys, code := openMaterialPacket(ctx, route, authority, wrapCore, s.Access.Wraps[wrapIndex], contract.CryptoStoredAuthenticationFailed, out)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		return contract.ValueEntry{}, nil, code
	}
	plain, err := custody.OpenValue(s.Core, s.Payload, keys)
	if plain != nil {
		defer clear(plain[:cap(plain)])
	}
	if err != nil {
		return contract.ValueEntry{}, nil, contract.CryptoStoredAuthenticationFailed
	}
	if a.finalExcludesReader(planIndex) {
		identity, ok := a.finalFreshIdentity(planIndex)
		if !ok {
			return contract.ValueEntry{}, nil, contract.CryptoInvalidAdmission
		}
		entry, access, code := a.sealFinalValue(ctx, identity, s.Entry.ValueSource, s.Entry.InputEncoding, a.graph.ValueEntryPlans[planIndex].OutputEncoding, s.Entry.Generated, final.plan.recipients[planIndex], plain, out)
		if code != contract.CryptoSuccess {
			return contract.ValueEntry{}, nil, code
		}
		body, err := contract.EncodeAccessRecord(access)
		if err != nil {
			return contract.ValueEntry{}, nil, contract.CryptoCustodyUnavailable
		}
		return entry, body, contract.CryptoSuccess
	}
	entry := s.Entry
	entry.OutputEncoding = plan.OutputEncoding
	entry.Recipients = slices.Clone(final.plan.recipients[planIndex])
	readers := generatedReaderUnion(entry.Recipients, selected.retained)
	access := s.Access
	access.Wraps = nil
	for bindingIndex, binding := range a.bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(readers, binding.SubjectID) {
			continue
		}
		if ctx.Err() != nil {
			return contract.ValueEntry{}, nil, contract.CryptoCancelled
		}
		identity := generatedBindingIdentity(binding, a.bindingDigests[bindingIndex])
		old := slices.IndexFunc(s.Access.Wraps, func(w contract.WrapRow) bool { return generatedWrapRowIdentity(w) == identity })
		if old >= 0 {
			access.Wraps = append(access.Wraps, s.Access.Wraps[old])
			continue
		}
		core, err := custody.ValueWrapCore(s.Core, binding)
		if err != nil {
			return contract.ValueEntry{}, nil, contract.CryptoCustodyUnavailable
		}
		wrap, err := custody.Wrap(core, binding.Binding, keys)
		uses := KeyUses{Completed: 1}
		if err != nil {
			uses = KeyUses{Failed: 1}
		}
		if !appendKeyUses(out, binding, contract.KeyUseMaterialWrap, uses, 1) {
			return contract.ValueEntry{}, nil, contract.CryptoResponseUnknown
		}
		if err != nil {
			return contract.ValueEntry{}, nil, contract.CryptoCustodyUnavailable
		}
		access.Wraps = append(access.Wraps, wrap)
	}
	body, err := contract.EncodeAccessRecord(access)
	if err != nil {
		return contract.ValueEntry{}, nil, contract.CryptoCustodyUnavailable
	}
	return entry, body, contract.CryptoSuccess
}

// Both sets come from the private admission: intended current membership and
// the authenticated predecessor canonical entry, rather than a change mask.
func generatedReaderUnion(current, retained []contract.ID) []contract.ID {
	readers := append(slices.Clone(current), retained...)
	slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(readers)
}

// Each inspection owns this census. No meaning survives the candidate check.
type generatedFinalRetainedCensus struct {
	callerDone   <-chan struct{}
	built, valid bool
	materials    map[contract.ID]generatedFinalRetainedMaterial
}

type generatedFinalRetainedMaterial struct {
	readers []contract.ID
	invalid bool
}

func (a *generatedAdmission) finalRetainedCensusCancelled(census *generatedFinalRetainedCensus) bool {
	return a.session != nil && sessionCancellationObserved(census.callerDone, a.session) != contract.CryptoSuccess
}

// A surviving canonical entry must be an unchanged authenticated predecessor
// row with a real selected consumer. A candidate cannot invent reader authority.
func (a *generatedAdmission) finalRetainedReaders(c generatedCandidate, value contract.ID) ([]contract.ID, bool) {
	census := c.retainedCensus
	if census == nil {
		census = &generatedFinalRetainedCensus{}
	}
	if !census.built {
		census.built = true
		census.materials, census.valid = a.buildFinalRetainedCensus(c, census)
	}
	if !census.valid || a.finalRetainedCensusCancelled(census) {
		return nil, false
	}
	material := census.materials[value]
	if material.invalid {
		return nil, false
	}
	return material.readers, true
}

func (a *generatedAdmission) buildFinalRetainedCensus(c generatedCandidate, census *generatedFinalRetainedCensus) (map[contract.ID]generatedFinalRetainedMaterial, bool) {
	type sourceMeaning struct {
		context contract.ID
		readers []contract.ID
		used    bool
	}
	type materialMeaning struct {
		sources map[contract.ID]*sourceMeaning
		invalid bool
	}
	materials := make(map[contract.ID]*materialMeaning)
	for _, row := range c.SupportRecords {
		if a.finalRetainedCensusCancelled(census) {
			return nil, false
		}
		if row.Kind != contract.RetainedCanonicalSupportKind {
			continue
		}
		record, err := contract.DecodeRetainedCanonicalRecord(row.Body)
		if err != nil {
			return nil, false
		}
		value := record.Entry.ValueState
		material := materials[value]
		if material == nil {
			material = &materialMeaning{sources: make(map[contract.ID]*sourceMeaning)}
			materials[value] = material
		}
		// Only a query for this material requires predecessor authority. Other
		// well-formed candidate sources can be admitted by the declaration.
		if a.purpose.output == nil {
			material.invalid = true
			continue
		}
		fact, err := contract.InspectSupportRecordDigest(c.Subject.DomainID, row)
		if err != nil || !slices.Contains(a.purpose.output.Rows.Facts, fact) {
			material.invalid = true
			continue
		}
		if _, duplicate := material.sources[row.RecordID]; duplicate {
			material.invalid = true
			continue
		}
		core, err := contract.ValueCoreForEntry(c.Subject.DomainID, a.request.Context.CompatibilityID, record.Entry)
		if err != nil {
			material.invalid = true
			continue
		}
		context, err := contract.ValueMaterialContextDigest(core)
		if err != nil {
			material.invalid = true
			continue
		}
		material.sources[row.RecordID] = &sourceMeaning{context: context, readers: record.Entry.Recipients}
	}
	if a.finalRetainedCensusCancelled(census) {
		return nil, false
	}
	carriers, ok := generatedCandidateCarrierIndex(c.SupportRecords)
	if !ok {
		return nil, false
	}
	for _, owner := range c.SupportRecords {
		if a.finalRetainedCensusCancelled(census) {
			return nil, false
		}
		if owner.Kind != contract.GeneratedDutySupportKind && owner.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		consumers, ok := generatedCandidateConsumers(carriers, len(c.SupportRecords), owner, c.Subject.DomainID)
		if !ok {
			return nil, false
		}
		ownerSources := make(map[contract.ID]contract.ID)
		for _, consumer := range consumers {
			if a.finalRetainedCensusCancelled(census) {
				return nil, false
			}
			if consumer.SubjectKind != contract.GeneratorConsumerRetainedCanonicalValue {
				continue
			}
			material := materials[consumer.MaterialID]
			if material == nil {
				material = &materialMeaning{sources: make(map[contract.ID]*sourceMeaning)}
				materials[consumer.MaterialID] = material
			}
			source, present := material.sources[consumer.SubjectID]
			prior := ownerSources[consumer.MaterialID]
			if !present || consumer.Purpose != contract.GeneratorConsumerUseRetainedCanonical ||
				consumer.ContextDigest != source.context || !prior.IsZero() && prior != consumer.SubjectID {
				material.invalid = true
				continue
			}
			ownerSources[consumer.MaterialID] = consumer.SubjectID
			source.used = true
		}
	}
	result := make(map[contract.ID]generatedFinalRetainedMaterial, len(materials))
	for value, material := range materials {
		if a.finalRetainedCensusCancelled(census) {
			return nil, false
		}
		var readers []contract.ID
		for _, source := range material.sources {
			if a.finalRetainedCensusCancelled(census) {
				return nil, false
			}
			if !source.used {
				material.invalid = true
			}
			readers = generatedReaderUnion(readers, source.readers)
		}
		result[value] = generatedFinalRetainedMaterial{readers: readers, invalid: material.invalid}
	}
	if a.finalRetainedCensusCancelled(census) {
		return nil, false
	}
	return result, true
}

// Final may remove only wraps whose canonical obligation ended. Reconstruct
// the exact preparation image with authenticated predecessor wraps, then check
// its digest. Required and newly prepared ciphertext remains byte-for-byte.
func (a *generatedAdmission) finalValueAccessMatches(c generatedCandidate, slot uint16, value contract.ID,
	access, original contract.AccessRecord, prepared contract.DigestLength) bool {
	final := a.purpose.final
	if final == nil || final.nonselecting || c.Subject.Purpose != contract.GeneratorAuthorityFinal {
		return false
	}
	retained, ok := a.finalRetainedReaders(c, value)
	if !ok {
		return false
	}
	var current []contract.ID
	index := slices.IndexFunc(a.graph.ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool { return row.Slot == slot })
	if index >= 0 && slices.ContainsFunc(c.PublicState.Rows, func(row contract.PublicStateRow) bool {
		return row.Slot == slot && row.Name == a.graph.ValueEntryPlans[index].Name
	}) {
		replaced := slices.ContainsFunc(final.supplied, func(row generatedSuppliedPreparation) bool {
			return row.plan == index && row.identity.ValueState != value
		}) || slices.ContainsFunc(final.entryPreparations, func(row generatedEntryPreparation) bool {
			return row.plan == index && row.Generated.GenerationID != value
		})
		if !replaced {
			current = final.plan.recipients[index]
		}
	}
	return a.finalValueAccessProjectionMatches(generatedReaderUnion(current, retained), access, original, prepared)
}

func (a *generatedAdmission) finalValueAccessProjectionMatches(readers []contract.ID, access, original contract.AccessRecord,
	prepared contract.DigestLength) bool {
	count := len(readers)
	if a.control.Recovery != nil {
		count++
	}
	if len(readers) == 0 || len(access.Wraps) != count {
		return false
	}
	for i, id := range readers {
		if access.Wraps[i].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[i].SubjectID != id {
			return false
		}
	}
	if a.control.Recovery != nil {
		wrap := access.Wraps[len(readers)]
		if wrap.SubjectKind != contract.RecoveryWrapSubject || wrap.SubjectID != a.control.Recovery.RoleID {
			return false
		}
	}
	reconstructed := access
	reconstructed.Wraps = slices.Clone(access.Wraps)
	for _, wrap := range original.Wraps {
		if wrap.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(readers, wrap.SubjectID) {
			reconstructed.Wraps = append(reconstructed.Wraps, wrap)
		}
	}
	slices.SortFunc(reconstructed.Wraps, func(a, b contract.WrapRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
	})
	body, err := contract.EncodeAccessRecord(reconstructed)
	return err == nil && prepared == (contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))})
}

func (a *generatedAdmission) suppliedFinalAccessMatches(c generatedCandidate, prepared generatedSuppliedPreparation, access contract.AccessRecord) bool {
	plan := a.graph.ValueEntryPlans[prepared.plan]
	if a.finalExcludesReader(prepared.plan) {
		body, err := contract.EncodeAccessRecord(access)
		return err == nil && prepared.access == (contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))})
	}
	var original contract.AccessRecord
	var preparationReaders []contract.ID
	switch {
	case generatedMembershipOnly(plan):
		index := slices.IndexFunc(a.purpose.final.membership, func(row generatedMembershipSelection) bool {
			return row.Selection.Slot == plan.Slot
		})
		if index < 0 {
			return false
		}
		original = a.purpose.final.membership[index].Selection.Access
		preparationReaders = generatedReaderUnion(a.purpose.final.plan.recipients[prepared.plan], a.purpose.final.membership[index].retained)
	case !prepared.canonical.IsZero():
		index := slices.IndexFunc(a.purpose.final.plan.canonicals, func(row generatedCanonicalSource) bool {
			return row.originalSlot == plan.Slot && row.core.ValueStateID == prepared.canonical
		})
		if index < 0 {
			return false
		}
		original = a.purpose.final.plan.canonicals[index].selectedAccess
		preparationReaders = generatedReaderUnion(a.purpose.final.plan.recipients[prepared.plan], generatedReaderUnion(a.purpose.final.plan.canonicals[index].recipients, a.purpose.final.plan.canonicals[index].retained))
	default:
		body, err := contract.EncodeAccessRecord(access)
		return err == nil && prepared.access == (contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))})
	}
	if prepared.currentOnlyReplay {
		return a.retainedReplayFinalAccessMatches(c, prepared, access, original)
	}
	// A former current-only reader can already be absent from preparation.
	// It must not be added back when reconstructing that immutable image.
	original.Wraps = slices.DeleteFunc(slices.Clone(original.Wraps), func(w contract.WrapRow) bool {
		return w.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(preparationReaders, w.SubjectID)
	})
	return a.finalValueAccessMatches(c, plan.Slot, prepared.identity.ValueState, access, original, prepared.access)
}

// The saved current-only image stays immutable. Its successor must preserve
// every saved wrap and borrow only exact authenticated wraps for surviving work.
func (a *generatedAdmission) retainedReplayFinalAccessMatches(c generatedCandidate, prepared generatedSuppliedPreparation,
	access, original contract.AccessRecord) bool {
	final := a.purpose.final
	if final == nil || final.nonselecting || final.preparedImage == nil || c.Subject.Purpose != contract.GeneratorAuthorityFinal {
		return false
	}
	plan := a.graph.ValueEntryPlans[prepared.plan]
	index := slices.IndexFunc(final.preparedImage.Supplied, func(row contract.CryptoPreparedSecret) bool {
		return row.Slot == plan.Slot && row.Name == plan.Name
	})
	if index < 0 {
		return false
	}
	body := final.preparedImage.Supplied[index].AccessRecord
	if prepared.access != (contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}) {
		return false
	}
	expected, err := contract.DecodeAccessRecord(body)
	if err != nil || expected.MaterialKind != original.MaterialKind || expected.MaterialID != original.MaterialID ||
		expected.MaterialContextDigest != original.MaterialContextDigest || expected.PackageCheck != original.PackageCheck {
		return false
	}
	retained, ok := a.finalRetainedReaders(c, prepared.identity.ValueState)
	if !ok {
		return false
	}
	current := final.plan.recipients[prepared.plan]
	for _, wrap := range original.Wraps {
		if wrap.SubjectKind == contract.OrdinaryWrapSubject && slices.Contains(retained, wrap.SubjectID) && !slices.Contains(current, wrap.SubjectID) {
			expected.Wraps = append(expected.Wraps, wrap)
		}
	}
	readers := generatedReaderUnion(current, retained)
	count := len(readers)
	if a.control.Recovery != nil {
		count++
	}
	if len(expected.Wraps) != count {
		return false
	}
	slices.SortFunc(expected.Wraps, func(a, b contract.WrapRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
	})
	for i, id := range readers {
		if expected.Wraps[i].SubjectKind != contract.OrdinaryWrapSubject || expected.Wraps[i].SubjectID != id {
			return false
		}
	}
	want, err := contract.EncodeAccessRecord(expected)
	got, gotErr := contract.EncodeAccessRecord(access)
	return err == nil && gotErr == nil && bytes.Equal(got, want)
}

func (a *generatedAdmission) predecessorRetainedReaders(core contract.ValueCore, payload []byte) ([]contract.ID, bool) {
	if !a.purpose.output.RetainedCanonicalsValid() {
		return nil, false
	}
	var readers []contract.ID
	for _, row := range a.purpose.output.Retained {
		record, err := contract.DecodeRetainedCanonicalRecord(row.Body)
		if err != nil {
			return nil, false
		}
		if record.Entry.ValueState != core.ValueStateID {
			continue
		}
		actual, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, record.Entry)
		if err != nil || actual != core || !bytes.Equal(record.Entry.ValueBytes, payload) {
			return nil, false
		}
		readers = generatedReaderUnion(readers, record.Entry.Recipients)
	}
	return readers, true
}

func (a *generatedAdmission) finalExcludesReader(index int) bool {
	if a.purpose.output == nil || a.purpose.final == nil {
		return false
	}
	plan := a.graph.ValueEntryPlans[index]
	before := slices.IndexFunc(a.purpose.output.EntriesBefore, func(row contract.MembershipRow) bool {
		return row.Name == plan.Name && row.Slot == plan.Slot
	})
	if before < 0 {
		return false
	}
	return slices.ContainsFunc(a.purpose.output.EntriesBefore[before].Recipients, func(id contract.ID) bool {
		return !slices.Contains(a.purpose.final.plan.recipients[index], id)
	})
}

func (a *generatedAdmission) finalFreshIdentity(index int) (contract.IdentityRow, bool) {
	plan, final := a.graph.ValueEntryPlans[index], a.purpose.final
	phase := final.materializationPhaseID
	value, err := contract.GeneratorPhaseValueID(phase, plan.Slot)
	snapshot, snapshotErr := contract.GeneratorPhaseSnapshotID(phase)
	transition, transitionErr := contract.GeneratorPhaseTransitionID(phase)
	return contract.IdentityRow{Name: plan.Name, Slot: plan.Slot, Incarnation: plan.EntryIncarnationID, ValueState: value,
		OriginSnapshot: snapshot, OriginTransition: transition}, err == nil && snapshotErr == nil && transitionErr == nil
}
