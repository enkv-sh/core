package crypto

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

type generatedCanonicalAccessPin struct {
	access contract.AccessRecord
	digest contract.DigestLength
}

// The installed private parent authenticates the selected closure before this
// handoff, as for admitCanonical and admitMembership. Selection fields alone
// are not a proof of selection. Bind these independent predecessor facts to
// this admission; a candidate never supplies its own expected access packets.
// Source bodies remain in the owned output census. Only access is copied here,
// once per material, independently of the active declaration's source quota.
func (a *generatedAdmission) admitFinalCanonicalAccess(input []contract.ConsumerSelection) bool {
	if a.purpose.final == nil || a.purpose.output == nil || !a.purpose.output.RetainedCanonicalsValid() || len(input) > contract.AccessMaterialLimit {
		return false
	}
	type meaning struct {
		core    contract.ValueCore
		payload contract.ID
		check   contract.ID
		readers []contract.ID
		entries map[contract.ID]bool
	}
	expected := make(map[contract.ID]*meaning)
	for _, source := range a.purpose.output.Retained {
		record, err := contract.DecodeRetainedCanonicalRecord(source.Body)
		if err != nil {
			return false
		}
		core, coreErr := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, record.Entry)
		payload, payloadErr := contract.InspectCanonicalPayload(record.Entry.ValueBytes)
		digest, digestErr := contract.PublicValueEntryDigest(a.request.Context.DomainID, record.OriginalSlot, record.Entry)
		payloadDigest := contract.Hash(record.Entry.ValueBytes)
		clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
		if coreErr != nil || payloadErr != nil || digestErr != nil {
			return false
		}
		prior := expected[core.ValueStateID]
		if prior == nil {
			prior = &meaning{core: core, payload: payloadDigest, check: payload.PackageCheck, entries: make(map[contract.ID]bool)}
			expected[core.ValueStateID] = prior
		} else if prior.core != core || prior.payload != payloadDigest {
			return false
		}
		prior.entries[digest] = true
		prior.readers = generatedReaderUnion(prior.readers, record.Entry.Recipients)
	}
	if len(input) != len(expected) {
		return false
	}
	for _, body := range a.purpose.output.EntryBodies {
		entry, err := contract.DecodeValueEntry(body)
		if err != nil {
			return false
		}
		prior := expected[entry.ValueState]
		if prior != nil {
			core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
			if err != nil || core != prior.core || contract.Hash(entry.ValueBytes) != prior.payload {
				clear(entry.ValueBytes[:cap(entry.ValueBytes)])
				return false
			}
			prior.readers = generatedReaderUnion(prior.readers, entry.Recipients)
		}
		clear(entry.ValueBytes[:cap(entry.ValueBytes)])
	}
	root, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		return false
	}
	access := make([]contract.AccessRecord, len(input))
	var revision contract.ID
	for i, selected := range input {
		prior := expected[selected.Core.ValueStateID]
		if prior == nil || !prior.entries[selected.EntryDigest] || selected.Core != prior.core ||
			contract.Hash(selected.Entry.ValueBytes) != prior.payload {
			return false
		}
		if _, _, valid := checkConsumerSelection(selected, a.control.Provider); !valid {
			return false
		}
		context := a.request.Context
		if selected.Root != root || selected.DomainID != context.DomainID || selected.HEADDigest != context.PredecessorHEADDigest ||
			selected.AccessRoot != context.CurrentAccessRoot || selected.Binding.SubjectID != a.control.AuthorityRecipientID ||
			!sameGeneratedBinding(selected.Binding.Binding, a.control.AuthorityKMSBinding) || !a.accessBindingsValid(selected.Access) ||
			selected.Access.PackageCheck != prior.check || !revision.IsZero() && revision != selected.HEADRevision {
			return false
		}
		revision = selected.HEADRevision
		condition, err := contract.MatchHeadCondition(selected.HEADToken)
		if err != nil {
			return false
		}
		digest, err := contract.CryptoConditionDigest(condition)
		if err != nil || digest != context.OriginalConditionDigest {
			return false
		}
		count := len(prior.readers)
		if a.control.Recovery != nil {
			count++
		}
		if len(selected.Access.Wraps) != count {
			return false
		}
		for j, reader := range prior.readers {
			wrap := selected.Access.Wraps[j]
			if wrap.SubjectKind != contract.OrdinaryWrapSubject || wrap.SubjectID != reader {
				return false
			}
		}
		if a.control.Recovery != nil {
			wrap := selected.Access.Wraps[len(prior.readers)]
			if wrap.SubjectKind != contract.RecoveryWrapSubject || wrap.SubjectID != a.control.Recovery.RoleID {
				return false
			}
		}
		access[i] = selected.Access
	}
	// This checks strict material order/dedup, AccessMaterialLimit and the
	// existing aggregate access-page byte bound before nested owned copies.
	if _, err := contract.AccessRecordsDescriptor(a.request.Context.DomainID, access); err != nil {
		return false
	}
	byMaterial := make(map[contract.ID]contract.AccessRecord, len(access))
	digests := make(map[contract.ID]contract.DigestLength, len(access))
	for _, row := range access {
		body, err := contract.EncodeAccessRecord(row)
		if err != nil {
			return false
		}
		digests[row.MaterialID] = contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}
		clear(body[:cap(body)])
		byMaterial[row.MaterialID] = row
	}
	// A grant can use prepared access as its later authority. Every selected
	// view of that same predecessor material must first agree with this pin.
	matchesPinned := func(row contract.AccessRecord) bool {
		pinned, present := byMaterial[row.MaterialID]
		return !present || sameAccessRecord(row, pinned)
	}
	for _, source := range a.purpose.final.plan.canonicals {
		if digest, pinned := digests[source.core.ValueStateID]; pinned {
			// Closed delete admission keeps only this digest, without opening
			// the source or owning its access body. An absent source admission
			// has neither form of access evidence and needs no overlap check.
			if source.access != (contract.DigestLength{}) && source.access != digest {
				return false
			}
			if source.selectedAccess.MaterialID != (contract.ID{}) &&
				(source.selectedAccess.MaterialID != source.core.ValueStateID || !matchesPinned(source.selectedAccess)) {
				return false
			}
		}
	}
	for _, selected := range a.purpose.final.plan.currentValues {
		if !matchesPinned(selected.Access) {
			return false
		}
	}
	for _, selected := range a.purpose.final.membership {
		if !matchesPinned(selected.Selection.Access) {
			return false
		}
	}
	for _, row := range access {
		pin := generatedCanonicalAccessPin{access: row, digest: digests[row.MaterialID]}
		pin.access.Wraps = slices.Clone(row.Wraps)
		for i := range pin.access.Wraps {
			pin.access.Wraps[i].RSACiphertext = bytes.Clone(row.Wraps[i].RSACiphertext)
		}
		a.purpose.final.canonicalAccess = append(a.purpose.final.canonicalAccess, pin)
	}
	return true
}

func (a *generatedAdmission) candidateCanonicalAccessMatches(c generatedCandidate, retained map[contract.ID][]contract.ID) bool {
	final := a.purpose.final
	if final == nil || len(final.canonicalAccess) == 0 {
		return true
	}
	access := make(map[contract.ID]contract.AccessRecord)
	for _, row := range c.AccessRecords {
		if row.MaterialKind == contract.ValueMaterialKind {
			if _, duplicate := access[row.MaterialID]; duplicate {
				return false
			}
			access[row.MaterialID] = row
		}
	}
	current := make(map[contract.ID][]contract.ID)
	for _, row := range c.Entries {
		if row.Entry.ConfidentialityClass == contract.Secret {
			current[row.Entry.ValueState] = generatedReaderUnion(current[row.Entry.ValueState], row.Entry.Recipients)
		}
	}
	prepared := make(map[contract.ID]generatedSuppliedPreparation)
	for _, row := range final.supplied {
		prepared[row.identity.ValueState] = row
	}
	for _, pin := range final.canonicalAccess {
		readers := generatedReaderUnion(current[pin.access.MaterialID], retained[pin.access.MaterialID])
		row, present := access[pin.access.MaterialID]
		if len(readers) == 0 {
			if present {
				return false
			}
			continue
		}
		if !present {
			return false
		}
		if c.Subject.Purpose == contract.GeneratorAuthorityFinal {
			if result, ok := prepared[pin.access.MaterialID]; ok {
				if !a.suppliedFinalAccessMatches(c, result, row) {
					return false
				}
			} else if !a.finalValueAccessProjectionMatches(readers, row, pin.access, pin.digest) {
				return false
			}
		} else {
			body, err := contract.EncodeAccessRecord(row)
			if err != nil || pin.digest != (contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}) {
				return false
			}
		}
	}
	return true
}
