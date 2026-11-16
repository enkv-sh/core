package core

import (
	"bytes"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// ValidateMetadataWorkOutput checks metadata, compact work and output relations.
// Generated operational facts retain their separate validation owner.
func (v DomainInspection) ValidateMetadataWorkOutput() error {
	if !validInspectionObservation(v.Observation) || len(v.Entries) > contract.CryptoMaxValueEntries || len(v.Recipients) > contract.CryptoMaxRecipients || len(v.Work.Groups) > 65535 || len(v.Work.GroupSelections) != len(v.Work.Groups) || len(v.Work.Pages) > contract.MaxChildPages || len(v.Work.PublicationOrder) > contract.MaxPublicationCoordinates || len(v.Output.Coordinates) > contract.MaxPublicationCoordinates ||
		v.DomainWarningBits & ^uint8(WarningOrphanGeneratedEffect|WarningLateDestructiveEffect|WarningPublicationOrderValue|WarningDiscardedExactEvidence|WarningPossibleStoreGarbage) != 0 ||
		v.Warnings.Domain != publicDomainWarnings(v.DomainWarningBits) || v.Warnings.Output != v.Output.Warnings {
		return contract.ErrRecord
	}
	recipients := make(map[contract.ID]bool, len(v.Recipients))
	for i, row := range v.Recipients {
		if row.RecipientID.IsZero() || len(row.DisplayName) > contract.CryptoMaxName || !utf8.ValidString(row.DisplayName) ||
			i > 0 && bytes.Compare(v.Recipients[i-1].RecipientID[:], row.RecipientID[:]) >= 0 {
			return contract.ErrRecord
		}
		switch row.Status {
		case contract.CurrentRecipient:
			if row.BindingID.IsZero() || row.BindingSerial == 0 || row.BindingFingerprint.IsZero() {
				return contract.ErrRecord
			}
			recipients[row.RecipientID] = true
		case contract.RetiredRecipient:
			if !row.BindingID.IsZero() || row.BindingSerial != 0 || !row.BindingFingerprint.IsZero() {
				return contract.ErrRecord
			}
		default:
			return contract.ErrRecord
		}
	}
	slots := make(map[uint16]bool, len(v.Entries))
	entries := make(map[contract.ID]InspectionEntry, len(v.Entries))
	generated, memberships := 0, 0
	var rawBytes uint64
	for i, row := range v.Entries {
		if !validInspectionEntry(row.Name, row.IncarnationID, row.ValueStateID, row.ValueSource, row.RawLength, row.GenerationID, row.Epoch) ||
			i > 0 && v.Entries[i-1].Name >= row.Name || row.Slot >= contract.CryptoMaxValueEntries || slots[row.Slot] || len(row.RecipientIDs) == 0 || len(row.RecipientIDs) > contract.CryptoMaxValueEntryRecipients {
			return contract.ErrRecord
		}
		if _, duplicate := entries[row.IncarnationID]; duplicate {
			return contract.ErrRecord
		}
		slots[row.Slot], entries[row.IncarnationID] = true, row
		memberships += len(row.RecipientIDs)
		rawBytes += uint64(row.RawLength)
		for j, id := range row.RecipientIDs {
			if !recipients[id] || j > 0 && bytes.Compare(row.RecipientIDs[j-1][:], id[:]) >= 0 {
				return contract.ErrRecord
			}
		}
		if row.ValueSource == contract.Generated {
			generated++

		} else if row.RetirementMode != 0 {
			return contract.ErrRecord
		}
	}
	if memberships > contract.CryptoMaxMemberships || rawBytes > contract.CryptoMaxRawSet {
		return contract.ErrRecordCapacity
	}
	if generated != len(v.Generated.CurrentGenerations) || generated > contract.GeneratedCurrentEntryLimit {
		return contract.ErrRecord
	}
	for i, row := range v.Generated.CurrentGenerations {
		entry, present := entries[row.EntryIncarnationID]
		if !present || entry.ValueSource != contract.Generated || row.Name != entry.Name || row.GenerationID != entry.GenerationID || row.Epoch != entry.Epoch || row.RetirementMode != entry.RetirementMode ||
			i > 0 && v.Generated.CurrentGenerations[i-1].Name >= row.Name {
			return contract.ErrRecord
		}
		switch row.LifecycleMode {
		case contract.GeneratorLifecycleNone:
			if row.RetirementMode != 0 {
				return contract.ErrRecord
			}
		case contract.GeneratorLifecycleManaged:
			if row.RetirementMode < contract.GeneratedRetirementManual || row.RetirementMode > contract.GeneratedRetirementAuto {
				return contract.ErrRecord
			}
		default:
			return contract.ErrRecord
		}
	}
	index := format.AdministrativeIndex{Domain: v.Observation.DomainID, Object: v.Observation.SnapshotID, SliceSnapshot: v.Observation.SnapshotID,
		Groups: v.Work.Groups, Pages: v.Work.Pages, PublicationOrder: v.Work.PublicationOrder}
	if !index.Valid() {
		return contract.ErrRecord
	}
	root := format.Root{Domain: v.Observation.DomainID}
	if v.ActiveOperation != nil {
		if v.ActiveOperation.OperationID.IsZero() || v.ActiveOperation.PhaseID.IsZero() || v.ActiveOperation.OperationKind == 0 {
			return contract.ErrRecord
		}
		root.Generated.ActiveOwner = v.ActiveOperation.OperationID
	}
	coordinates := make(map[contract.ID]contract.PublicationCoordinate, len(v.Output.Coordinates))
	for _, row := range v.Output.Coordinates {
		coordinates[row.CoordinateID] = row
	}
	for i, row := range v.Work.Groups {
		selection := v.Work.GroupSelections[i]
		parent := administrativeRequiredParentTarget(root, index, row)
		if parent.IsZero() != (selection.RequiredParentIndex == nil) || selection.RequiredParentIndex != nil && (int(*selection.RequiredParentIndex) >= len(index.Groups) || index.Groups[*selection.RequiredParentIndex].GroupID != parent) ||
			selection.Selectable != administrativeTargetSelectable(root, index, row, coordinates) {
			return contract.ErrRecord
		}
	}
	if err := v.Output.validate(v.Observation.DomainID, v.DomainWarningBits, v.Work.PublicationOrder); err != nil {
		return err
	}
	for _, binding := range v.Output.Configuration.Bindings {
		for _, target := range binding.Targets {
			if _, present := entries[target.EntryIncarnationID]; !present {
				return contract.ErrRecord
			}
		}
	}
	if uint64(len(v.Generated.Effects)) > GeneratedResultAttemptLimit || uint64(len(v.Generated.Duties))+uint64(len(v.Generated.Hazards)) > GeneratedResultWorkLimit || uint64(len(v.Generated.PendingReleases)) > GeneratedResultAttemptLimit {
		return contract.ErrRecordCapacity
	}
	if err := ValidateGeneratedPendingResultCleanup(v.Observation.DomainID, v.Generated.PendingReleases, v.Generated.Effects); err != nil {
		return err
	}
	var generatedWarnings GeneratedResultWarnings
	for _, row := range v.Generated.Effects {
		generatedWarnings = mergeGeneratedResultWarnings(generatedWarnings, row.Warnings)
	}
	for _, row := range v.Generated.Duties {
		generatedWarnings = mergeGeneratedResultWarnings(generatedWarnings, row.Warnings)
	}
	for _, row := range v.Generated.Hazards {
		generatedWarnings = mergeGeneratedResultWarnings(generatedWarnings, row.Warnings)
	}
	possibleGarbage := v.DomainWarningBits&WarningPossibleStoreGarbage != 0
	for _, row := range v.Generated.PendingReleases {
		possibleGarbage = possibleGarbage || row.State == contract.GeneratedReleaseUnknown || row.State == contract.GeneratedReleaseUnobserved
	}
	if v.Warnings.Generated != generatedWarnings || v.Warnings.PossibleStoreGarbage != possibleGarbage {
		return contract.ErrRecord
	}
	return nil
}

func (r PublicDomainInspectionResult) ValidateMetadataWorkOutput() error {
	if r.Operation != InspectOperation {
		return contract.ErrRecord
	}
	if r.Query == nil {
		if r.View != nil {
			return contract.ErrRecord
		}
		return validateUnboundPublicQuery(r.PublicQueryResult)
	}
	if err := r.Query.Validate(); err != nil {
		return err
	}
	if err := validatePublicQueryBinding(r.PublicQueryResult, r.Query.PublicQueryBasis, r.Query.Digest, contract.ID{}); err != nil {
		return err
	}
	if r.StateResult != PublicQuerySuccess {
		if r.View != nil {
			return contract.ErrRecord
		}
		return nil
	}
	if r.View == nil || r.Query.Observation == nil || r.View.Observation != *r.Query.Observation {
		return contract.ErrRecord
	}
	return r.View.ValidateMetadataWorkOutput()
}

func (r PublicRecipientInspectionResult) Validate() error {
	if r.Operation != InspectRecipientOperation {
		return contract.ErrRecord
	}
	if r.Query == nil {
		if r.View != nil {
			return contract.ErrRecord
		}
		return validateUnboundPublicQuery(r.PublicQueryResult)
	}
	if err := r.Query.Validate(); err != nil {
		return err
	}
	if err := validatePublicQueryBinding(r.PublicQueryResult, r.Query.PublicQueryBasis, r.Query.Digest, r.Query.RecipientID); err != nil {
		return err
	}
	if r.StateResult != PublicQuerySuccess {
		if r.View != nil {
			return contract.ErrRecord
		}
		return nil
	}
	if r.View == nil || r.Query.Observation == nil || r.View.Observation != *r.Query.Observation || r.View.RecipientID != r.Query.RecipientID {
		return contract.ErrRecord
	}
	return r.View.Validate()
}
