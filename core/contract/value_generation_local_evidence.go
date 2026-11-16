package contract

import "slices"

// LocalGeneratedEvidenceNeeded identifies detached local create evidence needed
// by exact successor metadata or an actually retained generated canonical copy.
// It does not authenticate those inputs or create a work owner.
func LocalGeneratedEvidenceNeeded(current []GeneratedEntryMetadata, retained []SupportRecord) (map[ID]bool, error) {
	needed := make(map[ID]bool)
	add := func(m GeneratedEntryMetadata) error {
		if _, err := GeneratedEntryMetadataLength(m); err != nil {
			return err
		}
		if m.SemanticLifecycleMode() == GeneratorLifecycleNone {
			needed[m.CreateResultID] = true
		}
		return nil
	}
	for _, m := range current {
		if err := add(m); err != nil {
			return nil, err
		}
	}
	for _, row := range retained {
		if row.Kind != RetainedCanonicalSupportKind {
			continue
		}
		canonical, err := InspectRetainedCanonicalRecord(row.Body)
		if err != nil {
			return nil, err
		}
		if canonical.Entry.ValueSource == Generated {
			if err := add(canonical.Entry.Generated); err != nil {
				return nil, err
			}
		}
	}
	return needed, nil
}

// LocalEvidenceAfter removes local evidence whose exact selected value
// and retained canonical consumers both end. Existing graph/result consumers
// can still need its shared intent independently of the detached evidence.
func (v *GeneratedSupportTransition) LocalEvidenceAfter(intent []CryptoIntentRow) (GeneratedSupportRows, error) {
	if err := v.IntentError(intent); err != nil {
		return GeneratedSupportRows{}, err
	}
	var current []GeneratedEntryMetadata
	for _, before := range v.CurrentGenerated {
		entry, err := InspectValueEntry(before.EntryBytes)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		for _, after := range intent {
			if after.Name == string(entry.Name) && after.ValueSource == Generated {
				current = append(current, entry.Generated)
				break
			}
		}
	}
	needed, err := LocalGeneratedEvidenceNeeded(current, v.Records)
	if err != nil {
		return GeneratedSupportRows{}, err
	}
	dropEvidence, obsoleteIntents := make(map[ID]bool), make(map[ID]bool)
	for _, row := range v.Records {
		if row.Kind != GeneratedCreateEvidenceSupportKind {
			continue
		}
		evidence, err := InspectGeneratedCreateEvidence(row.Body)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		if evidence.LifecycleMode != GeneratorLifecycleNone || needed[row.RecordID] {
			continue
		}
		facts, err := InspectGeneratorSafeFacts(evidence.SafeFacts)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		dropEvidence[row.RecordID], obsoleteIntents[facts.IntentDigest] = true, true
	}
	if len(dropEvidence) == 0 {
		return GeneratedSupportRows{Records: slices.Clone(v.Records), Facts: slices.Clone(v.RecordFacts)}, nil
	}
	for _, m := range current {
		delete(obsoleteIntents, m.IntentDigest)
	}
	for _, row := range v.Records {
		switch row.Kind {
		case GeneratedCreateEvidenceSupportKind:
			if dropEvidence[row.RecordID] {
				continue
			}
			evidence, err := InspectGeneratedCreateEvidence(row.Body)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			facts, err := InspectGeneratorSafeFacts(evidence.SafeFacts)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			delete(obsoleteIntents, facts.IntentDigest)
		case GeneratedResultSupportKind:
			result, err := InspectGeneratedResultRecord(row.Body)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			delete(obsoleteIntents, result.SafeFacts.IntentDigest)
		}
	}
	var bodies [][]byte
	deadBlobs, keptBlobs := make(map[ID]bool), make(map[ID]bool)
	for _, row := range v.Records {
		if row.Kind != GeneratorVectorSupportKind {
			continue
		}
		carrier, err := InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		if carrier.VectorKind != GeneratorVectorSlices {
			continue
		}
		if carrier.DomainID != v.DomainID || carrier.OwnerKind != GeneratorSnapshotOwner || carrier.OwnerID != v.BeforeSliceSnapshot {
			return GeneratedSupportRows{}, ErrRecord
		}
		location, err := InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		if location.ContentKind == GeneratorContentIntent && obsoleteIntents[location.ContentID] {
			deadBlobs[location.BlobID] = true
		} else {
			bodies = append(bodies, carrier.Row)
			keptBlobs[location.BlobID] = true
		}
	}
	dropFragments := make(map[ID]bool)
	for blob := range deadBlobs {
		if keptBlobs[blob] {
			continue
		}
		for i := uint16(0); i < GeneratedFragmentLocationLimit; i++ {
			id, err := GeneratorFragmentID(blob, i)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			dropFragments[id] = true
		}
	}
	out := GeneratedSupportRows{}
	for i, row := range v.Records {
		if row.Kind == GeneratedCreateEvidenceSupportKind && dropEvidence[row.RecordID] || row.Kind == GeneratedFragmentSupportKind && dropFragments[row.RecordID] {
			continue
		}
		if row.Kind == GeneratorVectorSupportKind {
			carrier, err := InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			if carrier.VectorKind == GeneratorVectorSlices {
				continue
			}
		}
		out.Records, out.Facts = append(out.Records, row), append(out.Facts, v.RecordFacts[i])
	}
	slices.SortFunc(bodies, func(a, b []byte) int { return generatorVectorRowCompare(GeneratorVectorSlices, a, b) })
	descriptor, err := GeneratorVectorDescriptor(GeneratorVectorSlices, bodies)
	if err != nil {
		return GeneratedSupportRows{}, err
	}
	for i, body := range bodies {
		carrier := GeneratorVectorCarrier{Schema: 1, DomainID: v.DomainID, OwnerKind: GeneratorSnapshotOwner, OwnerID: v.BeforeSliceSnapshot, VectorKind: GeneratorVectorSlices, Vector: descriptor, Ordinal: uint32(i), Row: body}
		encoded, err := EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		id, err := GeneratorVectorCarrierID(carrier)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		row := SupportRecord{Kind: GeneratorVectorSupportKind, RecordID: id, Body: encoded}
		fact, err := InspectSupportRecordDigest(v.DomainID, row)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		out.Records, out.Facts = append(out.Records, row), append(out.Facts, fact)
	}
	return out, nil
}
