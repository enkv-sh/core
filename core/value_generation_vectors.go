package core

import (
	"cmp"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedVectorKey struct {
	ownerKind uint8
	owner     contract.ID
	kind      contract.GeneratorVectorKind
	vector    contract.GeneratorDescriptor
}

type generatedVector struct {
	rows [][]byte
}

// The authenticated page bodies remain the sole owner of these row bytes.
// A carrier supplies neither a retention root nor authority for its contents.
type generatedVectorSet struct {
	entries map[generatedVectorKey]generatedVector
}

type generatedVectorValidation struct {
	facts   *generatedVectorSet
	claimed map[generatedVectorKey]bool
}

type generatedResultEvidence struct {
	digest contract.ID
	length uint64
}

func generatedHazardSupportOwner(h contract.GeneratedHazardRecord, bundles []contract.GeneratorPlanBundle, vectors generatedVectorSet) (contract.ID, error) {
	for _, bundle := range bundles {
		if bundle.Header.OperationID != h.OriginalOperationID {
			continue
		}
		x, _, ok := generatedTemplate(bundle, h.OriginalAttemptID)
		if !ok || x.Action != contract.GeneratorActionDelete {
			continue
		}
		return generatedDeleteHazardSupportOwner(h, vectors)
	}
	return h.OriginalOperationID, nil
}

func generatedDeleteHazardSupportOwner(h contract.GeneratedHazardRecord, vectors generatedVectorSet) (contract.ID, error) {
	rows, err := vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorTargets, h.Target)
	if err != nil || len(rows) != 1 {
		return contract.ID{}, contract.ErrRecord
	}
	target, err := contract.InspectGeneratorTarget(rows[0])
	if err != nil {
		return contract.ID{}, err
	}
	return target.OriginalOperationID, nil
}

func newGeneratedVectorSet(domain contract.ID, records []contract.SupportRecord) (generatedVectorSet, error) {
	const maxBytes = contract.MaxChildPages * (contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
	if domain.IsZero() || len(records) > maxBytes/contract.SupportRecordMinLength {
		return generatedVectorSet{}, contract.ErrRecordCapacity
	}
	bytes := 0
	for _, row := range records {
		if len(row.Body) > maxBytes-bytes-contract.SupportRecordOverhead {
			return generatedVectorSet{}, contract.ErrRecordCapacity
		}
		bytes += contract.SupportRecordOverhead + len(row.Body)
	}
	grouped := make(map[generatedVectorKey][]contract.GeneratorVectorCarrier)
	for _, record := range records {
		if record.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		v, err := contract.InspectGeneratorVectorCarrier(record.Body)
		if err != nil || v.DomainID != domain || uint64(v.Vector.Count) > uint64(len(records)) {
			return generatedVectorSet{}, contract.ErrRecord
		}
		id, err := contract.GeneratorVectorCarrierID(v)
		if err != nil || id != record.RecordID {
			return generatedVectorSet{}, contract.ErrRecord
		}
		key := generatedVectorKey{v.OwnerKind, v.OwnerID, v.VectorKind, v.Vector}
		grouped[key] = append(grouped[key], v)
	}
	out := generatedVectorSet{entries: make(map[generatedVectorKey]generatedVector, len(grouped))}
	for key, carriers := range grouped {
		if uint64(len(carriers)) != uint64(key.vector.Count) {
			return generatedVectorSet{}, contract.ErrRecord
		}
		slices.SortFunc(carriers, func(a, b contract.GeneratorVectorCarrier) int { return cmp.Compare(a.Ordinal, b.Ordinal) })
		rows := make([][]byte, len(carriers))
		for i, carrier := range carriers {
			if carrier.Ordinal != uint32(i) {
				return generatedVectorSet{}, contract.ErrRecord
			}
			rows[i] = carrier.Row
		}
		descriptor, err := contract.GeneratorVectorDescriptor(key.kind, rows)
		if err != nil || descriptor != key.vector {
			return generatedVectorSet{}, contract.ErrRecord
		}
		out.entries[key] = generatedVector{rows: rows}
	}
	return out, nil
}

func (s generatedVectorSet) resolve(ownerKind uint8, owner contract.ID, kind contract.GeneratorVectorKind, descriptor contract.GeneratorDescriptor) ([][]byte, error) {
	rows, err := s.borrow(ownerKind, owner, kind, descriptor)
	return slices.Clone(rows), err
}

// borrow lends immutable selected row bytes and headers for a synchronous
// private handoff. Callers must not change or retain this view independently.
func (s generatedVectorSet) borrow(ownerKind uint8, owner contract.ID, kind contract.GeneratorVectorKind, descriptor contract.GeneratorDescriptor) ([][]byte, error) {
	if owner.IsZero() || !contract.GeneratorVectorShapeValid(kind, descriptor) {
		return nil, contract.ErrRecord
	}
	if descriptor.Count == 0 {
		return nil, nil
	}
	key := generatedVectorKey{ownerKind, owner, kind, descriptor}
	vector, ok := s.entries[key]
	if !ok {
		return nil, contract.ErrRecord
	}
	return vector.rows, nil
}

func newGeneratedVectorValidation(facts *generatedVectorSet) *generatedVectorValidation {
	return &generatedVectorValidation{facts: facts, claimed: make(map[generatedVectorKey]bool)}
}

func (b *generatedVectorValidation) resolve(ownerKind uint8, owner contract.ID, kind contract.GeneratorVectorKind, descriptor contract.GeneratorDescriptor) ([][]byte, error) {
	if b == nil || b.facts == nil {
		return nil, contract.ErrRecord
	}
	rows, err := b.facts.resolve(ownerKind, owner, kind, descriptor)
	if err == nil && descriptor.Count != 0 {
		b.claimed[generatedVectorKey{ownerKind, owner, kind, descriptor}] = true
	}
	return rows, err
}

func (b *generatedVectorValidation) complete() bool {
	if b == nil || b.facts == nil {
		return false
	}
	for key := range b.facts.entries {
		if !b.claimed[key] {
			return false
		}
	}
	return true
}

// This verifies the closed descriptor-owner matrix. It does not replace graph
// reachability, signature verification, physical slice checks or live-consumer
// derivation, which must all succeed before selected state is usable.
func resolveGeneratedVectorOwners(domain, snapshot contract.ID, closure format.GeneratedClosure, records []contract.SupportRecord, entries []contract.ValueEntry, bundles []contract.GeneratorPlanBundle) (generatedVectorSet, error) {
	vectors, err := newGeneratedVectorSet(domain, records)
	if err != nil {
		return generatedVectorSet{}, err
	}
	builder := newGeneratedVectorValidation(&vectors)
	if err := builder.validateOwners(domain, snapshot, closure, records, entries, bundles); err != nil {
		return generatedVectorSet{}, err
	}
	return vectors, nil
}

func (vectors *generatedVectorValidation) validateOwners(domain, snapshot contract.ID, closure format.GeneratedClosure, records []contract.SupportRecord, entries []contract.ValueEntry, bundles []contract.GeneratorPlanBundle) error {
	if vectors == nil || vectors.facts == nil {
		return contract.ErrRecord
	}
	if _, err := vectors.resolve(contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, closure.Slices); err != nil {
		return err
	}
	attempts := make(map[contract.ID]contract.GeneratedAttemptRecord)
	results := make(map[contract.ID]generatedResultEvidence)
	releases := make(map[contract.ID]contract.PendingInboxReleaseRecord)
	for _, row := range records {
		actual, err := contract.SupportRecordDomain(row)
		if err != nil || !actual.IsZero() && actual != domain {
			return contract.ErrRecord
		}
		switch row.Kind {
		case contract.GeneratedAttemptSupportKind:
			v, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return err
			}
			if _, duplicate := attempts[v.AttemptID]; duplicate {
				return contract.ErrRecord
			}
			attempts[v.AttemptID] = v
		case contract.PendingInboxReleaseSupportKind:
			v, err := contract.InspectPendingInboxReleaseRecord(row.Body)
			if err != nil {
				return err
			}
			if _, duplicate := releases[v.OriginalResultID]; duplicate {
				return contract.ErrRecord
			}
			releases[v.OriginalResultID] = v
		case contract.GeneratedResultSupportKind:
			if _, duplicate := results[row.RecordID]; duplicate {
				return contract.ErrRecord
			}
			results[row.RecordID] = generatedResultEvidence{digest: contract.Hash(row.Body), length: uint64(len(row.Body))}
		}
	}
	proofs := func(operation contract.ID, d contract.GeneratorDescriptor) error {
		rows, err := vectors.resolve(contract.GeneratedParentSupportKind, operation, contract.GeneratorVectorProofs, d)
		if err != nil {
			return err
		}
		for _, row := range rows {
			p, err := contract.InspectGeneratorProof(row)
			if err != nil {
				return err
			}
			subject, err := contract.DecodeGeneratorAuthoritySubject(p.Subject)
			if err != nil || subject.DomainID != domain || subject.OperationID != operation {
				return contract.ErrRecord
			}
		}
		return nil
	}
	progress := func(ownerKind uint8, owner contract.ID, d contract.GeneratorDescriptor) error {
		rows, err := vectors.resolve(ownerKind, owner, contract.GeneratorVectorProgress, d)
		if err != nil {
			return err
		}
		for _, row := range rows {
			p, err := contract.InspectGeneratorProgress(row)
			if err != nil {
				return err
			}
			if ownerKind == contract.GeneratedAttemptSupportKind {
				ownerAttempt, present := attempts[owner]
				release, released := releases[ownerAttempt.ResultID]
				if present && released && p.CompletionClass == contract.GeneratedCompletionConfirmed {
					// The released probe owns a retained ACK prefix. Its result
					// bodies may already be disposed; the complete release reader
					// independently joins this prefix to scope, graph and history.
					if release.State == contract.GeneratedReleaseUnobserved || release.OriginalResultID != ownerAttempt.ResultID ||
						ownerAttempt.CompletionClass != p.CompletionClass || ownerAttempt.Stage != contract.GeneratedStageTerminal || len(rows) != 1 ||
						p.RequiredSteps != contract.GeneratorConfirmedRequiredSteps || p.CompletedSteps != contract.GeneratorProgressAcknowledged || p.Evidence.Count != 1 {
						return contract.ErrRecord
					}
					facts, err := vectors.resolve(ownerKind, owner, contract.GeneratorVectorFacts, ownerAttempt.Facts)
					if err != nil || len(facts) != 1 {
						return contract.ErrRecord
					}
					factRow, err := contract.InspectGeneratorFactsRow(facts[0])
					if err != nil || factRow.ResultID != ownerAttempt.ResultID {
						return contract.ErrRecord
					}
					fact, err := contract.InspectGeneratorSafeFacts(factRow.Facts)
					if err != nil || fact.Disposition != contract.GeneratorDispositionScopedUnusability || fact.PrecedingResultID != p.ResultID || fact.PrecedingResultBodyDigest != p.Evidence.Digest {
						return contract.ErrRecord
					}
					continue
				}
			}
			a, ok := attempts[p.AttemptID]
			if !ok || ownerKind == contract.GeneratedAttemptSupportKind && p.AttemptID != owner && (p.CompletionClass != contract.GeneratedCompletionConfirmed || attempts[owner].OwnerID != a.OwnerID) || p.ResultID != a.ResultID || p.CompletionClass != a.CompletionClass {
				return contract.ErrRecord
			}
			if p.CompletionClass == contract.GeneratedCompletionConfirmed {
				result, found := results[p.ResultID]
				if !found || p.Evidence.Digest != result.digest || p.Evidence.Length != result.length || p.Evidence.Count != 1 {
					return contract.ErrRecord
				}
				continue
			}
			if err := proofs(a.OperationID, p.Evidence); err != nil {
				return err
			}
		}
		return nil
	}
	entrySupport := func(m contract.ValueEntry) error {
		if m.ValueSource != contract.Generated {
			return nil
		}
		_, err := vectors.resolve(contract.GeneratedParentSupportKind, m.Generated.OriginOperationID, contract.GeneratorVectorSupport, m.Generated.RequiredSupport)
		return err
	}
	for _, record := range records {
		var anchors []generatedVectorKey
		switch record.Kind {
		case contract.GeneratedPhaseSupportKind:
			p, err := contract.InspectGeneratedPhaseRecord(record.Body)
			if err != nil || proofs(p.OperationID, p.Proofs) != nil {
				return contract.ErrRecord
			}
		case contract.RetainedCanonicalSupportKind:
			m, err := contract.DecodeRetainedCanonicalRecord(record.Body)
			if err != nil || entrySupport(m.Entry) != nil {
				return contract.ErrRecord
			}
		case contract.GeneratedAttemptSupportKind:
			a := attempts[record.RecordID]
			anchors = []generatedVectorKey{
				{contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorFacts, a.Facts},
				{contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorHistory, a.History},
				{contract.GeneratedParentSupportKind, a.OperationID, contract.GeneratorVectorSupport, a.Support},
			}
			if a.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				if a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
					return contract.ErrRecord
				}
			} else if err := progress(contract.GeneratedAttemptSupportKind, a.AttemptID, a.Progress); err != nil {
				return err
			}
		case contract.GeneratedDutySupportKind:
			d, err := contract.InspectGeneratedDutyRecord(record.Body)
			if err != nil {
				return err
			}
			anchors = []generatedVectorKey{
				{contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorHistory, d.History},
				{contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorConsumers, d.Consumers},
				{contract.GeneratedParentSupportKind, d.OriginalOperationID, contract.GeneratorVectorSupport, d.Support},
			}
			if d.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				if d.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) || d.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
					return contract.ErrRecord
				}
			} else {
				anchors = append(anchors, generatedVectorKey{contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorTargets, d.Target})
				if err := progress(contract.GeneratedDutySupportKind, d.DutyID, d.Progress); err != nil {
					return err
				}
			}
		case contract.GeneratedHazardSupportKind:
			h, err := contract.InspectGeneratedHazardRecord(record.Body)
			if err != nil {
				return err
			}
			supportOwner, err := generatedHazardSupportOwner(h, bundles, *vectors.facts)
			if err != nil {
				return err
			}
			anchors = []generatedVectorKey{
				{contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorTargets, h.Target},
				{contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorHistory, h.History},
				{contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorConsumers, h.Consumers},
				{contract.GeneratedParentSupportKind, supportOwner, contract.GeneratorVectorSupport, h.Support},
			}
		}
		for _, anchor := range anchors {
			if _, err := vectors.resolve(anchor.ownerKind, anchor.owner, anchor.kind, anchor.vector); err != nil {
				return err
			}
		}
	}
	for _, entry := range entries {
		if err := entrySupport(entry); err != nil {
			return err
		}
	}
	for _, bundle := range bundles {
		if _, err := contract.GeneratorPlanBundleLength(bundle); err != nil || bundle.Header.DomainID != domain {
			return contract.ErrRecord
		}
		if bundle.Header.OperationID != closure.ActiveOwner {
			continue
		}
		selected := false
		for _, row := range records {
			if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == closure.ActiveOwner {
				p, err := contract.InspectGeneratedPhaseRecord(row.Body)
				if err != nil {
					return err
				}
				selected = !p.SelectionPhaseID.IsZero()
			}
		}
		if selected {
			continue
		}
		for _, source := range bundle.SourceUses {
			if _, err := vectors.resolve(contract.GeneratedParentSupportKind, bundle.Header.OperationID, contract.GeneratorVectorConsumers, source.Consumers); err != nil {
				return err
			}
		}
	}
	if !vectors.complete() {
		return contract.ErrRecord
	}
	return nil
}
