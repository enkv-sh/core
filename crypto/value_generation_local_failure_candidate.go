package crypto

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

type generatedFailureFactKey struct {
	kind uint8
	id   contract.ID
}

func (a *generatedAdmission) candidateLocalFailureMatches(c generatedCandidate) bool {
	adoption := a.purpose.adoption
	if adoption == nil || adoption.localFailure == nil || !adoption.localFailure.prepared ||
		len(adoption.results) != 0 || len(adoption.validated) != 0 {
		return false
	}
	f := adoption.localFailure
	v, subject := f.attempt, c.Subject
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil || !generatedLocalTerminalAttempt(v) || subject.Purpose != contract.GeneratorAuthorityFailedTerminal ||
		subject.OwnerID != a.request.Parent.OperationID || subject.LineageID != v.LineageID || subject.AttemptID != v.AttemptID ||
		subject.ResultID != v.ResultID || !subject.ResultDigest.IsZero() || !subject.PredecessorAttemptID.IsZero() ||
		subject.DescriptorID != v.DescriptorID || subject.ConfigContractID != v.ConfigContractID || subject.ResultContractID != v.ResultContractID ||
		subject.ResultVector != contract.GeneratorDescriptor(empty) || subject.Intent != a.request.Parent.Declaration ||
		subject.CapacityReservation != a.request.Parent.Capacity || subject.BeforeAccessDigest != subject.AfterAccessDigest || f.beforeSliceSnapshot.IsZero() {
		return false
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(adoption.phaseID)
	if err != nil {
		return false
	}
	excluded, ok := a.localFailureWorkExclusions(subject.DomainID)
	if !ok {
		return false
	}
	factScratch := make([]contract.SupportRecordDigest, 0, len(a.purpose.output.Rows.Facts))
	beforeWork, ok := generatedFailureWorkDescriptor(subject.DomainID, a.purpose.output.Rows.Facts, excluded, factScratch)
	if !ok || beforeWork != subject.BeforeWork {
		return false
	}
	before := a.purpose.output.Rows.Facts
	if len(c.SupportRecords) != len(before) {
		return false
	}
	consumed := make([]byte, (len(before)+7)/8)
	remaining := len(before)
	consume := func(fact contract.SupportRecordDigest) bool {
		at, found := slices.BinarySearchFunc(before, generatedFailureFactKey{fact.Kind(), fact.RecordID()}, func(fact contract.SupportRecordDigest, key generatedFailureFactKey) int {
			if fact.Kind() < key.kind {
				return -1
			}
			if fact.Kind() > key.kind {
				return 1
			}
			id := fact.RecordID()
			return bytes.Compare(id[:], key.id[:])
		})
		if !found || consumed[at/8]&(1<<uint(at%8)) != 0 {
			return false
		}
		if before[at] != fact {
			return false
		}
		consumed[at/8] |= 1 << uint(at%8)
		remaining--
		return true
	}
	consumePredecessor := func(row contract.SupportRecord) bool {
		fact, err := contract.InspectSupportRecordDigest(v.DomainID, row)
		return err == nil && consume(fact)
	}
	for _, fact := range before {
		if fact.Kind() == contract.GeneratedResultSupportKind && fact.RecordID() == v.ResultID {
			return false
		}
	}
	var phase contract.GeneratedPhaseRecord
	afterFacts := factScratch[:0]
	attempts := make([]contract.GeneratedAttemptRecord, 0, a.graph.Header.TemplateCount)
	changedAttempt, changedDuty, changedPhase := false, false, false
	for _, row := range c.SupportRecords {
		fact, err := contract.InspectSupportRecordDigest(v.DomainID, row)
		if err != nil {
			return false
		}
		afterFacts = append(afterFacts, fact)
		if row.Kind == contract.GeneratedAttemptSupportKind {
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return false
			}
			if attempt.OperationID == v.OperationID {
				if len(attempts) == cap(attempts) {
					return false
				}
				attempts = append(attempts, attempt)
			}
		}
		switch {
		case row.Kind == contract.GeneratedResultSupportKind && row.RecordID == v.ResultID:
			return false
		case row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == v.AttemptID:
			actual, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if changedAttempt || err != nil || actual != v {
				return false
			}
			actual.State, actual.Stage, actual.FailureReason = contract.GeneratedEffectTransmitted, contract.GeneratedStageRetainedResult, 0
			body, err := contract.EncodeGeneratedAttemptRecord(actual)
			if err != nil || !consumePredecessor(contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: body}) {
				return false
			}
			changedAttempt = true
		case row.Kind == contract.GeneratedDutySupportKind && row.RecordID == v.OwnerID:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if changedDuty || err != nil || !generatedLocalDutyMatches(duty, v) {
				return false
			}
			duty.Status = contract.GeneratedEffectTransmitted
			body, err := contract.EncodeGeneratedDutyRecord(duty)
			if err != nil || !consumePredecessor(contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: body}) {
				return false
			}
			changedDuty = true
		case row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == v.OperationID:
			if changedPhase {
				return false
			}
			phase, err = contract.InspectGeneratedPhaseRecord(row.Body)
			body, oldErr := contract.EncodeGeneratedPhaseRecord(f.beforePhase)
			if err != nil || oldErr != nil || !consumePredecessor(contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: body}) {
				return false
			}
			changedPhase = true
		case row.Kind == contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return false
			}
			if carrier.OwnerKind != contract.GeneratorSnapshotOwner {
				if !consume(fact) {
					return false
				}
				continue
			}
			id, err := contract.GeneratorVectorCarrierID(carrier)
			if err != nil || carrier.DomainID != v.DomainID || carrier.OwnerID != snapshot || carrier.VectorKind != contract.GeneratorVectorSlices || id != row.RecordID {
				return false
			}
			carrier.OwnerID = f.beforeSliceSnapshot
			body, err := contract.EncodeGeneratorVectorCarrier(carrier)
			oldID, idErr := contract.GeneratorVectorCarrierID(carrier)
			if err != nil || idErr != nil || !consumePredecessor(contract.SupportRecord{Kind: row.Kind, RecordID: oldID, Body: body}) {
				return false
			}
		default:
			if !consume(fact) {
				return false
			}
		}
	}
	if remaining != 0 || !changedAttempt || !changedDuty || !changedPhase {
		return false
	}
	if !a.localFailurePhaseMatches(phase, c.SupportRecords, attempts) {
		return false
	}
	afterWork, ok := generatedFailureWorkDescriptor(subject.DomainID, afterFacts, excluded, afterFacts[:0])
	return ok && afterWork == subject.AfterWork
}

func (a *generatedAdmission) localFailurePhaseMatches(actual contract.GeneratedPhaseRecord, rows []contract.SupportRecord, attempts []contract.GeneratedAttemptRecord) bool {
	f, adoption := a.purpose.adoption.localFailure, a.purpose.adoption
	want := f.beforePhase
	want.PhaseID, want.Phase, want.Stage = adoption.phaseID, adoption.phase.AfterPhase, contract.GeneratedStageTerminal
	want.AcceptedResultID, want.ResultDigest = contract.ID{}, contract.ID{}
	if !want.SelectionPhaseID.IsZero() || int(want.LineageIndex) >= len(a.graph.Lineages) || a.graph.Lineages[want.LineageIndex].LineageID != f.attempt.LineageID {
		return false
	}
	for i := int(want.LineageIndex) + 1; i < len(a.graph.Lineages); i++ {
		lineage := a.graph.Lineages[i]
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		x := lineage.Templates[0]
		found := false
		for _, pending := range attempts {
			if pending.AttemptID == x.AttemptID {
				if found || pending.State != contract.GeneratedEffectTransmitted || pending.Stage != contract.GeneratedStageRetainedResult {
					return false
				}
				found = true
			}
		}
		if !found || slices.ContainsFunc(rows, func(row contract.SupportRecord) bool {
			return row.Kind == contract.GeneratedResultSupportKind && row.RecordID == x.ResultID
		}) {
			return false
		}
		want.LineageIndex, want.Branch = uint16(i), contract.GeneratorBranchInitial
		want.FrontierAttemptID, want.Stage = x.AttemptID, contract.GeneratedStageRetainedResult
		want.NoEffectUsed, want.ResidueUsed = 0, 0
		break
	}
	attemptIDs, dutyIDs := make([]contract.ID, 0, len(attempts)), make([]contract.ID, 0, len(attempts))
	for _, attempt := range attempts {
		attemptIDs = append(attemptIDs, attempt.AttemptID)
		dutyIDs = append(dutyIDs, attempt.OwnerID)
	}
	compareID := func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) }
	slices.SortFunc(attemptIDs, compareID)
	slices.SortFunc(dutyIDs, compareID)
	dutyIDs = slices.Compact(dutyIDs)
	attemptRows, ownedDuties := make([]contract.SupportRecord, 0, len(attempts)), make([]contract.SupportRecord, 0, len(dutyIDs))
	for _, row := range rows {
		if row.Kind == contract.GeneratedAttemptSupportKind {
			if _, found := slices.BinarySearchFunc(attemptIDs, row.RecordID, compareID); found {
				attemptRows = append(attemptRows, row)
			}
		}
		if row.Kind == contract.GeneratedDutySupportKind {
			if _, found := slices.BinarySearchFunc(dutyIDs, row.RecordID, compareID); found {
				ownedDuties = append(ownedDuties, row)
			}
		}
	}
	sortRows := func(rows []contract.SupportRecord) {
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	}
	sortRows(attemptRows)
	sortRows(ownedDuties)
	var err error
	want.Attempts, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseAttempts, f.attempt.DomainID, attemptRows)
	if err != nil {
		return false
	}
	want.Duties, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, f.attempt.DomainID, ownedDuties)
	return err == nil && actual == want
}

func (a *generatedAdmission) localFailureWorkExclusions(domain contract.ID) ([]contract.SupportRecordDigest, bool) {
	excluded := make([]contract.SupportRecordDigest, 0, 2*contract.MutationReceiptWindowLimit+1)
	if a.registry != nil {
		windows := a.registry.before
		receipts, err := windows.SupportRecords()
		if err != nil {
			return nil, false
		}
		for _, row := range receipts {
			fact, err := contract.InspectSupportRecordDigest(domain, row)
			if err != nil {
				return nil, false
			}
			excluded = append(excluded, fact)
		}
		if len(receipts) != 0 {
			indexes, err := windows.Indexes()
			if err != nil {
				return nil, false
			}
			successes, failures, order, err := indexes.Descriptors()
			if err != nil {
				return nil, false
			}
			blob, err := contract.MutationReceiptIndexBlobID(domain, successes, failures, order)
			if err != nil {
				return nil, false
			}
			body, err := contract.EncodeMutationReceiptIndexes(indexes)
			if err != nil {
				return nil, false
			}
			count := (len(body) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
			for i := 0; i < count; i++ {
				start, stop := i*contract.GeneratedFragmentMaxPayload, min((i+1)*contract.GeneratedFragmentMaxPayload, len(body))
				fragment := contract.GeneratedFragment{Schema: 1, BlobID: blob, Index: uint16(i), Count: uint16(count), TotalLength: uint64(len(body)), WholeDigest: contract.Hash(body), Offset: uint32(start), Payload: body[start:stop]}
				encoded, err := contract.EncodeGeneratedFragment(fragment)
				id, idErr := contract.GeneratorFragmentID(blob, uint16(i))
				if err != nil || idErr != nil {
					return nil, false
				}
				row := contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: encoded}
				fact, err := contract.InspectSupportRecordDigest(domain, row)
				if err != nil {
					return nil, false
				}
				excluded = append(excluded, fact)
			}
		}
	}
	slices.SortFunc(excluded, func(a, b contract.SupportRecordDigest) int {
		if a.Kind() < b.Kind() {
			return -1
		}
		if a.Kind() > b.Kind() {
			return 1
		}
		left, right := a.RecordID(), b.RecordID()
		return bytes.Compare(left[:], right[:])
	})
	return excluded, true
}

func generatedFailureWorkDescriptor(domain contract.ID, facts []contract.SupportRecordDigest, excluded []contract.SupportRecordDigest, scratch []contract.SupportRecordDigest) (contract.GeneratorDescriptor, bool) {
	if len(excluded) == 0 {
		for _, fact := range facts {
			if fact.Kind() == contract.MutationReceiptSupportKind {
				return contract.GeneratorDescriptor{}, false
			}
		}
		d, err := contract.GeneratorAuthorityWorkDescriptorFromDigests(domain, facts)
		return d, err == nil
	}
	selected := scratch[:0]
	if cap(selected) < len(facts) {
		return contract.GeneratorDescriptor{}, false
	}
	seen := 0
	for _, fact := range facts {
		key := generatedFailureFactKey{fact.Kind(), fact.RecordID()}
		at, found := slices.BinarySearchFunc(excluded, key, func(v contract.SupportRecordDigest, key generatedFailureFactKey) int {
			if v.Kind() < key.kind {
				return -1
			}
			if v.Kind() > key.kind {
				return 1
			}
			id := v.RecordID()
			return bytes.Compare(id[:], key.id[:])
		})
		if found {
			if fact != excluded[at] {
				return contract.GeneratorDescriptor{}, false
			}
			seen++
			continue
		}
		if fact.Kind() == contract.MutationReceiptSupportKind {
			return contract.GeneratorDescriptor{}, false
		}
		selected = append(selected, fact)
	}
	if seen != len(excluded) {
		return contract.GeneratorDescriptor{}, false
	}
	d, err := contract.GeneratorAuthorityWorkDescriptorFromDigests(domain, selected)
	return d, err == nil
}
