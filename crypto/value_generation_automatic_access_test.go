package crypto

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedAutomaticAccessGuardAllowsWholeUnusedRecordDrop(t *testing.T) {
	core, rows, _ := generatedSharedAccessFixture(t)
	body, err := contract.EncodeAccessRecord(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	unused, err := contract.DecodeAccessRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	unused.MaterialKind, unused.MaterialID = contract.ValueMaterialKind, consumerID("unused detached access")
	rows = append(rows, unused)
	slices.SortFunc(rows, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(core.DomainID, rows)
	if err != nil {
		t.Fatal(err)
	}
	core.AccessPageRefs[0].Length += uint32(len(body))
	root, err := contract.AccessRoot(core)
	if err != nil {
		t.Fatal(err)
	}
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: core.DomainID,
		OperationID: consumerID("anchored operation"), OwnerID: consumerID("anchored operation"),
		PlanGraphID: consumerID("anchored graph"), UsePlanDigest: consumerID("anchored use plan"),
		PhaseID: consumerID("later anchored phase"), SelectionPhaseID: consumerID("original selection phase"),
		Phase: 3, LineageIndex: contract.GeneratorMaxLineageTemplates, Stage: contract.GeneratedStageTerminal,
		AcceptedResults: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseResults),
		Attempts:        contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseAttempts),
		Duties:          contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseDuties),
		Hazards:         contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards),
		PendingReleases: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases),
		Proofs:          contract.EmptyGeneratorVector(contract.GeneratorVectorProofs)}
	phase.ChangedSubjects, err = contract.ChangedSubjectDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	phase.ChangedAccess, err = contract.AccessChangeDescriptor(core.DomainID, nil)
	if err != nil {
		t.Fatal(err)
	}
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	a := &generatedAdmission{inputOwner: new(generatedInputOwner), request: contract.CryptoGeneratedCompareRequest{
		Context: contract.ApplyContext{DomainID: core.DomainID, CurrentAccessRoot: root}}}
	a.graph.Header.OperationID = phase.OperationID
	if !a.admitAutomaticAccess(generatedSessionAdmissionInput{BeforeAccess: &core, BeforeAccessRecords: rows, SelectionPhase: &phase}) {
		t.Fatal("exact before-access image was not owned")
	}
	defer a.clear()
	candidate := generatedCandidate{SupportRecords: []contract.SupportRecord{{Kind: contract.GeneratedPhaseSupportKind,
		RecordID: phase.OperationID, Body: phaseBody}}, AccessRecords: a.beforeAccessRecords}
	if !a.candidateAutomaticAccessMatches(candidate) {
		t.Fatal("unchanged access image failed preservation")
	}
	// Core separately proves a complete record has no remaining owner. The
	// Crypto preservation guard pins every surviving record without requiring
	// an ended independent material to remain present.
	candidate.AccessRecords = slices.DeleteFunc(slices.Clone(candidate.AccessRecords), func(row contract.AccessRecord) bool {
		return row.MaterialID == unused.MaterialID
	})
	if len(candidate.AccessRecords) != 1 || !a.candidateAutomaticAccessMatches(candidate) {
		t.Fatal("whole unused access record could not end")
	}
	changed, err := contract.DecodeAccessRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	changed.Wraps[0].RSACiphertext[0] ^= 1
	candidate.AccessRecords[0] = changed
	if a.candidateAutomaticAccessMatches(candidate) {
		t.Fatal("whole-record removal allowed surviving ciphertext drift")
	}
}
