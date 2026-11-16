package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedVectorID(n byte) contract.ID {
	var id contract.ID
	for i := range id {
		id[i] = n
	}
	return id
}

func generatedVectorRows(t testing.TB, ownerKind uint8, owner contract.ID, kind contract.GeneratorVectorKind, rows [][]byte) (contract.GeneratorDescriptor, []contract.SupportRecord) {
	return generatedVectorRowsForDomain(t, generatedVectorID(1), ownerKind, owner, kind, rows)
}

func generatedVectorRowsForDomain(t testing.TB, domain contract.ID, ownerKind uint8, owner contract.ID,
	kind contract.GeneratorVectorKind, rows [][]byte) (contract.GeneratorDescriptor, []contract.SupportRecord) {
	t.Helper()
	d, err := contract.GeneratorVectorDescriptor(kind, rows)
	if err != nil {
		t.Fatal(err)
	}
	carriers := make([]contract.SupportRecord, len(rows))
	for i, row := range rows {
		c := contract.GeneratorVectorCarrier{Schema: 1, DomainID: domain, OwnerKind: ownerKind, OwnerID: owner,
			VectorKind: kind, Ordinal: uint32(i), Vector: d, Row: row}
		body, err := contract.EncodeGeneratorVectorCarrier(c)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorVectorCarrierID(c)
		if err != nil {
			t.Fatal(err)
		}
		carriers[i] = contract.SupportRecord{Kind: 14, RecordID: id, Body: body}
	}
	return d, carriers
}

// full_only: false
func TestGeneratedVectorResolutionRequiresExactOwnerAndWholeVector(t *testing.T) {
	id := generatedVectorID
	var bodies [][]byte
	for _, n := range []byte{2, 3} {
		row, err := contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1, AttemptID: id(n), ResultID: id(4),
			Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs), RequiredSteps: 1, CompletionClass: 1})
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, row)
	}
	d, records := generatedVectorRows(t, 10, id(5), contract.GeneratorVectorProgress, bodies)
	slices.Reverse(records)
	vectors, err := newGeneratedVectorSet(id(1), records)
	if err != nil {
		t.Fatal(err)
	}
	validation := newGeneratedVectorValidation(&vectors)
	if validation.complete() {
		t.Fatal("unreferenced carriers accepted")
	}
	for _, owner := range []struct {
		kind uint8
		id   contract.ID
	}{{9, id(5)}, {10, id(6)}} {
		if _, err := vectors.resolve(owner.kind, owner.id, contract.GeneratorVectorProgress, d); err == nil {
			t.Fatal("wrong vector owner accepted")
		}
	}
	for _, wrong := range []contract.GeneratorDescriptor{{Digest: id(9), Length: d.Length, Count: d.Count}, {Digest: d.Digest, Length: d.Length + 1, Count: d.Count}} {
		if _, err := vectors.resolve(10, id(5), contract.GeneratorVectorProgress, wrong); err == nil {
			t.Fatal("unequal descriptor accepted")
		}
	}
	borrowed, err := vectors.resolve(10, id(5), contract.GeneratorVectorProgress, d)
	if err != nil || len(borrowed) != 2 || validation.complete() {
		t.Fatal("pure vector lookup changed owner coverage", err)
	}
	key := generatedVectorKey{10, id(5), contract.GeneratorVectorProgress, d}
	if &borrowed[0][0] != &vectors.entries[key].rows[0][0] {
		t.Fatal("vector row did not borrow authenticated carrier bytes")
	}
	borrowed[0] = nil
	if vectors.entries[key].rows[0] == nil {
		t.Fatal("vector lookup shared its outer row container")
	}
	got, err := validation.resolve(10, id(5), contract.GeneratorVectorProgress, d)
	if err != nil || len(got) != 2 || !bytes.Equal(got[0], bodies[0]) || !bytes.Equal(got[1], bodies[1]) || !validation.complete() {
		t.Fatal("exact vector resolution", err)
	}
	// Several real consumers can anchor the same immutable vector.
	if _, err := vectors.resolve(10, id(5), contract.GeneratorVectorProgress, d); err != nil {
		t.Fatal(err)
	}
	for _, damaged := range [][]contract.SupportRecord{records[:1], append(slices.Clone(records), records[0])} {
		if _, err := newGeneratedVectorSet(id(1), damaged); err == nil {
			t.Fatal("missing or duplicate ordinal accepted")
		}
	}
	if _, err := newGeneratedVectorSet(id(9), records); err == nil {
		t.Fatal("cross-domain carrier accepted")
	}
	bad := slices.Clone(records)
	bad[0].RecordID = id(7)
	if _, err := newGeneratedVectorSet(id(1), bad); err == nil {
		t.Fatal("wrong carrier identity accepted")
	}
}

func generatedAttemptVectorFixture() contract.GeneratedAttemptRecord {
	id := generatedVectorID
	return contract.GeneratedAttemptRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedAttemptRecordSchema, DomainID: id(1), OperationID: id(2), LineageID: id(3), AttemptID: id(4),
		TemplateDigest: id(5), OwnerID: id(6), ResourceID: id(7), TransmissionID: id(8), ResultID: id(9), InboxID: id(10),
		ConfigContractID: id(11), ResourceContractID: id(12), ExecutorID: id(13), CredentialRouteID: id(14), DescriptorID: id(15), ResultContractID: id(16), RequestDigest: id(17),
		State: contract.GeneratedEffectTransmitted, Stage: contract.GeneratedStageRetainedResult, CompletionClass: 1,
		Facts: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts), Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress),
		Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)}
}

// full_only: false
func TestGeneratedVectorAnchorsIncludeDetachedAttemptSupport(t *testing.T) {
	id := generatedVectorID
	attempt := generatedAttemptVectorFixture()
	row, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 3, ContractID: id(20), ImplementationID: id(21), PublicBindingDigest: id(22)})
	if err != nil {
		t.Fatal(err)
	}
	d, records := generatedVectorRows(t, 2, attempt.OperationID, contract.GeneratorVectorSupport, [][]byte{row})
	attempt.Support = d
	body, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, contract.SupportRecord{Kind: 9, RecordID: attempt.AttemptID, Body: body})
	closure := format.EmptyGeneratedClosure()
	if _, err := resolveGeneratedVectorOwners(id(1), id(23), closure, records, nil, nil); err != nil {
		t.Fatal("detached operation support required an obsolete parent", err)
	}
	if facts, err := resolveGeneratedVectorOwners(id(1), id(23), closure, records[:1], nil, nil); err == nil || facts.entries != nil {
		t.Fatal("carrier alone became its own retention root")
	}
	attempt.OperationID = id(24)
	body, err = contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	records[1].Body = body
	if facts, err := resolveGeneratedVectorOwners(id(1), id(23), closure, records, nil, nil); err == nil || facts.entries != nil {
		t.Fatal("original support relabelled into another operation")
	}
}

// full_only: false
func TestGeneratedConfirmedProgressBindsIndexedResultEvidence(t *testing.T) {
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[g.phase.FrontierAttemptID]
	resultBody := generatedPublicResultFixture(t, a, 1)
	result := contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: a.record.ResultID, Body: resultBody}
	progress := contract.GeneratorProgress{Schema: 1, AttemptID: a.record.AttemptID, ResultID: a.record.ResultID,
		Evidence:      contract.GeneratorDescriptor{Digest: contract.Hash(resultBody), Length: uint64(len(resultBody)), Count: 1},
		RequiredSteps: 2, CompletedSteps: 1, CompletionClass: contract.GeneratedCompletionConfirmed}
	progressBody, err := contract.EncodeGeneratorProgress(progress)
	if err != nil {
		t.Fatal(err)
	}
	attempt := a.record
	attempt.CompletionClass = contract.GeneratedCompletionConfirmed
	descriptor, carriers := generatedVectorRowsForDomain(t, s.root.Domain, 9, attempt.AttemptID, contract.GeneratorVectorProgress, [][]byte{progressBody})
	attempt.Progress = descriptor
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	attemptRow := contract.SupportRecord{Kind: 9, RecordID: attempt.AttemptID, Body: attemptBody}
	records := append([]contract.SupportRecord{result, attemptRow}, carriers...)
	check := func(rows []contract.SupportRecord) error {
		facts, err := resolveGeneratedVectorOwners(s.root.Domain, s.root.Snapshot, format.EmptyGeneratedClosure(), rows, nil, nil)
		if err != nil && facts.entries != nil {
			t.Fatal("failed owner validation returned vector facts")
		}
		return err
	}
	if err := check(records); err != nil {
		t.Fatal("valid confirmed progress refused", err)
	}
	for _, damage := range []struct {
		name string
		rows []contract.SupportRecord
	}{
		{"missing result", records[1:]},
		{"duplicate result", append(slices.Clone(records), result)},
		{"changed result body", func() []contract.SupportRecord {
			rows := slices.Clone(records)
			rows[0].Body = append(bytes.Clone(resultBody), 0)
			return rows
		}()},
	} {
		t.Run(damage.name, func(t *testing.T) {
			if err := check(damage.rows); err == nil {
				t.Fatal("changed result evidence admitted")
			}
		})
	}
}

// full_only: false
func TestLocalGeneratedVectorOwnersKeepRemoteFieldsAbsent(t *testing.T) {
	id := generatedVectorID
	a := generatedAttemptVectorFixture()
	a.Schema, a.LifecycleMode = contract.GeneratedAttemptRecordSchema, contract.GeneratorLifecycleNone
	a.ResourceContractID = contract.ID{}
	a.CompletionClass, a.Progress = 0, contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a)
	if err != nil {
		t.Fatal(err)
	}
	d := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, LifecycleMode: contract.GeneratorLifecycleNone,
		DomainID: a.DomainID, DutyID: a.OwnerID, OriginalOperationID: a.OperationID, OriginalAttemptID: a.AttemptID, OwnerID: a.OwnerID, ResourceID: a.ResourceID,
		DescriptorID: a.DescriptorID, ConfigContractID: a.ConfigContractID, ResourceContractID: a.ResourceContractID, ExecutorID: a.ExecutorID, CredentialRouteID: a.CredentialRouteID, ResultContractID: a.ResultContractID,
		Kind: contract.GeneratedDutyCreate, Step: 1, Status: contract.GeneratedEffectTransmitted,
		CapacityReservation: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs), Target: contract.EmptyGeneratorVector(contract.GeneratorVectorTargets), Progress: a.Progress,
		History: a.History, Support: a.Support, Consumers: contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers)}
	dutyBody, err := contract.EncodeGeneratedDutyRecord(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []contract.SupportRecord{
		{Kind: contract.GeneratedAttemptSupportKind, RecordID: a.AttemptID, Body: attemptBody},
		{Kind: contract.GeneratedDutySupportKind, RecordID: d.DutyID, Body: dutyBody},
	} {
		name := "attempt"
		if row.Kind == contract.GeneratedDutySupportKind {
			name = "create duty"
		}
		t.Run(name, func(t *testing.T) {
			records := []contract.SupportRecord{row}
			if _, err := resolveGeneratedVectorOwners(id(1), id(23), format.EmptyGeneratedClosure(), records, nil, nil); err != nil {
				t.Fatal("local absent remote fields were required as vectors", err)
			}
			progress, err := contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1, AttemptID: a.AttemptID, ResultID: a.ResultID,
				Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs), RequiredSteps: 1, CompletionClass: 1})
			if err != nil {
				t.Fatal(err)
			}
			_, carriers := generatedVectorRows(t, row.Kind, row.RecordID, contract.GeneratorVectorProgress, [][]byte{progress})
			records = append(records, carriers...)
			if _, err := resolveGeneratedVectorOwners(id(1), id(23), format.EmptyGeneratedClosure(), records, nil, nil); err == nil {
				t.Fatal("local orphan remote progress carrier accepted")
			}
		})
	}
}
