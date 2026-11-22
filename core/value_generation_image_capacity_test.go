package core

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedAdmissionFinalImageDoesNotChargeUnusedRegistryReaders(t *testing.T) {
	// The existing authenticated canonical fixture has a 64-reader current row,
	// a different 64-reader retained alias, and their exact 127-reader union.
	// Add one current but unused registry row. It grants no material readership.
	s, _, _ := generatedCanonicalState(t, false)
	binding := generatedPublicBinding(t, 240)
	binding.Provider, binding.ProtectionClass = contract.AWS, contract.HardwareProtection
	binding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000240"
	binding.BindingID = contract.Hash([]byte("image capacity unused registry binding"))
	binding.BindingIncarnationID = contract.Hash([]byte("image capacity unused registry incarnation"))
	if s.recipients[15] == nil || s.recipients[15].Slots[7] != nil {
		t.Fatal("fixture must leave exactly the final slot free")
	}
	s.recipients[15].Slots[7] = &contract.RecipientRecord{RecipientID: generatedVectorID(240), Status: contract.CurrentRecipient, CurrentBinding: &binding}
	generatedSealSelectedFixture(t, s)
	basis, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	basis.Recipients = s.registry()
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(basis)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil || len(s.registry()) != 128 || len(selected.retainedReaders(generatedVectorID(82))) != 64 {
		t.Fatal("complete selected canonical/registry fixture", err)
	}
	current := s.valueEntry(7)
	retained, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: 7, Entry: *current})
	if err != nil {
		t.Fatal(err)
	}
	source := contract.GeneratorDeclarationEntry{InputEncoding: current.InputEncoding, OutputEncoding: current.OutputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained, Name: current.Name, Recipients: slices.Clone(current.Recipients), Payload: retained}
	base, _, _ := generatedEffectPlanFixture(t)
	request := base.Request
	request.OperationID = generatedVectorID(250)
	request.DomainID = s.admission.domain
	request.PredecessorRevisionID, request.PredecessorHEADDigest = s.head.Core.Revision, contract.Hash(s.body)
	request.ConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	graph, declaration, _ := generatedEffectPlanForRequest(t, &request, source)
	encoded, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectGeneratorDeclaration(encoded)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := s.generatedAdmissionShape(t.Context(), graph, view, selected)
	if err != nil {
		t.Fatal("qualified admission shape", err)
	}
	shape.DeclarationBytes = uint64(len(encoded))
	// Rebuild only the generic public-bound facts, independently of any private
	// selected-reader proof added to production admission. The generic fallback
	// must remain safe for callers which do not own that proof.
	generic := generatedCapacityShape{ValueEntryCount: shape.ValueEntryCount, ValueEntryPageCount: shape.ValueEntryPageCount,
		Recipients: shape.Recipients, Secrets: shape.Secrets, Memberships: shape.Memberships, SecretMemberships: shape.SecretMemberships,
		Generated: shape.Generated, OldGenerated: shape.OldGenerated, Creates: shape.Creates, Retirements: shape.Retirements,
		ValueEntryPlanCount: shape.ValueEntryPlanCount, Sources: shape.Sources, RetainedSources: shape.RetainedSources,
		ControlledRetirements: shape.ControlledRetirements, Cleanups: shape.Cleanups, ControlledCleanups: shape.ControlledCleanups,
		DeclarationBytes: shape.DeclarationBytes, OldIntentBytes: shape.OldIntentBytes, Recovery: shape.Recovery}
	charged, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := generatedCleanCapacity(generic)
	if err != nil {
		t.Fatal(err)
	}
	if shape.Creates != 1 || shape.ValueEntryPlanCount != 2 || shape.Recipients != 128 {
		t.Fatal("fixture lost one retained image row and one fresh create")
	}
	// The current/retained sets share the Authority: 64+64-1=127, not the
	// 128-row registry. The generic shape also reserves a 64-byte grant seal
	// for each of its 65 memberships. Neither image row adds a reader.
	want := fallback[contract.GeneratorCapacityAuxiliary].MaxFramedBytes - 489 - 65*64
	if charged[contract.GeneratorCapacityAuxiliary].MaxFramedBytes != want {
		t.Fatal("Final image charged an unused registry recipient", charged[contract.GeneratorCapacityAuxiliary], fallback[contract.GeneratorCapacityAuxiliary])
	}
	// This owner refinement affects only the prospective image term. Existing
	// backlog tests separately require complete 127-reader retained access.
	for tag := range charged {
		if tag != contract.GeneratorCapacityAuxiliary && charged[tag] != fallback[tag] {
			t.Fatal("image refinement changed another capacity group", tag)
		}
	}
}

// full_only: false
func TestGeneratedFinalImageReaderCountPreservesHistoricalUnions(t *testing.T) {
	id := generatedVectorID
	current := &contract.ValueEntry{ValueState: id(1), ConfidentialityClass: contract.Secret, Recipients: []contract.ID{id(2), id(3)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	historical := contract.ValueEntry{ValueState: id(1), ConfidentialityClass: contract.Secret, Recipients: []contract.ID{id(3), id(4)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	other := historical
	other.ValueState, other.Recipients = id(9), []contract.ID{id(8)}
	selected := &generatedSelection{canonical: map[contract.ID]generatedCanonical{
		id(10): {record: contract.RetainedCanonicalRecord{Entry: historical}},
		id(11): {record: contract.RetainedCanonicalRecord{Entry: historical}},
		id(12): {record: contract.RetainedCanonicalRecord{Entry: other}},
	}}
	for _, row := range []struct {
		name     string
		current  *contract.ValueEntry
		intended []contract.ID
		want     uint64
	}{
		{"unchanged alias union", current, []contract.ID{id(2), id(3)}, 3},
		{"grant", current, []contract.ID{id(2), id(3), id(5)}, 4},
		{"exclusion stays conservative", current, []contract.ID{id(2)}, 3},
		{"fresh material", nil, []contract.ID{id(2), id(5)}, 2},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, err := generatedFinalImageReaderCount(row.current, row.intended, selected, 8)
			if err != nil || got != row.want {
				t.Fatal("prospective reader union", got, row.want, err)
			}
		})
	}
	// The structural historical union remains 256 even though each selected
	// canonical/current row has at most64 members. No old64-row cap is restored.
	selected.canonical = make(map[contract.ID]generatedCanonical)
	for group := byte(0); group < 4; group++ {
		entry := historical
		entry.Recipients = nil
		for n := 0; n < 64; n++ {
			var reader contract.ID
			reader[0], reader[1] = group+1, byte(n)
			entry.Recipients = append(entry.Recipients, reader)
		}
		selected.canonical[id(group+20)] = generatedCanonical{record: contract.RetainedCanonicalRecord{Entry: entry}}
	}
	current.Recipients = slices.Clone(selected.canonical[id(20)].record.Entry.Recipients)
	got, err := generatedFinalImageReaderCount(current, current.Recipients, selected, 256)
	if err != nil || got != 256 {
		t.Fatal("historical union lost full structural bound", got, err)
	}
	if _, err := generatedFinalImageReaderCount(current, current.Recipients, selected, 255); err != contract.ErrRecordCapacity {
		t.Fatal("unbounded reader proof admitted", err)
	}
}

// full_only: false
func TestGeneratedFinalImageCapacityProofSharesAdministrativeReservation(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 50, ValueEntryPageCount: 4, Recipients: 256, Secrets: 50, Memberships: 50, SecretMemberships: 50,
		Generated: 1, Creates: 1, ValueEntryPlanCount: 50, DeclarationBytes: 512}
	generic, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	genericRows, _, _, err := generatedAdministrativeRowEnvelope(shape)
	if err != nil {
		t.Fatal(err)
	}
	proof := uint64(49)
	shape.finalImageReaders = &proof
	qualified, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	qualifiedRows, _, _, err := generatedAdministrativeRowEnvelope(shape)
	if err != nil {
		t.Fatal(err)
	}
	old, new := generic[contract.GeneratorCapacityAuxiliary], qualified[contract.GeneratorCapacityAuxiliary]
	// Independent scalar framing: fixed auxiliary2275328 + current entries
	// 4403074 (50 entries with 87384 retained bytes) + current access29550
	// + remaining image framing18681.
	// Generic adds 49*256*489 and 50*64 for possible grants. Qualified
	// adds 49*489 and has no new grant. Fragment payload 1048320
	// gives 13 vs 7 fragments; each fragment adds37+86=123 framing bytes.
	if old != (contract.GeneratorCapacityGroup{MaxCount: 13, MaxFramedBytes: 12865448, MaxPages: 7}) ||
		new != (contract.GeneratorCapacityGroup{MaxCount: 7, MaxFramedBytes: 6751455, MaxPages: 4}) ||
		old.MaxFramedBytes-new.MaxFramedBytes != 49*255*489+50*64+123*6 ||
		genericRows[contract.GeneratedFragmentSupportKind]-qualifiedRows[contract.GeneratedFragmentSupportKind] != 6 {
		t.Fatal("index did not use the same prospective fragment reserve", old, new)
	}
	proof = 49*256 + 1
	if _, err := generatedCleanCapacity(shape); err != contract.ErrRecordCapacity {
		t.Fatal("reader proof exceeded generic ceiling", err)
	}
}
