package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestInstalledApplyChangedSubjectsCommitsCompleteEntryAndMembershipChanges(t *testing.T) {
	id := func(n byte) contract.ID { return contract.ID{n} }
	s := &StateSession{}
	s.root.Domain = id(1)
	s.pages[0] = &format.ValueEntryPage{}
	s.pages[0].Slots[0] = &format.ValueEntry{Incarnation: id(10), ValueSource: contract.Supplied, Recipients: []contract.ID{id(2), id(3)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	s.pages[0].Slots[1] = &format.ValueEntry{Incarnation: id(11), ValueSource: contract.Supplied, Recipients: []contract.ID{id(2)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	c := &Comparison{session: s, desiredEntries: []ApplyEntryInput{{Name: "alpha", ValueSource: contract.Supplied, Recipients: []contract.ID{id(2), id(4)}}, {Name: "beta", ValueSource: contract.Supplied, Recipients: []contract.ID{id(2)}}}, slots: []uint16{0, 2}, changed: []uint16{0, 2}, added: []uint16{2}, removed: []uint16{1}}
	p := transitionPlan{incarnations: map[uint16]contract.ID{2: id(12)}}
	got, err := installedApplyChangedSubjects(c, p)
	if err != nil {
		t.Fatal(err)
	}
	// Independently derived with Python hashlib/struct. Hash each identity's
	// purpose, domain {1}, kind and padded primary/secondary IDs. Canonical
	// (kind,change,primary,secondary) rows are (1,3,10,0), (3,2,10,3),
	// (3,1,10,4), (1,2,11,0), (3,2,11,2), (1,1,12,0), (3,1,12,2).
	// Sort their 34-byte encodings; prefix count and every row with BE32
	// lengths. Hash the generator purpose plus B(the complete 270-byte vector).
	const digest = "948095bed86cfab982a6757447b58996878c0b5a1b4a56c44fb07248604c9df4"
	if got.Count != 7 || got.Length != 270 || hex.EncodeToString(got.Digest[:]) != digest {
		t.Fatal("changed-subject commitment differs", got)
	}
}

// full_only: false
func TestInstalledApplyChangedSubjectsEnforcesCompleteSetCeiling(t *testing.T) {
	s := &StateSession{}
	s.root.Domain = contract.Hash([]byte("subject ceiling domain"))
	c := &Comparison{session: s}
	for slot := uint16(0); slot < contract.CryptoMaxValueEntries; slot++ {
		page := int(slot) / format.PageSlots
		if s.pages[page] == nil {
			s.pages[page] = &format.ValueEntryPage{}
		}
		entry := &format.ValueEntry{ValueSource: contract.Supplied, Incarnation: contract.Hash(binary.BigEndian.AppendUint16([]byte("entry"), slot)), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
		for n := byte(1); n <= 31; n++ {
			entry.Recipients = append(entry.Recipients, contract.ID{n})
		}
		s.pages[page].Slots[int(slot)%format.PageSlots] = entry
		c.removed = append(c.removed, slot)
	}
	got, err := installedApplyChangedSubjects(c, transitionPlan{})
	if err != nil || got.Count != contract.MutationChangedSubjectLimit {
		t.Fatal("exact subject ceiling refused", got.Count, err)
	}
	s.pages[0].Slots[0].Recipients = append(s.pages[0].Slots[0].Recipients, contract.ID{32})
	if _, err := installedApplyChangedSubjects(c, transitionPlan{}); err != contract.ErrRecordCapacity {
		t.Fatal("incomplete over-limit commitment accepted", err)
	}
}

// full_only: false
func TestInstalledApplyChangedSubjectsIncludesGeneratedAndRegistryChanges(t *testing.T) {
	id := func(n byte) contract.ID { return contract.ID{n} }
	s := &StateSession{}
	s.root.Domain = id(1)
	s.pages[0] = &format.ValueEntryPage{}
	for i := range 3 {
		s.pages[0].Slots[i] = &format.ValueEntry{Incarnation: id(byte(10 + i)), ValueSource: contract.Generated,
			Generated: contract.GeneratedEntryMetadata{GenerationID: id(byte(20 + i))}, Recipients: []contract.ID{id(2)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	}
	s.recipients[0] = &format.RecipientPage{}
	s.recipients[0].Slots[0] = &format.Recipient{RecipientID: id(2)}
	s.recipients[0].Slots[1] = &format.Recipient{RecipientID: id(4)}
	c := &Comparison{session: s, desiredEntries: []ApplyEntryInput{
		{Name: "generated", ValueSource: contract.Generated, Recipients: []contract.ID{id(2)}},
		{Name: "supplied", ValueSource: contract.Supplied, Recipients: []contract.ID{id(2)}},
	}, slots: []uint16{0, 1}, changed: []uint16{0, 1}, removed: []uint16{2}, recipientChanges: []contract.ID{id(2), id(3), id(4)},
		retirement: &contract.RecipientRetirementRow{RecipientID: id(4)}}
	p := transitionPlan{incarnations: map[uint16]contract.ID{1: id(13)}, values: map[uint16]contract.ID{0: id(23)}}
	got, err := installedApplyChangedSubjects(c, p)
	// Independent Python hashlib/struct derivation uses domain {1}. Semantic
	// (kind,change,primary,secondary) rows are: removed entry12/generation22/
	// membership(12,2); updated entry10, removed generation20, added23; removed
	// entry11/generation21/membership(11,2), added entry13/membership(13,2);
	// updated recipient2, added3, removed4. Hash identities, sort all34-byte
	// rows, BE32-frame the14 rows and complete536-byte vector as above.
	const digest = "260a2fc0ae0acef90c1ab785a6c5d78c8f117e44e02ac5e7c617e4cf23cfcffb"
	if err != nil || got.Count != 14 || got.Length != 536 || hex.EncodeToString(got.Digest[:]) != digest {
		t.Fatal("generated/source-handoff/registry change set differs", got, err)
	}
}

// full_only: false
func TestInstalledApplyChangedSubjectsIncludesRemovedOutputBinding(t *testing.T) {
	root, _, before, _ := inspectionOutputFixture(t)
	if len(before.Bindings) != 1 {
		t.Fatal("fixture has no exact single output binding")
	}
	s := &StateSession{root: root}
	c := &Comparison{session: s, outputChanged: true, outputAfter: &outputApplySelection{transition: &contract.NormalOutputTransition{Before: before}}}
	got, err := installedApplyChangedSubjects(c, transitionPlan{operation: contract.ID{99}})
	identity := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), root.Domain[:]...)
	identity = append(identity, 5)
	identity = append(identity, before.Bindings[0].IncarnationID[:]...)
	identity = append(identity, make([]byte, 32)...)
	hash := sha256.Sum256(identity)
	row := append([]byte{5, 2}, hash[:]...)
	vector := binary.BigEndian.AppendUint32(nil, 1)
	vector = append(binary.BigEndian.AppendUint32(vector, 34), row...)
	preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/changed-subjects\x00"), uint32(len(vector)))
	want := contract.GeneratorDescriptor{Digest: sha256.Sum256(append(preimage, vector...)), Length: 42, Count: 1}
	if err != nil || got != want {
		t.Fatal("ordinary output removal omitted the exact binding subject", got, want, err)
	}
}

// full_only: false
func TestInstalledApplyChangedAccessCountsOnlyChangedSurvivingMaterial(t *testing.T) {
	s := generatedReservationState(t)
	old := s.access[0].Records[0]
	old.MaterialKind = contract.ValueMaterialKind
	changed := old
	changed.Wraps = slices.Clone(old.Wraps)
	grant := changed.Wraps[0]
	grant.SubjectID, grant.BindingID, grant.PublicBindingDigest = generatedVectorID(90), generatedVectorID(91), generatedVectorID(92)
	changed.Wraps = append(changed.Wraps, grant)
	fresh := changed
	fresh.MaterialID = generatedVectorID(93)
	for _, row := range []contract.AccessRecord{old, changed, fresh} {
		if _, err := contract.AccessRecordLength(row); err != nil {
			t.Fatal("ordinary access fixture is not valid", err)
		}
	}
	for _, test := range []struct {
		name  string
		after []contract.AccessRecord
		count uint32
	}{{"changed", []contract.AccessRecord{changed}, 1}, {"unchanged", []contract.AccessRecord{old}, 0},
		{"removed", nil, 0}, {"fresh-material", []contract.AccessRecord{fresh}, 0}, {"changed-and-fresh", []contract.AccessRecord{changed, fresh}, 1}} {
		t.Run(test.name, func(t *testing.T) {
			got, err := installedApplyAccessChanges([]contract.AccessRecord{old}, test.after, s.root.Domain)
			if err != nil || got.Count != test.count || got.Length != 4+102*uint64(test.count) {
				t.Fatal("ordinary changed-access count includes an unchanged, removed or fresh material", got, err)
			}
			if test.count == 0 {
				preimage := append([]byte("ENKV/GENERATOR/v1/changed-access\x00"), 0, 0, 0, 4, 0, 0, 0, 0)
				want := sha256.Sum256(preimage)
				if !bytes.Equal(got.Digest[:], want[:]) {
					t.Fatal("empty ordinary changed-access commitment differs")
				}
			}
		})
	}
}
