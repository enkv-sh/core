package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRecipientReplacementSubjectsIncludeRetainedOwnersExactlyOnce(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	id := generatedVectorID
	affected := contract.ValueEntry{Incarnation: id(91), ValueState: id(92), ValueSource: contract.Generated,
		ConfidentialityClass: contract.Secret, Generated: contract.GeneratedEntryMetadata{GenerationID: id(93)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	untouched := affected
	untouched.Incarnation, untouched.ValueState, untouched.Generated.GenerationID = id(94), id(95), id(96)
	g := &generatedSelection{canonical: map[contract.ID]generatedCanonical{
		id(97): {record: contract.RetainedCanonicalRecord{Entry: affected}},
		id(98): {record: contract.RetainedCanonicalRecord{Entry: affected}},
		id(99): {record: contract.RetainedCanonicalRecord{Entry: untouched}},
	}}
	root, ok := s.generatedSelectionRoot()
	if !ok {
		t.Fatal("valid public root fixture")
	}
	// The selected-facts cache isolates the owner projection from authentication,
	// which is covered by the real selected replacement and retained-work tests.
	s.generatedWork = &validatedGeneratedSelection{session: s, root: root, selection: g}
	intent := contract.RecipientReplacementIntent{RecipientID: id(90)}
	rows := []contract.CompactRow{
		{Coverage: contract.CoverageRow{MaterialKind: contract.ValueMaterialKind, MaterialID: affected.ValueState}},
		{Coverage: contract.CoverageRow{MaterialKind: contract.OperationSeedMaterialKind, MaterialID: id(100)}},
	}
	got, err := s.recipientReplacementSubjects(context.Background(), intent, rows)
	if err != nil {
		t.Fatal(err)
	}
	var encoded [][]byte
	for _, subject := range []struct {
		kind    byte
		primary contract.ID
	}{{1, id(91)}, {2, id(90)}, {4, id(93)}} {
		preimage := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), s.root.Domain[:]...)
		preimage = append(preimage, subject.kind)
		preimage = append(preimage, subject.primary[:]...)
		preimage = append(preimage, make([]byte, 32)...)
		digest := sha256.Sum256(preimage)
		encoded = append(encoded, append([]byte{subject.kind, 3}, digest[:]...))
	}
	slices.SortFunc(encoded, bytes.Compare)
	frame := binary.BigEndian.AppendUint32(nil, 3)
	for _, row := range encoded {
		frame = binary.BigEndian.AppendUint32(frame, 34)
		frame = append(frame, row...)
	}
	preimage := []byte("ENKV/GENERATOR/v1/changed-subjects\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(frame)))
	want := contract.GeneratorDescriptor{Digest: sha256.Sum256(append(preimage, frame...)), Length: 118, Count: 3}
	if got != want {
		t.Fatal("retained aliases duplicated owners, omitted generated identity or included untouched owners", got, want)
	}
	delete(g.canonical, id(97))
	delete(g.canonical, id(98))
	if _, err := s.recipientReplacementSubjects(context.Background(), intent, rows); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("affected value material without a selected owner was accepted", err)
	}
}
