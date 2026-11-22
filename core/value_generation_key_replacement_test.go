package core

import (
	"context"
	"encoding/hex"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedReplacementIncludesEveryLiveSeedConsumer(t *testing.T) {
	var previous contract.ID
	for _, sources := range [][]contract.GeneratorDeclarationEntry{nil,
		{generatedSealedSource(t, "alpha")},
		{generatedSealedSource(t, "alpha"), generatedSealedSource(t, "omega")}} {
		s := generatedReservationState(t, sources...)
		target := contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 95)}
		rows, err := s.replacementMaterialRows(t.Context(), 0, 1, target)
		if err != nil || len(rows) != 1 {
			t.Fatal("replacement lost occupied seed", err, len(rows))
		}
		row := rows[0]
		if row.Coverage.MaterialKind != 3 || row.Coverage.MaterialID != row.OperationMaterialCore.OperationMaterialID ||
			row.Coverage.RequiredConsumerDigest.IsZero() || row.Coverage.RequiredConsumerDigest == previous ||
			row.Coverage.SourceBindingIndex != 0 || len(row.Coverage.TargetBindingIndices) != 1 || row.Coverage.TargetBindingIndices[0] != 1 {
			t.Fatal("replacement omitted a source or result consumer")
		}
		previous = row.Coverage.RequiredConsumerDigest
	}
}

// full_only: false
func TestGeneratedReplacementDeduplicatesCurrentAndRetainedValue(t *testing.T) {
	// Independent Python concatenation uses schema 11, canonical-state/v14,
	// canonical intent-v3, initial epoch0 and fixed CryptoSupport metadata. The
	// alpha ValueCore is 327 bytes, its Duty consumer 132, and the vector 140.
	want, err := hex.DecodeString("a8f08f803ee93c261cf6fb82b334c17deae5a1e2c399c8a9f30a177e93d819d6")
	if err != nil {
		t.Fatal(err)
	}
	for _, recovery := range []bool{false, true} {
		for _, target := range []struct {
			kind    uint8
			subject byte
			count   int
		}{
			{1, 11, 2}, {1, 100, 1}, {1, 163, 1}, {1, 99, 0}, {2, 93, 2},
		} {
			if target.kind == 2 && !recovery {
				continue
			}
			s, retained, _ := generatedCanonicalState(t, recovery)
			binding := contract.BindingTableRow{SubjectKind: target.kind, SubjectID: generatedVectorID(target.subject), Binding: generatedPublicBinding(t, 95)}
			rows, err := s.replacementMaterialRows(t.Context(), 0, 1, binding)
			if err != nil || len(rows) != target.count {
				t.Fatalf("target %d/%d lost or duplicated material: err=%v rows=%d", target.kind, target.subject, err, len(rows))
			}
			if target.count == 0 {
				continue
			}
			value := rows[0]
			if value.Coverage.MaterialKind != 1 || value.Coverage.MaterialID != retained.Entry.ValueState ||
				value.Coverage.RequiredConsumerDigest != contract.ID(want) || value.ValueCore.ValueStateID != retained.Entry.ValueState ||
				len(value.BeforeAccessRecord.Wraps) != 127+boolInt(recovery) {
				t.Fatal("replacement changed the exact retained reader relation")
			}
		}
	}
}

// full_only: false
func TestGeneratedReplacementRejectsOrphanedAccessAndConsumers(t *testing.T) {
	for _, orphanAccess := range []bool{false, true} {
		s, _, consumers := generatedCanonicalState(t, false)
		if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !orphanAccess && generatedIndexRejectsAlteredSupport(t, s) {
			t.Fatal("valid replacement fixture was refused before the orphaned consumer")
		}
		if orphanAccess {
			extra := *generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82))
			extra.MaterialID = generatedVectorID(99)
			s.access[0].Records = append(s.access[0].Records, extra)
			s.root.AccessRecordCount++
			generatedCommitFixtureAccess(t, s)
			if _, err := format.EncodeRoot(s.root); err != nil {
				t.Fatal("orphan fixture refused before ownership check", err)
			}
			if !s.indexSelectedMaterials() {
				t.Fatal("material index")
			}
		} else {
			generatedSetDutyConsumersUnrefreshed(t, s, consumers[:2])
			if !generatedIndexRejectsAlteredSupport(t, s) {
				t.Fatal("orphaned consumer acquired authenticated ownership")
			}
			continue
		}
		rows, err := s.replacementMaterialRows(t.Context(), 0, 1, contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 95)})
		if err == nil || rows != nil {
			t.Fatal("invalid selected dependency reached replacement")
		}
	}
}

// full_only: false
func TestGeneratedReplacementRetainsValueWithoutCurrentMember(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		s, retained, _ := generatedCanonicalState(t, recovery)
		s.root.Names, s.root.ValueEntryCount, s.root.SecretCount = nil, 0, 0
		s.pages[0] = nil
		access := generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82))
		access.Wraps = slices.DeleteFunc(slices.Clone(access.Wraps), func(w contract.WrapRow) bool {
			return w.SubjectKind == 1 && !slices.Contains(retained.Entry.Recipients, w.SubjectID)
		})
		generatedSealSelectedFixture(t, s)
		if !s.indexSelectedMaterials() {
			t.Fatal("material index")
		}
		rows, err := s.replacementMaterialRows(t.Context(), 0, 1, contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 95)})
		if err != nil || len(rows) != 2 || rows[0].Coverage.MaterialID != retained.Entry.ValueState || len(rows[0].BeforeAccessRecord.Wraps) != 64+boolInt(recovery) {
			t.Fatal("live retained value depended on a current member")
		}
	}
}

// full_only: false
func TestGeneratedReplacementKeepsCurrentOnlyConsumerDigest(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		occupied, _, _ := generatedCanonicalState(t, recovery)
		s := generatedContentState(t, nil, nil)
		generatedFixtureSelectedShell(t, s)
		generatedInitializeFixtureOutput(t, s)
		s.admission.recipient = occupied.admission.recipient
		s.root.CurrentAccess, s.root.Names = occupied.root.CurrentAccess, occupied.root.Names
		s.root.ValueEntryCount, s.root.SecretCount, s.root.AccessRecordCount = 1, 1, 1
		s.pages, s.recipients = occupied.pages, occupied.recipients
		value := *generatedFixtureMaterialAccess(t, occupied, contract.ValueMaterialKind, generatedVectorID(82))
		value.Wraps = slices.DeleteFunc(slices.Clone(value.Wraps), func(w contract.WrapRow) bool {
			return w.SubjectKind == 1 && !slices.Contains(s.pages[0].Slots[7].Recipients, w.SubjectID)
		})
		s.access[0] = &format.AccessPage{Records: []contract.AccessRecord{value}}
		generatedSealSelectedFixture(t, s)
		if !s.indexSelectedMaterials() {
			t.Fatal("material index")
		}
		rows, err := s.replacementMaterialRows(t.Context(), 0, 1, contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 95)})
		if err != nil {
			t.Fatal("current-only replacement refused", err)
		}
		digest, err := contract.CurrentValueConsumerDigest(s.root.Domain)
		if err != nil || len(rows) != 1 || rows[0].Coverage.RequiredConsumerDigest != digest {
			t.Fatal("current-only consumer meaning changed", err)
		}
	}
}
