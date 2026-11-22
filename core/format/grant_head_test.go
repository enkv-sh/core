package format

import (
	"bytes"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGrantHeadBindsOnlySelectedFinalRows(t *testing.T) {
	head := generatedHeadFixture(t, true)
	head.Generator.RequiredAuthoritySet |= contract.GeneratorAuthorityGrant
	row := accessFixture().Records[0].Wraps[0]
	// Independent wire layout: page index, record index, and the ordinary
	// fixed-size recipient wrap. Both indices are unsigned big-endian words.
	wire := []byte{0, 3, 0, 8}
	body, err := contract.EncodeWrapRow(row)
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, body...)
	head.GrantWraps = wire
	head.Core.GrantDigest = contract.Hash(wire)
	core, err := EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: head.Core.PreviousToken.Family,
		Store: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody,
		Condition: conditionFixture(head.Core.PreviousToken), HeadCore: contract.Hash(core), HeadCoreLength: uint32(len(core))})
	if err != nil {
		t.Fatal(err)
	}
	subject := head.Generator
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(core), uint32(len(core))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(plan), uint32(len(plan))
	encoded, err := EncodeHead(head)
	if err != nil || !bytes.HasSuffix(encoded, wire) {
		t.Fatal("final grant encoding", err)
	}
	got, err := DecodeHead(encoded)
	if err != nil || !bytes.Equal(got.GrantWraps, wire) {
		t.Fatal("final grant decoding", err)
	}
	encoded[len(encoded)-1] ^= 1
	if !bytes.Equal(got.GrantWraps, wire) {
		t.Fatal("decoded grant borrowed input")
	}
	if _, err := DecodeHead(encoded); err == nil {
		t.Fatal("changed grant bytes accepted")
	}
	if _, err := DecodeHead(encoded[:len(encoded)-len(wire)]); err == nil {
		t.Fatal("missing grant bytes accepted")
	}
	subject.Purpose = contract.GeneratorAuthorityFinalPreparation
	if _, err := EncodeHead(head); err == nil {
		t.Fatal("checkpoint carried final grant wraps")
	}
}

// full_only: false
func TestGrantHeadCapacityIncludesProofsAndCoordinates(t *testing.T) {
	// Independent wire sums for a full envelope: 28 framing bytes, 418
	// fixed successor bytes, 32 digest bytes, and 493 bytes per row.
	// A lifecycle has 715 subject bytes. A generated Final has 1140.
	for _, tc := range []struct {
		generated       bool
		rows, token, k3 int
	}{{false, 130, 109, 0}, {false, 130, 37, 72}, {true, 129, 177, 0}, {true, 129, 105, 72}} {
		if !GrantHeadFits(tc.rows, tc.token, 72, tc.k3, tc.generated) || GrantHeadFits(tc.rows, tc.token+1, 72, tc.k3, tc.generated) {
			t.Fatal("incorrect 65,536/65,537 boundary", tc)
		}
	}
	if GrantHeadFits(135, 1, 8, 0, false) {
		t.Fatal("impossible count admitted")
	}
	for _, tokenSize := range []int{105, 106} {
		head := generatedHeadFixture(t, true)
		head.Core.PreviousToken.Value = `"` + strings.Repeat("x", tokenSize-2) + `"`
		subject := head.Generator
		subject.RequiredAuthoritySet |= contract.GeneratorAuthorityGrant
		wrap := accessFixture().Records[0].Wraps[0]
		for i := 0; i < 129; i++ {
			head.GrantWraps = append(head.GrantWraps, 0, 0, 0, byte(i))
			var err error
			head.GrantWraps, err = contract.AppendWrapRow(head.GrantWraps, wrap)
			if err != nil {
				t.Fatal(err)
			}
		}
		head.Core.GrantDigest = contract.Hash(head.GrantWraps)
		core, err := EncodeHeadCore(head.Core)
		if err != nil {
			t.Fatal(err)
		}
		condition := conditionFixture(head.Core.PreviousToken)
		subject.ConditionDigest, err = contract.CryptoConditionDigest(condition)
		if err != nil {
			t.Fatal(err)
		}
		subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(core), uint32(len(core))
		plan, err := EncodeConditionalPlan(ConditionalPlan{Family: head.Core.PreviousToken.Family, Store: head.Core.Store,
			Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Condition: condition,
			HeadCore: subject.HeadCoreDigest, HeadCoreLength: subject.HeadCoreLength})
		if err != nil {
			t.Fatal(err)
		}
		subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(plan), uint32(len(plan))
		b, err := EncodeHead(head)
		if tokenSize == 105 {
			if err != nil || len(b) != 65536 {
				t.Fatal("exact capacity", len(b), err)
			}
			if _, err := DecodeHead(b); err != nil {
				t.Fatal(err)
			}
		} else if err == nil || len(b) != 0 {
			t.Fatal("one extra byte serialized")
		}
	}
}

// full_only: false
func TestGrantPageRetainsNeighboursAndChecksCommittedRow(t *testing.T) {
	page := accessFixture()
	record := &page.Records[0]
	newRow := record.Wraps[0]
	newRow.SubjectID, newRow.BindingID = fid(8), fid(18)
	newRow.RSACiphertext = bytes.Repeat([]byte{0x81, 0x57}, 192)
	record.Wraps = append(record.Wraps, newRow)
	for id := byte(9); id < 210; id++ {
		retained := newRow
		retained.SubjectID = fid(id)
		retained.RSACiphertext = bytes.Repeat([]byte{id}, 384)
		record.Wraps = append(record.Wraps, retained)
	}
	original, err := EncodeAccessPage(page)
	if err != nil || len(original) <= 65536 {
		t.Fatal("dense fixture", err)
	}
	ref, err := Reference(AccessKind, page.Domain, page.Object, page.Index, original)
	if err != nil {
		t.Fatal(err)
	}
	base, rows, err := SplitGrantPage(page, map[ID][]ID{record.MaterialID: {newRow.SubjectID}})
	if err != nil || len(rows) != 493 {
		t.Fatal("one grant in dense page", err)
	}
	physical, err := EncodeAccessPage(base)
	if err != nil || len(physical) != len(original) || bytes.Contains(physical, newRow.RSACiphertext) {
		t.Fatal("staged bytes", err)
	}
	restore := func(physical, rows []byte) ([]byte, error) {
		owned, err := DecodeAccessPage(physical)
		if err != nil {
			return nil, err
		}
		_, body, err := RestoreGrantPage(ref, owned, rows)
		return body, err
	}
	got, err := restore(physical, rows)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("exact normalized page", err)
	}
	for _, index := range []int{0, 2, 8, len(rows) - 1} {
		bad := bytes.Clone(rows)
		bad[index] ^= 1
		if _, err := restore(physical, bad); err == nil {
			t.Fatal("changed row accepted", index)
		}
	}
	place := base.Records[0].Wraps[1]
	if place.SubjectID != newRow.SubjectID || place.PublicBindingDigest != contract.Hash(rows[4:]) ||
		!bytes.Equal(place.RSACiphertext, make([]byte, 384)) {
		t.Fatal("missing exact row commitment")
	}
	base.Records[0].Wraps[1].PublicBindingDigest = fid(4)
	damaged, err := EncodeAccessPage(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restore(damaged, rows); err == nil {
		t.Fatal("changed physical commitment accepted")
	}
}
