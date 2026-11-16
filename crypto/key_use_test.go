package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestKeyUsesAggregateExactRowsWithoutMergingOutcomes(t *testing.T) {
	// The consumer fixture owns the synthetic RSA binding; no Core key owner.
	selection, _ := consumerFixture(t)
	row := selection.Binding

	// Different nonzero counts make an outcome permutation observable.
	for i := range row.Binding.BindingID {
		row.Binding.BindingID[i] = 1
	}
	uses := KeyUses{Completed: 1, Denied: 2, Failed: 3, Unknown: 4}
	distinct := contract.CryptoResponse{Kind: contract.CryptoPrepare}
	if !appendKeyUses(&distinct, row, contract.KeyUseMaterialOpen, uses, 10) {
		t.Fatal("exact total-use limit refused")
	}
	var expected []contract.KeyUseRow
	for i := uint8(1); i <= 4; i++ {
		expected = append(expected, independentKeyUseRow(row, 3, i, uint32(i)))
	}
	if !slices.Equal(distinct.KeyUseRows, expected) {
		t.Fatalf("distinct outcomes differ: got=%+v want=%+v", distinct.KeyUseRows, expected)
	}
	before := slices.Clone(distinct.KeyUseRows)
	if appendKeyUses(&distinct, row, contract.KeyUseMaterialOpen, uses, 9) || !slices.Equal(distinct.KeyUseRows, before) {
		t.Fatal("total-use refusal changed existing evidence")
	}
	if !appendKeyUses(&distinct, row, contract.KeyUseMaterialOpen, uses, 10) {
		t.Fatal("same binding, purpose and outcomes did not merge")
	}
	for i := range expected {
		expected[i].Count *= 2
	}
	other := row
	for i := range other.Binding.BindingID {
		other.Binding.BindingID[i] = 2
	}
	if !appendKeyUses(&distinct, other, contract.KeyUseMaterialOpen, KeyUses{Completed: 7}, 7) ||
		!appendKeyUses(&distinct, row, contract.KeyUsePublicKeyRead, KeyUses{Completed: 5}, 5) {
		t.Fatal("distinct binding or purpose refused")
	}
	expected = append([]contract.KeyUseRow{independentKeyUseRow(row, 1, 1, 5)}, expected...)
	expected = append(expected, independentKeyUseRow(other, 3, 1, 7))
	if !slices.Equal(distinct.KeyUseRows, expected) {
		t.Fatalf("whole merged rows or order differ: got=%+v want=%+v", distinct.KeyUseRows, expected)
	}
	reply := contract.CryptoResponse{Kind: contract.CryptoPrepare}
	for range 512 {
		if !appendKeyUses(&reply, row, contract.KeyUseMaterialOpen, KeyUses{Completed: 1}, 1) {
			t.Fatal("bounded completed use refused")
		}
	}
	if !appendKeyUses(&reply, row, contract.KeyUseMaterialOpen, KeyUses{Denied: 1}, 1) {
		t.Fatal("denial fact refused")
	}
	if len(reply.KeyUseRows) != 2 || reply.KeyUseRows[0].Count != 512 || reply.KeyUseRows[1].Count != 1 {
		t.Fatal("uses did not aggregate by exact purpose/outcome")
	}
	if _, err := contract.KeyUseRowsLength(reply.KeyUseRows); err != nil {
		t.Fatal(err)
	}
	reply.KeyUseRows[0].Count = math.MaxUint32
	before = slices.Clone(reply.KeyUseRows)
	if appendKeyUses(&reply, row, contract.KeyUseMaterialOpen, KeyUses{Completed: 1}, 1) {
		t.Fatal("accepted use count overflow")
	}
	if !slices.Equal(reply.KeyUseRows, before) {
		t.Fatal("overflow damaged existing evidence")
	}
}

// The expected binding digest uses the documented KMSBinding field order and
// ordinary big-endian framing, independently of the contract encoder/hash writer.
func independentKeyUseRow(row contract.BindingTableRow, purpose, outcome uint8, count uint32) contract.KeyUseRow {
	b := row.Binding
	body := append([]byte(nil), b.BindingID[:]...)
	body = append(body, b.BindingIncarnationID[:]...)
	body = binary.BigEndian.AppendUint64(body, b.BindingSerial)
	body = append(body, byte(b.Provider))
	body = binary.BigEndian.AppendUint16(body, b.WrapProfile)
	body = append(body, b.ProtectionClass)
	body = binary.BigEndian.AppendUint32(body, uint32(len(b.KeySelector)))
	body = append(body, b.KeySelector...)
	body = append(body, b.SPKI...)
	body = append(body, b.Fingerprint[:]...)
	input := binary.BigEndian.AppendUint32([]byte("ENKV/CRYPTO/v2/binding\x00"), uint32(len(body)))
	input = append(input, body...)
	return contract.KeyUseRow{BindingID: b.BindingID, PublicBindingDigest: sha256.Sum256(input),
		SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, Provider: b.Provider,
		Purpose: purpose, Outcome: outcome, Count: count}
}
