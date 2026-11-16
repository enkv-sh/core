package crypto

import (
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedLocalFailureBackingUsesOneBoundedFactImage(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(contract.SupportRecordDigest{}) != 108 ||
		unsafe.Sizeof(contract.SupportRecord{}) != 64 || unsafe.Sizeof(contract.GeneratedAttemptRecord{}) != 784 || unsafe.Sizeof(contract.ID{}) != 32 ||
		unsafe.Sizeof(generatedLocalFailureOutcome{}) != 312 || unsafe.Sizeof(generatedLocalFailureAdmission{}) != 1608 {
		t.Fatal("local failure backing account changed its supported 64-bit layout")
	}
	const support = uint64(contract.MaxChildPages) * (contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
	const count = support / contract.SupportRecordMinLength
	if support != 536851712 || count != 4668275 {
		t.Fatal("generic selected support/count ceiling changed")
	}
	// One exact-capacity fact image is reused for the before projection, after
	// facts and in-place after projection. Complete consumption uses one bitset.
	facts := count * uint64(unsafe.Sizeof(contract.SupportRecordDigest{}))
	consumed := (count + 7) / 8
	if facts != 504173700 || consumed != 583535 {
		t.Fatal("fact image or consumed bitset exceeds the independent account")
	}
	const exclusions = 2*contract.MutationReceiptWindowLimit + 1
	const receiptCount = 2 * contract.MutationReceiptWindowLimit
	index := uint64(2*contract.MutationReceiptIndexesMaxLength + contract.GeneratedFragmentHeaderLength)
	receipts := uint64(receiptCount) * uint64(contract.CompactMutationReceiptLength+unsafe.Sizeof(contract.SupportRecord{}))
	excludedFacts := uint64(exclusions) * uint64(unsafe.Sizeof(contract.SupportRecordDigest{}))
	// The active graph bounds the typed Attempt census, its two sorted ID
	// arrays and two borrowed support-header arrays; unrelated Duties are not
	// copied. The final 16 KiB covers the three fixed replacement bodies and
	// scalar/slice headers conservatively.
	active := uint64(contract.GeneratorMaxTemplates) * uint64(unsafe.Sizeof(contract.GeneratedAttemptRecord{})+2*unsafe.Sizeof(contract.ID{})+2*unsafe.Sizeof(contract.SupportRecord{}))
	guards := uint64(contract.GeneratorMaxCreateLineages)*uint64(unsafe.Sizeof(generatedLocalFailureOutcome{})) + uint64(unsafe.Sizeof(generatedLocalFailureAdmission{}))
	owned := facts + consumed + index + receipts + excludedFacts + active + guards + (16 << 10)
	if exclusions != 513 || owned >= support {
		t.Fatal("local failure backing exceeds the derived selected-support byte size", owned, support)
	}
}
