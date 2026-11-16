package contract

import (
	"bytes"
	"testing"
)

// full_only: false
func TestReceiptWarningsKeepDomainAndEffectMeaningsSeparate(t *testing.T) {
	for _, cell := range []struct {
		domain uint8
		packed uint64
	}{{1, 4}, {2, 8}, {4, 16}, {8, 32}, {16, 64}} {
		packed, err := EncodeReceiptWarningBits(OperationApplyDeclaration, cell.domain, 0)
		if err != nil || packed != cell.packed {
			t.Fatal("single domain warning packing differs", cell, packed, err)
		}
		row := mutationReceiptFixture()
		row.OperationKind, row.EffectSummary, row.WarningBits = OperationApplyDeclaration, ReceiptEffectNoChange, cell.packed
		if _, err := EncodeCompactMutationReceipt(row); err != nil {
			t.Fatal("domain warning acquired an operation count requirement", cell, err)
		}
	}
	for _, condition := range []string{"domain", "domain-and-possible-live", "domain-and-acknowledged", "domain-and-both-effects"} {
		t.Run(condition, func(t *testing.T) {
			row := mutationReceiptFixture()
			row.OperationKind, row.EffectSummary = OperationApplyDeclaration, ReceiptEffectNoChange
			// Five domain flags occupy bits 2 through 6. The two operation
			// flags retain bits 0 and 1; these expected integers are independent.
			row.WarningBits = 124
			if condition == "domain-and-possible-live" || condition == "domain-and-both-effects" {
				row.WarningBits++
				row.SummaryCounts[ReceiptHazardCount] = 1
			}
			if condition == "domain-and-acknowledged" || condition == "domain-and-both-effects" {
				row.WarningBits += 2
				row.AcknowledgedCount = 1
				row.SummaryCounts[ReceiptEffectCount], row.SummaryCounts[ReceiptSummarySuccessCount] = 1, 1
				row.EffectSummary, row.EvidenceCeiling = ReceiptEffectComplete, ReceiptEvidenceAcknowledged
			}
			body, err := EncodeCompactMutationReceipt(row)
			if err != nil {
				t.Fatal("independent domain/effect warning combination refused", row.WarningBits, err)
			}
			// The fixed scalar prefix is 12 bytes, then six IDs, one outcome
			// byte and two 44-byte descriptors before the big-endian u64.
			if len(body) != 471 || !bytes.Equal(body[293:301], []byte{0, 0, 0, 0, 0, 0, 0, byte(row.WarningBits)}) {
				t.Fatal("warning representation or fixed receipt length changed")
			}
			decoded, err := InspectCompactMutationReceipt(body)
			if err != nil || decoded != row {
				t.Fatal("domain/effect warning round trip differs", err)
			}
			domain, effects, err := DecodeReceiptWarningBits(row.OperationKind, row.WarningBits)
			if err != nil || domain != 31 || effects != row.WarningBits&3 {
				t.Fatal("operation-aware warning extraction differs", domain, effects, err)
			}
			packed, err := EncodeReceiptWarningBits(row.OperationKind, domain, effects)
			if err != nil || packed != row.WarningBits {
				t.Fatal("operation-aware warning packing differs", packed, err)
			}
			row.WarningBits |= 128
			if _, err := EncodeCompactMutationReceipt(row); err == nil {
				t.Fatal("unknown warning bit admitted")
			}
		})
	}
	t.Run("administrative-domain-byte", func(t *testing.T) {
		row := administrativeReceiptFixture()
		body, err := EncodeCompactMutationReceipt(row)
		if err != nil || row.WarningBits != 31 {
			t.Fatal("administrative domain warning byte changed", err)
		}
		decoded, err := InspectCompactMutationReceipt(body)
		if err != nil || decoded != row {
			t.Fatal("administrative warning round trip differs", err)
		}
		domain, effects, err := DecodeReceiptWarningBits(row.OperationKind, row.WarningBits)
		if err != nil || domain != 31 || effects != 0 {
			t.Fatal("administrative domain warnings became effect flags", domain, effects, err)
		}
		row.WarningBits = 124
		if _, err := EncodeCompactMutationReceipt(row); err == nil {
			t.Fatal("administrative receipt accepted ordinary shifted warnings")
		}
	})
	t.Run("domain-flags-do-not-prove-effect-warnings", func(t *testing.T) {
		row := mutationReceiptFixture()
		row.OperationKind, row.WarningBits = OperationApplyDeclaration, 124
		row.EffectSummary, row.EvidenceCeiling = ReceiptEffectComplete, ReceiptEvidenceAcknowledged
		row.SummaryCounts[ReceiptEffectCount], row.SummaryCounts[ReceiptSummarySuccessCount] = 1, 1
		row.AcknowledgedCount = 1
		if _, err := EncodeCompactMutationReceipt(row); err == nil {
			t.Fatal("domain warning replaced required acknowledgement warning")
		}
		row.WarningBits = 126
		if _, err := EncodeCompactMutationReceipt(row); err != nil {
			t.Fatal("exact acknowledgement and domain warning control refused", err)
		}
		row.WarningBits, row.AcknowledgedCount, row.UnknownCount = 124, 0, 2
		row.SummaryCounts[ReceiptSummarySuccessCount] = 0
		row.SummaryCounts[ReceiptEffectCount], row.SummaryCounts[ReceiptSummaryUnknownCount] = 2, 1
		row.EvidenceCeiling, row.SummaryCounts[ReceiptPreservedResidueCount] = ReceiptEvidenceProviderFacts, 1
		row.EffectSummary, row.StateResult = ReceiptEffectUnknown, ReceiptStateEffectUnknown
		row.CanonicalOutcome, row.ObservedRevisionID = ReceiptCanonicalNotSelected, generatedRecordID(9)
		if _, err := EncodeCompactMutationReceipt(row); err == nil {
			t.Fatal("domain warning replaced required possible-live warning")
		}
		row.WarningBits = 125
		if _, err := EncodeCompactMutationReceipt(row); err != nil {
			t.Fatal("exact possible-live and domain warning control refused", err)
		}
	})
}

// full_only: false
func TestInitializationReceiptRequiresZeroWarnings(t *testing.T) {
	row, err := GenesisReceiptFields(generatedRecordID(1), generatedRecordID(2), generatedRecordID(7))
	if err != nil {
		t.Fatal(err)
	}
	row.RequestIdentityDigest = generatedRecordID(5)
	row.CompleteResult = mutationReceiptFixture().CompleteResult
	if _, err := EncodeCompactMutationReceipt(row); err != nil {
		t.Fatal("zero-warning initialization receipt control refused", err)
	}
	for _, bit := range []uint64{1, 2, 4} {
		damaged := row
		damaged.WarningBits = bit
		if _, err := EncodeCompactMutationReceipt(damaged); err == nil {
			t.Errorf("initialization receipt admitted warning bit %d", bit)
		}
	}
}

// full_only: false
func TestReceiptWarningCodecRefusesUnknownMeanings(t *testing.T) {
	for _, cell := range []struct {
		operation uint16
		domain    uint8
		effects   uint64
	}{{0, 0, 0}, {65535, 0, 0}, {OperationApplyDeclaration, 32, 0}, {OperationApplyDeclaration, 0, 4}, {OperationEndSelectedWork, 0, 1}} {
		if _, err := EncodeReceiptWarningBits(cell.operation, cell.domain, cell.effects); err == nil {
			t.Fatal("unknown warning meaning encoded", cell)
		}
	}
	for _, cell := range []struct {
		operation uint16
		bits      uint64
	}{{0, 0}, {65535, 0}, {OperationApplyDeclaration, 128}, {OperationEndSelectedWork, 32}} {
		if _, _, err := DecodeReceiptWarningBits(cell.operation, cell.bits); err == nil {
			t.Fatal("unknown warning meaning decoded", cell)
		}
	}
}
