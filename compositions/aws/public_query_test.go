package compositionaws

import (
	"context"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"testing"
	"time"
)

// full_only: false
func TestPublicQueryReadersKeepIndependentSourceBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	c := readerConfig(t)
	pins := core.AdministrativeSourcePins{FileID: contract.ID{1}, Format: 1, EditableDigest: contract.ID{2}, EditableLength: 1, GeneratedDigest: contract.ID{3}, GeneratedLength: 1, HasGenerated: true}
	check := func(context.Context) error { return nil }
	receipt, err := NewReceiptReader(ReceiptReaderConfig{ReaderConfig: c, CompositionID: contract.ID{4}, SourcePins: pins, CheckSource: check})
	if err != nil || receipt == nil {
		t.Fatal("public receipt construction", err)
	}
	receipt.Close()
	receipt.Close()
	inspection, err := NewInspectionReader(InspectionReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: check})
	if err != nil || inspection == nil {
		t.Fatal("public inspection construction", err)
	}
	inspection.Close()
	inspection.Close()
	if _, err := NewReceiptReader(ReceiptReaderConfig{ReaderConfig: c, CompositionID: contract.ID{4}, SourcePins: pins}); err == nil {
		t.Fatal("missing source check accepted")
	}
	if _, err := NewInspectionReader(InspectionReaderConfig{ReaderConfig: c, CheckSource: check}); err == nil {
		t.Fatal("missing exact source pins accepted")
	}
	_ = ctx
}
