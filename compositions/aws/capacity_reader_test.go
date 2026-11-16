package compositionaws

import (
	"context"
	"reflect"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestCapacityReaderKeepsAWSReadAndEnumerationSeparate(t *testing.T) {
	pins := core.AdministrativeSourcePins{FileID: contract.ID{1}, Format: 1, EditableDigest: contract.ID{2}, EditableLength: 1, GeneratedDigest: contract.ID{3}, GeneratedLength: 1, HasGenerated: true}
	r, err := NewCapacityReader(CapacityReaderConfig{ReaderConfig: readerConfig(t), SourcePins: pins, CheckSource: func(context.Context) error { return nil }})
	if err != nil || r == nil {
		t.Fatal(err)
	}
	r.Close()
	var ordinary core.PublicSelectedReader = &publicSelectedStore{}
	if _, ok := ordinary.(contract.BoundedEnumerationStore); ok || reflect.TypeOf(ordinary).NumMethod() != 4 {
		t.Fatal("ordinary reader gained LIST")
	}
	var bounded core.PublicCapacityReader = &capacitySelectedStore{&publicSelectedStore{}}
	if _, ok := bounded.(contract.Store); ok || reflect.TypeOf(bounded).NumMethod() != 5 {
		t.Fatal("capacity reader gained mutation reach")
	}
	bounded.Close()
	if got := bounded.ListPage(t.Context(), ""); got.Status != contract.ListPageInvalid {
		t.Fatal("closed reader listed", got)
	}
	if r, err := NewDefaultCapacityReader(t.Context(), CapacityReaderConfig{ReaderConfig: readerConfig(t)}); err == nil || r != nil {
		t.Fatal("missing public pins reached default credentials")
	}
}
