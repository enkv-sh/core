package core

import (
	"errors"
	"slices"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestProspectiveGeneratedMetadataStorageBound(t *testing.T) {
	if contract.GeneratedCurrentEntryLimit != 128 || unsafe.Sizeof(contract.GeneratedEntryMetadata{}) != 440 || unsafe.Sizeof([128]contract.GeneratedEntryMetadata{}) != 56320 {
		t.Fatal("prospective metadata storage bound changed")
	}
	for _, entries := range [][]contract.GeneratedEntryMetadata{nil, {}} {
		ids, err := generatedIntentIDs(entries)
		if err != nil || len(ids) != 0 {
			t.Fatal("explicit empty metadata acquired current intents", err)
		}
	}
	low, high := contract.ID{1}, contract.ID{2}
	ids, err := generatedIntentIDs([]contract.GeneratedEntryMetadata{{IntentDigest: high}, {IntentDigest: low}, {IntentDigest: high}})
	if err != nil || !slices.Equal(ids, []contract.ID{low, high}) {
		t.Fatal("shared intent set is not unique and ordered", err)
	}
	if _, err := generatedIntentIDs([]contract.GeneratedEntryMetadata{{}}); err == nil {
		t.Fatal("zero intent ID accepted")
	}
	excess := make([]contract.GeneratedEntryMetadata, 129)
	for i := range excess {
		excess[i].IntentDigest = low
	}
	if _, err := generatedIntentIDs(excess); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatal("metadata row bound refused at wrong stage", err)
	}
}
