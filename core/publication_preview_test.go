package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationPreviewRequestedRefusalIsExplicit(t *testing.T) {
	var reader *ReaderEngine
	result := reader.Compare(t.Context(), contract.Hash([]byte("publication preview request")), contract.PublicConfiguration{}, contract.ComparisonOptions{Publish: true})
	if !result.PublicationRequested || result.Publication == nil || result.Publication.Complete || result.Publication.ReasonCode != uint8(AdmissionInvalid) || len(result.Publication.Entries) != 0 || result.StateResult == contract.ReaderSuccess {
		t.Fatal("requested discovery became absent or successful after refusal", result)
	}
	plain := reader.Compare(t.Context(), contract.Hash([]byte("plain comparison request")), contract.PublicConfiguration{})
	if plain.PublicationRequested || plain.Publication != nil {
		t.Fatal("plain comparison acquired publication discovery")
	}
	duplicate := reader.Compare(t.Context(), contract.Hash([]byte("ambiguous preview options")), contract.PublicConfiguration{}, contract.ComparisonOptions{Publish: true}, contract.ComparisonOptions{Publish: true})
	if duplicate.StateResult != contract.ReaderRefused || duplicate.Publication == nil || duplicate.Publication.Complete {
		t.Fatal("multiple option sets did not refuse", duplicate)
	}
}
