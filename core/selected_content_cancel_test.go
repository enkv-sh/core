package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestCanceledSelectedContentPreflightKeepsReadResult(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	want := failure(EvidenceUnavailable, ReadUnavailable)

	t.Run("receipt blob", func(t *testing.T) {
		s := &StateSession{fragmentFacts: make(map[format.FragmentLocation]selectedFragmentFact)}
		_, err := s.supportBlobSelected(ctx, contract.ID{1}, 1)
		got, ok := selectedReadResult(err)
		if !ok || got != want {
			t.Fatalf("canceled receipt read: result=%+v typed=%t error=%v", got, ok, err)
		}
	})

	t.Run("logical slice", func(t *testing.T) {
		content := &generatedContent{}
		_, err := content.streamSelectedSliceWith(ctx, 1, contract.ID{1}, 1,
			func([]byte) error { return nil },
			func(context.Context, format.FragmentLocation, func([]byte) error) (Result, error) {
				t.Fatal("canceled selected slice reached Store")
				return Result{}, nil
			})
		got, ok := selectedReadResult(err)
		if !ok || got != want {
			t.Fatalf("canceled slice read: result=%+v typed=%t error=%v", got, ok, err)
		}
	})
}
