package core

import (
	"context"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// full_only: false
func TestPublicationEarlyRowBounds(t *testing.T) {
	for _, tc := range []struct {
		name         string
		kind         contract.SupportRecordKind
		count, width int
	}{
		{"coordinate_count", contract.PublicationCoordinateSupportKind, contract.MaxPublicationCoordinates + 1, 0},
		{"marker_count", contract.PublicationMarkerSupportKind, contract.MaxPublicationMarkers + 1, 0},
		{"coordinate_width", contract.PublicationCoordinateSupportKind, 1, contract.MaxPublicationCoordinateRecordBytes - contract.SupportRecordOverhead + 1},
		{"marker_width", contract.PublicationMarkerSupportKind, 1, contract.MaxPublicationMarkerRecordBytes - contract.SupportRecordOverhead + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := make([]contract.SupportRecord, tc.count)
			for i := range rows {
				rows[i] = contract.SupportRecord{Kind: tc.kind, Body: make([]byte, tc.width)}
			}
			if _, err := publicationRowsRelation(publicationRelationID(1), rows, nil); !errors.Is(err, contract.ErrRecordCapacity) {
				t.Fatalf("relation must refuse scalar bounds before decode: %v", err)
			}
			if _, err := publicationOrderForRows(publicationRelationID(1), rows, nil); !errors.Is(err, contract.ErrRecordCapacity) {
				t.Fatalf("order must refuse scalar bounds before decode: %v", err)
			}
		})
	}
}

// full_only: false
func TestPublicationEarlySharedCallerBounds(t *testing.T) {
	state := publicationCapacityState(t)
	rows := make([]contract.SupportRecord, contract.MaxPublicationCoordinates+1)
	for i := range rows {
		rows[i] = contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind}
	}
	if _, err := generatedReservationGroupsWithSource(state, state, rows, nil, nil); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatalf("grouping must reject bounds before opaque facts/maps: %v", err)
	}
	pages := []format.RequiredSupportPage{{Records: rows}}
	root := state.root
	root.RequiredSupport = root.RequiredSupport[:1]
	if _, err := state.buildAdministrativeIndex(t.Context(), root, pages, nil, nil, state); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatalf("index must reject bounds before row planning: %v", err)
	}
	next := *state
	next.support = []format.RequiredSupportPageView{{}}
	for _, row := range rows {
		next.support[0].Records = append(next.support[0].Records, contract.SupportRecordView(row))
	}
	next.root.RequiredSupport = root.RequiredSupport
	if err := state.installAdministrativeIndex(t.Context(), &next, &Candidate{}); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatalf("install must reject bounds before support copy: %v", err)
	}
}

type successorReadFailureStore struct {
	contract.Store
	calls int
}

func (s *successorReadFailureStore) Read(context.Context, string, uint32) contract.ReadResult {
	s.calls++
	return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
}

// full_only: false
func TestOrdinarySuccessorEncodingPreservesCapacityAndStoreFailure(t *testing.T) {
	t.Run("wrapped support capacity", func(t *testing.T) {
		state := generatedEmptyPredecessor(t)
		next := *state
		next.support = slices.Clone(state.support)
		next.support[0].Records = slices.Clone(state.support[0].Records)
		// The scalar bound is independent of row content. This also distinguishes
		// capacity from a malformed row still inside that bound.
		next.support[0].Records[0].Body = make([]byte, contract.OutputConfigurationSliceBodyOverhead+contract.MaxOutputConfigurationSliceBytes+1)
		err := state.installAdministrativeIndex(t.Context(), &next, &Candidate{})
		if !errors.Is(err, contract.ErrRecordCapacity) || err == contract.ErrRecordCapacity {
			t.Fatalf("fixture did not produce wrapped capacity: %v", err)
		}
		candidate, result := state.encodeSuccessor(t.Context(), &next, transitionPlan{}, lifecycleAuthority{}, nil)
		if candidate != nil || result != refused(CapacityExceeded) {
			t.Fatalf("result=%+v", result)
		}
	})
	for _, length := range []int{1, contract.OutputConfigurationSliceBodyOverhead + contract.MaxOutputConfigurationSliceBytes} {
		t.Run(fmt.Sprintf("invalid relation inside scalar bound %d", length), func(t *testing.T) {
			state := generatedEmptyPredecessor(t)
			next := *state
			next.support = slices.Clone(state.support)
			next.support[0].Records = slices.Clone(state.support[0].Records)
			next.support[0].Records[0].Body = make([]byte, length)
			candidate, result := state.encodeSuccessor(t.Context(), &next, transitionPlan{}, lifecycleAuthority{}, nil)
			if candidate != nil || result != refused(InvalidRelation) {
				t.Fatalf("result=%+v", result)
			}
		})
	}

	t.Run("Store unavailable", func(t *testing.T) {
		state := generatedEmptyPredecessor(t)
		state.cache = nil
		store := &successorReadFailureStore{Store: state.store}
		state.store = store
		next := *state
		next.support = selectedConversionBodylessSupport(state.support)
		err := state.installAdministrativeIndex(t.Context(), &next, &Candidate{})
		want := failure(EvidenceUnavailable, ReadUnavailable)
		want.StoreReason = contract.ReasonAccess
		got, typed := selectedReadResult(err)
		if !typed || got != want || store.calls != 1 {
			t.Fatalf("fixture read=%+v typed=%t calls=%d error=%v", got, typed, store.calls, err)
		}
		store.calls = 0
		candidate, result := state.encodeSuccessor(t.Context(), &next, transitionPlan{}, lifecycleAuthority{}, nil)
		if candidate != nil || result != want || store.calls != 1 {
			t.Fatalf("result=%+v calls=%d", result, store.calls)
		}
	})
}
