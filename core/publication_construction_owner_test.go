package core

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationConstructionOwnsExactInputAndOneUse(t *testing.T) {
	for _, route := range []string{"reservation", "close"} {
		t.Run(route, func(t *testing.T) {
			for _, condition := range []string{"healthy", "raw-caller-input-owned", "typed-builder-detached", "changed-head", "changed-token", "changed-index", "success-is-one-use", "failure-is-one-use"} {
				t.Run(condition, func(t *testing.T) {
					state, offered := publicationReservationFixture(t, false)
					if route == "close" {
						offered = publicationNoEffectRows(t, state)
					}
					want := make(map[generatedRecordKey][]byte, len(offered))
					for _, row := range offered {
						want[generatedRecordKey{row.Kind, row.RecordID}] = bytes.Clone(row.Body)
					}
					var input *publicationConstruction
					var err error
					if condition == "typed-builder-detached" {
						selected, inspectErr := inspectPublicationRows(state.root.Domain, offered)
						if inspectErr != nil {
							t.Fatal("fixture typed relation", inspectErr)
						}
						rows, encodingErr := publicationRows(selected)
						if encodingErr != nil {
							t.Fatal("fixture typed row encoding", encodingErr)
						}
						input, err = state.preparePublicationConstruction(t.Context(), rows)
						clear(selected.coordinates)
						clear(selected.markers)
					} else {
						input, err = state.preparePublicationConstruction(t.Context(), offered)
					}
					if err != nil || input == nil || input.pageCount() == 0 {
						t.Fatal("healthy checked construction refused", err)
					}
					if condition == "raw-caller-input-owned" {
						for i := range offered {
							if len(offered[i].Body) != 0 {
								offered[i].Body[0] ^= 1
							}
						}
						clear(offered)
					}
					materialize := func(next *StateSession, candidate *Candidate, pages []contract.ID) error {
						if route == "reservation" {
							return state.materializePublicationReservationConstruction(t.Context(), next, candidate, input, pages)
						}
						return state.materializePublicationRewriteConstruction(t.Context(), next, candidate, input, pages)
					}
					next := *state
					next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
					candidate := Candidate{session: state}
					pages := publicationJointPageIDs(state.root.Domain, "owner-control-page", input.pageCount())
					switch condition {
					case "changed-head":
						state.body = []byte("different authenticated predecessor HEAD")
					case "changed-token":
						state.token.Value = `"different-selected-token"`
					case "changed-index":
						state.root.AdministrativeIndex.Object = publicationRelationID(106)
					}
					beforeState := snapshotPublicationConstructionControl(t, state)
					beforeNext := snapshotPublicationConstructionControl(t, &next)
					if condition == "failure-is-one-use" {
						err = materialize(&next, &candidate, nil)
					} else {
						err = materialize(&next, &candidate, pages)
					}
					refused := condition == "changed-head" || condition == "changed-token" || condition == "changed-index" || condition == "failure-is-one-use"
					if refused {
						if !errors.Is(err, contract.ErrRecord) || len(candidate.objects) != 0 || !reflect.DeepEqual(beforeNext, snapshotPublicationConstructionControl(t, &next)) || !reflect.DeepEqual(beforeState, snapshotPublicationConstructionControl(t, state)) {
							t.Fatal("mismatched construction changed its source/successor or emitted objects", err, len(candidate.objects))
						}
						if condition == "failure-is-one-use" {
							if err := materialize(&next, &candidate, pages); !errors.Is(err, contract.ErrRecord) || len(candidate.objects) != 0 || !reflect.DeepEqual(beforeNext, snapshotPublicationConstructionControl(t, &next)) {
								t.Fatal("failed construction restored a materialization right", err)
							}
						}
						return
					}
					if err != nil || !reflect.DeepEqual(beforeState, snapshotPublicationConstructionControl(t, state)) {
						t.Fatal("healthy construction failed or changed its predecessor", err)
					}
					seen := make(map[generatedRecordKey]bool, len(want))
					for _, page := range next.support {
						for _, row := range page.Records {
							if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
								continue
							}
							key := generatedRecordKey{row.Kind, row.RecordID}
							expected, present := want[key]
							if !present || seen[key] || !bytes.Equal(row.Body, expected) {
								t.Fatal("emitted publication rows differ from admitted owned input", row.Kind)
							}
							seen[key] = true
						}
					}
					if len(seen) != len(want) || next.publicationProof == nil || !next.publicationProof.validFor(next.selectedImage()) {
						t.Fatal("actual finished successor lacks its exact complete selected proof")
					}
					if condition == "success-is-one-use" {
						repeated := *state
						repeated.root.Snapshot, repeated.root.Transition = publicationRelationID(90), publicationRelationID(91)
						before := snapshotPublicationConstructionControl(t, &repeated)
						second := Candidate{session: state}
						if err := materialize(&repeated, &second, pages); !errors.Is(err, contract.ErrRecord) || len(second.objects) != 0 || !reflect.DeepEqual(before, snapshotPublicationConstructionControl(t, &repeated)) {
							t.Fatal("successful construction materialized twice", err)
						}
					}
				})
			}
		})
	}
}

type publicationConstructionControlSnapshot struct {
	root, index, head []byte
	token             contract.Token
	support           []format.RequiredSupportPageView
}

func snapshotPublicationConstructionControl(t *testing.T, state *StateSession) publicationConstructionControlSnapshot {
	t.Helper()
	root, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal("fixture root snapshot", err)
	}
	index, err := format.EncodeAdministrativeIndex(state.adminIndex)
	if err != nil {
		t.Fatal("fixture index snapshot", err)
	}
	out := publicationConstructionControlSnapshot{root: root, index: index, head: bytes.Clone(state.body), token: state.token, support: slices.Clone(state.support)}
	for i, page := range out.support {
		out.support[i].Records = slices.Clone(page.Records)
		for j, row := range page.Records {
			out.support[i].Records[j].Body = bytes.Clone(row.Body)
		}
	}
	return out
}
