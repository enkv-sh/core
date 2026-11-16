package core

import (
	"bytes"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationRetainedFragmentFixture(t *testing.T) (*StateSession, contract.GeneratorSliceLocation, []byte) {
	t.Helper()
	state, _, _ := generatedDetachedRetirementState(t, "absent", 0)
	generatedMaterializeFixtureSupport(t, state)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	rows := publicationRelationRows(t, coordinate, marker)
	for _, row := range rows {
		index := generatedFixtureFreeSupportIndex(t, state)
		state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: contract.Hash(row.RecordID[:]), Index: index, Records: []contract.SupportRecordView{contract.SupportRecordView(row)}})
	}
	state.admission.composition = publicationRelationID(87)
	state.admission.expires = time.Now().Add(time.Minute)
	state.admission.store.HeadKey = state.admission.store.Prefix + "/HEAD"
	generatedRefreshSupport(t, state)
	image := state.selectedImage()
	if result := verifySelectedGeneratedSlices(t.Context(), image, state.selectedObjectReader()); result.Outcome != 0 {
		t.Fatal("publication fixture selected slices", result)
	}
	state.generatedSliceLocations = image.generatedSliceLocations
	if len(state.generatedSliceLocations) == 0 {
		t.Fatal("publication fixture has no logical generated slices")
	}
	content := state.generatedSliceLocations[0]
	source, err := newGeneratedContentValidation(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := source.read(content.ContentKind, content.ContentID, content.Length)
	if err != nil {
		t.Fatal(err)
	}
	var ok bool
	state.generatedSlicesRoot, ok = state.generatedSelectionRoot()
	if !ok {
		t.Fatal("publication fixture root")
	}
	if err := state.bindPreservedOutputConfiguration(state); err != nil {
		t.Fatal("publication fixture output binding", err)
	}
	if err := state.bindPreservedPublication(t.Context(), state); err != nil {
		t.Fatal("publication fixture publication binding", err)
	}
	for i := range state.support {
		for j, row := range state.support[i].Records {
			if row.Kind == contract.GeneratedFragmentSupportKind {
				state.support[i].Records[j].Body = nil
			}
		}
	}
	if _, err := state.selectedGeneratedWork(t.Context()); err != nil {
		t.Fatal("publication fixture generated relation", err)
	}
	if _, err := state.publicStateProjection(); err != nil {
		t.Fatal("publication fixture public state", err)
	}
	return state, content, payload
}

// full_only: false
func TestPublicationConstructionPreservesRetainedGeneratedFragments(t *testing.T) {
	for _, reserve := range []bool{false, true} {
		name := "close"
		if reserve {
			name = "reserve"
		}
		t.Run(name, func(t *testing.T) {
			state, content, payload := publicationRetainedFragmentFixture(t)
			configurationReads := make(map[string]int)
			for i, page := range state.support {
				for j, row := range page.Records {
					if row.Kind != contract.OutputConfigurationSliceSupportKind {
						continue
					}
					key, err := format.Key(state.admission.store.Prefix, state.root.RequiredSupport[i])
					if err != nil {
						t.Fatal(err)
					}
					// The index installer validates the declaration once. Its ordered
					// source reads each selected configuration slice exactly once.
					configurationReads[key]++
					state.support[i].Records[j].Body = nil
				}
			}
			if len(configurationReads) == 0 {
				t.Fatal("fixture has no retained configuration slices")
			}
			store := state.store.(*generatedFixtureSupportStore)
			startReads := len(store.keys)
			original := state.root.Generated.Fragments[0]
			oldFact := state.fragmentFacts[original]
			var rows []contract.SupportRecord
			if reserve {
				_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
				coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
				old := marker
				marker = publicationReservedDeleteMarker(t, old)
				coordinate.LastAdmissionOrdinal++
				marker.AttemptID, marker.OperationID, marker.AdmissionOrdinal = publicationRelationID(120), publicationRelationID(121), coordinate.LastAdmissionOrdinal
				marker.State = contract.PublicationMayHaveEntered
				marker.BlockerCount = 1
				var err error
				marker.BlockerDigest, err = contract.PublicationBlockerDigest([]contract.ID{old.AttemptID})
				if err != nil {
					t.Fatal(err)
				}
				coordinate.LatestUnresolvedAttemptID = marker.AttemptID
				rows = publicationRelationRows(t, coordinate, old)
				body, err := contract.EncodePublicationMarker(marker)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
			} else {
				rows = publicationNoEffectRows(t, state)
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			var err error
			if reserve {
				construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
				if constructionErr == nil {
					constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
				}
				err = constructionErr
			} else {
				construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
				if constructionErr == nil {
					constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
				}
				err = constructionErr
			}
			if err != nil {
				t.Fatal("retained generated construction", err)
			}
			for key, want := range configurationReads {
				var got int
				for _, read := range store.keys[startReads:] {
					if read == key {
						got++
					}
				}
				if got != want {
					t.Fatalf("configuration reread after successor validation: reads=%d want=%d", got, want)
				}
			}
			if !slices.Equal(next.root.Generated.Fragments, state.root.Generated.Fragments) || !maps.Equal(next.fragmentFacts, state.fragmentFacts) || state.fragmentFacts[original] != oldFact ||
				!slices.Equal(next.generatedSliceLocations, state.generatedSliceLocations) || next.generatedSlicesRoot.IsZero() || next.publicationProof == nil || !next.publicationProof.validFor(next.selectedImage()) || !next.selectedOutputComplete() {
				t.Fatal("retained physical facts or generated/publication/output selection lost")
			}
			root, ok := next.generatedSelectionRoot()
			if !ok || next.generatedSlicesRoot != root {
				t.Fatal("generated facts bound to foreign root")
			}
			for _, page := range next.support {
				for _, row := range page.Records {
					if (row.Kind == contract.GeneratedFragmentSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind) && row.Body != nil {
						t.Fatal("construction rehydrated retained fragment or configuration body")
					}
				}
			}
			reads := len(state.store.(*generatedFixtureSupportStore).keys)
			if _, err := next.publicStateProjection(); err != nil {
				t.Fatal("retained successor public state", err)
			}
			if len(state.store.(*generatedFixtureSupportStore).keys) != reads {
				t.Fatal("public-state projection read retained fragment bodies")
			}
			source, err := newGeneratedContentValidation(t.Context(), &next)
			if err != nil {
				t.Fatal(err)
			}
			got, err := source.read(content.ContentKind, content.ContentID, content.Length)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("retained generated content", err)
			}
			for _, image := range candidate.objects {
				if image.ref == oldFact.ref {
					t.Fatal("retained physical page rewritten")
				}
			}
		})
	}
}

// full_only: false
func TestPublicationConstructionRejectsChangedRetainedGeneratedFacts(t *testing.T) {
	for _, damage := range []string{"foreign_ref", "physical_ordinal", "fragment_body_fact", "foreign_slice_root", "missing_slice_proof"} {
		t.Run(damage, func(t *testing.T) {
			state, _, _ := publicationRetainedFragmentFixture(t)
			rows := publicationNoEffectRows(t, state)
			construction, err := state.preparePublicationConstruction(t.Context(), rows)
			if err != nil {
				t.Fatal("healthy construction before source mutation", err)
			}
			location := state.root.Generated.Fragments[0]
			state.fragmentFacts = maps.Clone(state.fragmentFacts)
			fact := state.fragmentFacts[location]
			switch damage {
			case "foreign_ref":
				fact.ref.Digest = publicationRelationID(122)
			case "physical_ordinal":
				fact.physical++
			case "fragment_body_fact":
				fact.row = contract.SupportRecordDigest{}
			case "foreign_slice_root":
				state.generatedSlicesRoot = publicationRelationID(122)
			case "missing_slice_proof":
				state.generatedSlicesRoot = contract.ID{}
			}
			state.fragmentFacts[location] = fact
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			initial := next
			candidate := Candidate{session: state}
			err = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			if err == nil || len(candidate.objects) != 0 || !reflect.DeepEqual(next, initial) {
				t.Fatal("changed retained facts accepted or changed refused construction", err)
			}
		})
	}
}
