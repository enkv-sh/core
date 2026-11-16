package core

import (
	"context"
	"errors"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationCapacityState(t *testing.T) *StateSession {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState = contract.PublicationBindingRetired
	coordinate.ActiveBindingIncarnationID = contract.ID{}
	rows := publicationRelationRows(t, coordinate, marker)
	state.support = append(state.support,
		format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(20), Index: 1, Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0])}},
		format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(21), Index: 2, Records: []contract.SupportRecordView{contract.SupportRecordView(rows[1])}})

	generatedRefreshSupport(t, state)
	state.recountChildren()
	return state
}

// full_only: false
func TestPublicationAdmissionRequiresAdministrativeExit(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "complete"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			for _, damage := range []string{"missing_envelope", "missing_index", "read_required"} {
				t.Run(damage, func(t *testing.T) {
					state := publicationCapacityState(t)
					if partial {
						for i := range state.support {
							if len(state.support[i].Records) == 1 && state.support[i].Records[0].Kind == contract.PublicationMarkerSupportKind {
								state.support[i].Records = nil
							}
						}
					}
					switch damage {
					case "missing_envelope":
						for i := range state.adminIndex.Groups {
							group := &state.adminIndex.Groups[i]
							if group.OwnerKind == format.AdministrativePublicationMarker {
								group.OwnerKind = format.AdministrativeGeneratedHazard
								group.PublicationIncarnationID, group.AdmissionOrdinal = contract.ID{}, 0
								group.UncertainCreateProof = 0
							}
						}
						if !state.adminIndex.Valid() {
							t.Fatal("invalid regression index")
						}
					case "missing_index":
						state.adminIndex = format.AdministrativeIndex{}
					case "read_required":
						for i := range state.adminIndex.Pages {
							page := &state.adminIndex.Pages[i]
							if len(page.Rows) == 1 && page.Rows[0].Kind == contract.PublicationMarkerSupportKind {
								page.ReadRequired = true
								page.Rows = nil
								page.Spans[0].Mandatory = true
							}
						}
						if !state.adminIndex.Valid() {
							t.Fatal("invalid carrier-association regression")
						}
					}
					if err := state.reserveFirstEndWork(t.Context()); !errors.Is(err, contract.ErrRecord) {
						t.Fatalf("publication exit required %s evidence: %v", damage, err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationCapacityUsesSignedOptionalFacts(t *testing.T) {
	complete := publicationCapacityState(t)
	plan, err := complete.planPublicationRewrite(t.Context(), complete.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	capacity, err := plan.capacity()
	if err != nil {
		t.Fatal(err)
	}
	// Fixed framing is 648 coordinate bytes and 763 marker bytes. The fixture
	// adds 54 and 28 string bytes, plus 37 per support record. A future ACK
	// reserves three 1024-byte result strings.
	const expected = 648 + 54 + 37 + 763 + 28 + 37 + 3072
	if capacity.framedBytes != expected || capacity.pages != 2 || capacity.pageDelta != 0 {
		t.Fatalf("signed capacity: framed=%d expected=%d pages=%d delta=%d", capacity.framedBytes, expected, capacity.pages, capacity.pageDelta)
	}
	partial := *complete
	partial.support = append([]format.RequiredSupportPageView(nil), complete.support...)
	for i := range partial.support {
		if len(partial.support[i].Records) == 1 && partial.support[i].Records[0].Kind == contract.PublicationMarkerSupportKind {
			partial.support[i].Records = nil
		}
	}
	partialPlan, err := partial.planPublicationRewrite(t.Context(), partial.adminIndex)
	if err != nil {
		t.Fatal("partial plan", err)
	}
	partialCapacity, err := partialPlan.capacity()
	if err != nil || partialCapacity != capacity {
		t.Fatalf("partial changed signed reservation: %#v %#v %v", capacity, partialCapacity, err)
	}
	// A plan owns its input; later caller mutation cannot alter the guarantee.
	complete.adminIndex.Pages[1].Rows[0].BodyLength++
	retained, err := plan.capacity()
	if err != nil || retained != capacity {
		t.Fatal("plan borrowed mutable input", err)
	}
}

// full_only: false
func TestPublicationCapacityRejectsChangedSelectedFacts(t *testing.T) {
	for _, damage := range []string{"mandatory_body", "evidence_summary", "signed_length", "filtered_work", "unknown_owner"} {
		t.Run(damage, func(t *testing.T) {
			state := publicationCapacityState(t)
			work := clonePublicationWork(state.adminIndex)
			switch damage {
			case "mandatory_body":
				for i := range state.support {
					if len(state.support[i].Records) == 1 && state.support[i].Records[0].Kind == contract.PublicationCoordinateSupportKind {
						state.support[i].Records = nil
					}
				}
			case "evidence_summary":
				for i := range state.adminIndex.Groups {
					if state.adminIndex.Groups[i].OwnerKind == format.AdministrativePublicationMarker {
						state.adminIndex.Groups[i].SelectedEvidenceSummary = contract.AdministrativeEvidenceAcknowledged
					}
				}
				work = state.adminIndex
			case "signed_length":
				for i := range state.adminIndex.Pages {
					for j := range state.adminIndex.Pages[i].Rows {
						if state.adminIndex.Pages[i].Rows[j].Kind == contract.PublicationMarkerSupportKind {
							state.adminIndex.Pages[i].Rows[j].BodyLength++
						}
					}
				}
				work = state.adminIndex
			case "filtered_work":
				work.Pages[1].Rows[0].BodyLength++
			case "unknown_owner":
				for i := range state.adminIndex.Groups {
					if state.adminIndex.Groups[i].OwnerKind == format.AdministrativePublicationMarker {
						state.adminIndex.Groups[i].OwnerID = publicationRelationID(99)
						state.adminIndex.Groups[i].TargetID = state.adminIndex.Groups[i].OwnerID
					}
				}
				work = state.adminIndex
			}
			if _, err := state.planPublicationRewrite(t.Context(), work); !errors.Is(err, contract.ErrRecord) {
				t.Fatalf("damaged facts accepted: %v", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedAdmissionReservesPublicationPeerOverlap(t *testing.T) {
	state := publicationCapacityState(t)
	proof, result, err := validateSelectedPublicationConfiguration(t.Context(), state.selectedImage(), nil)
	if err != nil || result.Outcome != 0 {
		t.Fatal(err, result)
	}
	state.publicationProof = proof
	selected, err := state.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1,
		Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal(err)
	}
	groups, err = state.generatedPublicationCapacity(t.Context(), groups)
	if err != nil {
		t.Fatal(err)
	}
	owners := groups[contract.GeneratorCapacityOwners]
	// Six owner groups each reserve two 37-byte frames, a 661-byte Duty,
	// a 120-byte carrier and a 559-byte Target. Publication keeps its original
	// rows and a separate future image with three 1024-byte result strings.
	const original = 6*1414 + 739 + 828
	const future = 739 + 828 + 3072
	if owners.MaxCount != 8 || owners.MaxPages != 4 || owners.MaxFramedBytes != original+future {
		t.Fatal("future overlap lost/doubled a charge", owners)
	}
	t.Run("invalid_index", func(t *testing.T) {
		state := publicationCapacityState(t)
		state.adminIndex = format.AdministrativeIndex{}
		if _, err := state.generatedPublicationCapacity(t.Context(), groups); !errors.Is(err, contract.ErrRecord) {
			t.Fatal("invalid selected index accepted", err)
		}
	})
	t.Run("cancelled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := state.generatedPublicationCapacity(ctx, groups); !errors.Is(err, contract.ErrRecord) {
			t.Fatal("cancelled publication charge accepted", err)
		}
	})
	t.Run("actual_admission", func(t *testing.T) {
		state := publicationCapacityState(t)
		generatedSealSelectedFixture(t, state)
		proof, result, err := validateSelectedPublicationConfiguration(t.Context(), state.selectedImage(), nil)
		if err != nil || result.Outcome != 0 || proof == nil {
			t.Fatal("actual admission publication proof", result, err)
		}
		state.publicationProof = proof
		input := generatedPlanInputFixture(t, state)
		plan, err := state.generatedPlanRequest(t.Context(), input)
		if err != nil || plan == nil || state.prepared {
			t.Fatal("publication-aware generated admission", err)
		}
		if actual := plan.capacity.Groups[contract.GeneratorCapacityOwners]; actual != owners {
			t.Fatal("actual admission lost publication overlap", actual, owners)
		}
		state.adminIndex = format.AdministrativeIndex{}
		// A cleared Slice snapshot fails the format-owned selected reader first.
		if plan, err := state.generatedPlanRequest(t.Context(), input); !errors.Is(err, format.ErrFormat) || plan != nil || state.prepared {
			t.Fatal("invalid publication selection reached preparation", err)
		}
	})
}
