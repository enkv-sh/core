package core

import (
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeSliceSnapshotRequiresExactRetainedCarrier(t *testing.T) {
	for _, damage := range []string{"retained", "fresh", "foreign_owner", "new_ref_old_owner", "mutated_body_old_ref"} {
		t.Run(damage, func(t *testing.T) {
			state := publicationMixedPeerState(t)
			state.admission.composition = publicationRelationID(87)
			state.admission.expires = time.Now().Add(time.Minute)
			state.admission.store.HeadKey = state.admission.store.Prefix + "/HEAD"
			state.store.(*generatedFixtureSupportStore).descriptor = state.admission.store
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			if damage == "fresh" {
				next.support = slices.Clone(state.support)
				next.root.RequiredSupport = slices.Clone(state.root.RequiredSupport)
				for i, page := range state.adminIndex.Pages {
					if !page.ReadRequired {
						continue
					}
					var rows []contract.SupportRecord
					for _, row := range state.support[i].Records {
						rows = append(rows, contract.SupportRecord(row))
					}
					rows, err := rebindSnapshotSliceRecords(rows, state.root.Domain, state.adminIndex.SliceSnapshot, next.root.Snapshot)
					if err != nil {
						t.Fatal(err)
					}
					object := contract.Hash(append([]byte("fresh carrier"), byte(page.Ref.Index)))
					ref, view, _, err := endWorkSupportPage(state.root.Domain, object, page.Ref.Index, rows, nil)
					if err != nil {
						t.Fatal(err)
					}
					next.root.RequiredSupport[i], next.support[i] = ref, view
				}
			}

			pages := make([]format.RequiredSupportPage, len(next.support))
			next.root.RequiredSupport = slices.Clone(next.root.RequiredSupport)
			for i, page := range next.support {
				pages[i] = format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index}
				for _, row := range page.Records {
					pages[i].Records = append(pages[i].Records, contract.SupportRecord(row))
				}
				for j, row := range pages[i].Records {
					if row.Kind != contract.GeneratorVectorSupportKind {
						continue
					}
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if carrier.VectorKind != contract.GeneratorVectorSlices {
						continue
					}
					switch damage {
					case "foreign_owner":
						carrier.OwnerID = publicationRelationID(98)
					case "mutated_body_old_ref":
						carrier.Vector.Digest = publicationRelationID(99)
					case "new_ref_old_owner":
						ref := next.root.RequiredSupport[i]
						ref.Object = publicationRelationID(99)
						next.root.RequiredSupport[i] = ref
						pages[i].Object = ref.Object
					}
					if damage == "foreign_owner" || damage == "mutated_body_old_ref" {
						pages[i].Records[j].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
						if err != nil {
							t.Fatal(err)
						}
						pages[i].Records[j].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			index, err := state.buildAdministrativeIndex(t.Context(), next.root, pages, nil, nil, &next)
			if damage == "retained" || damage == "fresh" {
				expected := state.adminIndex.SliceSnapshot
				if damage == "fresh" {
					expected = next.root.Snapshot
				}
				if err != nil || index.SliceSnapshot != expected {
					t.Fatal("valid slice owner refused", err, index.SliceSnapshot, expected)
				}
			} else if err == nil {
				t.Fatal("invalid slice carrier accepted")
			}
		})
	}
}
