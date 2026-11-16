package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeRowOwnershipBorrowsSelectedMetadata(t *testing.T) {
	state := generatedReservationState(t)
	owners, err := state.priorAdministrativeRows()
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) == 0 {
		t.Fatal("fixture has no selected ownership")
	}
	var ownedIDs uint64
	for _, owner := range owners {
		value := reflect.ValueOf(owner)
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.Kind() == reflect.Slice && field.Type().Elem() == reflect.TypeOf(contract.ID{}) {
				ownedIDs += uint64(field.Cap())
			}
		}
	}
	if ownedIDs != 0 {
		t.Fatal("prior ownership expands selected owner indices into owned IDs", ownedIDs, ownedIDs*32)
	}
}

// full_only: false
func TestPublicationWorkspaceBorrowsPlanOwnedPeers(t *testing.T) {
	state := publicationMixedPeerState(t)
	plan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	shared, mixed := 0, 0
	for _, peer := range plan.peers {
		i := slices.IndexFunc(plan.work.Pages, func(page format.AdministrativePage) bool { return page.Ref == peer.Ref })
		if i < 0 {
			t.Fatal("peer not in owned work")
		}
		page := plan.work.Pages[i]
		publication := slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
			return row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind
		})
		if !publication {
			shared++
			if unsafe.SliceData(peer.Spans) != unsafe.SliceData(page.Spans) || unsafe.SliceData(peer.Rows) != unsafe.SliceData(page.Rows) {
				t.Fatal("unchanged peer owns duplicate metadata")
			}
		} else {
			mixed++
		}
		for _, span := range peer.Spans {
			j := slices.IndexFunc(page.Spans, func(original format.AdministrativeSpan) bool { return original.First == span.First })
			if j < 0 || !slices.Equal(span.GroupIndexes, page.Spans[j].GroupIndexes) ||
				unsafe.SliceData(span.GroupIndexes) != unsafe.SliceData(page.Spans[j].GroupIndexes) {
				t.Fatal("peer does not borrow owned span owners")
			}
		}
	}
	if shared == 0 || mixed == 0 {
		t.Fatal("fixture missing unchanged or mixed peer", shared, mixed)
	}
	capacity, err := plan.capacity()
	if err != nil {
		t.Fatal(err)
	}
	for i := range state.adminIndex.Pages {
		for j := range state.adminIndex.Pages[i].Rows {
			state.adminIndex.Pages[i].Rows[j].BodyLength++
		}
		for j := range state.adminIndex.Pages[i].Spans {
			state.adminIndex.Pages[i].Spans[j].Mandatory = !state.adminIndex.Pages[i].Spans[j].Mandatory
		}
	}
	got, err := plan.capacity()
	if err != nil || got != capacity {
		t.Fatal("mutable predecessor changed owned reservation", err)
	}
	if samePublicationWork(plan.work, state.adminIndex) {
		t.Fatal("complete selected input mutation not detected")
	}
}

// full_only: false
func TestAdministrativeWriterDisposableDigestMatchesFraming(t *testing.T) {
	state := publicationMixedPeerState(t)
	checkSelectedDisposableFraming(t, state)
	t.Logf("64-bit sizes: group=%d page=%d span=%d summary=%d support=%d planned=%d location=%d prior=%d",
		unsafe.Sizeof(format.AdministrativeGroup{}), unsafe.Sizeof(format.AdministrativePage{}),
		unsafe.Sizeof(format.AdministrativeSpan{}), unsafe.Sizeof(format.AdministrativeRowSummary{}),
		unsafe.Sizeof(contract.SupportRecord{}), unsafe.Sizeof(administrativePlannedRow{}),
		unsafe.Sizeof(contract.GeneratorSliceLocation{}), unsafe.Sizeof(priorAdministrativeRow{}))
}

func checkSelectedDisposableFraming(t *testing.T, state *StateSession) {
	t.Helper()
	for _, group := range state.adminIndex.Groups {
		var records []byte
		var count uint32
		for i, page := range state.adminIndex.Pages {
			logical := 0
			for _, span := range page.Spans {
				for offset := 0; offset < int(span.Count); offset++ {
					row := state.support[i].Records[logical]
					logical++
					if !slices.ContainsFunc(span.GroupIndexes, func(index uint16) bool {
						return state.adminIndex.Groups[index].GroupID == group.GroupID
					}) {
						continue
					}
					records = binary.BigEndian.AppendUint32(records, 37)
					records = append(records, row.Kind)
					records = append(records, row.RecordID[:]...)
					records = binary.BigEndian.AppendUint32(records, uint32(len(row.Body)))
					count++
				}
			}
		}
		body := binary.BigEndian.AppendUint32(nil, count)
		body = append(body, records...)
		preimage := append([]byte("ENKV/admin-descriptor/v1/selected-disposable\x00"), body...)
		want := sha256.Sum256(preimage)
		if !bytes.Equal(group.Disposable.Digest[:], want[:]) || group.Disposable.Length != uint64(len(body)) || group.Disposable.Count != count {
			t.Fatal("selected-disposable framing changed", count, group.Disposable.Length, len(body))
		}
	}
}

// full_only: false
func TestEndWorkRechargeDisposableDigestMatchesFraming(t *testing.T) {
	state := publicationMixedPeerState(t)
	next := *state
	next.adminIndex = clonePublicationWork(state.adminIndex)
	views := make(map[format.Ref]format.RequiredSupportPageView)
	for i, page := range next.adminIndex.Pages {
		if page.ReadRequired {
			views[page.Ref] = next.support[i]
		}
	}
	if err := rechargeEndWorkGroups(&next.adminIndex, views); err != nil {
		t.Fatal(err)
	}
	checkSelectedDisposableFraming(t, &next)
	for i, group := range next.adminIndex.Groups {
		before := state.adminIndex.Groups[i]
		if group.ChargedPages != before.ChargedPages || group.ChargedBytes != before.ChargedBytes {
			t.Fatal("recharge changed physical page or byte charge", i, group.ChargedPages, before.ChargedPages, group.ChargedBytes, before.ChargedBytes)
		}
	}
}

// full_only: false
func TestPublicationWorkspaceRejectsCompleteInputMutation(t *testing.T) {
	for _, damage := range []string{"group_descriptor", "peer_summary", "physical_span", "incarnation_order"} {
		t.Run(damage, func(t *testing.T) {
			state := publicationMixedPeerState(t)
			rows := publicationNoEffectRows(t, state)
			construction, err := state.preparePublicationConstruction(t.Context(), rows)
			if err != nil {
				t.Fatal("healthy construction before source mutation", err)
			}
			switch damage {
			case "group_descriptor":
				state.adminIndex.Groups[0].Affected.Digest[0] ^= 1
			case "peer_summary":
				changed := false
				for i := range state.adminIndex.Pages {
					for j := range state.adminIndex.Pages[i].Rows {
						row := &state.adminIndex.Pages[i].Rows[j]
						if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
							row.BodyLength++
							changed = true
							break
						}
					}
					if changed {
						break
					}
				}
				if !changed {
					t.Fatal("fixture has no peer summary")
				}
			case "physical_span":
				state.adminIndex.Pages[0].Spans[0].First++
			case "incarnation_order":
				state.adminIndex.PublicationOrder[0].Incarnations[0][0] ^= 1
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			err = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			if !errors.Is(err, contract.ErrRecord) || len(candidate.objects) != 0 {
				t.Fatal("changed complete input accepted or emitted objects", err, len(candidate.objects))
			}
		})
	}
}

// full_only: false
func TestPublicationDispositionBindsAlignedFacts(t *testing.T) {
	for _, condition := range []string{"raw", "aligned", "sparse", "optional_unreadable", "wrong_ref", "missing_fact", "missing_page_facts", "wrong_identity", "wrong_body", "wrong_ordinal", "short_ordinals"} {
		t.Run(condition, func(t *testing.T) {
			state := publicationCapacityState(t)
			if condition != "raw" {
				generatedInstallFixtureSupportReader(t, state)
			}
			position := slices.IndexFunc(state.support, func(page format.RequiredSupportPageView) bool {
				return len(page.Records) == 1 && page.Records[0].Kind == contract.PublicationMarkerSupportKind
			})
			if position < 0 {
				t.Fatal("fixture has no optional publication page")
			}
			switch condition {
			case "sparse":
				page := state.adminIndex.Pages[position]
				row := contract.SupportRecord(state.support[position].Records[0])
				obsolete := row
				obsolete.RecordID = publicationRelationID(101)
				marker, err := contract.InspectPublicationMarker(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				marker.AttemptID = obsolete.RecordID
				obsolete.Body, err = contract.EncodePublicationMarker(marker)
				if err != nil {
					t.Fatal(err)
				}
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Ref.Domain, Object: page.Ref.Object,
					Index: page.Ref.Index, Records: []contract.SupportRecord{obsolete, row}})
				if err != nil {
					t.Fatal(err)
				}
				ref, err := format.Reference(contract.RequiredSupportKind, page.Ref.Domain, page.Ref.Object, page.Ref.Index, body)
				if err != nil {
					t.Fatal(err)
				}
				state.root.RequiredSupport[position], state.adminIndex.Pages[position].Ref, state.supportFacts[position].ref = ref, ref, ref
				state.adminIndex.Pages[position].Spans[0].First = 1
				state.supportFacts[position].ordinals[0] = 1
			case "optional_unreadable":
				state.support[position].Records = nil
				state.supportFacts[position].rows, state.supportFacts[position].ordinals = nil, nil
			case "wrong_ref":
				state.supportFacts[position].ref.Digest[0] ^= 1
			case "missing_fact":
				state.supportFacts[position].rows = nil
			case "missing_page_facts":
				state.supportFacts[position].rows, state.supportFacts[position].ordinals = nil, nil
			case "wrong_identity":
				state.supportFacts[position].rows[0] = state.supportFacts[position-1].rows[0]
			case "wrong_body":
				body := bytes.Clone(state.support[position].Records[0].Body)
				body[len(body)-1] ^= 1
				state.support[position].Records[0].Body = body
			case "wrong_ordinal":
				state.supportFacts[position].ordinals[0]++
			case "short_ordinals":
				state.supportFacts[position].ordinals = nil
			}
			owners, loaded, err := state.publicationLoadedRowsForDisposition()
			valid := condition == "raw" || condition == "aligned" || condition == "sparse" || condition == "optional_unreadable"
			if !valid {
				if !errors.Is(err, contract.ErrRecord) {
					t.Fatalf("damaged selected fact accepted: condition=%s err=%v", condition, err)
				}
				return
			}
			wantLoaded := 2
			if condition == "optional_unreadable" {
				wantLoaded = 1
			}
			if err != nil || len(owners) != 2 || len(loaded) != wantLoaded {
				t.Fatalf("selected rows: condition=%s owners=%d loaded=%d want=%d err=%v", condition, len(owners), len(loaded), wantLoaded, err)
			}
		})
	}
}

// full_only: false
func TestPublicationExitProofKeepsCoordinateAndFamilyScope(t *testing.T) {
	for _, condition := range []string{"independent", "cross_coordinate", "publication_depends_on_generated", "generated_depends_on_publication", "generated_row_owner", "read_required_owner"} {
		t.Run(condition, func(t *testing.T) {
			state := publicationMixedPeerState(t)
			rows, order := publicationJointRows(t, state.root.Domain, 1)
			state.adminIndex.PublicationOrder = append(state.adminIndex.PublicationOrder, order...)
			slices.SortFunc(state.adminIndex.PublicationOrder, func(a, b format.PublicationCoordinateOrder) int {
				return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
			})
			page := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(105), Index: generatedFixtureFreeSupportIndex(t, state)}
			for _, row := range rows {
				page.Records = append(page.Records, contract.SupportRecordView(row))
			}
			state.support = append(state.support, page)
			generatedRefreshSupport(t, state, generatedFixtureBundles(t, state)...)
			coordinates, err := state.publicationCoordinatesForDisposition()
			if err != nil || len(coordinates) != 2 {
				t.Fatal("independent selected coordinates", len(coordinates), err)
			}
			marker, generated, otherCoordinate := -1, -1, -1
			for i, group := range state.adminIndex.Groups {
				if marker < 0 && group.OwnerKind == format.AdministrativePublicationMarker {
					marker = i
				}
				if generated < 0 && group.OwnerKind == format.AdministrativeGeneratedDuty {
					generated = i
				}
			}
			if marker < 0 || generated < 0 {
				t.Fatal("fixture has no publication marker or generated Duty")
			}
			for i, group := range state.adminIndex.Groups {
				if group.OwnerKind == format.AdministrativePublicationCoordinate && group.GroupID != state.adminIndex.Groups[marker].OwnerID {
					otherCoordinate = i
				}
			}
			if otherCoordinate < 0 {
				t.Fatal("fixture has no other coordinate")
			}
			switch condition {
			case "cross_coordinate", "publication_depends_on_generated", "generated_depends_on_publication":
				from, to := marker, otherCoordinate
				switch condition {
				case "publication_depends_on_generated":
					to = generated
				case "generated_depends_on_publication":
					from, to = generated, marker
				}
				state.adminIndex.Groups[from].RelatedGroupIndexes = append(state.adminIndex.Groups[from].RelatedGroupIndexes, uint16(to))
				slices.Sort(state.adminIndex.Groups[from].RelatedGroupIndexes)
			case "generated_row_owner", "read_required_owner":
				changed := false
				for i := range state.adminIndex.Pages {
					page := &state.adminIndex.Pages[i]
					if condition == "read_required_owner" && !page.ReadRequired || condition == "generated_row_owner" && page.ReadRequired {
						continue
					}
					logical := 0
					for j := range page.Spans {
						span := &page.Spans[j]
						if page.ReadRequired || logical < len(page.Rows) && page.Rows[logical].Kind == contract.GeneratedDutySupportKind {
							span.GroupIndexes = append(span.GroupIndexes, uint16(marker))
							slices.Sort(span.GroupIndexes)
							changed = true
							break
						}
						logical += int(span.Count)
					}
					if changed {
						break
					}
				}
				if !changed {
					t.Fatal("fixture missing ownership countercase", condition)
				}
			}
			if !state.adminIndex.Valid() {
				t.Fatal("countercase is not a structurally valid index", condition)
			}
			got := publicationExitsAreCoordinateLocal(state.adminIndex, coordinates)
			if got != (condition == "independent") {
				t.Fatalf("coordinate-local exit proof: condition=%s got=%t", condition, got)
			}
		})
	}
}

// full_only: false
func TestPublicationExitChecksActualIntentCompaction(t *testing.T) {
	for _, condition := range []string{"noncanonical", "canonical", "no_intents"} {
		t.Run(condition, func(t *testing.T) {
			state := publicationCapacityState(t)
			if condition != "no_intents" {
				state = generatedSelectedEntryState(t)
				_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
				coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
				page := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(106), Index: generatedFixtureFreeSupportIndex(t, state)}
				for _, row := range publicationRelationRows(t, coordinate, marker) {
					page.Records = append(page.Records, contract.SupportRecordView(row))
				}
				state.support = append(state.support, page)
				generatedRefreshSupport(t, state)
				generatedRepackSupport(t, state, state.supportRecords(), nil)
			}
			compactIntent, err := hex.DecodeString("00010909090909090909090909090909090909090909090909090909090909090909020707070707070707070707070707070707070707070707070707070707070707000000027b7d")
			if err != nil {
				t.Fatal(err)
			}
			compactBlob := contract.ID{
				0xad, 0x1c, 0xca, 0xe6, 0x1c, 0xfb, 0xcc, 0xdf,
				0x41, 0xad, 0x11, 0xef, 0x76, 0x47, 0xe2, 0x6a,
				0x20, 0xda, 0xe2, 0xc5, 0xce, 0x0d, 0x80, 0xbb,
				0xe7, 0xfd, 0x44, 0x11, 0xad, 0x95, 0x7e, 0x7a,
			}
			if condition == "canonical" {
				for i := range state.support {
					for j, row := range state.support[i].Records {
						switch row.Kind {
						case contract.GeneratedFragmentSupportKind:
							fragment, err := contract.InspectGeneratedFragment(row.Body)
							if err != nil {
								t.Fatal(err)
							}
							if fragment.BlobID != generatedVectorID(30) {
								continue
							}
							fragment.BlobID = compactBlob
							state.support[i].Records[j].Body, err = contract.EncodeGeneratedFragment(contract.GeneratedFragment(fragment))
							if err != nil {
								t.Fatal(err)
							}
							state.support[i].Records[j].RecordID, err = contract.GeneratorFragmentID(compactBlob, fragment.Index)
							if err != nil {
								t.Fatal(err)
							}
						case contract.GeneratorVectorSupportKind:
							carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
							if err != nil {
								t.Fatal(err)
							}
							if carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.VectorKind != contract.GeneratorVectorSlices {
								continue
							}
							location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
							if err != nil {
								t.Fatal(err)
							}
							location.BlobID = compactBlob
							carrier.Row, err = contract.EncodeGeneratorSliceLocation(location)
							if err != nil {
								t.Fatal(err)
							}
							state.root.Generated.Slices, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, [][]byte{carrier.Row})
							if err != nil {
								t.Fatal(err)
							}
							carrier.Vector = state.root.Generated.Slices
							state.support[i].Records[j].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
							if err != nil {
								t.Fatal(err)
							}
							state.support[i].Records[j].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				for i := range state.root.Generated.Fragments {
					if state.root.Generated.Fragments[i].BlobID == generatedVectorID(30) {
						state.root.Generated.Fragments[i].BlobID = compactBlob
					}
				}
				generatedRefreshSupport(t, state)
			}
			coordinates, err := state.publicationCoordinatesForDisposition()
			if err != nil || !publicationExitsAreCoordinateLocal(state.adminIndex, coordinates) {
				t.Fatal("independent publication fixture", err)
			}
			plan, err := state.planAdministrativeCurrentIntents(t.Context(), state.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			if condition != "no_intents" && (plan.blob != compactBlob || plan.total != 73 || plan.fragments != 1 || len(plan.before) != 1 || len(plan.after) != 1 ||
				plan.after[0].BlobID != compactBlob || plan.after[0].Offset != 0 || plan.after[0].Length != 73) {
				t.Fatalf("literal current intent projection: blob=%x bytes=%d fragments=%d before=%d after=%d", plan.blob, plan.total, plan.fragments, len(plan.before), len(plan.after))
			}
			if condition == "noncanonical" && (!plan.changed || !plan.emit || len(plan.dropBlobs) != 1 || !plan.dropBlobs[generatedVectorID(30)] || plan.before[0].BlobID != generatedVectorID(30)) {
				t.Fatal("known noncanonical blob was not projected for compaction")
			}
			if condition != "noncanonical" && (plan.changed || len(plan.dropBlobs) != 0) {
				t.Fatal("canonical or absent current intents need compaction")
			}
			noCompaction, err := state.publicationExitNeedsNoIntentCompaction(t.Context())
			if err != nil || noCompaction != (condition != "noncanonical") {
				t.Fatalf("publication shortcut compaction proof: condition=%s allowed=%t err=%v", condition, noCompaction, err)
			}
			if err := state.reserveFirstEndWork(t.Context()); err != nil {
				t.Fatal("actual small first-exit reservation", err)
			}
			if condition == "noncanonical" {
				marker := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
					return group.OwnerKind == format.AdministrativePublicationMarker
				})
				if marker < 0 {
					t.Fatal("fixture has no publication marker")
				}
				work, ended, err := state.administrativeWorkClosure(state.adminIndex.Groups[marker].GroupID)
				if err != nil || len(ended) != 1 || ended[0].OwnerKind != format.AdministrativePublicationMarker {
					t.Fatal("publication-only actual exit closure", len(ended), err)
				}
				work, err = state.administrativeWorkWithoutOldReceipts(work)
				if err != nil {
					t.Fatal(err)
				}
				exitPlan, err := state.planAdministrativeCurrentIntents(t.Context(), work)
				if err != nil || !exitPlan.changed || len(exitPlan.dropBlobs) != 1 || !exitPlan.dropBlobs[generatedVectorID(30)] ||
					exitPlan.blob != compactBlob || exitPlan.total != 73 || exitPlan.fragments != 1 {
					t.Fatal("publication-only exit must retain actual intent compaction", err)
				}
				owners, err := state.prepareAdministrativeIntentRemoval(&work, exitPlan)
				if err != nil {
					t.Fatal(err)
				}
				selected, err := state.administrativeCurrentIntentSelection(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				images, views, directory, added, err := state.addAdministrativeCurrentIntentBlob(t.Context(), &work,
					endWorkIDs{operation: publicationRelationID(107)}, selected, exitPlan, owners)
				if err != nil || len(images) != 1 || len(views) != 1 || len(directory) != 1 || added != 1 || directory[0].BlobID != compactBlob {
					t.Fatalf("actual compact image: images=%d views=%d directory=%d added=%d err=%v", len(images), len(views), len(directory), added, err)
				}
				for _, view := range views {
					if len(view.Records) != 1 {
						t.Fatal("compact fragment page row count", len(view.Records))
					}
					fragment, err := contract.InspectGeneratedFragment(view.Records[0].Body)
					if err != nil || fragment.BlobID != compactBlob || fragment.WholeDigest != compactBlob || fragment.TotalLength != 73 || !bytes.Equal(fragment.Payload, compactIntent) {
						t.Fatal("actual compact fragment differs from literal intent", err)
					}
				}
			}
		})
	}
}
