package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationJointID(domain contract.ID, label string, n int) contract.ID {
	return contract.Hash([]byte(fmt.Sprintf("publication-joint/%x/%s/%d", domain, label, n)))
}

// Each coordinate has six distinct retained incarnations: two entered markers,
// three compacted ACK stamps, and the unreferenced current incarnation.
func publicationJointRows(t *testing.T, domain contract.ID, count int) ([]contract.SupportRecord, []format.PublicationCoordinateOrder) {
	t.Helper()
	var rows []contract.SupportRecord
	var orders []format.PublicationCoordinateOrder
	for i := 0; i < count; i++ {
		_, c, m, _ := publicationRelationFixtureForDomain(t, domain)
		c.CanonicalTarget = fmt.Sprintf("account/joint/%04d", i)
		var err error
		c.CoordinateID, err = contract.PublicationCoordinateID(domain, c.ServiceContractID, c.CanonicalTarget)
		if err != nil {
			t.Fatal(err)
		}
		c.BindingState, c.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
		c.CurrentPublicationIncarnationID = publicationJointID(domain, "current", i)
		c.LastAdmissionOrdinal = math.MaxUint64
		c.LastValueAckAttemptID, c.LastValueDigest = publicationJointID(domain, "value-attempt", i), publicationJointID(domain, "value-digest", i)
		c.LastPolicyAckAttemptID, c.LastPolicyDigest = publicationJointID(domain, "policy-attempt", i), publicationJointID(domain, "policy-digest", i)
		c.LastDeleteAckAttemptID = publicationJointID(domain, "delete-attempt", i)
		c.LastValueAckIncarnationID, c.LastValueAckOrdinal = publicationJointID(domain, "value-incarnation", i), 1
		c.LastPolicyAckIncarnationID, c.LastPolicyAckOrdinal = publicationJointID(domain, "policy-incarnation", i), 1
		c.LastDeleteAckIncarnationID, c.LastDeleteAckOrdinal = publicationJointID(domain, "delete-incarnation", i), 1
		order := format.PublicationCoordinateOrder{CoordinateID: c.CoordinateID, Incarnations: []contract.ID{c.LastValueAckIncarnationID, c.LastPolicyAckIncarnationID, c.LastDeleteAckIncarnationID}}
		for j := 0; j < 2; j++ {
			marker := m
			marker.CoordinateID, marker.Projection.CoordinateID = c.CoordinateID, c.CoordinateID
			marker.AttemptID = publicationJointID(domain, fmt.Sprintf("marker-%d", j), i)
			marker.OperationID = publicationJointID(domain, fmt.Sprintf("operation-%d", j), i)
			marker.PublicationIncarnationID = publicationJointID(domain, fmt.Sprintf("marker-incarnation-%d", j), i)
			marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
			if err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodePublicationMarker(marker)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
			order.Incarnations = append(order.Incarnations, marker.PublicationIncarnationID)
			c.LatestUnresolvedAttemptID = marker.AttemptID
		}
		order.Incarnations = append(order.Incarnations, c.CurrentPublicationIncarnationID)
		body, err := contract.EncodePublicationCoordinate(c)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: c.CoordinateID, Body: body})
		orders = append(orders, order)
	}
	slices.SortFunc(orders, func(a, b format.PublicationCoordinateOrder) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	return rows, orders
}

func publicationJointPageIDs(domain contract.ID, label string, count int) []contract.ID {
	ids := make([]contract.ID, count)
	for i := range ids {
		ids[i] = publicationJointID(domain, label, i)
	}
	return ids
}

// full_only: false
func TestPublicationJointRetainedCapacity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		count        int
		acknowledged bool
	}{
		{"small", 2, false}, {"maximum", 1024, false},
		{"small-ack", 2, true}, {"maximum-ack", 1024, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := tc.count
			state := generatedEmptyPredecessor(t)
			rows, order := publicationJointRows(t, state.root.Domain, count)
			if tc.acknowledged {
				for i := range rows {
					if rows[i].Kind != contract.PublicationCoordinateSupportKind {
						continue
					}
					coordinate, err := contract.InspectPublicationCoordinate(rows[i].Body)
					if err != nil {
						t.Fatal(err)
					}
					coordinate.DeletionConsumerLocator = strings.Repeat("l", 1024)
					rows[i].Body, err = contract.EncodePublicationCoordinate(coordinate)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			state.root.WarningBits = WarningPublicationOrderValue | WarningDiscardedExactEvidence
			state.adminIndex.PublicationOrder = order
			var mandatory administrativeMandatorySupport
			if _, err := mandatory.selectedPublication(state.root.Domain, rows, order); err != nil {
				t.Fatal(err)
			}
			var groups []format.RequiredSupportGroup
			for _, row := range rows {
				keep, err := mandatory.row(row)
				if err != nil {
					t.Fatal(err)
				}
				groups = append(groups, format.RequiredSupportGroup{Class: format.OwnerSupport, Owner: row.RecordID, Mandatory: keep, Records: []contract.SupportRecord{row}})
			}
			packed, err := format.PackRequiredSupportRows(state.root.Domain, groups, 0)
			if err != nil {
				t.Fatal(err)
			}
			for i, page := range packed {
				view := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationJointID(state.root.Domain, "source-page", i), Index: uint16(i + 1)}
				for _, row := range page {
					view.Records = append(view.Records, contract.SupportRecordView(row))
				}
				state.support = append(state.support, view)
			}
			generatedRefreshSupport(t, state)
			selected, err := selectedPublicationRelation(state.selectedImage())
			if err != nil || len(selected.coordinates) != count || len(selected.markers) != 2*count {
				t.Fatalf("selected counts coordinates=%d markers=%d err=%v", len(selected.coordinates), len(selected.markers), err)
			}
			retained, err := publicationIncarnationOrder(state.adminIndex, selected.coordinates, false)
			if err != nil || !reflect.DeepEqual(retained, order) {
				t.Fatal("retained union/order", err)
			}
			total := 0
			for _, row := range retained {
				total += len(row.Incarnations)
			}
			if total != 6*count {
				t.Fatal("retained union count", total)
			}
			plan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := plan.capacity()
			if err != nil {
				t.Fatal(err)
			}
			// Fixed coordinate framing is 648 bytes; fixture strings add 54 and
			// the joint target adds 6. The ACK case replaces its 7-byte static locator
			// with 1024 bytes before admission. Each support frame adds 37 bytes.
			coordinateFrame := 648 + 54 + 6 + 37
			if tc.acknowledged {
				coordinateFrame += 1024 - 7
			}
			const markerFrame = 763 + 28 + 37
			want := uint64(count * (coordinateFrame + 2*(markerFrame+3072)))
			if bound.framedBytes != want {
				t.Fatalf("future framed bytes=%d want=%d", bound.framedBytes, want)
			}
			proof, result, err := validateSelectedPublicationConfiguration(t.Context(), state.selectedImage(), nil)
			if err != nil || result.Outcome != 0 || proof == nil {
				t.Fatal("replacement predecessor proof", result, err)
			}
			state.publicationProof = proof
			generated, err := state.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("replacement selected work", err)
			}
			shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1,
				Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
			replacement, err := generatedCapacityWithBacklog(shape, generated)
			if err != nil {
				t.Fatal("replacement overlap charge", err)
			}
			replacement, err = state.generatedPublicationCapacity(t.Context(), replacement)
			if err != nil {
				t.Fatal("replacement publication overlap charge", err)
			}
			owners := replacement[contract.GeneratorCapacityOwners]
			// A clean generated create permits six 1414-byte owner reservations. Retained
			// publication uses its original bodies and a distinct future result image;
			// the 3072-byte evidence growth belongs only to that future image.
			wantOriginal := uint64(count * (coordinateFrame + 2*markerFrame))
			if owners.MaxCount != uint64(6+3*count) || owners.MaxFramedBytes != 6*1414+wantOriginal+want {
				t.Fatalf("replacement owners count=%d framed=%d original=%d future=%d", owners.MaxCount, owners.MaxFramedBytes, wantOriginal, want)
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationJointID(state.root.Domain, "close-snapshot", 0), publicationJointID(state.root.Domain, "close-transition", 0)
			closed := publicationNoEffectRows(t, state)
			if tc.acknowledged {
				for i := range closed {
					row := &closed[i]
					switch row.Kind {
					case contract.PublicationMarkerSupportKind:
						marker, err := contract.InspectPublicationMarker(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						marker.State, marker.Evidence.Class = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged
						marker.Evidence.NormalizedStatus = 201
						marker.Evidence.ConsumerLocator = strings.Repeat("l", 1024)
						row.Body, err = contract.EncodePublicationMarker(marker)
						if err != nil {
							t.Fatal(err)
						}
					case contract.PublicationCoordinateSupportKind:
						coordinate, err := contract.InspectPublicationCoordinate(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						before := selected.coordinates[row.RecordID]
						birth := selected.markers[before.LatestUnresolvedAttemptID]
						coordinate.OwnerState, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, birth.AttemptID
						coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(state.root.Domain, coordinate.CoordinateID,
							birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, strings.Repeat("s", 1024))
						if err != nil {
							t.Fatal(err)
						}
						row.Body, err = contract.EncodePublicationCoordinate(coordinate)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			var closeMandatory administrativeMandatorySupport
			if _, err := closeMandatory.selectedPublication(state.root.Domain, closed, order); err != nil {
				t.Fatal(err)
			}
			var closeGroups []format.RequiredSupportGroup
			for _, row := range closed {
				keep, err := closeMandatory.row(row)
				if err != nil {
					t.Fatal(err)
				}
				closeGroups = append(closeGroups, format.RequiredSupportGroup{Class: format.OwnerSupport, Owner: row.RecordID, Mandatory: keep, Records: []contract.SupportRecord{row}})
			}
			closePacked, err := format.PackRequiredSupportRows(state.root.Domain, closeGroups, uint32(len(plan.peers)))
			if err != nil {
				t.Fatal(err)
			}
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), closed)
			if constructionErr == nil {
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, publicationJointPageIDs(state.root.Domain, "close-page", len(closePacked)))
			}
			if err := constructionErr; err != nil {
				t.Fatal("worst actual result packing", err)
			}
			for _, image := range candidate.objects {
				if err := format.CheckReference(image.ref, image.body); err != nil {
					t.Fatal(err)
				}
			}
			if next.root.WarningBits != state.root.WarningBits || next.root.OutputConfiguration != state.root.OutputConfiguration {
				t.Fatal("close changed mandatory state")
			}
			// No-effect results admit two strings; acknowledged creates admit all
			// three and attain the complete reserved result growth without padding.
			actualGrowth := 2048
			if tc.acknowledged {
				actualGrowth = 3072
			}
			actualFramed := uint64(count * (coordinateFrame + 2*(markerFrame+actualGrowth)))
			var physical uint64
			for _, ref := range next.root.RequiredSupport {
				physical += uint64(ref.Length)
			}
			var peers uint64
			for _, peer := range plan.peers {
				peers += uint64(peer.Ref.Length)
			}
			wantPhysical := peers + actualFramed + uint64(len(closePacked))*contract.RequiredSupportPageHeaderLength
			if physical != wantPhysical || physical > bound.physicalBytes {
				t.Fatalf("actual support bytes=%d exact=%d reserve=%d", physical, wantPhysical, bound.physicalBytes)
			}
			logical, err := format.EncodeAdministrativeIndex(next.adminIndex)
			if err != nil || uint64(len(logical)) > bound.indexBytes {
				t.Fatalf("actual logical index bytes=%d reserve=%d err=%v", len(logical), bound.indexBytes, err)
			}
			shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
			decoded, decodeErr := format.DecodeAdministrativeIndexPages(shards)
			roundTrip, roundTripErr := format.EncodeAdministrativeIndex(decoded)
			if err != nil || decodeErr != nil || roundTripErr != nil || !bytes.Equal(roundTrip, logical) ||
				!reflect.DeepEqual(next.adminIndex.PublicationOrder, order) {
				t.Fatalf("actual index/order round trip shards=%d err=%v decode=%v", len(shards), err, decodeErr)
			}
			var shardBytes uint64
			for _, shard := range shards {
				shardBytes += uint64(len(shard.Body))
			}
			// Each physical index shard adds116 bytes to its logical payload.
			if shardBytes != uint64(len(logical))+116*uint64(len(shards)) {
				t.Fatalf("physical index bytes=%d logical=%d shards=%d", shardBytes, len(logical), len(shards))
			}
			// This empty-value predecessor retains one recipient page. The complete
			// root charge includes every physical support and index shard exactly once.
			wantChildren := uint32(len(next.root.RequiredSupport) + len(shards) + 1)
			wantChildBytes := physical + shardBytes + uint64(state.root.Recipients[0].Length)
			if next.root.ChildCount != wantChildren || next.root.ChildEncodedBytes != wantChildBytes {
				t.Fatalf("root physical charge children=%d want=%d bytes=%d want=%d", next.root.ChildCount, wantChildren, next.root.ChildEncodedBytes, wantChildBytes)
			}
			after, err := selectedPublicationRelation(next.selectedImage())
			if err != nil || len(after.coordinates) != count || len(after.markers) != 2*count {
				t.Fatalf("actual closed relation coordinates=%d markers=%d err=%v", len(after.coordinates), len(after.markers), err)
			}
			for id, before := range selected.coordinates {
				wantCoordinate := before
				wantCoordinate.OwnerState = contract.PublicationOwnerNone
				if tc.acknowledged {
					birth := selected.markers[before.LatestUnresolvedAttemptID]
					wantCoordinate.OwnerState, wantCoordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, birth.AttemptID
					preimage := []byte("ENKV/PUBLICATION/OWNED-INSTANCE/v2\x00")
					for _, id := range [...]contract.ID{state.root.Domain, before.CoordinateID, birth.Projection.BindingIncarnationID,
						birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID} {
						preimage = append(preimage, id[:]...)
					}
					preimage = binary.BigEndian.AppendUint32(preimage, 1024)
					preimage = append(preimage, strings.Repeat("s", 1024)...)
					wantCoordinate.OwnedInstanceDigest = contract.ID(sha256.Sum256(preimage))
				}
				wantCoordinate.LatestUnresolvedAttemptID = contract.ID{}
				if !after.coordinates[id].Equal(wantCoordinate) {
					t.Fatalf("closed coordinate differs id=%x", id)
				}
			}
			for id, before := range selected.markers {
				wantMarker := before
				wantMarker.State, wantMarker.Evidence.Class = contract.PublicationQualifiedNoEffectState, contract.PublicationQualifiedNoEffect
				wantMarker.Evidence.SafeRequestID, wantMarker.Evidence.SafeResourceID = strings.Repeat("r", 1024), strings.Repeat("s", 1024)
				if tc.acknowledged {
					wantMarker.State, wantMarker.Evidence.Class = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged
					wantMarker.Evidence.NormalizedStatus, wantMarker.Evidence.ConsumerLocator = 201, strings.Repeat("l", 1024)
				}
				if after.markers[id] != wantMarker {
					t.Fatalf("closed marker differs id=%x", id)
				}
			}
			// Exercise the format-only union boundary even with a small selected
			// state. The maximum case above separately proves a real retained union.
			excess := clonePublicationWork(state.adminIndex)
			for i := 6 * count; i < 6144; i++ {
				excess.PublicationOrder[0].Incarnations = append(excess.PublicationOrder[0].Incarnations, publicationJointID(state.root.Domain, "index-bound", i))
			}
			if _, err := format.EncodeAdministrativeIndex(excess); err != nil {
				t.Fatal("index6144 refused", err)
			}
			excess.PublicationOrder[0].Incarnations = append([]contract.ID{publicationJointID(state.root.Domain, "excess", 0)}, excess.PublicationOrder[0].Incarnations...)
			if _, err := format.EncodeAdministrativeIndex(excess); !errors.Is(err, format.ErrFormat) {
				t.Fatal("index6145 accepted", err)
			}
		})
	}
}
