package core

import (
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func administrativeCheckpointOwnershipFixture(t *testing.T) (contract.GeneratedParentRecord, contract.GeneratedFinalPreparationRecord, []format.RequiredSupportPage, contract.GeneratorSliceLocation, contract.ID) {
	t.Helper()
	_, _, parent := generatedEffectPlanFixture(t)
	parentBody, err := contract.EncodeGeneratedParentRecord(parent)
	if err != nil {
		t.Fatal("parent record", err)
	}
	evidence, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		t.Fatal("materialization phase evidence", err)
	}
	// This blob is an ownership witness, not a qualified encrypted image.
	// Full image schema and cryptographic recovery have separate connected tests.
	blob := []byte{1}
	imageID := contract.Hash(blob)
	preparation := contract.GeneratedFinalPreparationRecord{Schema: contract.GeneratorRecordSchema,
		DomainID: parent.DomainID, OperationID: parent.OperationID,
		MaterializationPhase: contract.GeneratorPhaseIdentity{RequestIdentityDigest: parent.RequestIdentityDigest,
			ObservedHEADDigest: generatedVectorID(201), ConditionDigest: generatedVectorID(202),
			TransitionKind: contract.GeneratorAuthorityFinal, BeforePhase: 1, AfterPhase: 2,
			Evidence: contract.GeneratorDescriptor(evidence)},
		Image: contract.GeneratorLogicalSlice{Schema: contract.GeneratorRecordSchema,
			ContentKind: contract.GeneratorContentFinalPreparation, ContentID: imageID, Digest: imageID, Length: uint32(len(blob))},
		ControlBindingDigest: generatedVectorID(203)}
	preparationBody, err := contract.EncodeGeneratedFinalPreparationRecord(preparation)
	if err != nil || len(preparationBody) != 318 {
		t.Fatal("exact preparation descriptor", err)
	}
	location := contract.GeneratorSliceLocation{Schema: contract.GeneratorRecordSchema,
		ContentKind: contract.GeneratorContentFinalPreparation, ContentID: imageID, BlobID: imageID,
		Digest: imageID, Length: uint32(len(blob))}
	locationBody, err := contract.EncodeGeneratorSliceLocation(location)
	if err != nil {
		t.Fatal("image slice", err)
	}
	snapshot := generatedVectorID(204)
	_, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, [][]byte{locationBody})
	if err != nil {
		t.Fatal("image slice carrier", err)
	}
	fragments, err := generatedFragmentRows(imageID, blob)
	if err != nil {
		t.Fatal("image fragment", err)
	}
	pages := []format.RequiredSupportPage{
		{Domain: parent.DomainID, Object: generatedVectorID(205), Records: []contract.SupportRecord{
			{Kind: contract.GeneratedParentSupportKind, RecordID: parent.OperationID, Body: parentBody},
			{Kind: contract.GeneratedFinalPreparationSupportKind, RecordID: parent.OperationID, Body: preparationBody}}},
		{Domain: parent.DomainID, Object: generatedVectorID(206), Index: 1, Records: carriers},
		{Domain: parent.DomainID, Object: generatedVectorID(207), Index: 2, Records: fragments},
	}
	return parent, preparation, pages, location, snapshot
}

// full_only: false
func TestAdministrativeCheckpointImageKeepsExactParentAndOptionalDisposition(t *testing.T) {
	parent, _, pages, location, snapshot := administrativeCheckpointOwnershipFixture(t)
	root := format.Root{Domain: parent.DomainID, Snapshot: snapshot}
	root.Generated.ActiveOwner = parent.OperationID
	views := make([]format.RequiredSupportPageView, len(pages))
	for i, page := range pages {
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("checkpoint page", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("checkpoint page reference", err)
		}
		root.RequiredSupport = append(root.RequiredSupport, ref)
		views[i], err = format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("checkpoint page view", err)
		}
	}
	seed := &StateSession{admission: openAdmission{domain: parent.DomainID}, root: format.Root{Domain: parent.DomainID}}
	index, err := seed.buildAdministrativeIndex(t.Context(), root, pages, nil, nil, nil)
	if err != nil || len(index.Groups) != 1 || index.Groups[0].GroupID != parent.OperationID || index.Groups[0].OwnerKind != format.AdministrativeGeneratedParent {
		t.Fatal("checkpoint does not have its exact parent group", err)
	}
	for _, page := range index.Pages {
		for _, span := range page.Spans {
			if span.Mandatory || len(span.GroupIndexes) != 1 || index.Groups[span.GroupIndexes[0]].GroupID != parent.OperationID {
				t.Fatal("checkpoint row acquired another owner or administrative payload requirement", span)
			}
		}
	}
	if !index.Pages[1].ReadRequired {
		t.Fatal("image slice directory lost its structural readability")
	}
	mandatory := administrativeMandatorySupportForEntries(nil, []contract.GeneratorSliceLocation{location})
	for _, page := range pages {
		for _, row := range page.Records {
			keep, err := mandatory.row(row)
			if err != nil || keep {
				t.Fatal("checkpoint payload became administratively mandatory", row.Kind, err)
			}
		}
	}
	root.AdministrativeIndex.Object = index.Object
	state := StateSession{root: root, adminIndex: index, support: views}
	state.support[0].Records, state.support[2].Records = nil, nil
	after, err := state.administrativeWorkDisposition(parent.OperationID)
	if err != nil || len(after.Groups) != 0 || len(after.Pages) != 0 {
		t.Fatal("End did not dispose the exact checkpoint with unavailable optional backing", err)
	}
}

// full_only: false
func TestAdministrativeCheckpointOwnershipRefusesMissingAndDuplicateAssociations(t *testing.T) {
	for _, condition := range []string{"missing-parent", "wrong-parent", "wrong-record-id", "wrong-image", "duplicate-image-descriptor", "duplicate-parent-descriptor", "duplicate-slice"} {
		t.Run(condition, func(t *testing.T) {
			parent, preparation, pages, location, snapshot := administrativeCheckpointOwnershipFixture(t)
			if _, err := selectedAdministrativeConsumers(pages, nil, nil); err != nil {
				t.Fatal("positive checkpoint ownership refused before mutation", err)
			}
			locations := []contract.GeneratorSliceLocation{location}
			switch condition {
			case "missing-parent":
				pages[0].Records = pages[0].Records[1:]
			case "wrong-parent":
				parent.OperationID = generatedVectorID(208)
				body, err := contract.EncodeGeneratedParentRecord(parent)
				if err != nil {
					t.Fatal("valid other parent", err)
				}
				pages[0].Records[0].RecordID, pages[0].Records[0].Body = parent.OperationID, body
			case "wrong-record-id":
				pages[0].Records[1].RecordID = generatedVectorID(208)
			case "wrong-image":
				locations[0].Digest = generatedVectorID(208)
			case "duplicate-image-descriptor":
				pages[0].Records = append(pages[0].Records, pages[0].Records[1])
			case "duplicate-parent-descriptor":
				blob := []byte{2}
				id := contract.Hash(blob)
				preparation.Image.ContentID, preparation.Image.Digest = id, id
				body, err := contract.EncodeGeneratedFinalPreparationRecord(preparation)
				if err != nil {
					t.Fatal("valid second image descriptor", err)
				}
				pages[0].Records = append(pages[0].Records, contract.SupportRecord{Kind: contract.GeneratedFinalPreparationSupportKind, RecordID: preparation.OperationID, Body: body})
				locations = append(locations, contract.GeneratorSliceLocation{Schema: contract.GeneratorRecordSchema,
					ContentKind: contract.GeneratorContentFinalPreparation, ContentID: id, BlobID: id, Digest: id, Length: 1})
				fragments, err := generatedFragmentRows(id, blob)
				if err != nil {
					t.Fatal("second image fragment", err)
				}
				pages[2].Records = append(pages[2].Records, fragments...)
			case "duplicate-slice":
				// Each directory is independently well formed. The ownership
				// reader must still refuse the same logical image in two
				// selected directories; the canonical vector encoder correctly
				// refuses duplicate rows inside one vector before that boundary.
				body, err := contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal("duplicate logical slice", err)
				}
				_, other, err := generatedCarrierRows(parent.DomainID, contract.GeneratorSnapshotOwner, generatedVectorID(209), contract.GeneratorVectorSlices, [][]byte{body})
				if err != nil {
					t.Fatal("individually valid duplicate slice directory", err)
				}
				pages = append(pages, format.RequiredSupportPage{Domain: parent.DomainID, Object: generatedVectorID(208), Index: 3, Records: other})
			}
			var bodies [][]byte
			for _, location := range locations {
				body, err := contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal("mutated slice", err)
				}
				bodies = append(bodies, body)
			}
			_, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, bodies)
			if err != nil {
				t.Fatal("mutated slice carriers", err)
			}
			pages[1].Records = carriers
			if _, err := selectedAdministrativeConsumers(pages, nil, nil); err == nil {
				t.Fatal("checkpoint accepted inconsistent parent/image ownership", condition)
			}
		})
	}
}
