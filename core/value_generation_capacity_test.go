package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedCapacityEncodedProfileRows(t *testing.T) {
	id := generatedVectorID
	for _, mode := range []contract.GeneratorLifecycleMode{contract.GeneratorLifecycleManaged, contract.GeneratorLifecycleNone} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate, LifecycleMode: mode, Disposition: contract.GeneratorDispositionCompleteCreate, RequestDigest: id(3), IntentDigest: id(4)}
			completion := uint8(0)
			if mode == contract.GeneratorLifecycleManaged {
				facts.ResourceContractID = id(1)
				facts.Target = bytes.Repeat([]byte{5}, 32)
				facts.ResourceData = bytes.Repeat([]byte{2}, 32)
				completion = contract.GeneratedCompletionAcknowledged
			}
			// Ordinary facts:115 bytes framing plus3981 aggregate target/resource/provider bytes.
			facts.ProviderFacts = bytes.Repeat([]byte{6}, 3981-len(facts.Target)-len(facts.ResourceData))
			core := contract.GeneratedResultCore{Schema: contract.GeneratedResultCoreSchema, Profile: 2, DomainID: id(1), OperationID: id(2), MaterialID: id(3), UsePlanDigest: id(4), PlanGraphID: id(5), AttemptID: id(6), TransmissionID: id(7), ResultID: id(8), ExecutorID: id(9), DescriptorID: id(10), ConfigContractID: id(11), ResultContractID: id(12), RequestDigest: facts.RequestDigest}
			evidence := contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema, LifecycleMode: mode, OriginalResultID: core.ResultID, CredentialRouteID: id(21), Intent: contract.GeneratorDescriptor{Digest: id(20), Length: 73, Count: 1}, CompletionClass: completion}
			var err error
			evidence.SafeFacts, err = contract.EncodeGeneratorSafeFacts(facts)
			if err != nil || len(evidence.SafeFacts) != 4096 {
				t.Fatal("complete maximum facts", len(evidence.SafeFacts), err)
			}
			core.SafeFactsDigest, err = contract.GeneratorSafeFactsDigest(facts)
			if err != nil {
				t.Fatal(err)
			}
			evidence.ResultCore, err = contract.EncodeGeneratedResultCore(core)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := contract.EncodeGeneratedCreateEvidence(evidence)
			// Independent120-byte evidence header +452-byte core +4096-byte facts.
			if err != nil || len(encoded) != 4668 || contract.SupportRecordOverhead+len(encoded) != 4705 || generatedCurrentEvidenceCharge != 4705 {
				t.Fatal("maximum create evidence exceeds reservation", len(encoded), err)
			}
			if _, err := contract.InspectGeneratedCreateEvidence(encoded); err != nil {
				t.Fatal(err)
			}
			descriptor, err := contract.GeneratedCreateEvidenceDescriptor(evidence)
			if err != nil || descriptor.Length != 4676 || descriptor.Count != 1 {
				t.Fatal("maximum evidence descriptor differs", descriptor, err)
			}
			if _, err := contract.InspectGeneratedCreateEvidence(append(encoded, 0)); err != contract.ErrRecordCapacity {
				t.Fatal("maximum evidence first excess admitted", err)
			}
			facts.ProviderFacts = append(facts.ProviderFacts, 7)
			if _, err := contract.EncodeGeneratorSafeFacts(facts); err != contract.ErrRecordCapacity {
				t.Fatal("aggregate facts one-over admitted", err)
			}
			facts.ProviderFacts = facts.ProviderFacts[:len(facts.ProviderFacts)-1]
			facts.ScopeID = id(21)
			if _, err := contract.EncodeGeneratorSafeFacts(facts); err == nil {
				t.Fatal("create acquired scoped retirement observation")
			}
		})
	}
	e := contract.EmptyGeneratorVector
	duty := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, LifecycleMode: contract.GeneratorLifecycleManaged, DomainID: id(1), DutyID: id(2), OriginalOperationID: id(3), OriginalAttemptID: id(4), OwnerID: id(2), ResourceID: id(6), ConfigContractID: id(7), ResourceContractID: id(8), ExecutorID: id(9), CredentialRouteID: id(10), DescriptorID: id(11), ResultContractID: id(12), Kind: contract.GeneratedDutyCreate, CompletionClass: contract.GeneratedCompletionAcknowledged, Step: 1, Status: contract.GeneratedEffectTransmitted, CapacityReservation: contract.GeneratorDescriptor{Digest: id(20), Length: 4}, Progress: e(contract.GeneratorVectorProgress), History: e(contract.GeneratorVectorHistory), Support: e(contract.GeneratorVectorSupport), Consumers: e(contract.GeneratorVectorConsumers)}
	target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: strings.Repeat("\x00", 256), IncarnationID: id(5), ResourceID: duty.ResourceID, ResourceDigest: id(14), ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID, OriginalOperationID: duty.OriginalOperationID, OriginalAttemptID: duty.OriginalAttemptID, ResultContractID: duty.ResultContractID, CompletionClass: duty.CompletionClass}
	targetBody, err := contract.EncodeGeneratorTarget(target)
	if err != nil || len(targetBody) != 528 {
		t.Fatal("maximum target", len(targetBody), err)
	}
	duty.Target, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{targetBody})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		kind uint8
		want int
	}{{"managed Duty", contract.GeneratedDutySupportKind, 1377}, {"Hazard", contract.GeneratedHazardSupportKind, 1376}, {"none Duty", contract.GeneratedDutySupportKind, 692}} {
		t.Run(tc.name, func(t *testing.T) {
			d := duty
			none := tc.name == "none Duty"
			if none {
				d.LifecycleMode = contract.GeneratorLifecycleNone
				d.ResourceContractID = contract.ID{}
				d.CompletionClass = 0
				d.Target = e(contract.GeneratorVectorTargets)
			}
			var body []byte
			var err error
			owner := d.DutyID
			if tc.kind == contract.GeneratedHazardSupportKind {
				owner = id(21)
				body, err = contract.EncodeGeneratedHazardRecord(contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: d.DomainID, HazardID: owner, OriginalOperationID: d.OriginalOperationID, OriginalAttemptID: d.OriginalAttemptID, OwnerID: d.OwnerID, ResourceID: d.ResourceID, ConfigContractID: d.ConfigContractID, ResourceContractID: d.ResourceContractID, ExecutorID: d.ExecutorID, CredentialRouteID: d.CredentialRouteID, DescriptorID: d.DescriptorID, ResultContractID: d.ResultContractID, Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: d.CompletionClass, Fenced: 1, Eligibility: contract.GeneratedExposurePossibleLive, CapacityReservation: d.CapacityReservation, OriginalResults: contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults), Target: d.Target, History: d.History, Support: d.Support, Consumers: d.Consumers})
			} else {
				body, err = contract.EncodeGeneratedDutyRecord(d)
			}
			if err != nil {
				t.Fatal("owner row", err)
			}
			rows := []contract.SupportRecord{{Kind: tc.kind, RecordID: owner, Body: body}}
			if !none {
				carrier := contract.GeneratorVectorCarrier{Schema: 1, DomainID: d.DomainID, OwnerKind: tc.kind, OwnerID: owner, VectorKind: contract.GeneratorVectorTargets, Vector: d.Target, Row: targetBody}
				encoded, err := contract.EncodeGeneratorVectorCarrier(carrier)
				if err != nil {
					t.Fatal(err)
				}
				carrierID, err := contract.GeneratorVectorCarrierID(carrier)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, contract.SupportRecord{Kind: contract.GeneratorVectorSupportKind, RecordID: carrierID, Body: encoded})
			}
			groups, err := generatedReservationGroups(rows, nil, nil)
			if err != nil || len(groups) != 1 || groups[0].Class != format.OwnerSupport || len(groups[0].Records) != len(rows) {
				t.Fatal("exact physical owner group", err)
			}
			width := 0
			for _, row := range groups[0].Records {
				width += contract.SupportRecordOverhead + len(row.Body)
			}
			// Duty655/Hazard654; support frame37; target carrier120+528+37.
			if width != tc.want || uint64(width) > generatedOwnerGroupCharge {
				t.Fatal("physical owner width", width, tc.want)
			}
		})
	}
}

// full_only: false
func TestGeneratedDesiredOutputCapacityKeepsIndependentImageBound(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1, Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
	baseline, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	// A generated payload fragment holds 1,048,320 bytes. Its complete row adds
	// 86 header bytes and 37 framing bytes; two fit a support page. The logical
	// image adds one 120+111+37-byte carrier, independent of its fragment count.
	for _, tc := range []struct {
		name                   string
		size, fragments, bytes uint64
		pages                  uint32
	}{
		{"empty-image", 16, 1, 139, 1},
		{"exact-fragment", 1048320, 1, 1048443, 1},
		{"next-fragment", 1048321, 2, 1048567, 1},
		{"complete-image-bound", 37748736, 37, 37753287, 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proposed := shape
			proposed.DesiredOutputBytes = tc.size
			groups, err := generatedCleanCapacity(proposed)
			if err != nil {
				t.Fatal(err)
			}
			a, b := groups[contract.GeneratorCapacityAuxiliary], baseline[contract.GeneratorCapacityAuxiliary]
			if a.MaxCount-b.MaxCount != tc.fragments || a.MaxFramedBytes-b.MaxFramedBytes != tc.bytes || a.MaxPages-b.MaxPages != tc.pages {
				t.Fatal("desired image was not charged with its own fragments and pages", a, b)
			}
			a, b = groups[contract.GeneratorCapacityGraph], baseline[contract.GeneratorCapacityGraph]
			if a.MaxCount-b.MaxCount != 1 || a.MaxFramedBytes-b.MaxFramedBytes != 268 {
				t.Fatal("desired image lost its logical carrier charge", a, b)
			}
		})
	}
	shape.DesiredOutputBytes = 37748737
	if _, err := generatedCleanCapacity(shape); err != contract.ErrRecordCapacity {
		t.Fatal("one-over desired image capacity was admitted", err)
	}
}

// full_only: false
func TestGeneratedBacklogCapacityCharges510PartitionedSliceGroups(t *testing.T) {
	domain, snapshot := generatedVectorID(1), generatedVectorID(2)
	var bodies [][]byte
	locations := make(map[generatedContentKey]contract.GeneratorSliceLocation)
	var currentIntent contract.ID
	for i := 0; i < 510; i++ {
		intent := contract.Hash([]byte(fmt.Sprintf("capacity intent %d", i)))
		if i == 0 {
			currentIntent = intent
		}
		location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent,
			ContentID: intent, BlobID: generatedVectorID(3), Length: 1, Digest: generatedVectorID(4)}
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		locations[generatedContentKey{location.ContentKind, location.ContentID}] = location
	}
	slices.SortFunc(bodies, func(a, b []byte) int { return bytes.Compare(a[2:35], b[2:35]) })
	_, carriers := generatedVectorRowsForDomain(t, domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, bodies)
	s := &StateSession{root: format.Root{Domain: domain, Snapshot: snapshot, Names: []format.NameEntry{{Name: "x", Slot: 0}}}}
	s.pages[0] = &format.ValueEntryPage{}
	s.pages[0].Slots[0] = &format.ValueEntry{Name: "x", ValueState: generatedVectorID(5), ValueSource: contract.Generated,
		Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, IntentDigest: currentIntent}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	selected := &generatedSelection{session: s, image: s.selectedImage(), content: &generatedContent{locations: locations}, records: make(map[generatedRecordKey]contract.SupportRecord)}
	for _, row := range carriers {
		selected.records[generatedRecordKey{row.Kind, row.RecordID}] = row
	}
	plain, err := generatedReservationGroups(carriers, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pages, err := format.PackRequiredSupportRows(domain, plain, 0); err != nil || len(pages) != 1 {
		t.Fatal("unpartitioned carrier bytes do not fit one page", len(pages), err)
	}
	partitioned, err := generatedReservationGroupsForState(s, carriers, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pages, err := format.PackRequiredSupportRows(domain, partitioned, 0); err != nil || len(pages) != 2 {
		t.Fatal("mandatory/optional carriers did not use two pages", len(pages), err)
	}
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1,
		Memberships: 1, SecretMemberships: 1, Generated: 1, OldGenerated: 1,
		ValueEntryPlanCount: 1, DeclarationBytes: 512}
	clean, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	charged, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal(err)
	}
	if charged[contract.GeneratorCapacityGraph].MaxPages != clean[contract.GeneratorCapacityGraph].MaxPages+2 {
		t.Fatal("one packed carrier page and its mandatory split were not charged", charged[contract.GeneratorCapacityGraph])
	}
}

// full_only: false
func TestGeneratedCleanCapacityReservesReachableContinuations(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 512, ValueEntryPageCount: 32, Recipients: 256, Secrets: 512, Memberships: 4096,
		SecretMemberships: 4096, Generated: 128, OldGenerated: 128, Creates: 128, Retirements: 128,
		ValueEntryPlanCount: 512, Sources: 384, DeclarationBytes: 32 << 20, OldIntentBytes: 48 << 20, Recovery: true}
	if _, err := generatedCleanCapacity(shape); err != contract.ErrRecordCapacity {
		t.Fatal("clean helper accepted old intents without selected physical blobs", err)
	}
	clean := shape
	clean.OldIntentBytes = 0
	groups, err := generatedCleanCapacity(clean)
	if err != nil {
		t.Fatal(err)
	}
	// The clean charge includes the 32 MiB declaration. Selected old intent
	// blobs and mandatory/optional packing boundaries are charged separately.
	want := [...]uint32{32, 32, 2, 1, 3, 0, 24, 14, 1, 1, 13, 17, 1, 2, 17, 4, 32}
	pages := uint32(0)
	for i, group := range groups {
		if group.MaxPages != want[i] {
			t.Fatal("wrong capacity group", i, group, want[i])
		}
		pages += group.MaxPages
	}
	if pages != 196 || groups[contract.GeneratorCapacityCreates].MaxCount != 384 || groups[contract.GeneratorCapacityDeletes].MaxCount != 512 ||
		groups[contract.GeneratorCapacitySeedAccess].MaxCount != 896 || groups[contract.GeneratorCapacityOwners].MaxCount != 1024 {
		t.Fatal("latent templates were charged as entered or a continuation was omitted", groups)
	}
	if groups[contract.GeneratorCapacityGraph].MaxFramedBytes != 5_406_976+6*123+6913*268 ||
		groups[contract.GeneratorCapacityAuxiliary].MaxFramedBytes != 65_815_801+63*123 {
		t.Fatal("graph or auxiliary framing is missing")
	}
	v := contract.GeneratorCapacityEvidence{Schema: 1, BeforeRootDigest: generatedVectorID(1), PlanGraphID: generatedVectorID(2),
		Declaration: contract.GeneratorDescriptor{Digest: generatedVectorID(3), Length: 32 << 20, Count: 1}, Groups: groups}
	if _, err := contract.GeneratorCapacityDescriptor(v); err != nil {
		t.Fatal("complete clean capacity evidence refused", err)
	}
	backlog, _, _ := capacityWithIndependentOldIntentsFixture(t, shape, groups)
	wantBacklog := [...]uint32{32, 32, 2, 1, 3, 0, 24, 14, 1, 1, 13, 17, 1, 2, 82, 5, 34}
	var backlogPages uint32
	for i, group := range backlog {
		if group.MaxPages != wantBacklog[i] {
			t.Fatal("selected independent old intents changed the sealed-source charge", i, group, wantBacklog[i])
		}
		backlogPages += group.MaxPages
	}
	if backlogPages != 264 {
		t.Fatal("full sealed-source scalar backlog charge", backlogPages)
	}
}

// This retains the 128 independent full-size old blobs. The declaration and
// other new-operation populations remain scalar reservations, not a signed
// predecessor or evidence that the complete maximum state is reachable.
func capacityWithIndependentOldIntentsFixture(t testing.TB, shape generatedCapacityShape,
	clean [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, *generatedSelection, [][]contract.SupportRecord) {
	t.Helper()
	selected, physical, oldBytes := independentOldIntentBacklogFixture(t)
	if shape.OldIntentBytes != oldBytes || shape.DeclarationBytes != 32<<20 {
		t.Fatal("combined intent dimensions", shape.OldIntentBytes, shape.DeclarationBytes)
	}
	packed, err := format.PackRequiredSupportRows(selected.session.root.Domain, physical, 0)
	if err != nil || len(packed) != 64 {
		t.Fatal("128 independent mandatory old fragments did not pack to 64 pages", len(packed), err)
	}
	if shape.RetainedSources != 0 {
		_, source := generatedCanonicalSource(t)
		shape.RetainedRows = make(map[contract.ID][]byte, shape.RetainedSources)
		for i := uint64(0); i < shape.RetainedSources; i++ {
			source.OriginalSlot = uint16(128 + i)
			source.Entry.Name = fmt.Sprintf("capacity-source-%03d", i)
			source.Entry.ValueState = contract.Hash([]byte(source.Entry.Name))
			body, err := contract.EncodeRetainedCanonicalRecord(source)
			if err != nil {
				t.Fatal("declared retained source", i, err)
			}
			shape.RetainedRows[source.Entry.ValueState] = body
		}
	}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal("selected physical old-intent backlog", err)
	}
	// 128 old fragments plus 33 new fragments have separate mandatory and
	// optional runs: 64+17 physical pages. The generic charge is 82 pages.
	want := clean
	want[contract.GeneratorCapacityIntents] = contract.GeneratorCapacityGroup{MaxCount: 161, MaxFramedBytes: 83_905_883, MaxPages: 82}
	want[contract.GeneratorCapacityGraph].MaxPages++
	want[contract.GeneratorCapacityAuxiliary].MaxPages += 2
	if groups != want {
		t.Fatal("independent old blobs or class partitions changed the full charge", groups, want)
	}
	return groups, selected, packed
}

func independentOldIntentBacklogFixture(t testing.TB) (*generatedSelection, []format.RequiredSupportGroup, uint64) {
	t.Helper()
	const oldCount = contract.GeneratedCurrentEntryLimit
	var oldBytes uint64
	physical := make([]format.RequiredSupportGroup, 0, oldCount+1)
	s := &StateSession{root: format.Root{Domain: generatedVectorID(1)}}
	locations := make(map[generatedContentKey]contract.GeneratorSliceLocation)
	records := make(map[generatedRecordKey]contract.SupportRecord)
	for i := 0; i < oldCount; i++ {
		// Canonical framing71 +JSON quotes2 +index3 +filler reaches393216.
		settings := []byte(`"` + fmt.Sprintf("%03d", i) + strings.Repeat("x", contract.GeneratorIntentMaxLength-76) + `"`)
		payload := generatedFixtureCanonicalIntent(t, settings, defaultGeneratedFixtureProfile())
		contentID, err := contract.GeneratorIntentDigest(payload)
		if err != nil {
			t.Fatal("old intent digest", i, err)
		}
		blobID := contract.Hash([]byte(fmt.Sprintf("old-intent-blob-%d", i)))
		location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent,
			ContentID: contentID,
			BlobID:    blobID,
			Length:    contract.GeneratorIntentMaxLength, Digest: contract.Hash(payload)}
		if _, err := contract.EncodeGeneratorSliceLocation(location); err != nil {
			t.Fatal("distinct old intent location", i, err)
		}
		locations[generatedContentKey{location.ContentKind, location.ContentID}] = location
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blobID,
			Count: 1, TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal("old fragment", i, err)
		}
		fragmentID, err := contract.GeneratorFragmentID(blobID, 0)
		if err != nil {
			t.Fatal("old fragment ID", i, err)
		}
		row := contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: body}
		physical = append(physical, format.RequiredSupportGroup{Class: format.IntentFragmentSupport, Owner: blobID,
			Mandatory: true, Records: []contract.SupportRecord{row}})
		records[generatedRecordKey{row.Kind, row.RecordID}] = row
		name := fmt.Sprintf("old-intent-%03d", i)
		slot := uint16(i)
		if s.pages[slot/format.PageSlots] == nil {
			s.pages[slot/format.PageSlots] = &format.ValueEntryPage{}
		}
		s.pages[slot/format.PageSlots].Slots[slot%format.PageSlots] = &format.ValueEntry{Name: name,
			ValueSource: contract.Generated, Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, IntentDigest: contentID}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
		s.root.Names = append(s.root.Names, format.NameEntry{Name: name, Slot: slot})
		oldBytes += uint64(location.Length)
	}
	if oldBytes != 48<<20 || len(physical) != 128 || len(locations) != 128 {
		t.Fatal("independent old intent dimensions", oldBytes, len(physical), len(locations))
	}
	selected := &generatedSelection{session: s, image: s.selectedImage(), content: &generatedContent{locations: locations}, records: records}
	return selected, physical, oldBytes
}

// full_only: false
func TestGeneratedBacklogCapacityCountsIndependentOldIntentBlobs(t *testing.T) {
	// This is a physical-backlog calculator test, not a signed predecessor.
	// Each current generated value owns a separately addressed full-size
	// intent. Logical bytes alone cannot represent these 128 selected blobs.
	const oldCount = contract.GeneratedCurrentEntryLimit
	selected, physical, oldBytes := independentOldIntentBacklogFixture(t)
	newBlob := contract.Hash([]byte("new-declaration-fragment"))
	newPayload := []byte{255}
	newBody, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: newBlob,
		Count: 1, TotalLength: 1, WholeDigest: contract.Hash(newPayload), Payload: newPayload})
	if err != nil {
		t.Fatal("new fragment", err)
	}
	newFragmentID, err := contract.GeneratorFragmentID(newBlob, 0)
	if err != nil {
		t.Fatal("new fragment ID", err)
	}
	physical = append(physical, format.RequiredSupportGroup{Class: format.IntentFragmentSupport, Owner: newBlob,
		Records: []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind,
			RecordID: newFragmentID, Body: newBody}}})
	packed, err := format.PackRequiredSupportRows(generatedVectorID(1), physical, 0)
	if err != nil || len(packed) != 65 {
		t.Fatalf("128 mandatory old fragments plus one optional new fragment: %d pages: %v", len(packed), err)
	}
	if oldBytes != 48<<20 {
		t.Fatal("old intent dimension", oldBytes)
	}
	shape := generatedCapacityShape{ValueEntryCount: 128, ValueEntryPageCount: 8, Recipients: 1,
		Secrets: 128, Memberships: 128, SecretMemberships: 128, Generated: oldCount, OldGenerated: oldCount,
		Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512, OldIntentBytes: oldBytes}
	if _, err := generatedCleanCapacity(shape); err != contract.ErrRecordCapacity {
		t.Fatal("clean helper accepted old logical bytes without selected blobs", err)
	}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal(err)
	}
	intents := groups[contract.GeneratorCapacityIntents]
	if intents.MaxCount != oldCount+1 || intents.MaxFramedBytes != 512+generatedFragmentCharge+oldCount*(contract.GeneratorIntentMaxLength+generatedFragmentCharge) ||
		intents.MaxPages < uint32(len(packed)) {
		t.Fatalf("128 selected old blobs plus one new declaration undercharged: %d fragments, %d bytes, %d pages", intents.MaxCount, intents.MaxFramedBytes, intents.MaxPages)
	}
}

// full_only: false
func TestGeneratedBacklogCapacityChargesCompactFullOldIntentBlob(t *testing.T) {
	// This checks the encoded calculator input. It is not a signed selected
	// predecessor or a proof that one writer can create this current set.
	const oldCount = contract.GeneratedCurrentEntryLimit
	const intentSize = contract.GeneratorIntentMaxLength
	domain, blobID := generatedVectorID(1), contract.Hash([]byte("compact 48 MiB old intents"))
	blob := make([]byte, oldCount*intentSize)
	s := &StateSession{root: format.Root{Domain: domain}}
	locations := make(map[generatedContentKey]contract.GeneratorSliceLocation)
	for i := 0; i < oldCount; i++ {
		start, end := i*intentSize, (i+1)*intentSize
		settings := []byte(`"` + fmt.Sprintf("%03d", i) + strings.Repeat("x", intentSize-76) + `"`)
		copy(blob[start:end], generatedFixtureCanonicalIntent(t, settings, defaultGeneratedFixtureProfile()))
		intent := blob[start:end]
		intentID, err := contract.GeneratorIntentDigest(intent)
		if err != nil {
			t.Fatal("old intent digest", i, err)
		}
		location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent,
			ContentID: intentID, BlobID: blobID, Offset: uint64(start), Length: intentSize, Digest: contract.Hash(intent)}
		if _, err := contract.EncodeGeneratorSliceLocation(location); err != nil {
			t.Fatal("old intent location", i, err)
		}
		locations[generatedContentKey{location.ContentKind, location.ContentID}] = location
		name, slot := fmt.Sprintf("compact-intent-%03d", i), uint16(i)
		if s.pages[slot/format.PageSlots] == nil {
			s.pages[slot/format.PageSlots] = &format.ValueEntryPage{}
		}
		s.pages[slot/format.PageSlots].Slots[slot%format.PageSlots] = &format.ValueEntry{Name: name,
			ValueSource: contract.Generated, Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, IntentDigest: intentID}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
		s.root.Names = append(s.root.Names, format.NameEntry{Name: name, Slot: slot})
	}
	rows, err := generatedFragmentRows(blobID, blob)
	if err != nil || len(rows) != 49 {
		t.Fatal("48 MiB compact blob fragment count", len(rows), err)
	}
	packed, err := format.PackRequiredSupportRows(domain, []format.RequiredSupportGroup{{
		Class: format.IntentFragmentSupport, Owner: blobID, Mandatory: true, Records: rows,
	}}, 0)
	if err != nil || len(packed) != 25 {
		t.Fatal("48 MiB compact blob physical pages", len(packed), err)
	}
	records := make(map[generatedRecordKey]contract.SupportRecord, len(rows))
	for _, row := range rows {
		records[generatedRecordKey{row.Kind, row.RecordID}] = row
	}
	selected := &generatedSelection{session: s, image: s.selectedImage(), content: &generatedContent{locations: locations}, records: records}
	shape := generatedCapacityShape{ValueEntryCount: 512, ValueEntryPageCount: 32, Recipients: 256,
		Secrets: 512, Memberships: 4096, SecretMemberships: 4096, Generated: 128, OldGenerated: 128,
		Creates: 128, Retirements: 128, ControlledRetirements: 128, ValueEntryPlanCount: 512,
		Sources: 384, DeclarationBytes: 32 << 20, OldIntentBytes: uint64(len(blob)), Recovery: true}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal("selected physical old intent charge", err)
	}
	intents := groups[contract.GeneratorCapacityIntents]
	const newFragments = uint64(33)
	const totalFragments = uint64(49) + newFragments
	if intents.MaxCount != totalFragments ||
		intents.MaxFramedBytes != uint64(len(blob))+(32<<20)+totalFragments*generatedFragmentCharge ||
		intents.MaxPages != 42 {
		t.Fatal("48 MiB old and 32 MiB new fragment classes", intents)
	}

	for _, tc := range []struct {
		name        string
		declaration uint64
		want        contract.GeneratorCapacityGroup
	}{
		{name: "declaration_boundary", declaration: 28_304_640,
			want: contract.GeneratorCapacityGroup{MaxCount: 76, MaxFramedBytes: 78_645_636, MaxPages: 39}},
		{name: "declaration_one_byte_over", declaration: 28_304_641,
			want: contract.GeneratorCapacityGroup{MaxCount: 77, MaxFramedBytes: 78_645_760, MaxPages: 40}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := shape
			v.DeclarationBytes = tc.declaration
			groups, err := generatedCapacityWithBacklog(v, selected)
			if err != nil || groups[contract.GeneratorCapacityIntents] != tc.want {
				t.Fatal("exact new declaration and retained fragment boundary", groups[contract.GeneratorCapacityIntents], tc.want, err)
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanCapacityRequiresSelectedOldIntentBacklog(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1,
		Secrets: 1, Memberships: 1, SecretMemberships: 1, Generated: 1, OldGenerated: 1,
		ValueEntryPlanCount: 1, DeclarationBytes: 512, OldIntentBytes: 1}
	if _, err := generatedCleanCapacity(shape); err != contract.ErrRecordCapacity {
		t.Fatal("logical old-intent bytes were accepted without selected physical blobs", err)
	}
}

// full_only: false
func TestGeneratedCleanCapacityUsesExactOwnerGroupBound(t *testing.T) {
	const ownerGroupMax = 2*contract.SupportRecordOverhead + contract.GeneratedDutyRecordBodyLength +
		contract.GeneratorCarrierFixedLength + contract.GeneratorTargetMaxLength
	const ownerCount = 1280
	const supportPayload = contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength
	if contract.GeneratedDutyRecordBodyLength != 661 || contract.GeneratedHazardRecordBodyLength != 654 ||
		ownerGroupMax != 1414 || ownerCount*ownerGroupMax != 1_809_920 || ownerCount*ownerGroupMax > supportPayload {
		t.Fatal("closed owner body or one-page arithmetic changed")
	}
	shape := generatedCapacityShape{Recipients: 256, ValueEntryCount: 512, ValueEntryPageCount: 32,
		Secrets: 512, Memberships: 4096, SecretMemberships: 4096, Generated: 128, OldGenerated: 128,
		Creates: 128, Retirements: 128, ControlledRetirements: 128, ValueEntryPlanCount: 512,
		RetainedSources: 384, DeclarationBytes: 32 << 20, Recovery: true}
	groups, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	owner := groups[contract.GeneratorCapacityOwners]
	if owner.MaxCount != ownerCount || owner.MaxFramedBytes != ownerCount*ownerGroupMax || owner.MaxPages != 1 {
		t.Fatal("owner group reservation differs from encoded limit", owner)
	}
	selected := generatedReservationState(t)
	work, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	locations, err := format.ResolveGeneratedSlices(selected.root.Domain, selected.root.Snapshot, selected.root.Generated, selected.support)
	if err != nil {
		t.Fatal(err)
	}
	physical, err := generatedReservationGroupsForState(selected, selected.supportRecords(), locations, work.bundles)
	if err != nil {
		t.Fatal(err)
	}
	seenOwner := false
	for _, group := range physical {
		if group.Class != format.OwnerSupport {
			continue
		}
		seenOwner = true
		if group.Mandatory || len(group.Records) > 2 {
			t.Fatal("owner group gained a mandatory row or another carrier", group)
		}
		width := 0
		for _, row := range group.Records {
			width += contract.SupportRecordOverhead + len(row.Body)
		}
		if width > ownerGroupMax {
			t.Fatal("selected owner group exceeds closed maximum", width)
		}
	}
	if !seenOwner {
		t.Fatal("selected fixture has no owner group")
	}
}

// full_only: false
func TestGeneratedCleanCapacityChargesOldCurrentRetainedBytes(t *testing.T) {
	shape := generatedCapacityShape{Recipients: 256, ValueEntryCount: 512, ValueEntryPageCount: 32,
		Secrets: 512, Memberships: 4096, SecretMemberships: 4096, Generated: 128, OldGenerated: 128,
		Creates: 128, Retirements: 128, ControlledRetirements: 128, ValueEntryPlanCount: 512,
		RetainedSources: 384, DeclarationBytes: 32 << 20, Recovery: true}
	groups, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	// New optional retained supplied entries share one old root: 8 MiB raw,
	// 4,096 recipient memberships, 384 names and fixed record framing.
	// The 128 current generated evidence rows are mandatory, and their
	// complete generic create-evidence rows fit the 4,705-byte framed charge.
	// Encoded profile cases above pin the actual maxima.
	old := groups[contract.GeneratorCapacityOldValues]
	if old.MaxCount != 512 || old.MaxFramedBytes != 9_373_440 || old.MaxPages != 6 {
		t.Fatal("old retained/current evidence charge lost selected-root correlation", old)
	}
	shape.RetainedSources = 0
	shape.ValueEntryPlanCount = 128
	groups, err = generatedCleanCapacity(shape)
	if err != nil || groups[contract.GeneratorCapacityOldValues].MaxPages != 1 {
		t.Fatal("current generated evidence needs one mandatory page", err)
	}
	shape.OldGenerated = 0
	shape.OldIntentBytes = 0
	shape.Generated = 0
	groups, err = generatedCleanCapacity(shape)
	if err != nil || groups[contract.GeneratorCapacityOldValues] != (contract.GeneratorCapacityGroup{}) {
		t.Fatal("absent old values acquired a page", err)
	}
}

// full_only: false
func TestGeneratedCleanCapacityChargesCurrentAndHistoricalReaders(t *testing.T) {
	shape := generatedCapacityShape{Recipients: 256, ValueEntryCount: 512, ValueEntryPageCount: 32,
		Secrets: 512, Memberships: 4096, SecretMemberships: 4096, Generated: 128, OldGenerated: 128,
		Creates: 128, ValueEntryPlanCount: 128, DeclarationBytes: 512, Recovery: true}
	groups, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	// Current and source5 producers cannot retain Generated canonical sources.
	// This conservative allowance exceeds their current-only access: 4,096
	// current memberships, an unused extra 128*64 allowance, and Recovery.
	const wraps = 4096 + 128*64 + 128
	const bytes = 128*contract.AccessRecordFixedLength + wraps*contract.WrapRowWireLength
	old := groups[contract.GeneratorCapacityOldAccess]
	if bytes != 6_084_480 || old.MaxCount != 128 || old.MaxFramedBytes != bytes || old.MaxPages != 3 {
		t.Fatal("old current and selected historical reader union was not reserved", old)
	}

	// Fresh creates need no predecessor wrap allowance. Each non-create row
	// can carry supported historical unions of all 256 registered readers. These scalar
	// envelopes do not assert that the entire maximum is reachable.
	for _, tc := range []struct {
		name    string
		creates uint64
		want    contract.GeneratorCapacityGroup
	}{
		{name: "fresh_replacement", creates: 128,
			want: contract.GeneratorCapacityGroup{MaxCount: 16, MaxFramedBytes: 16_706_729, MaxPages: 8}},
		{name: "mixed_retained_readers", creates: 1,
			want: contract.GeneratorCapacityGroup{MaxCount: 30, MaxFramedBytes: 30_542_307, MaxPages: 15}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := shape
			v.Creates = tc.creates
			groups, err := generatedCleanCapacity(v)
			if err != nil || groups[contract.GeneratorCapacityAuxiliary] != tc.want {
				t.Fatal("prepared image reader allowance", groups[contract.GeneratorCapacityAuxiliary], tc.want, err)
			}
			if groups[contract.GeneratorCapacityOldAccess] != old {
				t.Fatal("prepared image allowance changed live old access", groups[contract.GeneratorCapacityOldAccess], old)
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanCapacityUsesEncodedMaterialRows(t *testing.T) {
	shape := generatedCapacityShape{Recipients: 256, ValueEntryCount: 512, ValueEntryPageCount: 32,
		Secrets: 512, Memberships: 4096, SecretMemberships: 4096, Generated: 128, OldGenerated: 128,
		Creates: 128, Retirements: 128, ControlledRetirements: 128, ValueEntryPlanCount: 512,
		RetainedSources: 384, DeclarationBytes: 32 << 20, Recovery: true}
	groups, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	material := groups[contract.GeneratorCapacityMaterial]
	// 1024*(236+37) material bytes plus the separate (592+37) parent.
	if material.MaxCount != 1024 || material.MaxFramedBytes != 280_181 || material.MaxPages != 1 {
		t.Fatal("fixed material and parent rows exceeded one page", material)
	}
	selected := generatedReservationState(t)
	work, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	locations, err := format.ResolveGeneratedSlices(selected.root.Domain, selected.root.Snapshot, selected.root.Generated, selected.support)
	if err != nil {
		t.Fatal(err)
	}
	physical, err := generatedReservationGroupsForState(selected, selected.supportRecords(), locations, work.bundles)
	if err != nil {
		t.Fatal(err)
	}
	seenMaterial, seenParent := false, false
	for _, group := range physical {
		if group.Class != format.MaterialSupport {
			continue
		}
		if group.Mandatory {
			t.Fatal("material group gained a mandatory page split")
		}
		for _, row := range group.Records {
			switch row.Kind {
			case contract.OperationMaterialSupportKind:
				seenMaterial = true
				if len(row.Body) != 236 {
					t.Fatal("OperationMaterial encoded length changed", len(row.Body))
				}
			case contract.GeneratedParentSupportKind:
				seenParent = true
				if len(row.Body) != contract.GeneratedParentRecordBodyLength {
					t.Fatal("Parent encoded length changed", len(row.Body))
				}
			default:
				t.Fatal("unaccounted material row kind", row.Kind)
			}
		}
	}
	if !seenMaterial || !seenParent {
		t.Fatal("selected material or Parent row missing")
	}
}

// full_only: false
func TestGeneratedBacklogKeepsCorrelatedOwnerAndOldValueCharges(t *testing.T) {
	selectedState, _, _ := generatedCreateHazardState(t, 2, 0)
	selected, err := selectedState.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shape := generatedCapacityShape{Recipients: 1, Creates: 128, ValueEntryPlanCount: 128,
		DeclarationBytes: 512}
	clean, err := generatedCleanCapacity(shape)
	if err != nil || clean[contract.GeneratorCapacityOwners].MaxPages != 1 {
		t.Fatal("clean owner charge", err)
	}
	charged, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal("actual selected backlog charge", err)
	}
	if charged[contract.GeneratorCapacityOwners].MaxPages > clean[contract.GeneratorCapacityOwners].MaxPages+2 ||
		charged[contract.GeneratorCapacityMaterial].MaxPages > clean[contract.GeneratorCapacityMaterial].MaxPages+1 ||
		charged[contract.GeneratorCapacityOldValues].MaxPages > 2 {
		t.Fatal("a historical row reset correlated charges to generic group limits", charged)
	}
}

// full_only: false
func TestGeneratedCleanCapacityAllocatesActualSmallShape(t *testing.T) {
	v := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1,
		Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
	groups, err := generatedCleanCapacity(v)
	if err != nil {
		t.Fatal(err)
	}
	pages := uint32(0)
	for _, group := range groups {
		pages += group.MaxPages
	}
	if pages >= 32 || groups[contract.GeneratorCapacityOldValues] != (contract.GeneratorCapacityGroup{}) ||
		groups[contract.GeneratorCapacityCurrentAccess].MaxFramedBytes != 591 || groups[contract.GeneratorCapacityCreates].MaxCount != 3 {
		t.Fatal("small shape charged as a maximum or lost its continuation", pages, groups)
	}
	for name, change := range map[string]func(*generatedCapacityShape){
		"member limit":          func(v *generatedCapacityShape) { v.ValueEntryCount = 513 },
		"page limit":            func(v *generatedCapacityShape) { v.ValueEntryPageCount = 33 },
		"members without pages": func(v *generatedCapacityShape) { v.ValueEntryPageCount = 0 },
		"recipient limit":       func(v *generatedCapacityShape) { v.Recipients = 257 },
		"generated limit":       func(v *generatedCapacityShape) { v.Generated = 129 },
		"create limit":          func(v *generatedCapacityShape) { v.Creates = 129 },
		"old limit":             func(v *generatedCapacityShape) { v.OldGenerated = 129 },
		"retirement limit":      func(v *generatedCapacityShape) { v.Retirements = 129 },
		"membership limit":      func(v *generatedCapacityShape) { v.Memberships = 4097 },
		"wrap subset":           func(v *generatedCapacityShape) { v.SecretMemberships = 2 },
		"source limit":          func(v *generatedCapacityShape) { v.Sources = 513 },
		"declaration limit":     func(v *generatedCapacityShape) { v.DeclarationBytes = 32<<20 + 1 },
		"old intent limit":      func(v *generatedCapacityShape) { v.OldIntentBytes = 48<<20 + 1 },
		"count overflow":        func(v *generatedCapacityShape) { v.Creates = ^uint64(0) },
		"length overflow":       func(v *generatedCapacityShape) { v.DeclarationBytes = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			change(&bad)
			if _, err := generatedCleanCapacity(bad); err == nil {
				t.Fatal("invalid capacity input accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanCapacityChargesRetainedSourcesBeyondCreateAttempts(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 512, ValueEntryPageCount: 32, Recipients: 1,
		Memberships: 512, Creates: 1, ValueEntryPlanCount: 512, RetainedSources: 511, DeclarationBytes: 32 << 20}
	groups, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	// An initial reservation keeps one old-value support row for every
	// retained declaration source, before it has any generated candidate.
	old := groups[contract.GeneratorCapacityOldValues].MaxCount
	if old != shape.RetainedSources || groups[contract.GeneratorCapacityCandidateValues] != (contract.GeneratorCapacityGroup{}) {
		t.Fatalf("retained source rows charged to wrong storage class: %d for %d sources", old, shape.RetainedSources)
	}
	_, source := generatedCanonicalSource(t)
	rows := make([]contract.SupportRecord, 0, shape.RetainedSources)
	for i := uint64(0); i < shape.RetainedSources; i++ {
		source.OriginalSlot = uint16(i)
		source.Entry.Name = fmt.Sprintf("source-%03d", i)
		source.Entry.ValueState = contract.Hash([]byte(source.Entry.Name))
		body, err := contract.EncodeRetainedCanonicalRecord(source)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: source.Entry.ValueState, Body: body})
	}
	physical, err := generatedReservationGroups(rows, nil, nil)
	if err != nil || len(physical) != int(shape.RetainedSources) {
		t.Fatal("retained sources lost their physical owner groups", len(physical), err)
	}
	for _, group := range physical {
		if group.Class != format.OldValueSupport {
			t.Fatal("retained source assigned to an uncharged class", group.Class)
		}
	}
	packed, err := format.PackRequiredSupportRows(generatedVectorID(1), physical, 0)
	if err != nil || len(packed) > int(groups[contract.GeneratorCapacityOldValues].MaxPages) {
		t.Fatal("retained sources exceeded their physical page charge", len(packed), groups[contract.GeneratorCapacityOldValues], err)
	}
	// The initial writer also emits one Duty consumer and one Parent source-use
	// consumer for each retained source. The declaration contributes a source
	// slice for each row, in addition to the generated entry and graph slices.
	// Count these real carrier streams before relying on the graph group charge.
	minimumCarriers := 2*shape.RetainedSources + shape.ValueEntryPlanCount + 2
	if groups[contract.GeneratorCapacityGraph].MaxCount < minimumCarriers {
		t.Fatalf("graph carrier count undercharges retained sources: %d < %d", groups[contract.GeneratorCapacityGraph].MaxCount, minimumCarriers)
	}
}

// full_only: false
func TestGeneratedCleanCapacitySeparatesSealedAndRetainedAtJointLimit(t *testing.T) {
	base := generatedCapacityShape{ValueEntryCount: 512, ValueEntryPageCount: 32, Recipients: 256,
		Secrets: 512, Memberships: 4096, SecretMemberships: 4096, Generated: 128, OldGenerated: 128,
		Creates: 128, Retirements: 128, ControlledRetirements: 128, ValueEntryPlanCount: 512,
		DeclarationBytes: 32 << 20, Recovery: true}
	for _, tc := range []struct {
		name                                  string
		sealedCount, retainedCount, oldValues uint64
	}{{name: "all sealed", sealedCount: 384, oldValues: 128},
		{name: "all retained", retainedCount: 384, oldValues: 512},
		{name: "mixed", sealedCount: 192, retainedCount: 192, oldValues: 320}} {
		t.Run(tc.name, func(t *testing.T) {
			shape := base
			shape.Sources, shape.RetainedSources = tc.sealedCount, tc.retainedCount
			groups, err := generatedCleanCapacity(shape)
			if err != nil {
				t.Fatal(err)
			}
			if groups[contract.GeneratorCapacityOldValues].MaxCount != tc.oldValues {
				t.Fatal("physical old-value row count omitted retained declarations")
			}
			rows, _, _, err := generatedAdministrativeRowEnvelope(shape)
			if err != nil || rows[contract.RetainedCanonicalSupportKind] != tc.retainedCount ||
				rows[contract.GeneratedCreateEvidenceSupportKind] != 128+contract.GeneratorMaxEnteredCreateAttempts*shape.Creates {
				t.Fatal("administrative rows did not separate retained kind 6 from evidence kind 13", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedBacklogCapacityAdmitsDetachedRetirement(t *testing.T) {
	s, _, _ := generatedDetachedRetirementState(t, "absent", 0)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Normal removal leaves a real retirement duty but no current generated
	// entry. A delete-only plan must still reserve its continuation.
	shape := generatedCapacityShape{Recipients: 1, Retirements: 1, DeclarationBytes: 70}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal("detached retirement capacity refused", err)
	}
	if groups[contract.GeneratorCapacityDeletes].MaxCount != 1 || groups[contract.GeneratorCapacityOwners].MaxCount != 3 {
		t.Fatal("detached duty or new delete continuation omitted", groups)
	}
	capacity := contract.GeneratorCapacityEvidence{Schema: 1, BeforeRootDigest: generatedVectorID(1),
		PlanGraphID: generatedVectorID(2), Declaration: contract.GeneratorDescriptor{Digest: generatedVectorID(3), Length: 70, Count: 1}, Groups: groups}
	if _, err := contract.GeneratorCapacityDescriptor(capacity); err != nil {
		t.Fatal("detached retirement proof refused", err)
	}
	shape.Retirements = 129
	if _, err := generatedCleanCapacity(shape); err != contract.ErrRecordCapacity {
		t.Fatal("129 retirements admitted", err)
	}
}

// full_only: false
func TestGeneratedBacklogCapacityKeepsCurrentEvidenceInItsExistingCharge(t *testing.T) {
	s := generatedSelectedEntryState(t)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1,
		Generated: 1, OldGenerated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512, OldIntentBytes: 384 << 10}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal(err)
	}
	if groups[contract.GeneratorCapacityOldValues].MaxCount != 1 || groups[contract.GeneratorCapacityOldAccess].MaxCount != 1 {
		t.Fatal("current generation charged twice as older backlog")
	}
	// The retained fragment replaces the old-intent estimate. There is one
	// new declaration fragment and one actual old intent fragment, not both
	// the estimate and another copy of that intent.
	var oldBytes uint64
	for _, row := range selected.records {
		if row.Kind == 3 {
			oldBytes += uint64(37 + len(row.Body))
		}
	}
	if group := groups[contract.GeneratorCapacityIntents]; group.MaxCount != 2 || group.MaxFramedBytes != 512+123+oldBytes {
		t.Fatal("old intent was omitted or charged twice", group)
	}
}

// full_only: false
func TestGeneratedBacklogCapacitySeparatesCurrentEvidenceAndRetainedRow(t *testing.T) {
	s := generatedSelectedEntryState(t)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entry := *s.valueEntry(0)
	body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: 0, Entry: entry})
	if err != nil {
		t.Fatal(err)
	}
	key := generatedRecordKey{kind: contract.RetainedCanonicalSupportKind, id: entry.ValueState}
	selected.records[key] = contract.SupportRecord{Kind: key.kind, RecordID: key.id, Body: body}
	shape := generatedCapacityShape{ValueEntryCount: 2, ValueEntryPageCount: 1, Recipients: 1, Secrets: 2,
		Memberships: 2, SecretMemberships: 2, Generated: 2, OldGenerated: 1,
		Creates: 1, ValueEntryPlanCount: 2, DeclarationBytes: 512}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil || groups[contract.GeneratorCapacityOldValues].MaxCount != 2 {
		t.Fatal("kind-6 retained row was confused with current kind-13 evidence", groups[contract.GeneratorCapacityOldValues], err)
	}
	shape.RetainedSources = 1
	shape.RetainedRows = map[contract.ID][]byte{entry.ValueState: body}
	groups, err = generatedCapacityWithBacklog(shape, selected)
	if err != nil || groups[contract.GeneratorCapacityOldValues].MaxCount != 2 {
		t.Fatal("exact re-declaration was charged twice", groups[contract.GeneratorCapacityOldValues], err)
	}
	changed := bytes.Clone(body)
	changed[len(changed)-1] ^= 1
	shape.RetainedRows[entry.ValueState] = changed
	if _, err = generatedCapacityWithBacklog(shape, selected); err != contract.ErrRecord {
		t.Fatal("different bytes at the selected row key reached private reservation", err)
	}
}

// full_only: false
func TestGeneratedBacklogCapacityDoesNotReopenReleasedInboxes(t *testing.T) {
	for _, action := range []uint8{1, 2} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			s, _, _ := generatedInboxReleaseTemplateState(t, action, 2, contract.GeneratedReleasePending)
			selected, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1,
				Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
			groups, err := generatedCapacityWithBacklog(shape, selected)
			if err != nil {
				t.Fatal(err)
			}
			if groups[contract.GeneratorCapacityCreateResults].MaxCount != 3 || groups[contract.GeneratorCapacitySeedAccess].MaxCount != 6 {
				t.Fatal("released inbox reserved new private result material")
			}
			tag := contract.GeneratorCapacityCreates
			if action == 2 {
				tag = contract.GeneratorCapacityDeletes
			}
			if groups[tag].MaxCount != 4 {
				t.Fatal("release provenance lost its original continuation charge")
			}
		})
	}
}

// full_only: false
func TestGeneratedBacklogCapacityIncludesRetainedCanonicalAccess(t *testing.T) {
	s, _, _ := generatedCreateHazardState(t, 2, 0)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shape := generatedCapacityShape{ValueEntryCount: 2, ValueEntryPageCount: 1, Recipients: 127, Secrets: 2, Memberships: 65, SecretMemberships: 65,
		Generated: 1, Creates: 1, ValueEntryPlanCount: 2, DeclarationBytes: 512}
	groups, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil {
		t.Fatal(err)
	}
	if groups[contract.GeneratorCapacityOldValues].MaxCount != 1 || groups[contract.GeneratorCapacityOldAccess].MaxCount != 1 ||
		groups[contract.GeneratorCapacityOldAccess].MaxFramedBytes != 102+127*489 {
		t.Fatal("retained canonical value or its reader-union access omitted")
	}
}

// full_only: false
func TestGeneratedBacklogCapacityKeepsDeleteResultsInTheirContinuation(t *testing.T) {
	for kind := uint8(0); kind < 3; kind++ {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			s, _, _, _ := generatedDeleteHazardState(t, kind)
			selected, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1,
				Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
			groups, err := generatedCapacityWithBacklog(shape, selected)
			if err != nil {
				t.Fatal(err)
			}
			if groups[contract.GeneratorCapacityDeletes].MaxCount != 4 || groups[contract.GeneratorCapacityCreateResults].MaxCount != 3 ||
				groups[contract.GeneratorCapacitySeedAccess].MaxCount != 7 {
				t.Fatal("delete result used a separate create-result allocation")
			}
		})
	}
}
