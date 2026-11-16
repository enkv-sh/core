package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedStockCapacityIncludesRetainedBacklog(t *testing.T) {
	type profile struct {
		name                                                string
		generated, old, creates, retirements, values, plans uint64
		cleanPages                                          uint32
		priorReleases                                       uint64
		predecessor                                         string
	}
	for _, row := range []profile{
		{"first-create", 1, 0, 1, 0, 1, 1, 18, 0, "empty"},
		{"first-rotation", 1, 1, 1, 1, 1, 1, 20, 0, "current"},
		{"second-rotation", 1, 1, 1, 1, 1, 1, 20, 1, "current"},
		{"first-exact-retirement", 1, 1, 0, 1, 1, 1, 16, 0, "current-and-detached"},
		{"second-exact-retirement", 1, 1, 0, 1, 1, 1, 16, 1, "current-and-detached"},
		{"final-detached-retirement", 0, 0, 0, 1, 2, 2, 14, 2, "detached"},
	} {
		t.Run(row.name, func(t *testing.T) {
			shape := generatedCapacityShape{ValueEntryCount: row.values, ValueEntryPageCount: 1,
				Recipients: 2, Secrets: 1, Memberships: row.values, SecretMemberships: 1,
				Generated: row.generated, OldGenerated: row.old, Creates: row.creates,
				Retirements: row.retirements, ValueEntryPlanCount: row.plans,
				DeclarationBytes: 393425, RegistryBytes: 4010, Recovery: true}
			if row.creates != 0 {
				shape.DesiredOutputBytes = 128
			}
			clean, err := generatedCleanCapacity(shape)
			if err != nil {
				t.Fatal("fixed stock clean shape", err)
			}
			var cleanPages uint32
			for _, group := range clean {
				cleanPages += group.MaxPages
			}
			if cleanPages != row.cleanPages {
				t.Fatal("independent clean page count differs", cleanPages, row.cleanPages)
			}
			var before *StateSession
			switch row.predecessor {
			case "empty":
				before = generatedEmptyPredecessor(t)
			case "current":
				id := generatedVectorID
				settings := []byte(`"` + strings.Repeat("c", contract.GeneratorIntentMaxLength-73) + `"`)
				before = generatedSelectedEntryOriginWithIntent(t, id(10), id(11), 0, "generated", id(9), id(12), id(10), id(21), id(30), settings)
			case "current-and-detached":
				before, _, _ = generatedDetachedRetirementState(t, "generated", 0)
			case "detached":
				before, _, _ = generatedDetachedRetirementState(t, "absent", 0)
			}
			if row.old != 0 {
				shape.OldIntentBytes = contract.GeneratorIntentMaxLength
			}
			if row.creates == 0 {
				// One role-7 binding: vector count4 + item length4 + binding1684.
				shape.deleteSupport = contract.GeneratorDescriptor{Count: 1, Length: 1692, Digest: generatedVectorID(92)}
			}
			baseline, err := before.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("stock predecessor without retained releases", err)
			}
			baselineProjection, err := planGeneratedCurrentIntents(t.Context(), before, baseline, selectedGeneratedLocations(baseline))
			if err != nil {
				t.Fatal("stock intent projection without retained releases", err)
			}
			baselineGroups, err := generatedCapacityWithProjectedBacklog(shape, baseline, &baselineProjection)
			if err != nil {
				t.Fatal("stock capacity without retained releases", err)
			}
			stockInstallRetainedRetirements(t, before, row.priorReleases)
			selected, err := before.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("selected stock predecessor", err)
			}
			if uint64(len(selected.releases)) != row.priorReleases {
				t.Fatal("fixed stock predecessor omitted retained releases", len(selected.releases), row.priorReleases)
			}

			projection, err := planGeneratedCurrentIntents(t.Context(), before, selected, selectedGeneratedLocations(selected))
			if err != nil {
				t.Fatal("selected intent projection", err)
			}
			groups, err := generatedCapacityWithProjectedBacklog(shape, selected, &projection)
			if err != nil {
				t.Fatal("complete stock backlog", err)
			}
			if row.creates == 0 {
				withoutCopy := shape
				withoutCopy.deleteSupport = contract.GeneratorDescriptor{}
				baseline, err := generatedCapacityWithProjectedBacklog(withoutCopy, selected, &projection)
				if err != nil {
					t.Fatal("delete support baseline", err)
				}
				got, prior := groups[contract.GeneratorCapacityAuxiliary], baseline[contract.GeneratorCapacityAuxiliary]
				if got.MaxCount != prior.MaxCount+1 || got.MaxFramedBytes != prior.MaxFramedBytes+1841 {
					t.Fatal("role-7 support copy omitted its carrier or framing", got, prior)
				}
			}
			var pages uint32
			var framed uint64
			for _, group := range groups {
				pages += group.MaxPages
				framed += group.MaxFramedBytes
			}
			// The receipt scalar uses512 maximum4KiB groups. Actual compact
			// receipts have471 body bytes plus37 framing bytes each. Exact release
			// continuations replace only their own generic64KiB charges. Reserve a
			// complete512KiB administrative shard and256KiB root separately.
			receipts := groups[contract.GeneratorCapacityReceipts].MaxFramedBytes
			releasedBytes := stockReleasedContinuationBytes(t, selected)
			encoded := framed - receipts - row.priorReleases*(64<<10) + releasedBytes + 512*(471+37) + uint64(pages)*contract.RequiredSupportPageHeaderLength + (512 << 10) + (256 << 10)
			var baselineBytes uint64
			for _, group := range baselineGroups {
				baselineBytes += group.MaxFramedBytes
			}
			// Charge the full independent release bound, including five page
			// headers, even when the selected fixture graph is smaller.
			maximumEncoded := baselineBytes - baselineGroups[contract.GeneratorCapacityReceipts].MaxFramedBytes +
				512*(471+37) + 32*contract.RequiredSupportPageHeaderLength + (512 << 10) + (256 << 10) + row.priorReleases*9828
			if uint64(pages)+2 > 32+5*row.priorReleases || encoded > maximumEncoded || maximumEncoded > 4<<20 {
				t.Fatal("fixed stock candidate exceeds reservation", pages+2, encoded, maximumEncoded)
			}
			t.Log("fixed stock image bytes", encoded, "maximum", maximumEncoded)
			counts, _, newGroups, err := generatedAdministrativeRowEnvelope(shape)
			var newRows uint64
			for _, count := range counts {
				newRows += count
			}
			if err != nil || newRows > 700 || newGroups > 9 {
				t.Fatal("fixed administrative envelope grew", newRows, newGroups, err)
			}
			shards, err := before.generatedAdministrativeShardReserve(shape)
			if err != nil || shards != 1 {
				t.Fatal("fixed stock administrative index needs another shard", shards, err)
			}
		})
	}
	t.Run("distinct-current-and-detached-intent-partitions", func(t *testing.T) {
		id := generatedVectorID
		state := &StateSession{root: format.Root{Domain: id(1)}}
		state.pages[0] = &format.ValueEntryPage{}
		state.root.Names = []format.NameEntry{{Name: "generated", Slot: 0}}
		var rows []contract.SupportRecord
		var locations []contract.GeneratorSliceLocation
		for i, label := range []byte{'c', 'd'} {
			settings := []byte(`"` + strings.Repeat(string(label), contract.GeneratorIntentMaxLength-73) + `"`)
			payload := generatedFixtureCanonicalIntent(t, settings, defaultGeneratedFixtureProfile())
			if len(payload) != 393216 {
				t.Fatal("maximum intent witness length", len(payload))
			}
			intent, err := contract.GeneratorIntentDigest(payload)
			if err != nil {
				t.Fatal(err)
			}
			blob := id(byte(70 + i))
			body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
				TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			fragment, err := contract.GeneratorFragmentID(blob, 0)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragment, Body: body})
			locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent,
				ContentID: intent, BlobID: blob, Length: uint32(len(payload)), Digest: contract.Hash(payload)})
			if i == 0 {
				state.pages[0].Slots[0] = &format.ValueEntry{Name: "generated", ValueSource: contract.Generated,
					Generated: contract.GeneratedEntryMetadata{IntentDigest: intent}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
			}
		}
		groups, err := generatedReservationGroupsForState(state, rows, locations, nil)
		if err != nil {
			t.Fatal("current and detached physical groups", err)
		}
		if len(groups) != 2 || groups[0].Mandatory == groups[1].Mandatory {
			t.Fatal("intent partitions were merged", groups)
		}
		pages, err := format.PackRequiredSupportRows(state.root.Domain, groups, 0)
		if err != nil || len(pages) != 2 {
			t.Fatal("intent partition page count", len(pages), err)
		}
		selected := &generatedSelection{session: state, image: state.selectedImage(), records: map[generatedRecordKey]contract.SupportRecord{},
			content: &generatedContent{locations: map[generatedContentKey]contract.GeneratorSliceLocation{}}}
		for _, row := range rows {
			selected.records[generatedRecordKey{row.Kind, row.RecordID}] = row
		}
		for _, loc := range locations {
			selected.content.locations[generatedContentKey{loc.ContentKind, loc.ContentID}] = loc
		}
		shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 2, Secrets: 1,
			Memberships: 1, SecretMemberships: 1, Generated: 1, OldGenerated: 1, Creates: 1, Retirements: 1,
			ValueEntryPlanCount: 1, DeclarationBytes: 393425, RegistryBytes: 4010, DesiredOutputBytes: 128,
			OldIntentBytes: 393216, Recovery: true}
		charged, err := generatedCapacityWithProjectedBacklog(shape, selected, nil)
		if err != nil {
			t.Fatal("maximum distinct intent backlog", err)
		}
		if got := charged[contract.GeneratorCapacityIntents]; got.MaxPages != 3 || got.MaxCount != 3 || got.MaxFramedBytes != 1180226 {
			t.Fatal("mandatory old blob partition omitted", charged[contract.GeneratorCapacityIntents])
		}
	})
	t.Run("terminal-retained-release-image", func(t *testing.T) {
		before := generatedEmptyPredecessor(t)
		stockInstallRetainedRetirements(t, before, 3)
		selected, err := before.selectedGeneratedWork(t.Context())
		if err != nil || len(selected.releases) != 3 || len(selected.bundles) != 3 || len(selected.attempts) != 0 {
			t.Fatal("terminal stock image lost its exact release-only owners", err)
		}
		if stockReleasedContinuationBytes(t, selected) != 3135 {
			t.Fatal("terminal stock continuation bytes")
		}
		var releaseBytes, releasePages uint64
		for _, page := range before.support {
			var rows []contract.SupportRecord
			for _, row := range page.Records {
				if row.Kind != contract.OutputConfigurationSliceSupportKind {
					rows = append(rows, contract.SupportRecord(row))
				}
			}
			if len(rows) == 0 {
				continue
			}
			releasePages++
			releaseBytes += contract.RequiredSupportPageHeaderLength
			for _, row := range rows {
				releaseBytes += uint64(contract.SupportRecordOverhead + len(row.Body))
			}
		}
		if releasePages > 15 || releaseBytes > 29484 || 1903209+2000000+releaseBytes > 4<<20 {
			t.Fatal("terminal stock image exceeds ordinary object or byte bound", releasePages, releaseBytes)
		}
	})
	t.Run("maximum-organization-policy-output", func(t *testing.T) {
		id := generatedVectorID
		configuration := contract.OutputConfiguration{Schema: 4, DomainID: id(1)}
		var destinations []string
		for bindingIndex := range 4 {
			destination := strings.Repeat("d", 255) + string(rune('a'+bindingIndex))
			destinations = append(destinations, destination)
			// Stock organization policy has65535 eight-byte IDs plus5 bytes
			// of framing. It is stored in destination and both target rows.
			policyBytes := 32
			if bindingIndex == 2 {
				policyBytes = 524285
			}
			policy := contract.OutputPolicy{ContractID: strings.Repeat("p", 256), Data: make([]byte, policyBytes)}
			binding := contract.OutputBinding{IncarnationID: id(byte(20 + bindingIndex)), DestinationID: destination,
				Destination: contract.OutputDestination{ConfigContractID: strings.Repeat("c", 256), ServiceContractID: strings.Repeat("s", 256),
					CanonicalSettings: []byte(`"` + strings.Repeat("x", contract.MaxOutputDestinationSettings-2) + `"`), Policy: policy, Capabilities: 63}}
			for entryIndex := range 2 {
				target := strings.Repeat("t", 1022) + string(rune('a'+bindingIndex)) + string(rune('a'+entryIndex))
				binding.Targets = append(binding.Targets, contract.OutputTarget{EntryIncarnationID: id(byte(10 + entryIndex)),
					ServiceContractID: binding.Destination.ServiceContractID, TargetContractID: strings.Repeat("q", 256),
					CanonicalTarget: target, ConsumerLocator: strings.Repeat("l", 1024), TargetData: make([]byte, contract.MaxOutputTargetDataBytes),
					PayloadEncoding: contract.OutputEncodingRaw, Capabilities: 63,
					CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: policy})
			}
			configuration.Bindings = append(configuration.Bindings, binding)
		}
		configuration.Routes = []contract.OutputRoute{
			{EntryIncarnationID: id(10), Destinations: slices.Clone(destinations)},
			{EntryIncarnationID: id(11), Destinations: slices.Clone(destinations)},
		}
		configuration.Groups = [][]contract.ID{{id(10), id(11)}}
		body, err := contract.EncodeOutputConfiguration(configuration)
		if err != nil || len(body) >= 2000000 {
			t.Fatal("fixed maximum output configuration", len(body), err)
		}
		descriptor, slices, err := contract.SplitOutputConfiguration(configuration.DomainID, body)
		if err != nil || descriptor.SliceCount != 2 {
			t.Fatal("maximum organization policy must use two slices", descriptor.SliceCount, err)
		}
		var rows []contract.SupportRecord
		for _, slice := range slices {
			encoded, err := contract.EncodeOutputConfigurationSlice(slice)
			if err != nil {
				t.Fatal(err)
			}
			record, err := contract.OutputConfigurationSliceID(configuration.DomainID, descriptor.ConfigurationDigest, slice.SliceIndex)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: record, Body: encoded})
		}
		pages, err := format.PackRequiredSupportRows(configuration.DomainID, []format.RequiredSupportGroup{{Class: format.OutputConfigurationSupport, Owner: descriptor.ConfigurationDigest, Records: rows}}, 0)
		if err != nil || len(pages) != 1 {
			t.Fatal("two fixed output slices exceed one physical page", len(pages), err)
		}
		// The other fixed populations include all26 publication rows, current
		// generated evidence/intent, receipts, access, root and the index shard.
		if uint64(len(body))+1903209+3*9828 > 4<<20 {
			t.Fatal("complete output candidate exceeds four MiB", len(body))
		}
	})
	// Worst old/new row and group counts include512 receipts,26 publication
	// rows and15 retained-release rows/pages. This independent wire calculation includes maximum old-owner span
	// expansion and treats every new row as shared by every owner.
	const maximumIndex = 77523 + 2*615*47 + 247*9 + 2*(47+9) + 108*256 + 7*(615+700) + 37*700 + 2*(9*615+(47+9)*700)
	if maximumIndex != 289891 {
		t.Fatal("independent administrative arithmetic")
	}
	if shards, err := format.AdministrativeIndexShardCount(maximumIndex); err != nil || shards != 1 {
		t.Fatal("complete stock index does not fit one shard", shards, err)
	}
	if shards, err := format.AdministrativeIndexShardCount(maximumIndex + endWorkMaximumReceiptIndexBytes); err != nil || shards != 1 {
		t.Fatal("first administrative exit exceeds the stock index shard", shards, err)
	}
}

func stockInstallRetainedRetirements(t testing.TB, before *StateSession, count uint64) {
	t.Helper()
	if count == 0 {
		return
	}
	generatedMaterializeFixtureSupport(t, before)
	rows := before.supportRecords()
	locations := generatedFixtureSliceLocations(t, rows)
	bundles := generatedFixtureBundles(t, before)
	owners := []contract.ID{}
	for _, row := range rows {
		if row.Kind == contract.GeneratedDutySupportKind {
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			owners = append(owners, duty.DutyID)
		}
	}
	for i := uint64(0); i < count; i++ {
		s, attempt, _, _ := generatedEnteredRetirementForOperation(t, generatedVectorID(byte(150+i)), true)
		selected, err := s.selectedGeneratedWork(t.Context())
		if err != nil {
			t.Fatal("retained stock retirement", err)
		}
		closed, err := selected.generatedRetirementAcknowledgement(t.Context(), attempt.record.AttemptID, generatedVectorID(byte(160+i)))
		if err != nil {
			t.Fatal("retained stock acknowledgement", err)
		}
		if len(selected.bundles) != 1 {
			t.Fatal("retained stock graph population")
		}
		bundle := stockRetainedRetirementGraph(t, selected.bundles[0], i)
		wantPlans := 1
		if i == 2 {
			wantPlans = 2
		}
		if len(bundle.ValueEntryPlans) != wantPlans || int(bundle.Header.ValueEntryPlanCount) != wantPlans {
			t.Fatal("retained stock graph omitted current entry plans", i, len(bundle.ValueEntryPlans), bundle.Header.ValueEntryPlanCount, wantPlans)
		}
		for planIndex, plan := range bundle.ValueEntryPlans {
			wantSource, wantClass := uint8(contract.Generated), uint8(contract.Secret)
			if i == 2 {
				wantSource = contract.Supplied
				if planIndex == 0 {
					wantClass = contract.Plain
				}
			}
			if plan.ValueSource != wantSource || plan.ConfidentialityClass != wantClass {
				t.Fatal("retained stock graph changed current entry plan population", i, planIndex, plan)
			}
		}
		if len(bundle.Lineages) != 1 || bundle.Lineages[0].Purpose != contract.GeneratorLineageRetirement || bundle.Lineages[0].TemplateCount != 1 ||
			bundle.Lineages[0].Templates[0].Action != contract.GeneratorActionDelete || len(bundle.ValueEntryPlans) > 2 || len(bundle.Edges) != 2 || len(bundle.ResultUses) != 1 || len(bundle.SourceUses) != 0 {
			t.Fatal("retained stock graph is not one manual Delete")
		}
		attempt.expected.Plan = bundle.UsePlan
		attempt.material.Core.UsePlanDigest, err = contract.GeneratorUsePlanDigest(bundle.UsePlan)
		if err != nil {
			t.Fatal("retained stock result use plan", err)
		}
		result := generatedRetirementResultFixture(t, s, attempt, contract.GeneratorDispositionRetirementAcknowledged)
		boundResult, err := contract.InspectGeneratedResultRecord(result)
		if err != nil || boundResult.Core.PlanGraphID != bundle.UsePlan.PlanGraphID || boundResult.Core.UsePlanDigest != attempt.material.Core.UsePlanDigest {
			t.Fatal("retained stock result lost its complete graph binding", err)
		}
		closed.release.SelectedHandoffDigest, closed.release.ObjectLength = contract.Hash(result), uint32(len(result))
		graph, err := contract.EncodeGeneratorPlanBundle(bundle)
		if err != nil || len(graph) > 6171 {
			t.Fatal("retained stock graph byte bound", len(graph), err)
		}
		blob := contract.Hash(graph)
		fragments, err := generatedFragmentRows(blob, graph)
		if err != nil || len(fragments) != 1 || len(fragments[0].Body)+contract.SupportRecordOverhead > 6294 {
			t.Fatal("retained stock graph fragment bound", err)
		}
		rows = append(rows, fragments...)
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentGraph,
			ContentID: bundle.UsePlan.PlanGraphID, BlobID: blob, Length: uint32(len(graph)), Digest: contract.Hash(graph)})
		// The fixed route body is public contract data at its complete wire bound.
		route := []byte{0, 1}
		routeContract := generatedVectorID(byte(170 + i))
		route = append(route, routeContract[:]...)
		route = append(route, 1, 0)
		route = binary.BigEndian.AppendUint32(route, 1541)
		route = append(route, bytes.Repeat([]byte{'r'}, 1541)...)
		preimage := append([]byte("ENKV/CREDENTIAL-ROUTE/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(route)))...)
		preimage = append(preimage, route...)
		binding, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 7,
			ContractID: routeContract, ImplementationID: attempt.record.ExecutorID, PublicBindingDigest: sha256.Sum256(preimage), Binding: route})
		if err != nil || len(binding) != 1684 {
			t.Fatal("retained stock support byte bound", len(binding), err)
		}
		mapping := closed.attempt.record
		var carriers []contract.SupportRecord
		mapping.Support, carriers, err = generatedCarrierRows(before.root.Domain, contract.GeneratedParentSupportKind, mapping.OperationID, contract.GeneratorVectorSupport, [][]byte{binding})
		if err != nil || len(carriers) != 1 || len(carriers[0].Body)+contract.SupportRecordOverhead != 1841 {
			t.Fatal("retained stock support carrier", err)
		}
		rows = append(rows, carriers...)
		body, err := contract.EncodeGeneratedAttemptRecord(mapping)
		if err != nil || len(body)+contract.SupportRecordOverhead != 797 {
			t.Fatal("retained stock Attempt bytes", len(body), err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: mapping.AttemptID, Body: body})
		body, err = contract.EncodePendingInboxReleaseRecord(closed.release)
		if err != nil || len(body)+contract.SupportRecordOverhead != 248 {
			t.Fatal("retained stock release bytes", len(body), err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.PendingInboxReleaseSupportKind, RecordID: closed.release.InboxID, Body: body})
		owners = append(owners, closed.release.InboxID)
		bundles = append(bundles, bundle)
	}
	rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		return carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
	})
	locations, err := generatedUniqueLocations(locations)
	if err != nil {
		t.Fatal(err)
	}
	var encoded [][]byte
	var graphIDs []contract.ID
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, body)
		if location.ContentKind == contract.GeneratorContentGraph {
			graphIDs = append(graphIDs, location.ContentID)
		}
	}
	var carriers []contract.SupportRecord
	before.root.Generated.Slices, carriers = generatedVectorRows(t, contract.GeneratorSnapshotOwner, before.root.Snapshot, contract.GeneratorVectorSlices, encoded)
	rows = append(rows, carriers...)
	slices.SortFunc(graphIDs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	before.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, slices.Compact(graphIDs))
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	before.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	before.root.Generated.Attempts += uint32(count)
	before.root.Generated.PendingReleases += uint32(count)
	generatedRepackSupportAtLocations(t, before, rows, bundles, locations)
}

func stockReleasedContinuationBytes(t testing.TB, selected *generatedSelection) uint64 {
	t.Helper()
	rows := make([]contract.SupportRecord, 0, len(selected.records))
	for _, row := range selected.records {
		rows = append(rows, row)
	}
	var locations []contract.GeneratorSliceLocation
	for _, location := range selected.content.locations {
		locations = append(locations, location)
	}
	groups, err := generatedReservationGroupsForState(selected.session, rows, locations, selected.bundles)
	if err != nil {
		t.Fatal("retained stock continuation groups", err)
	}
	var count, framed uint64
	for _, group := range groups {
		released, exists := selected.releases[group.Owner]
		if !exists {
			continue
		}
		if group.Class != format.DeleteContinuationSupport || len(group.Records) != 2 || released.template.Action != contract.GeneratorActionDelete {
			t.Fatal("retained stock continuation population")
		}
		var attempt, mapping bool
		var size uint64
		for _, row := range group.Records {
			switch row.Kind {
			case contract.GeneratedAttemptSupportKind:
				v, err := contract.InspectGeneratedAttemptRecord(row.Body)
				if err != nil || v != released.attempt || v.AttemptID != group.Owner || v.State != contract.GeneratedEffectSucceeded || v.Stage != contract.GeneratedStageTerminal {
					t.Fatal("retained stock terminal Attempt", err)
				}
				attempt = true
			case contract.PendingInboxReleaseSupportKind:
				v, err := contract.InspectPendingInboxReleaseRecord(row.Body)
				if err != nil || v != released.release || v.State != contract.GeneratedReleasePending {
					t.Fatal("retained stock pending mapping", err)
				}
				mapping = true
			default:
				t.Fatal("retained stock continuation has another row")
			}
			size += uint64(contract.SupportRecordOverhead + len(row.Body))
		}
		if !attempt || !mapping || size != 1045 {
			t.Fatal("retained stock continuation wire bytes", size)
		}
		count++
		framed += size
	}
	if count != uint64(len(selected.releases)) {
		t.Fatal("retained stock continuation owner missing", count, len(selected.releases))
	}
	return framed
}

func stockRetainedRetirementGraph(t testing.TB, bundle contract.GeneratorPlanBundle, retirement uint64) contract.GeneratorPlanBundle {
	t.Helper()
	current := generatedSelectedEntryState(t)
	work, err := current.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("stock current declaration predecessor", err)
	}
	if retirement == 2 {
		secret := *current.pages[0].Slots[0]
		secret.Name, secret.ValueSource, secret.Generated = "secret", contract.Supplied, contract.GeneratedEntryMetadata{}
		plain := contract.ValueEntry{Name: "plain", Incarnation: generatedVectorID(180), ValueState: generatedVectorID(181),
			OriginSnapshot: current.root.Snapshot, OriginTransition: current.root.Transition, ValueSource: contract.Supplied,
			ConfidentialityClass: contract.Plain, ValueBytes: []byte("stock plugin plain value"), Recipients: secret.Recipients, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("stock plugin plain value"))), RetainedLength: uint32(len([]byte("stock plugin plain value")))}
		current.pages[0].Slots[0], current.pages[0].Slots[1] = &plain, &secret
		current.root.Names = []format.NameEntry{{Name: "plain", Slot: 0}, {Name: "secret", Slot: 1}}
		current.root.ValueEntryCount, current.root.Generated.GeneratedCurrent = 2, 0
	}
	declaration, plans, err := current.installedGeneratedCurrentDeclaration(work, bundle.Header.OperationID)
	if err != nil {
		t.Fatal("stock retained current entry plans", err)
	}
	bundle.ValueEntryPlans = plans
	bundle.Header.ValueEntryPlanCount = uint16(len(plans))
	bundle.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal("stock retained declaration descriptor", err)
	}
	bundle.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(bundle.Request)
	if err != nil {
		t.Fatal("stock retained request digest", err)
	}
	join, err := contract.GeneratorCompleteJoinID(bundle.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal("stock retained complete join", err)
	}
	bundle.Edges = slices.Clone(bundle.Edges)
	for i := range bundle.Edges {
		bundle.Edges[i].DestinationTemplateID = join
	}
	bundle.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(bundle.Header, bundle.ValueEntryPlans, bundle.Lineages, bundle.Edges)
	if err != nil {
		t.Fatal("stock retained graph identity", err)
	}
	return bundle
}
