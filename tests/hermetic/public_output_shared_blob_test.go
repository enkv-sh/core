package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPendingOutputOperationKeepsSharedBlobAcrossIntentRelocationAndExactEnding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	authority := f.selected.admission.recipient
	plain := ApplyEntryInput{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("shared output fixture"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	seed := f.engine(t, f.selected, []ApplyEntryInput{plain}, nil)
	if result := seed.Apply(ctx, fixtureID(f.env.Domain, "kind8 shared lifecycle seed"), []ApplyEntryInput{plain}); result.Result.Outcome != ObservedCurrent {
		t.Fatal("lifecycle fixture seed", result.Result)
	}
	seed.Close()
	f.selected = f.open(t, ctx)
	lifecycle := f.selected
	implementation := process.Implementation
	meta := func() *contract.GeneratorDeclaredGeneration {
		return &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}
	}
	input := []ApplyEntryInput{{Name: "current", ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{authority}, Generated: meta()}, plain}
	currentEngine := publicGeneratedOutputEngine(t, ctx, f, input, &outputApplyInput{}, installedGeneratedTestCallbacks(t, f, process))
	currentResult := currentEngine.Apply(ctx, fixtureID(f.env.Domain, "kind8 shared independent current"), input)
	currentEngine.Close()
	if currentResult.Result.Outcome != ObservedCurrent {
		t.Fatal("independent generated current selection", currentResult.Result)
	}
	f.selected = f.open(t, ctx)
	currentEntry := ownScenarioValueEntry(*f.selected.valueEntry(entrySlot(t, f.selected, "current")))
	input = append(input, ApplyEntryInput{Name: "next", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{authority}, Generated: meta(), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("next", "kind8-shared-next")}}}, groups: [][]string{{"next"}}}
	installOutputFixtureSource(t, f.selected, output)
	f.admitted = OpenContext{admission: &f.selected.admission}
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	pendingEngine := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
	pending := pendingEngine.Apply(ctx, fixtureID(f.env.Domain, "kind8 shared pending owner"), input)
	pendingEngine.Close()
	f.selected = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, f.selected)
	if work.parent == nil || work.parent.OperationID != pending.OperationID || work.parent.OperationID == currentEntry.Generated.OriginOperationID || f.selected.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("fixture has no independent current intent and real pending parent", pending.Result)
	}
	originalGraph, err := work.retainedGraph(pending.OperationID)
	if err != nil || originalGraph.Request.Schema != contract.GeneratorApplyRequestCoreSchema {
		t.Fatal("pending owner was not admitted by public v4 apply", err)
	}
	outputKey := generatedContentKey{contract.GeneratorContentOutputConfiguration, pending.OperationID}
	intentKey := generatedContentKey{contract.GeneratorContentIntent, currentEntry.Generated.IntentDigest}
	registryKey := generatedContentKey{contract.GeneratorContentRecipientRegistry, pending.OperationID}
	image, err := work.readSelectedSlice(ctx, outputKey.kind, outputKey.id, contract.MaxOutputConfigurationBytes)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := work.readSelectedSlice(ctx, intentKey.kind, intentKey.id, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(intent, process.Intent) {
		t.Fatal("independent current intent", err)
	}
	registryImage, err := work.readSelectedSlice(ctx, registryKey.kind, registryKey.id, contract.GeneratedRecipientRegistryMaxLength)
	if err != nil {
		t.Fatal("pending recipient registry", err)
	}
	originalLogical := work.content.locations[outputKey].Logical()
	originalRegistryLogical := work.content.locations[registryKey].Logical()
	shared := append(bytes.Clone(image), registryImage...)
	sharedID := contract.Hash(shared)
	intentBlobID := fixtureID(f.env.Domain, "kind8 shared independent current physical")
	if intentBlobID == contract.Hash(intent) {
		t.Fatal("independent current intent fixture is already compact")
	}
	locations := selectedGeneratedLocations(work)
	for i := range locations {
		switch (generatedContentKey{locations[i].ContentKind, locations[i].ContentID}) {
		case outputKey:
			locations[i].BlobID, locations[i].Offset = sharedID, 0
		case registryKey:
			locations[i].BlobID, locations[i].Offset = sharedID, uint64(len(image))
		case intentKey:
			locations[i].BlobID, locations[i].Offset = intentBlobID, 0
		}
	}
	sharedFragments, err := generatedFragmentRows(sharedID, shared)
	if err != nil || len(sharedFragments) != 1 || len(sharedFragments[0].Body) != 86+len(shared) {
		t.Fatal("independent shared fragment framing", err)
	}
	intentFragments, err := generatedFragmentRows(intentBlobID, intent)
	if err != nil {
		t.Fatal("independent current intent physical representation", err)
	}
	// This representation-only fixture keeps the real accepted graph and all
	// canonical/effect evidence. Existing writers rebuild and sign the actual
	// physical support/index/root, then cold Open validates that full image.
	persist := func(before *StateSession, locations []contract.GeneratorSliceLocation, extra []contract.SupportRecord, label string) *StateSession {
		t.Helper()
		var rows []contract.SupportRecord
		for p, ref := range before.root.RequiredSupport {
			body, result := before.readObjectBorrowedUncached(ctx, ref)
			if result.Outcome != 0 {
				t.Fatal("shared physical source", result)
			}
			page, err := format.InspectRequiredSupportPage(body)
			if err != nil {
				t.Fatal(err)
			}
			for _, ordinal := range before.supportFacts[p].ordinals {
				rows = append(rows, contract.SupportRecord(page.Records[ordinal]))
			}
		}
		used := make(map[contract.ID]bool)
		for _, location := range locations {
			used[location.BlobID] = true
		}
		indexBlob, err := before.receiptIndexID()
		if err != nil {
			t.Fatal(err)
		}
		used[indexBlob] = true
		rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
			if row.Kind == contract.GeneratorVectorSupportKind {
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
			}
			if row.Kind == contract.GeneratedFragmentSupportKind {
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return !used[fragment.BlobID]
			}
			return false
		})
		rows = append(rows, extra...)
		next := *before
		next.root.Snapshot, next.root.Transition = fixtureID(f.env.Domain, label+" snapshot"), fixtureID(f.env.Domain, label+" transition")
		slices.SortFunc(locations, compareGeneratedLocationKey)
		var bodies [][]byte
		for _, location := range locations {
			body, err := contract.EncodeGeneratorSliceLocation(location)
			if err != nil {
				t.Fatal(err)
			}
			bodies = append(bodies, body)
		}
		descriptor, carriers, err := generatedCarrierRows(f.env.Domain, contract.GeneratorSnapshotOwner, next.root.Snapshot, contract.GeneratorVectorSlices, bodies)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, carriers...)
		next.root.Generated.Slices = descriptor
		generatedRepackSupportAtLocations(t, &next, rows, work.bundles, locations)
		store := requireAdmittedMemoryStore(t, f.env.Store)
		put := func(ref format.Ref, body []byte) {
			t.Helper()
			if err := format.CheckReference(ref, body); err != nil {
				t.Fatal(err)
			}
			if err := store.putSelected(mustKey(t, store.desc.Prefix, ref), body); err != nil {
				t.Fatal(err)
			}
		}
		for i, page := range next.support {
			records := make([]contract.SupportRecord, len(page.Records))
			for j, row := range page.Records {
				records[j] = contract.SupportRecord(row)
			}
			body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: records})
			if err != nil {
				t.Fatal(err)
			}
			put(next.root.RequiredSupport[i], body)
		}
		shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
		if err != nil {
			t.Fatal(err)
		}
		for _, shard := range shards {
			put(shard.Ref, shard.Body)
		}
		_, opened := writeSignedCurrentIntentImage(t, f.env, lifecycle, before, &next, store, label, put)
		return opened
	}
	sharedState := persist(f.selected, locations, append(sharedFragments, intentFragments...), "kind8 shared physical variant")
	check := func(selected *StateSession) *generatedSelection {
		t.Helper()
		g := mustSelectedGeneratedWork(t, selected)
		graph, err := g.retainedGraph(pending.OperationID)
		body, readErr := g.readSelectedSlice(ctx, outputKey.kind, outputKey.id, contract.MaxOutputConfigurationBytes)
		location := g.content.locations[outputKey]
		if err != nil || readErr != nil || !reflect.DeepEqual(graph, originalGraph) || location.Logical() != originalLogical || location.BlobID != sharedID || !bytes.Equal(body, image) {
			t.Fatal("pending kind8 changed across physical ownership", err, readErr)
		}
		registryBody, registryErr := g.readSelectedSlice(ctx, registryKey.kind, registryKey.id, contract.GeneratedRecipientRegistryMaxLength)
		registryLocation := g.content.locations[registryKey]
		if registryErr != nil || registryLocation.Logical() != originalRegistryLogical || registryLocation.BlobID != sharedID || !bytes.Equal(registryBody, registryImage) {
			t.Fatal("pending registry changed across physical ownership", registryErr)
		}
		var pages []format.RequiredSupportPage
		for _, page := range selected.support {
			owned := format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index}
			for _, row := range page.Records {
				owned.Records = append(owned.Records, contract.SupportRecord(row))
			}
			pages = append(pages, owned)
		}
		consumers, err := selectedAdministrativeConsumersWithValidated(pages, nil, g.bundles, g)
		if err != nil || !slices.Equal(consumers.contentOwners(location), []contract.ID{pending.OperationID}) || !slices.Equal(consumers.contentOwners(registryLocation), []contract.ID{pending.OperationID}) {
			t.Fatal("kind8 did not have its exact operation owner", err)
		}
		fragmentID, err := contract.GeneratorFragmentID(sharedID, 0)
		if err != nil {
			t.Fatal(err)
		}
		matched := 0
		for p, page := range selected.adminIndex.Pages {
			logical := 0
			for _, span := range page.Spans {
				for j := 0; j < int(span.Count); j++ {
					fact := selected.supportFacts[p].rows[logical]
					logical++
					if fact.Kind() != contract.GeneratedFragmentSupportKind || fact.RecordID() != fragmentID {
						continue
					}
					var owners []contract.ID
					for _, index := range span.GroupIndexes {
						owners = append(owners, selected.adminIndex.Groups[index].GroupID)
					}
					if span.Mandatory || !slices.Equal(owners, []contract.ID{pending.OperationID}) || fact.BodyLength() != uint32(86+len(shared)) {
						t.Fatal("shared fragment owner/codec charge differs", span, owners)
					}
					matched++
				}
			}
		}
		if matched != 1 {
			t.Fatal("shared physical fragment missing or duplicated", matched)
		}
		groupIndex := slices.IndexFunc(selected.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == pending.OperationID })
		if groupIndex < 0 {
			t.Fatal("accepted parent owner group missing")
		}
		var framed uint64
		var chargedPages uint16
		for p, page := range selected.adminIndex.Pages {
			logical, charged := 0, false
			for _, span := range page.Spans {
				for j := 0; j < int(span.Count); j++ {
					fact := selected.supportFacts[p].rows[logical]
					logical++
					if slices.Contains(span.GroupIndexes, uint16(groupIndex)) {
						framed += 37 + uint64(fact.BodyLength())
						charged = true
					}
				}
			}
			if charged {
				chargedPages++
			}
		}
		group := selected.adminIndex.Groups[groupIndex]
		if group.ChargedBytes != framed || group.ChargedPages != chargedPages {
			t.Fatal("exact parent physical/frame charge differs", group.ChargedBytes, framed, group.ChargedPages, chargedPages)
		}
		return g
	}
	sharedWork := check(sharedState)
	if sharedWork.content.locations[intentKey].BlobID != intentBlobID {
		t.Fatal("independent current intent did not retain its separate physical representation")
	}
	projection, err := planGeneratedCurrentIntents(ctx, sharedState, sharedWork, selectedGeneratedLocations(sharedWork))
	if err != nil || !projection.changed || !projection.dropBlobs[intentBlobID] || projection.dropBlobs[sharedID] || projection.blob != contract.Hash(intent) {
		t.Fatal("current intent relocation pruned kind8 physical blob", err)
	}
	emitted, err := emitGeneratedCurrentIntents(ctx, sharedWork, projection)
	if err != nil {
		t.Fatal(err)
	}
	relocated := persist(sharedState, slices.Clone(projection.after), emitted, "kind8 shared current relocation")
	relocatedWork := check(relocated)
	if relocatedWork.content.locations[intentKey].Logical() != sharedWork.content.locations[intentKey].Logical() || relocatedWork.content.locations[intentKey].BlobID != contract.Hash(intent) {
		t.Fatal("independent current intent changed during relocation")
	}
	beforeCreates, beforeDeletes := effects()
	admin, observed := openAdministrative(ctx, OpenContext{admission: &relocated.admission}, f.env.Store)
	if admin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("shared parent administrative reopen", observed)
	}
	candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, pending.OperationID, f.env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("last kind8 owner ending", prepared)
	}
	ended, selected := admin.selectCandidate(ctx, candidate)
	if ended == nil || selected.Outcome != ObservedCurrent {
		t.Fatal("last kind8 owner selection", selected)
	}
	cold := generatedLifecycleReopen(t, ctx, ended, f.env.Store)
	remaining := mustSelectedGeneratedWork(t, cold)
	_, outputPresent := remaining.content.locations[outputKey]
	_, registryPresent := remaining.content.locations[registryKey]
	if outputPresent || registryPresent || slices.ContainsFunc(cold.root.Generated.Fragments, func(fragment format.FragmentLocation) bool { return fragment.BlobID == sharedID }) {
		t.Fatal("last kind8 consumer did not release its mapping/blob")
	}
	if got := cold.valueEntry(entrySlot(t, cold, "current")); !reflect.DeepEqual(*got, currentEntry) {
		t.Fatal("ending pending parent changed independent current value")
	}
	currentIntent, err := remaining.readSelectedSlice(ctx, intentKey.kind, intentKey.id, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(currentIntent, intent) {
		t.Fatal("last owner ending lost independently relocated intent", err)
	}
	if creates, deletes := effects(); creates != beforeCreates || deletes != beforeDeletes || creates != 2 || deletes != 0 {
		t.Fatal("physical relocation or exact ending sent provider work", creates, deletes)
	}
}
