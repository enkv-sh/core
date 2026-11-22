package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: true
func TestPublicV4OutputAdmissionPacksExactDeclarationAtJointCapacity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	authority := f.selected.admission.recipient
	plain := ApplyEntryInput{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("joint declaration seed"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	seed := f.engine(t, f.selected, []ApplyEntryInput{plain}, nil)
	if result := seed.Apply(ctx, fixtureID(f.env.Domain, "v4 joint lifecycle seed"), []ApplyEntryInput{plain}); result.Result.Outcome != ObservedCurrent {
		t.Fatal("joint lifecycle seed", result.Result)
	}
	seed.Close()
	f.selected = f.open(t, ctx)
	lifecycle := f.selected
	rows, orders := publicationJointRows(t, f.env.Domain, 1023)
	var markerBytes, coordinateBytes uint64
	for _, row := range rows {
		switch row.Kind {
		case contract.PublicationMarkerSupportKind:
			markerBytes += uint64(37 + len(row.Body))
		case contract.PublicationCoordinateSupportKind:
			coordinateBytes += uint64(37 + len(row.Body))
		default:
			t.Fatal("unexpected joint fixture row", row.Kind)
		}
	}
	// These are real selected rows and real index/root pages. The one remaining
	// coordinate slot belongs to the requested generated output target.
	f.env, f.selected = publicationJointSelectedImage(t, f.env, lifecycle, f.selected, rows, orders, 0, 0, "v4 exact declaration joint predecessor")
	f.admitted = OpenContext{admission: &f.selected.admission}
	selected, err := selectedPublicationRelation(f.selected.selectedImage())
	if err != nil || len(selected.coordinates) != 1023 || len(selected.markers) != 2046 || len(installedOutputConfiguration(t, ctx, f.selected).Bindings) != 0 {
		t.Fatal("legal joint predecessor dimensions", err)
	}
	implementation := process.Implementation
	meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}
	input := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{authority}, Generated: meta, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}, plain}
	// The generic policy record is schema3 plus two blob32 fields. Its
	// independently sized opaque body carries the remaining requested bytes.
	policyOfLength := func(length int) contract.OutputPolicy {
		p := contract.OutputPolicy{ContractID: "joint-capacity-members"}
		n := length - 10 - len(p.ContractID)
		if n < 0 {
			t.Fatal("policy length cannot be represented", length)
		}
		p.Data = bytes.Repeat([]byte{'x'}, n)
		if got := capacityPolicyLength(t, p); got != length {
			t.Fatal("independent policy width", got, length)
		}
		return p
	}

	makeOutput := func(large bool, extra int) *outputApplyInput {
		out := &outputApplyInput{groups: [][]string{{"generated"}}, routes: []outputApplyRoute{{entryName: "generated", destinations: []string{"joint-00"}}}}
		for i := 0; i < 64; i++ {
			name := fmt.Sprintf("joint-%02d", i)
			destination := contract.OutputDestination{ConfigContractID: "aws", ServiceContractID: "aws", CanonicalSettings: hermeticDestinationSettings([][2]string{{"a", "v"}, {"b", "v"}, {"fixture_destination", name}}), Policy: contract.OutputPolicy{}, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)}
			if large && i != 0 {
				destination.Policy = policyOfLength(524546)
			}
			binding := outputApplyBinding{destinationID: name, destination: destination}
			if i == 0 {
				binding.targets = []outputApplyTarget{outputConfigurationTarget("generated", "joint-new-generated")}
			}
			out.bindings = append(out.bindings, binding)
		}
		if large {
			// IDs have a fixed32-byte width. This independently assembled preview
			// is only a length oracle; the real accepted operation supplies IDs.
			preview := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: f.env.Domain, Groups: [][]contract.ID{{fixtureID(f.env.Domain, "length entry")}}, Routes: []contract.OutputRoute{{EntryIncarnationID: fixtureID(f.env.Domain, "length entry"), Destinations: []string{"joint-00"}}}}
			for i, binding := range out.bindings {
				row := contract.OutputBinding{DestinationID: binding.destinationID, IncarnationID: fixtureID(f.env.Domain, fmt.Sprintf("length binding %d", i)), Destination: binding.destination}
				if i == 0 {
					target := binding.targets[0].target
					target.EntryIncarnationID = preview.Groups[0][0]
					row.Targets = []contract.OutputTarget{target}
				}
				preview.Bindings = append(preview.Bindings, row)
			}
			declaration, _ := capacityConfigurationLengths(t, preview)
			remaining := 33554432 - declaration
			if remaining%2 != 0 {
				out.bindings[0].destination.CanonicalSettings = append(out.bindings[0].destination.CanonicalSettings, ' ')
				remaining--
			}
			first := policyOfLength(remaining / 2)
			out.bindings[0].destination.Policy, out.bindings[0].targets[0].target.Policy = first, first
		}
		out.bindings[63].destination.CanonicalSettings = append(out.bindings[63].destination.CanonicalSettings, bytes.Repeat([]byte{' '}, extra)...)
		return out
	}
	// Full expected meaning is assembled from offered declarations and fixed
	// accepted entry IDs. It is never copied from ConfigurationAfter/normalizer.
	wantConfiguration := func(graph contract.GeneratorPlanBundle, out *outputApplyInput) contract.OutputConfiguration {
		entry := contract.ID{}
		for _, row := range graph.ValueEntryPlans {
			if row.Name == "generated" {
				entry = row.EntryIncarnationID
			}
		}
		if entry.IsZero() {
			t.Fatal("accepted generated entry identity missing")
		}
		want := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: f.env.Domain, Groups: [][]contract.ID{{entry}}, Routes: []contract.OutputRoute{{EntryIncarnationID: entry, Destinations: []string{"joint-00"}}}}
		for _, binding := range out.bindings {
			row := contract.OutputBinding{DestinationID: binding.destinationID, IncarnationID: publicOutputApplyExpectedBinding(f.env.Domain, graph.Header.OperationID, binding.destinationID), Destination: binding.destination}
			for _, named := range binding.targets {
				target := named.target
				target.EntryIncarnationID = entry
				row.Targets = append(row.Targets, target)
			}
			want.Bindings = append(want.Bindings, row)
		}
		return want
	}
	probe := func(out *outputApplyInput) *generatedPlan {
		t.Helper()
		installOutputFixtureSource(t, f.selected, out)
		f.admitted = OpenContext{admission: &f.selected.admission}
		engine := publicGeneratedOutputEngine(t, ctx, f, input, out, installedGeneratedTestCallbacks(t, f, process))
		defer engine.Close()
		mapped, complete, result := f.selected.installedApplyInputs(ctx, engine.installation, input)
		if result.Outcome != 0 {
			t.Fatal("complete joint plan inputs", result)
		}
		deadline, _ := ctx.Deadline()
		plan, err := f.selected.installedGeneratedPlan(ctx, engine.installation, mapped, complete, deadline)
		if err != nil || plan == nil {
			t.Fatal("actual joint v4 admission", err)
		}
		return plan
	}
	small, large := makeOutput(false, 0), makeOutput(true, 0)
	smallPlan, largePlan := probe(small), probe(large)
	want := wantConfiguration(largePlan.input.graph, large)
	declaration, routing := capacityConfigurationLengths(t, want)
	image, err := contract.EncodeOutputConfiguration(want)
	if err != nil || declaration != 33554432 || len(image) != 33554432+4+routing {
		t.Fatal("exact legal canonical declaration width", declaration, routing, len(image), err)
	}
	if len(image) != len(largePlan.input.outputConfiguration) || !bytes.Equal(image, largePlan.input.outputConfiguration) {
		t.Fatal("v4 plan lost exact independent output bytes")
	}
	request, err := contract.AppendGeneratorRequestCore(nil, largePlan.input.graph.Request)
	if err != nil || len(request) != 394 || largePlan.input.graph.Request.OutputConfiguration.TotalLength != uint32(len(image)) {
		t.Fatal("v4 exact image request framing", len(request), err)
	}
	// Independent widths: raw fragment86+37; canonical slice78+37;
	// physical maxima1048320 and1048423; logical carrier120+111+37.
	rawCount := (len(image) + 1048319) / 1048320
	canonicalCount := (len(image) + 1048422) / 1048423
	if rawCount != 33 || canonicalCount != 33 {
		t.Fatal("exact declaration did not reach33 actual fragments/slices", rawCount, canonicalCount)
	}
	smallBytes := len(smallPlan.input.outputConfiguration)
	a, b := largePlan.capacity.Groups[contract.GeneratorCapacityAuxiliary], smallPlan.capacity.Groups[contract.GeneratorCapacityAuxiliary]
	if a.MaxCount-b.MaxCount != 64 || a.MaxFramedBytes-b.MaxFramedBytes != uint64(2*(len(image)-smallBytes)+32*(123+115)) || a.MaxPages-b.MaxPages != 32 {
		t.Fatal("joint admission omitted raw/canonical image packing charge", a, b)
	}
	// The changed successor support contains exactly33 canonical slices and
	// one coordinate, alongside the selected1023/2046 backlog.
	view, err := contract.InspectGeneratorDeclaration(largePlan.input.declaration)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := f.selected.admitGeneratedRegistry(ctx, largePlan.input.registryImage, largePlan.input.graph.Request, true)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := f.selected.generatedAdmissionShapeWithRegistry(ctx, largePlan.input.graph, view, mustSelectedGeneratedWork(t, f.selected), registry, largePlan.input.outputConfiguration)
	if err != nil || shape.outputSupport == nil || shape.outputSupport.configuration.MaxCount != 33 || shape.outputSupport.configuration.MaxPages != 17 || shape.outputSupport.configuration.MaxFramedBytes != uint64(len(image)+33*115) || shape.outputSupport.coordinates.MaxCount != 1 {
		t.Fatal("canonical/coordinate support not charged by actual v4 admission", err)
	}
	target := large.bindings[0].targets[0].target
	// A fresh coordinate has 648 fixed bytes, two populated strings and a 37-byte support record header.
	newCoordinateWidth := uint64(648 + len(target.ServiceContractID) + len(target.CanonicalTarget) + 37)
	if shape.outputSupport.coordinates.MaxFramedBytes != newCoordinateWidth || shape.outputSupport.coordinates.MaxPages != 1 {
		t.Fatal("admission did not reserve the exact fresh coordinate", shape.outputSupport.coordinates)
	}
	shape.DeclarationBytes, shape.RegistryBytes = uint64(len(largePlan.input.declaration)), uint64(len(largePlan.input.registryImage))
	shards, err := f.selected.generatedAdministrativeShardReserve(shape)
	if err != nil || shards == 0 {
		t.Fatal("joint prospective administrative charge", shards, err)
	}
	// The one-byte-over case stays inside every individual field/count bound.
	// Only the complete encoded declaration changes33554432 ->33554433.
	over := makeOutput(true, 1)
	overWant := wantConfiguration(largePlan.input.graph, over)
	overLength, _ := capacityConfigurationLengths(t, overWant)
	if overLength != 33554433 || !bytes.HasSuffix(over.bindings[63].destination.CanonicalSettings, []byte{' '}) || capacityPolicyLength(t, over.bindings[63].destination.Policy) != 524546 {
		t.Fatal("one-byte-over fixture crossed another field/count bound", overLength)
	}
	installOutputFixtureSource(t, f.selected, over)
	f.admitted = OpenContext{admission: &f.selected.admission}
	// The public constructor bounds the complete owned source before Apply.
	// Offer the over-bound declaration there; do not mutate an installed engine
	// to bypass that public ownership/admission boundary.
	template := publicGeneratedOutputEngine(t, ctx, f, input, large, installedGeneratedTestCallbacks(t, f, process))
	installation := template.installation
	publicOutputApplyProposal(&installation.PublicConfiguration, over)
	asserted := over.bindings[0].targets[0]
	installation.PublicConfiguration.OutputBindings.Value[0].Targets = observedPublicField([]contract.PublicOutputTarget{hermeticPublicOutputTarget(asserted.entryName, asserted.target)})
	template.Close()
	store := requireAdmittedMemoryStore(t, f.env.Store)
	beforeHead := bytes.Clone(store.objects[store.desc.HeadKey].Body)
	writes, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
	bad, overErr := NewInstalledApply(installation)
	if bad != nil {
		bad.Close()
	}
	if bad != nil || overErr != contract.ErrRecordCapacity || store.creates != writes || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs || !bytes.Equal(beforeHead, store.objects[store.desc.HeadKey].Body) {
		t.Fatal("over-bound complete declaration crossed public construction", overErr)
	}
	if creates, deletes := effects(); creates != 0 || deletes != 0 {
		t.Fatal("over-bound declaration sent provider work")
	}
	// Admit the exact input through the actual public reservation and stop at
	// Final after one create, so the raw kind8 packing is inspected selected.
	installOutputFixtureSource(t, f.selected, large)
	f.admitted = OpenContext{admission: &f.selected.admission}
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	engine := publicGeneratedOutputEngine(t, ctx, f, input, large, callbacks)
	stopped := engine.Apply(ctx, fixtureID(f.env.Domain, "v4 joint exact declaration"), input)
	engine.Close()
	f.selected = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, f.selected)
	graph, err := work.retainedGraph(stopped.OperationID)
	if err != nil || graph.Request.Schema != 4 || f.selected.root.Generated.ActiveOwner != stopped.OperationID {
		t.Fatal("exact v4 parent was not actually packed/selected", err, stopped.Result)
	}
	remaining := continuationTestBound(t, f.selected).Remaining
	want = wantConfiguration(graph, large)
	expectedImage, err := contract.EncodeOutputConfiguration(want)
	if err != nil {
		t.Fatal(err)
	}
	location := work.content.locations[generatedContentKey{contract.GeneratorContentOutputConfiguration, stopped.OperationID}]
	packedImage, err := work.readSelectedSlice(ctx, contract.GeneratorContentOutputConfiguration, stopped.OperationID, contract.MaxOutputConfigurationBytes)
	if err != nil || !bytes.Equal(packedImage, expectedImage) {
		t.Fatal("actual selected kind8 image differs", err)
	}
	count, framed := 0, uint64(0)
	for _, fragment := range f.selected.root.Generated.Fragments {
		if fragment.BlobID != location.BlobID {
			continue
		}
		fact, ok := f.selected.fragmentFacts[fragment]
		if !ok {
			t.Fatal("actual output fragment fact missing")
		}
		count++
		framed += 37 + uint64(fact.row.BodyLength())
	}
	if count != 33 || framed != uint64(len(expectedImage)+33*123) {
		t.Fatal("actual raw image fragment count/framing", count, framed)
	}
	ownerIndex := slices.IndexFunc(f.selected.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == stopped.OperationID })
	if ownerIndex < 0 {
		t.Fatal("operation-owned kind8 administrative group missing")
	}
	var ownerBytes uint64
	var ownerPages uint16
	for p, page := range f.selected.adminIndex.Pages {
		logical, charged := 0, false
		for _, span := range page.Spans {
			for j := 0; j < int(span.Count); j++ {
				fact := f.selected.supportFacts[p].rows[logical]
				logical++
				if slices.Contains(span.GroupIndexes, uint16(ownerIndex)) {
					ownerBytes += 37 + uint64(fact.BodyLength())
					charged = true
				}
			}
		}
		if charged {
			ownerPages++
		}
	}
	owner := f.selected.adminIndex.Groups[ownerIndex]
	if owner.ChargedBytes != ownerBytes || owner.ChargedPages != ownerPages || ownerBytes < framed+268 {
		t.Fatal("actual administrative owner packing charge", owner.ChargedBytes, ownerBytes, owner.ChargedPages, ownerPages)
	}
	pendingRelation, err := selectedPublicationRelation(f.selected.selectedImage())
	if err != nil || len(pendingRelation.coordinates) != 1023 || len(pendingRelation.markers) != 2046 || len(installedOutputConfiguration(t, ctx, f.selected).Bindings) != 0 {
		t.Fatal("reservation selected desired output early", err)
	}
	resume := publicGeneratedOutputEngine(t, ctx, f, input, &outputApplyInput{}, installedGeneratedTestCallbacks(t, f, process))
	result := resume.Continue(ctx, fixtureID(f.env.Domain, "v4 joint exact continuation"), stopped.OperationID)
	resume.Close()
	cold := f.open(t, ctx)
	if result.Result.Outcome != ObservedCurrent || result.RequestIdentity != stopped.RequestIdentity {
		t.Fatal("exact declaration Final packing failed", result.Result)
	}
	publicOutputApplyAssertConfiguration(t, installedOutputConfiguration(t, ctx, cold), want)
	actualRelation, err := selectedPublicationRelation(cold.selectedImage())
	if err != nil || len(actualRelation.coordinates) != 1024 || len(actualRelation.markers) != 2046 || cold.root.OutputConfiguration.SliceCount != 33 {
		t.Fatal("actual joint canonical/coordinate packing", err, len(actualRelation.coordinates), len(actualRelation.markers), cold.root.OutputConfiguration)
	}
	var actualMarkers, actualCoordinates uint64
	for _, page := range cold.supportFacts {
		for _, fact := range page.rows {
			switch fact.Kind() {
			case contract.PublicationMarkerSupportKind:
				actualMarkers += 37 + uint64(fact.BodyLength())
			case contract.PublicationCoordinateSupportKind:
				actualCoordinates += 37 + uint64(fact.BodyLength())
			}
		}
	}
	if actualMarkers != markerBytes || actualCoordinates != coordinateBytes+newCoordinateWidth {
		t.Fatal("Final discarded joint backlog charge or new coordinate", actualMarkers, markerBytes, actualCoordinates, coordinateBytes)
	}
	if creates, deletes := effects(); creates != 1 || deletes != 0 {
		t.Fatal("exact continuation repeated provider work", creates, deletes)
	}
	if cold.root.ChildCount > 254 || len(cold.root.AdministrativeIndexShards)+1 > int(shards) {
		t.Fatal("actual packed index/children exceeded admitted reservation", cold.root.ChildCount, shards)
	}
	report, err := publicCapacityBound(remaining)
	if err != nil {
		t.Fatal("public remaining-capacity report", err)
	}
	t.Run(report.Status, func(t *testing.T) {
		switch remaining.Status {
		case capacitySufficient:
			continuationTestCandidateWithin(t, cold, remaining)
		case capacityNotEstablished:
			// The report gives no numeric guarantee in this case.
		default:
			t.Fatal("unrecognized remaining-capacity outcome for active generated work", remaining.Status)
		}
	})
}
