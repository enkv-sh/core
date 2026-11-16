package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicGeneratedOutputPendingImageSurvivesRecipientReplacementAndReconstruction(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
	members := []contract.ID{authority, reader}
	slices.SortFunc(members, compareGeneratedIDs)
	implementation := process.Implementation
	meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: members, Generated: meta}}
	target := outputConfigurationTarget("generated", "pending-key-replacement")
	target.target.PayloadEncoding = contract.OutputEncodingBase64
	input[0].OutputEncoding = contract.OutputEncodingBase64
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}, groups: [][]string{{"generated"}}}
	installOutputFixtureSource(t, f.selected, output)
	f.admitted = OpenContext{admission: &f.selected.admission}
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	engine := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
	stopped := engine.Apply(ctx, fixtureID(f.env.Domain, "pending output replacement stop"), input)
	engine.Close()
	f.selected = f.open(t, ctx)
	creates, deletes := effects()
	if creates != 1 || deletes != 0 || stopped.OperationID.IsZero() || f.selected.root.Generated.ActiveOwner != stopped.OperationID || f.selected.root.ValueEntryCount != 0 {
		t.Fatal("pending v4 fixture did not reach Final", stopped.Result, creates, deletes)
	}
	before := mustSelectedGeneratedWork(t, f.selected)
	graph, err := before.retainedGraph(stopped.OperationID)
	if err != nil || graph.Request.Schema != contract.GeneratorApplyRequestCoreSchema {
		t.Fatal("pending parent is not accepted v4", err)
	}
	location := before.content.locations[generatedContentKey{contract.GeneratorContentOutputConfiguration, stopped.OperationID}]
	image, err := before.readSelectedSlice(ctx, contract.GeneratorContentOutputConfiguration, stopped.OperationID, contract.MaxOutputConfigurationBytes)
	if err != nil || location.ContentID != stopped.OperationID {
		t.Fatal("pending complete output image missing", err)
	}
	// Lose the replaced reader's old private resource before selecting the
	// successor. Only the Authority opens retained material for this operation.
	binding := f.keys.RecipientSuccessor(t, reader)
	f.keys.LoseRecipientPredecessor(reader)
	permit := admitReaderReplacement(t, f.selected, f.keys, reader, binding)
	candidate, result := f.selected.PrepareRecipientReplacement(ctx, permit, f.env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("pending reader replacement preparation", result)
	}
	if result := f.selected.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("pending reader replacement selection", result)
	}
	f.keys.RetireAccess()
	if err := f.keys.ActivateRecipientSuccessor(reader); err != nil {
		t.Fatal(err)
	}
	f.selected = f.open(t, ctx)
	afterReplacement := mustSelectedGeneratedWork(t, f.selected)
	afterGraph, err := afterReplacement.retainedGraph(stopped.OperationID)
	afterImage, imageErr := afterReplacement.readSelectedSlice(ctx, contract.GeneratorContentOutputConfiguration, stopped.OperationID, contract.MaxOutputConfigurationBytes)
	afterLocation := afterReplacement.content.locations[generatedContentKey{contract.GeneratorContentOutputConfiguration, stopped.OperationID}]
	if err != nil || imageErr != nil || !reflect.DeepEqual(afterGraph, graph) || !bytes.Equal(afterImage, image) || afterLocation.Logical() != location.Logical() {
		t.Fatal("key replacement changed accepted output commitment", err, imageErr)
	}
	for _, row := range f.selected.registry() {
		if row.RecipientID == reader && (row.CurrentBinding == nil || row.CurrentBinding.BindingID != binding.BindingID) {
			t.Fatal("reader successor did not remain selected")
		}
	}
	store := requireAdmittedMemoryStore(t, f.env.Store)
	writes, cas := store.creates, store.cas
	projection := reconstructProjectionFixture(t, f.env, f.selected, store)
	returned := reconstructionReturnedSession(t, projection, f.selected)
	// The oracle reads only complete support row bodies returned by the
	// source-bound reconstruction, rather than fetching the original blob.
	reconstructed, err := contract.InspectGeneratedImmutableSlice(f.env.Domain, returned.adminIndex.SliceSnapshot,
		returned.supportRecords(), afterLocation, contract.MaxOutputConfigurationBytes)
	if err != nil || !bytes.Equal(reconstructed, image) || store.creates != writes || store.cas != cas {
		t.Fatal("source-bound reconstruction lost pending kind8", err)
	}
	if currentCreates, currentDeletes := effects(); currentCreates != creates || currentDeletes != deletes {
		t.Fatal("replacement or reconstruction performed provider work")
	}
	// A different local proposal cannot change either accepted declaration.
	edited := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local-edit", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("unrelated")}}
	resumed := publicGeneratedOutputEngine(t, ctx, f, edited, &outputApplyInput{}, installedGeneratedTestCallbacks(t, f, process))
	continued := resumed.Continue(ctx, fixtureID(f.env.Domain, "pending output replacement continuation"), stopped.OperationID)
	resumed.Close()
	cold := f.open(t, ctx)
	if continued.Result.Outcome != ObservedCurrent || continued.RequestIdentity != stopped.RequestIdentity || !cold.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("pending continuation failed after replacement/reconstruction", continued.Result)
	}
	selectedEntry := cold.valueEntry(entrySlot(t, cold, "generated"))
	if selectedEntry.OutputEncoding != contract.OutputEncodingBase64 || !slices.Equal(selectedEntry.Recipients, members) {
		t.Fatal("continuation changed accepted memberships")
	}
	for _, row := range cold.registry() {
		if row.RecipientID == reader && row.CurrentBinding.BindingID != binding.BindingID {
			t.Fatal("accepted registry restored a replaced key")
		}
	}
	wantTarget := target.target
	wantTarget.EntryIncarnationID = selectedEntry.Incarnation
	want := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: f.env.Domain,
		Bindings: []contract.OutputBinding{{DestinationID: "app", IncarnationID: publicOutputApplyExpectedBinding(f.env.Domain, stopped.OperationID, "app"), Destination: output.bindings[0].destination,
			Targets: []contract.OutputTarget{wantTarget}}},
		Routes: []contract.OutputRoute{{EntryIncarnationID: selectedEntry.Incarnation, Destinations: []string{"app"}}}, Groups: [][]contract.ID{{selectedEntry.Incarnation}}}
	publicOutputApplyAssertConfiguration(t, installedOutputConfiguration(t, ctx, cold), want)
	if currentCreates, currentDeletes := effects(); currentCreates != creates || currentDeletes != deletes {
		t.Fatal("continuation repeated provider work")
	}
	publicOutputApplyAssertNoPublication(t, cold)
}
