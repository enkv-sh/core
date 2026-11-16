package core

import (
	"context"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestManifestAssignedLocatorFinishesOutputStreamBeforeBorrowedStoreReuse(t *testing.T) {
	_, selected, f, env := opaqueManifestFixture(t, "qualified")
	publicationRefs := make(map[format.Ref]bool)
	for _, proof := range selected.image.publicationProof.rows {
		publicationRefs[proof.ref] = true
	}
	outputPages := 0
	for _, page := range selected.image.supportFacts {
		for _, row := range page.rows {
			if row.Kind() == contract.OutputConfigurationSliceSupportKind {
				outputPages++
				if publicationRefs[page.ref] {
					t.Fatal("fixture must put publication records outside the output slice page")
				}
			}
		}
	}
	if outputPages == 0 {
		t.Fatal("fixture has no output slice")
	}
	// Capacity covers every admitted page, so every subsequent successful GET
	// replaces the same backing, including an output slice with unread routes.
	reused := &reusedProjectionReadSource{store: f.store, backing: make([]byte, 0, contract.MaxRequiredSupportPageLength)}
	selected.basis.reader.source, selected.basis.reader.cache = reused, nil
	creates, cas := f.store.creates, f.store.cas
	public, private := env.Custody.Calls()
	got, failed := manifestSelectionForTest(env.operationContext(), selected, contract.ManifestRequest{
		TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames,
		TargetRecipientID: f.session.admission.recipient, EntryNames: []string{"TOKEN"},
	})
	if failed.Outcome != 0 || got == nil || len(got.Entries) != 1 || len(got.Entries[0].Destinations) != 1 {
		t.Fatal("assigned locator lost the authenticated output stream under Store buffer reuse", got, failed, reused.reuseCount)
	}
	destination := got.Entries[0].Destinations[0]

	if got.Entries[0].Name != "TOKEN" || destination.DestinationID != "app" || destination.ConsumerLocator != "consumer:opaque-created-resource-17/current" || destination.PayloadEncoding != contract.OutputEncodingRaw || destination.PolicyPresent || destination.PolicyContractID != "" || len(destination.PolicyData) != 0 || !destination.PolicyDigest.IsZero() {
		t.Fatal("independent manifest fields changed under Store buffer reuse", got)
	}
	if reused.reuseCount == 0 {
		t.Fatal("Store did not reuse its read buffer")
	}
	if f.store.creates != creates || f.store.cas != cas {
		t.Fatal("manifest wrote selected state")
	}
	if p, q := env.Custody.Calls(); p != public || q != private {
		t.Fatal("manifest used private custody")
	}
}

// full_only: false
func TestManifestAssignedLocatorsReadEachImmutablePageOncePerPhase(t *testing.T) {
	rows := []struct{ name, slot, resource, locator string }{
		{"TOKEN0", "channel:token0", "opaque-created-resource-0", "consumer:opaque-created-resource-0/current"},
		{"TOKEN1", "channel:token1", "opaque-created-resource-1", "consumer:opaque-created-resource-1/current"},
		{"TOKEN2", "channel:token2", "opaque-created-resource-2", "consumer:opaque-created-resource-2/current"},
		{"TOKEN3", "channel:token3", "opaque-created-resource-3", "consumer:opaque-created-resource-3/current"},
		{"TOKEN4", "channel:token4", "opaque-created-resource-4", "consumer:opaque-created-resource-4/current"},
		{"TOKEN5", "channel:token5", "opaque-created-resource-5", "consumer:opaque-created-resource-5/current"},
		{"TOKEN6", "channel:token6", "opaque-created-resource-6", "consumer:opaque-created-resource-6/current"},
		{"TOKEN7", "channel:token7", "opaque-created-resource-7", "consumer:opaque-created-resource-7/current"},
	}
	env := memoryScenarioEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	env.Context = ctx
	initial := newEnvironmentFixture(t, t.Context(), env, nil, false)
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: initial.admission, session: initial.session}
	entries := make([]ApplyEntryInput, len(rows))
	names := make([]string, len(rows))
	targets := make([]outputApplyTarget, len(rows))
	namespaces := make([]publicationNamespace, len(rows))
	for index, row := range rows {
		names[index] = row.name
		entries[index] = sharingSecretNamed(t, env, row.name, "opaque source bytes", []contract.ID{f.session.admission.recipient})
		target := outputFixtureTarget("opaque-output", row.slot, "", contract.OutputEncodingRaw, 63, contract.OutputPolicy{})
		target.LocatorRequiresCreation = true
		targets[index] = outputApplyTarget{entryName: row.name, target: target}
		namespaces[index] = publicationNamespace{domain: env.Domain, service: "opaque-output", physical: row.slot,
			premise: fixtureID(env.Domain, "independent opaque namespace "+row.slot)}
	}
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: targets}},
		routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}}
	f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
	f.session.admission.publicationNamespaces = namespaces
	f.admission = OpenContext{admission: &f.session.admission}
	desiredDigest := f.session.root.OutputConfiguration.ConfigurationDigest
	p := newPublicationControlledPrivate()
	p.configureOwner = func(owner *publicationControlledOwner) {
		for _, row := range rows {
			if owner.input.Target.CanonicalTarget == row.slot {
				owner.resource, owner.consumerLocator = row.resource, row.locator
				return
			}
		}
		t.Fatal("unexpected controlled creation slot", owner.input.Target.CanonicalTarget)
	}
	input := publicationInput{names: names, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	created := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if created.summary != contract.PublicationSummaryComplete || len(created.output.Entries) != len(rows) || len(p.owners) != len(rows) {
		t.Fatal("packed selected creation fixture", created)
	}
	for _, owner := range p.owners {
		if owner.sent != 1 {
			t.Fatal("creation owner did not send exactly once", owner.sent)
		}
	}
	opened, result := Open(t.Context(), f.admission, f.store)
	if opened == nil || opened.root.OutputConfiguration.ConfigurationDigest != desiredDigest {
		t.Fatal("cold selected creation changed desired configuration", result)
	}
	f.session = opened
	e, _, _ := readerEngineFixture(t, env, opened)
	inv, failed := e.beginReaderInvocation(env.operationContext(), contract.ReaderManifestOperation, fixtureID(env.Domain, "packed opaque manifest request"))
	if failed.Outcome != 0 {
		t.Fatal(failed)
	}
	t.Cleanup(inv.Close)
	selected, failed := inv.loadPublicSelection(env.operationContext(), contract.ReaderManifestOperation, inv.admission.request, nil)
	if failed.Outcome != 0 {
		t.Fatal("complete packed publication selection", failed)
	}
	for _, page := range selected.image.support {
		if len(page.Records) != 0 {
			t.Fatal("Reader retained support bodies")
		}
	}
	coordinateRefs, birthRefs := make(map[format.Ref]bool), make(map[format.Ref]bool)
	for _, row := range rows {
		id, err := contract.PublicationCoordinateID(env.Domain, "opaque-output", row.slot)
		if err != nil {
			t.Fatal(err)
		}
		proof, present := selected.image.publicationProof.rows[generatedRecordKey{kind: contract.PublicationCoordinateSupportKind, id: id}]
		if !present {
			t.Fatal("missing real selected coordinate proof", row.slot)
		}
		coordinateRefs[proof.ref] = true
	}
	for _, entry := range created.output.Entries {
		if len(entry.Actions) != 1 || entry.Actions[0].Action != contract.PublicationCreateWithValue || entry.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
			t.Fatal("fixture did not select an acknowledged creation", entry)
		}
		proof, present := selected.image.publicationProof.rows[generatedRecordKey{kind: contract.PublicationMarkerSupportKind, id: entry.Actions[0].AttemptID}]
		if !present {
			t.Fatal("missing real selected birth proof", entry)
		}
		birthRefs[proof.ref] = true
	}
	if len(coordinateRefs) >= len(rows) || len(birthRefs) >= len(rows) {
		t.Fatal("fixture does not pack multiple coordinates and births together", len(coordinateRefs), len(birthRefs))
	}
	expectedReads := make(map[string]int)
	for _, refs := range []map[format.Ref]bool{coordinateRefs, birthRefs} {
		for ref := range refs {
			key, err := format.Key(f.store.Descriptor().Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			expectedReads[key]++
		}
	}
	reads := make(map[string]int)
	f.store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
		if key == f.store.Descriptor().HeadKey {
			t.Fatal("locator reread HEAD")
		}
		if expectedReads[key] != 0 {
			reads[key]++
		}
		return read
	}
	t.Cleanup(func() { f.store.readHook = nil })
	selected.basis.reader.cache = nil
	creates, cas := f.store.creates, f.store.cas
	public, private := env.Custody.Calls()
	got, failed := manifestSelectionForTest(env.operationContext(), selected, contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: opened.admission.recipient, EntryNames: names})
	if failed.Outcome != 0 || got == nil || len(got.Entries) != len(rows) {
		t.Fatal("packed assigned manifest", got, failed)
	}
	for index, row := range rows {
		entry := got.Entries[index]
		if entry.Name != row.name || len(entry.Destinations) != 1 || entry.Destinations[0].ConsumerLocator != row.locator || entry.Destinations[0].DestinationID != "app" {
			t.Fatal("independent packed consumer locator", entry, row.locator)
		}
	}
	for key, maximum := range expectedReads {
		if reads[key] == 0 || reads[key] > maximum {
			t.Fatalf("immutable locator page GETs=%d; want 1..%d for %s", reads[key], maximum, key)
		}
	}
	if f.store.creates != creates || f.store.cas != cas {
		t.Fatal("manifest wrote selected state")
	}
	if p, q := env.Custody.Calls(); p != public || q != private {
		t.Fatal("manifest used private custody")
	}
}
