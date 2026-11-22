package core

import (
	"bytes"
	"context"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func opaqueManifestFixture(t *testing.T, mode string) (*ReaderEngine, publicSelection, *fixture, fixtureEnvironment) {
	t.Helper()
	env := memoryScenarioEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	env.Context = ctx
	initial := newEnvironmentFixture(t, t.Context(), env, nil, false)
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: initial.admission, session: initial.session}
	// Retain the independently sealed source for later output-only selections.
	// The current stored secret is a canonical value, not a supplied envelope.
	entries := []ApplyEntryInput{sharingSecretNamed(t, env, "TOKEN", "opaque source bytes", []contract.ID{f.session.admission.recipient})}
	target := outputFixtureTarget("opaque-output", "channel:token", "", contract.OutputEncodingRaw, 63, contract.OutputPolicy{})
	target.LocatorRequiresCreation = true
	if mode == "deterministic" {
		target.ConsumerLocator, target.LocatorRequiresCreation = "channel:token/current", false
	}
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{{entryName: "TOKEN", target: target}}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}}
	f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
	f.session.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "opaque-output", physical: "channel:token", premise: fixtureID(env.Domain, "independent opaque namespace")}}
	f.admission = OpenContext{admission: &f.session.admission}
	configurationDigest := f.session.root.OutputConfiguration.ConfigurationDigest
	if mode != "no-birth" && mode != "deterministic" {
		p := newPublicationControlledPrivate()
		p.configureOwner = func(o *publicationControlledOwner) {
			o.resource, o.consumerLocator = "opaque-created-resource-17", "consumer:opaque-created-resource-17/current"
			if mode == "bad-resource" {
				o.resource, o.consumerLocator = "unrelated-resource", "consumer:unrelated-resource/current"
			}
			if mode == "unselected-close" {
				o.onSend = func() { f.store.casMode = "refused" }
			}
		}
		if mode == "unknown-create" {
			p.evidence = contract.PublicationUnproved
		}
		input := publicationInput{names: []string{"TOKEN"}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
		got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if len(p.owners) != 1 || p.owners[0].sent != 1 || len(got.output.Entries) != 1 {
			t.Fatal("creation fixture did not send exactly once", got)
		}
		f.store.casMode = ""
	}
	opened, result := Open(t.Context(), f.admission, f.store)
	if opened == nil {
		t.Fatal("cold opaque selected state", result)
	}
	f.session = opened
	if opened.root.OutputConfiguration.ConfigurationDigest != configurationDigest {
		t.Fatal("creation wrote desired configuration")
	}
	if mode == "readded-without-delete" {
		before, err := selectedPublicationRelation(opened.selectedImage())
		if err != nil || len(before.coordinates) != 1 {
			t.Fatal("original ownership before binding removal", err)
		}
		f.session = selectAdmittedOutputConfiguration(t, t.Context(), opened, env, env.Custody, entries, &outputApplyInput{})
		f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
		f.admission = OpenContext{admission: &f.session.admission}
		after, err := selectedPublicationRelation(f.session.selectedImage())
		if err != nil || len(after.coordinates) != 1 || len(after.markers) != len(before.markers) {
			t.Fatal("readded binding lost historical ownership", err)
		}
		for id, old := range before.coordinates {
			current := after.coordinates[id]
			if current.ActiveBindingIncarnationID == old.LastBindingIncarnationID || current.LastBindingIncarnationID != old.LastBindingIncarnationID || current.OwnedBirthAttemptID != old.OwnedBirthAttemptID || current.DeletionConsumerLocator != "consumer:opaque-created-resource-17/current" || !current.LastDeleteAckAttemptID.IsZero() {
				t.Fatal("binding replacement did not retain exact old ownership", current)
			}
		}
		opened = f.session
	}
	if mode == "unknown-delete" || mode == "deleted-readded" || mode == "delete-ack-same-binding" || mode == "new-birth-after-delete" {
		withdrawn := &outputApplyInput{}
		var originalBinding contract.ID
		if mode == "delete-ack-same-binding" {
			before, state := opened.currentOutputConfigurationForApply(t.Context())
			if state.Outcome != 0 || len(before.Bindings) != 1 || len(before.Bindings[0].Targets) != 1 {
				t.Fatal("same-binding deletion original configuration", state)
			}
			originalBinding = before.Bindings[0].IncarnationID
			// Keep the declared destination while removing its effective target and
			// every route. Readding the route must retain this exact binding.
			withdrawn.bindings = []outputApplyBinding{{destinationID: "app", destination: output.bindings[0].destination}}
		}
		f.session = selectAdmittedOutputConfiguration(t, t.Context(), opened, env, env.Custody, entries, withdrawn)
		if mode == "delete-ack-same-binding" {
			dormant, state := f.session.currentOutputConfigurationForApply(t.Context())
			if state.Outcome != 0 || len(dormant.Bindings) != 1 || dormant.Bindings[0].IncarnationID != originalBinding ||
				len(dormant.Bindings[0].Targets) != 0 || len(dormant.Routes) != 0 {
				t.Fatal("dormant declaration changed binding or retained targets/routes", state)
			}
		}
		f.admission = OpenContext{admission: &f.session.admission}
		coordinate, err := contract.PublicationCoordinateID(env.Domain, target.ServiceContractID, target.CanonicalTarget)
		if err != nil {
			t.Fatal(err)
		}
		p := newPublicationControlledPrivate()
		p.configureOwner = func(o *publicationControlledOwner) {
			o.resource, o.consumerLocator = "opaque-created-resource-17", "consumer:opaque-created-resource-17/current"
		}
		if mode == "unknown-delete" {
			p.evidence = contract.PublicationUnproved
		}
		input := publicationInput{deletes: []contract.ID{coordinate}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
		deletion := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if len(p.owners) != 1 || p.owners[0].sent != 1 || len(deletion.output.Entries) != 1 {
			t.Fatal("selected deletion did not enter", deletion)
		}
		f.session, _ = Open(t.Context(), f.admission, f.store)
		if f.session == nil {
			t.Fatal("cannot reopen selected deletion")
		}
		var disposed contract.PublicationCoordinate
		var deleteAttempt contract.ID
		if mode == "new-birth-after-delete" || mode == "delete-ack-same-binding" {
			if deletion.summary != contract.PublicationSummaryComplete || len(deletion.output.Entries[0].Actions) != 1 ||
				deletion.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged ||
				deletion.output.Entries[0].Actions[0].Action != contract.PublicationDeleteOwned {
				t.Fatal("creation proof control lacks acknowledged owned deletion", deletion)
			}
			deleteAttempt = deletion.output.Entries[0].Actions[0].AttemptID
			beforeExit := publicationEngineReopen(t, f)
			disposed = beforeExit.coordinates[coordinate]
			if disposed.OwnerState != contract.PublicationOwnerQualified || disposed.OwnedBirthAttemptID.IsZero() ||
				disposed.LastDeleteAckAttemptID != deleteAttempt || disposed.BindingState != contract.PublicationBindingRetired ||
				!disposed.ActiveBindingIncarnationID.IsZero() {
				t.Fatal("retired deletion lost exact old ownership and acknowledgement", disposed)
			}
		}
		if mode == "new-birth-after-delete" {
			entry := f.session.valueEntry(f.session.root.Names[0].Slot).Incarnation
			admin, state := openAdministrative(t.Context(), f.admission, f.store)
			if admin == nil || state.Outcome != ObservedCurrent {
				t.Fatal("new birth disposal admission", state)
			}
			candidate, state := prepareTestEndSelectedWork(t, admin, t.Context(), coordinate, f.trust)
			if candidate == nil || state.Outcome != ObservedCurrent {
				t.Fatal("new birth coordinate disposal preparation", state)
			}
			if selected, state := admin.selectCandidate(t.Context(), candidate); selected == nil || state.Outcome != ObservedCurrent {
				t.Fatal("new birth coordinate disposal selection", state)
			}
			afterExit := publicationEngineReopen(t, f)
			if len(afterExit.coordinates) != 0 || len(afterExit.markers) != 0 ||
				f.session.valueEntry(f.session.root.Names[0].Slot).Incarnation != entry {
				t.Fatal("coordinate disposal retained old proof or changed current entry")
			}
		}
		f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
		f.admission = OpenContext{admission: &f.session.admission}
		if mode == "delete-ack-same-binding" {
			restored := publicationEngineReopen(t, f)
			current := restored.coordinates[coordinate]
			birth := restored.markers[current.OwnedBirthAttemptID]
			ack := restored.markers[current.LastDeleteAckAttemptID]
			entry := f.session.valueEntry(f.session.root.Names[0].Slot).Incarnation
			if f.session.root.OutputConfiguration.ConfigurationDigest != configurationDigest ||
				current.BindingState != contract.PublicationBindingActive || current.ActiveBindingIncarnationID != originalBinding ||
				current.LastBindingIncarnationID != originalBinding || current.LastEntryIncarnationID != entry ||
				current.OwnerState != contract.PublicationOwnerQualified || current.OwnedBirthAttemptID != disposed.OwnedBirthAttemptID ||
				birth.Projection.BindingIncarnationID != originalBinding || birth.Projection.EntryIncarnationID != entry ||
				birth.Projection.TargetRowDigest != current.DeletionTargetRowDigest || birth.State != contract.PublicationAcknowledged ||
				birth.Evidence.Class != contract.PublicationRequestAcknowledged || birth.Evidence.SafeResourceID != "opaque-created-resource-17" ||
				current.LastDeleteAckAttemptID != deleteAttempt || ack.State != contract.PublicationAcknowledged ||
				ack.Evidence.Class != contract.PublicationRequestAcknowledged || ack.Projection.Action != contract.PublicationDeleteOwned ||
				ack.Projection.OwnedBirthAttemptID != birth.AttemptID || birth.PublicationIncarnationID != ack.PublicationIncarnationID ||
				ack.AdmissionOrdinal <= birth.AdmissionOrdinal || current.LastDeleteAckIncarnationID != ack.PublicationIncarnationID ||
				current.LastDeleteAckOrdinal != ack.AdmissionOrdinal {
				t.Fatal("delete ACK control lacks matching current binding, exact old birth or later acknowledged deletion", current, birth, ack)
			}
		}
		if mode == "new-birth-after-delete" {
			p = newPublicationControlledPrivate()
			p.configureOwner = func(o *publicationControlledOwner) {
				o.resource, o.consumerLocator = "opaque-created-resource-28", "consumer:opaque-created-resource-28/current"
			}
			input = publicationInput{names: []string{"TOKEN"}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
			creation := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			if creation.summary != contract.PublicationSummaryComplete || len(p.owners) != 1 || p.owners[0].sent != 1 ||
				len(creation.output.Entries) != 1 || len(creation.output.Entries[0].Actions) != 1 ||
				creation.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged ||
				creation.output.Entries[0].Actions[0].Evidence.SafeResourceID != "opaque-created-resource-28" ||
				creation.output.Entries[0].Actions[0].AttemptID == disposed.OwnedBirthAttemptID ||
				creation.output.Entries[0].Actions[0].AttemptID == deleteAttempt {
				t.Fatal("new selected birth failed", creation)
			}
			f.session, _ = Open(t.Context(), f.admission, f.store)
			if f.session == nil {
				t.Fatal("cannot reopen new selected birth")
			}
			newRelation := publicationEngineReopen(t, f)
			newCoordinate := newRelation.coordinates[coordinate]
			if newCoordinate.OwnerState != contract.PublicationOwnerQualified ||
				newCoordinate.OwnedBirthAttemptID != creation.output.Entries[0].Actions[0].AttemptID ||
				newCoordinate.ActiveBindingIncarnationID == disposed.LastBindingIncarnationID ||
				newCoordinate.CurrentPublicationIncarnationID == disposed.CurrentPublicationIncarnationID ||
				!newCoordinate.LastDeleteAckAttemptID.IsZero() {
				t.Fatal("new birth reused disposed ownership or deletion proof", newCoordinate)
			}
		}
		opened = f.session
	}
	if mode == "encoding-change" {
		output.bindings[0].targets[0].target.PayloadEncoding = contract.OutputEncodingBase64
		f.session = selectAdmittedOutputConfiguration(t, t.Context(), opened, env, env.Custody, entries, output)
		f.admission = OpenContext{admission: &f.session.admission}
		if f.session.root.OutputConfiguration.ConfigurationDigest == configurationDigest {
			t.Fatal("encoding change did not change desired configuration")
		}
		opened = f.session
	}
	e, _, _ := readerEngineFixture(t, env, opened)
	inv, failure := e.beginReaderInvocation(env.operationContext(), contract.ReaderManifestOperation, fixtureID(env.Domain, "opaque manifest request"))
	if failure.Outcome != 0 {
		t.Fatal(failure)
	}
	t.Cleanup(inv.Close)
	selection, failure := inv.loadPublicSelection(env.operationContext(), contract.ReaderManifestOperation, inv.admission.request, nil)
	if failure.Outcome != 0 {
		t.Fatal("complete opaque selected observation", failure)
	}
	for _, page := range selection.image.support {
		if len(page.Records) != 0 {
			t.Fatal("Reader retained support bodies")
		}
	}
	return e, selection, f, env
}

// full_only: false
func TestPublicationReservesSpaceForAssignedLocator(t *testing.T) {
	_, _, f, _ := opaqueManifestFixture(t, "no-birth")
	locator := strings.Repeat("l", 1024)
	var coordinateID contract.ID
	var promised uint64
	private := newPublicationControlledPrivate()
	private.configureOwner = func(owner *publicationControlledOwner) {
		owner.resource, owner.consumerLocator = "created-resource", locator
		owner.onSend = func() {
			pending, result := Open(t.Context(), f.admission, f.store)
			if pending == nil {
				t.Fatal("open selected reservation", result)
			}
			relation, err := selectedPublicationRelation(pending.selectedImage())
			if err != nil || len(relation.coordinates) != 1 {
				t.Fatal("selected publication coordinate", err)
			}
			plan, err := pending.planPublicationRewrite(t.Context(), pending.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			for id, coordinate := range relation.coordinates {
				coordinateID = id
				body, err := contract.EncodePublicationCoordinate(coordinate)
				promised = plan.widths[generatedRecordKey{contract.PublicationCoordinateSupportKind, id}]
				if err != nil || !coordinate.LocatorRequiresCreation || coordinate.DeletionConsumerLocator != "" || promised != uint64(37+len(body)+1024) {
					t.Fatal("pending coordinate did not reserve its assigned locator", promised, err)
				}
			}
		}
	}
	input := publicationInput{names: []string{"TOKEN"}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	publicationEnginePlan(t, f, input, private).execute(t.Context(), private.callbacks(), publicationEngineCurrent(f))
	cold, result := Open(t.Context(), f.admission, f.store)
	if cold == nil {
		t.Fatal("reopen after receiving the assigned locator", result)
	}
	relation, err := selectedPublicationRelation(cold.selectedImage())
	if err != nil || coordinateID.IsZero() || len(private.owners) != 1 || private.owners[0].sent != 1 {
		t.Fatal("assigned locator did not finish one send", err)
	}
	coordinate := relation.coordinates[coordinateID]
	body, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil || coordinate.DeletionConsumerLocator != locator || uint64(37+len(body)) != promised {
		t.Fatal("selected locator width differs from its reservation", len(body), promised, err)
	}
}

// full_only: false
func TestManifestOpaqueServiceBoundaryRequiresOnlyAssignedCreationProof(t *testing.T) {
	for _, mode := range []string{"deterministic", "qualified", "readded-without-delete", "encoding-change", "unknown-delete", "deleted-readded", "delete-ack-same-binding", "new-birth-after-delete", "no-birth", "unknown-create", "unselected-close", "bad-resource"} {
		t.Run(mode, func(t *testing.T) {
			engine, selected, f, env := opaqueManifestFixture(t, mode)
			creates, cas := f.store.creates, f.store.cas
			public, private := env.Custody.Calls()
			service := "opaque-output"
			got, failure := manifestSelectionForTest(env.operationContext(), selected, contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: f.session.admission.recipient, EntryNames: []string{"TOKEN"}, ServiceFilter: &service})
			valid := mode == "deterministic" || mode == "qualified" || mode == "encoding-change" || mode == "new-birth-after-delete" || mode == "bad-resource"
			if valid {
				want := "consumer:opaque-created-resource-17/current"
				if mode == "bad-resource" {
					want = "consumer:unrelated-resource/current"
				}
				if mode == "deterministic" {
					want = "channel:token/current"
				}
				if mode == "new-birth-after-delete" {
					want = "consumer:opaque-created-resource-28/current"
				}
				if failure.Outcome != 0 || got == nil || len(got.Entries) != 1 || len(got.Entries[0].Destinations) != 1 || got.Entries[0].Destinations[0].ConsumerLocator != want {
					t.Fatal("opaque consumer meaning", got, failure)
				}
				if mode == "encoding-change" && got.Entries[0].Destinations[0].PayloadEncoding != contract.OutputEncodingBase64 {
					t.Fatal("current encoding lost through frozen birth")
				}
			} else if got != nil || failure.diagnostic != contract.ReasonLocatorUnusable {
				t.Fatal("unselected/unqualified creation emitted artifact", got, failure)
			}
			if mode == "qualified" || mode == "readded-without-delete" || mode == "unknown-delete" {
				inspection, _, failed := projectInspectionOutput(env.operationContext(), &selected)
				if failed.Outcome != 0 || len(inspection.CurrentTargets) != 1 {
					t.Fatal("inspection of retained birth", inspection, failed)
				}
				row := inspection.CurrentTargets[0]
				if mode == "qualified" {
					if row.LocatorBasis != InspectionQualifiedBirth || row.ResolvedConsumerLocator == nil || *row.ResolvedConsumerLocator != "consumer:opaque-created-resource-17/current" {
						t.Fatal("inspection lost current binding birth locator", row)
					}
				} else if row.LocatorBasis == InspectionQualifiedBirth || row.ResolvedConsumerLocator != nil {
					t.Fatal("inspection inherited old binding locator", row)
				}
				if mode == "unknown-delete" {
					if len(inspection.Coordinates) != 1 || len(inspection.Markers) != 2 || len(inspection.CurrentBlockers) != 1 || len(inspection.CurrentBlockers[0].MarkerIndexes) != 1 {
						t.Fatal("unknown deletion lost exact retained history or blockers", inspection)
					}
					coordinate := inspection.Coordinates[0]
					marker := inspection.Markers[inspection.CurrentBlockers[0].MarkerIndexes[0]]
					if coordinate.ActiveBindingIncarnationID == coordinate.LastBindingIncarnationID || coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedBirthAttemptID.IsZero() || !coordinate.LastDeleteAckAttemptID.IsZero() || coordinate.DeletionConsumerLocator != "consumer:opaque-created-resource-17/current" || marker.State != contract.PublicationUnknown || marker.Projection.Action != contract.PublicationDeleteOwned || marker.Projection.OwnedBirthAttemptID != coordinate.OwnedBirthAttemptID {
						t.Fatal("unknown delete proved absence or replaced historical ownership", coordinate, marker)
					}
				}
				engine.validator = NewPublicConfigurationValidator(f.session.admission.outputInterpreter)
				actual, failed := engine.projectPublicConfiguration(env.operationContext(), selected)
				if failed.Outcome != 0 || !actual.Valid || !actual.Complete {
					t.Fatal("public declaration before binding preview", failed)
				}
				preview, _, failed := engine.projectPublicationPreview(env.operationContext(), &selected, actual, actual)
				if failed.Outcome != 0 || !preview.Complete || len(preview.Entries) != 1 {
					t.Fatal("binding preview incomplete", preview, failed)
				}
				locator := preview.Entries[0].ConsumerLocator
				if mode == "qualified" && (locator == nil || *locator != "consumer:opaque-created-resource-17/current") || mode != "qualified" && locator != nil {
					t.Fatal("preview inherited another binding locator", preview.Entries[0])
				}
				if mode == "unknown-delete" && (preview.Entries[0].Basis != "blocked" || len(preview.Entries[0].BlockerIDs) != 1 || preview.Entries[0].BlockerIDs[0] != inspection.Markers[inspection.CurrentBlockers[0].MarkerIndexes[0]].AttemptID || !preview.Entries[0].RemoteValueMayRemain) {
					t.Fatal("preview lost unresolved deletion or possible remote ownership", preview.Entries[0])
				}
				issuer, _, _ := readerEngineFixture(t, env, f.session)
				issuer.validator = NewPublicConfigurationValidator(f.session.admission.outputInterpreter)
				issued := issuer.Manifest(env.operationContext(), fixtureID(env.Domain, "binding manifest issuance"), hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: f.session.admission.recipient, EntryNames: []string{"TOKEN"}}))
				if mode == "qualified" {
					if issued.StateResult != contract.ReaderSuccess || issued.Artifact == nil {
						t.Fatal("current binding manifest issuance refused", issued.StateResult, issued.FailureReason)
					}
				} else if issued.Artifact != nil || issued.Payload != nil || issued.StateResult != contract.ReaderRefused {
					t.Fatal("old binding produced a complete or partial artifact", issued.StateResult)
				}
			}
			if f.store.creates != creates || f.store.cas != cas {
				t.Fatal("Reader wrote publication/configuration")
			}
			if p, q := env.Custody.Calls(); p != public || q != private {
				t.Fatal("Reader used private custody")
			}
		})
	}
}

// full_only: false
func TestManifestAssignedLocatorRereadsOnlyFixedImmutableBirthProof(t *testing.T) {
	for _, mode := range []string{"fixed-head", "missing-coordinate", "damaged-birth", "wrong-record-id", "wrong-row-digest", "wrong-root", "wrong-index", "wrong-current-binding", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			_, selected, f, env := opaqueManifestFixture(t, "qualified")
			coordinateID, _ := contract.PublicationCoordinateID(env.Domain, "opaque-output", "channel:token")
			key := generatedRecordKey{kind: contract.PublicationCoordinateSupportKind, id: coordinateID}
			coordinateProof := selected.image.publicationProof.rows[key]
			coordinateObject, err := format.Key(f.store.Descriptor().Prefix, coordinateProof.ref)
			if err != nil {
				t.Fatal(err)
			}
			var birthProof selectedPublicationRowProof
			for key, row := range selected.image.publicationProof.rows {
				if key.kind == contract.PublicationMarkerSupportKind {
					birthProof = row
				}
			}
			birthObject, err := format.Key(f.store.Descriptor().Prefix, birthProof.ref)
			if err != nil {
				t.Fatal(err)
			}
			ctx := env.operationContext()
			binding := contract.ID{}
			if mode == "wrong-record-id" {
				row := selected.image.publicationProof.rows[key]
				delete(selected.image.publicationProof.rows, key)
				key.id[0] ^= 1
				selected.image.publicationProof.rows[key] = row
			}
			if mode == "wrong-row-digest" {
				row := selected.image.publicationProof.rows[key]
				row.bodyDigest[0] ^= 1
				selected.image.publicationProof.rows[key] = row
			}
			if mode == "wrong-root" {
				selected.image.publicationProof.rootDigest[0] ^= 1
			}
			if mode == "wrong-index" {
				selected.image.publicationProof.indexRef.Digest[0] ^= 1
			}
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			reads := 0
			f.store.readHook = func(object string, read contract.ReadResult) contract.ReadResult {
				if object == f.store.Descriptor().HeadKey {
					t.Fatal("locator read a replacement HEAD")
				}
				if object == coordinateObject || object == birthObject {
					reads++
				}
				if mode == "missing-coordinate" && object == coordinateObject {
					return contract.ReadResult{Status: contract.ReadMissing}
				}
				if mode == "damaged-birth" && object == birthObject {
					read.Body = bytes.Clone(read.Body)
					read.Body[0] ^= 1
				}
				return read
			}
			defer func() { f.store.readHook = nil }()
			var got *manifestsdk.Projection
			var failed readerFailure
			if mode == "wrong-current-binding" {
				_, failed = manifestConsumerLocators(ctx, selected, []manifestLocatorRequest{{binding: binding,
					target: contract.OutputTarget{EntryIncarnationID: f.session.valueEntry(f.session.root.Names[0].Slot).Incarnation, ServiceContractID: "opaque-output", TargetContractID: "fixture/target/v1", CanonicalTarget: "channel:token", TargetData: []byte("target:channel:token"), LocatorRequiresCreation: true, PayloadEncoding: contract.OutputEncodingRaw}}})
			} else {
				got, failed = manifestSelectionForTest(ctx, selected, contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: f.session.admission.recipient, EntryNames: []string{"TOKEN"}})
			}
			if mode == "fixed-head" {
				if failed.Outcome != 0 || got == nil || reads < 2 {
					t.Fatal("fixed immutable reread", got, failed, reads)
				}
			} else if failed.Outcome == 0 || got != nil {
				t.Fatal("untrusted immutable record accepted", got, failed)
			}
		})
	}
}
