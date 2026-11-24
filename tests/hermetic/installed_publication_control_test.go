package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledCombinedPublicationRetainsApplyWhenDeletionSupportIsUnavailable(t *testing.T) {
	for _, support := range []string{"matching", "missing", "wrong-contract"} {
		t.Run(support, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			entries := []ApplyEntryInput{
				{Name: "old-output", Recipients: []contract.ID{f.selected.admission.recipient}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Plain, ValueSource: contract.Supplied, InputBytes: []byte("published value")},
				{Name: "unrelated", Recipients: []contract.ID{f.selected.admission.recipient}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Plain, ValueSource: contract.Supplied, InputBytes: []byte("before")},
			}
			target := hermeticNativeOutputTarget("retained-slot", "retained-slot", contract.OutputEncodingRaw, contract.OutputPolicy{})
			f.selected = selectAdmittedOutputConfiguration(t, ctx, f.selected, f.env, f.keys, entries, &outputApplyInput{
				bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{{entryName: entries[0].Name, target: target}}}},
				routes:   []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{"publication"}}},
			})
			f.admitted = OpenContext{admission: &f.selected.admission}
			fixture := &fixture{store: requireAdmittedMemoryStore(t, f.env.Store), trust: f.env.Trust.(*fixtureTrust), admission: f.admitted, session: f.selected}
			private := newPublicationControlledPrivate()
			created := installedPublicationEngine(t, fixture, private.callbacks()).Publish(ctx, fixtureID(f.env.Domain, "combined original birth"), PublicationRequest{Names: []string{entries[0].Name}})
			assertInstalledPublicationVector(t, created, contract.PublicationSummaryComplete, 1)
			birth := created.Output.Entries[0].Actions[0]
			coordinate := created.Output.Entries[0].CoordinateID
			if birth.Action != contract.PublicationCreateWithValue || birth.Disposition != contract.PublicationOutcomeAcknowledged || len(private.owners) != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 1 {
				t.Fatal("exact acknowledged birth fixture unavailable")
			}
			f.selected = f.open(t, ctx)
			fixture.session = f.selected
			entries[1].InputBytes = []byte("after")
			validator := NewPublicConfigurationValidator(f.selected.admission.outputInterpreter)
			recipients := currentApplyRecipients(f.selected.registry())
			configuration := installedApplyTestConfiguration(t, ctx, f.selected, entries, recipients, validator)
			configuration.OutputBindings = observedPublicField([]contract.PublicOutputBinding{})
			configuration.Routing = observedPublicField([]contract.PublicRoutingRule{})
			configuration.Groups = observedPublicField([][]string{})
			file := fixtureID(f.env.Domain, "combined removal source")
			engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis,
				ExpectedControl: currentControlOf(f.selected), DesiredRecipients: recipients, PublicConfiguration: configuration, ConfigurationValidator: validator,
				Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: file, CloseInstalled: func() {},
				AdmitCustody: func(ctx context.Context, request contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warning uint8, deadline time.Time) (*InstalledApplyCustody, error) {
					owner, err := f.keys.NewApplyCustody(request, control, current, file, plain, support, witness, revision, before, warning, deadline)
					if err != nil {
						return nil, err
					}
					return &InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
				}})
			if err != nil {
				t.Fatal("combined removal apply installation refused", err)
			}
			defer engine.Close()
			later := newPublicationControlledPrivate()
			callbacks := later.callbacks()
			if support == "wrong-contract" {
				actions := callbacks.Actions
				callbacks.Actions = func(ctx context.Context, input publicationExecutionInput) (publicationActionFacts, error) {
					facts, err := actions(ctx, input)
					if !input.DeleteCoordinate.IsZero() {
						facts.ConfigContractDigest = fixtureID(f.env.Domain, "wrong deletion contract")
					}
					return facts, err
				}
			}
			var publisher *InstalledPublication
			if support != "missing" {
				publisher = installedPublicationEngine(t, fixture, callbacks)
			}
			request, publication := fixtureID(f.env.Domain, "combined apply "+support), fixtureID(f.env.Domain, "combined publication "+support)
			result := engine.ApplyAndPublish(ctx, request, publication, entries, publisher, nil)
			if result.Apply.RequestID != request || result.Apply.Result.Outcome != ObservedCurrent || result.Apply.Result.CommitMayHaveOccurred || result.Apply.OperationID.IsZero() || result.Apply.RequestIdentity.IsZero() || len(result.Apply.Receipt) == 0 {
				t.Fatal("publication support prevented or erased the completed apply", result.Apply.Result)
			}
			selected := f.open(t, ctx)
			entry := selectedPlanningEntry(selected.selectedImage(), "unrelated")
			facts, err := selectedPublicationRelation(selected.selectedImage())
			retained := facts.coordinates[coordinate]
			if err != nil || entry == nil || !bytes.Equal(entry.ValueBytes, []byte("after")) || selected.root.OutputConfiguration.BindingCount != 0 || retained.BindingState != contract.PublicationBindingRetired || retained.OwnedBirthAttemptID != birth.AttemptID {
				t.Fatal("cold state lost the completed change or retained birth", err)
			}
			if support == "missing" {
				if result.Publication.Stage != "unstarted" || result.Publication.Reason != "selection-unavailable" || result.Publication.Result != nil || len(later.owners) != 0 {
					t.Fatal("missing support invented publication completion", result.Publication)
				}
				return
			}
			if result.Publication.Stage != "evaluated" || result.Publication.Result == nil || result.Publication.Result.RequestID != publication {
				t.Fatal("publication did not retain its separately admitted result", result.Publication)
			}
			if support == "wrong-contract" {
				if result.Publication.Result.Result.Outcome != AdmissionRefused || result.Publication.Result.Output != nil || len(later.owners) != 0 || !retained.LastDeleteAckAttemptID.IsZero() {
					t.Fatal("wrong deletion contract granted an effect or erased apply")
				}
				return
			}
			assertInstalledPublicationVector(t, *result.Publication.Result, contract.PublicationSummaryComplete, 1)
			deleted := result.Publication.Result.Output.Entries[0]
			if deleted.CoordinateID != coordinate || len(deleted.Actions) != 1 || deleted.Actions[0].Action != contract.PublicationDeleteOwned || deleted.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || retained.LastDeleteAckAttemptID != deleted.Actions[0].AttemptID || len(later.owners) != 1 || later.owners[0].sent != 1 || later.owners[0].retired != 1 {
				t.Fatal("combined publication did not delete the exact retained birth once")
			}
		})
	}
}
