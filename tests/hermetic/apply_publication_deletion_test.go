package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestApplyPublicationLateRetainedDeletionConflictKeepsWholeVector(t *testing.T) {
	f, env, selection, base, staging := nativePublicationFixture(t, false)
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), 2*time.Minute)
	defer cancel()
	created := installedPublicationEngine(t, f, base, recorder).Publish(ctx, fixtureID(env.Domain, "retired deletion birth"), PublicationRequest{Names: selection.names})
	assertInstalledPublicationVector(t, created, contract.PublicationSummaryComplete, 1)
	assertNativePublicationJoined(t, recorder, staging, 1)
	retired, birth := created.Output.Entries[0].CoordinateID, created.Output.Entries[0].Actions[0].AttemptID
	publicationEngineReopen(t, f)
	// The independent coordinate hash helper fixes the live write before the
	// retained delete. Completion order cannot change the requested vector order.
	slot := publicationScenarioOrderedSlot(t, env.Domain, "plain-target-live-", []string{"plain-target"}, false)
	entries := []ApplyEntryInput{{Name: "live", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.session.admission.recipient}, InputBytes: []byte("private data")}}
	output := nativePublicationOutput(entries, []uint64{1, 9})
	hermeticRetargetOutput(&output.bindings[0].targets[0].target, slot, slot)
	f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
	f.admission = OpenContext{admission: &f.session.admission}
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil || selected.coordinates[retired].BindingState != contract.PublicationBindingRetired || selected.coordinates[retired].OwnedBirthAttemptID != birth {
		t.Fatal("source removal lost exact retained deletion inputs", err)
	}
	private := base
	original := private.NewOwner
	owners, retiredOwners := 0, 0
	concurrentDelete := contract.ID{}
	private.NewOwner = func(callctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
		owners++
		if owners != 1 || input.Projection.Action != contract.PublicationCreateWithValue {
			t.Fatal("changed retained relation reached another private owner")
		}
		owner, err := original(callctx, input)
		if err != nil {
			return nil, err
		}
		return &publicationBetweenActionsOwner{publicationPrivateOwner: owner, afterRetire: func() {
			retiredOwners++
			publicationEngineReopen(t, f)
			deleted := installedPublicationEngine(t, f, base, recorder).Publish(ctx, fixtureID(env.Domain, "independent retained deletion"), PublicationRequest{DeleteCoordinates: []contract.ID{retired}})
			assertInstalledPublicationVector(t, deleted, contract.PublicationSummaryComplete, 1)
			row := deleted.Output.Entries[0].Actions[0]
			if row.Action != contract.PublicationDeleteOwned || row.Disposition != contract.PublicationOutcomeAcknowledged {
				t.Fatal("controlled independent deletion did not select its exact acknowledgement")
			}
			concurrentDelete = row.AttemptID
			publicationEngineReopen(t, f)
		}}, nil
	}
	a := publicPublicationApplyFixture(env, f)
	input := installedApplyCurrentInput(f.session)
	apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
	joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "retained deletion combined apply"), fixtureID(env.Domain, "retained deletion combined publication"), input, installedPublicationEngine(t, f, private, recorder), nil)
	result := applyPublicationAssertStage(t, joined, contract.PublicationSummaryMixedTerminal, 2)
	if owners != 1 || retiredOwners != 1 || concurrentDelete.IsZero() || result.Output.Entries[0].CoordinateID == retired || result.Output.Entries[1].CoordinateID != retired {
		t.Fatal("retained deletion conflict did not occur after the first acknowledged write", owners, retiredOwners)
	}
	first, later := result.Output.Entries[0].Actions, result.Output.Entries[1].Actions
	if len(first) != 1 || first[0].Action != contract.PublicationCreateWithValue || first[0].Disposition != contract.PublicationOutcomeAcknowledged ||
		len(later) != 1 || later[0].Action != contract.PublicationDeleteOwned || later[0].Disposition != contract.PublicationNotSent || !later[0].AttemptID.IsZero() || later[0].CoreReason != uint16(DifferentSelection) {
		t.Fatal("deletion conflict lost fixed action rows or invented a new delete")
	}
	after := publicationEngineReopen(t, f)
	if after.coordinates[retired].OwnedBirthAttemptID != birth || after.coordinates[retired].LastDeleteAckAttemptID != concurrentDelete {
		t.Fatal("combined refusal rewrote independent selected deletion evidence")
	}
	assertNativePublicationJoined(t, recorder, staging, 2)
}
