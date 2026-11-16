package core

import (
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

// full_only: false
func TestApplyPublicationIndependentActiveOwnerAfterCaptureStartsNoAction(t *testing.T) {
	f, env, _, private, staging := nativePublicationFixture(t, true)
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
	defer cancel()
	env.Context = ctx
	captureStore := &installedPublicationCaptureStore{memoryStore: f.store, capture: recorder}
	env.Store = captureStore
	input := installedApplyCurrentInput(f.session)
	for i := range input {
		if input[i].Name == "secret" {
			input[i] = suppliedSecret(t, env, "secret", "completed apply before independent owner", custody.AlternateStandardValue, f.session.admission.recipient)
		}
	}
	a := publicPublicationApplyFixture(env, f)
	engine := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
	engine.installation.Store = captureStore
	admitCustody := engine.installation.AdmitCustody
	beforeCAS := f.store.cas
	operation := fixtureID(env.Domain, "independent owner after combined capture")
	var appliedRevision, ownerRevision contract.ID
	var selectedOwner *StateSession
	var ownerWork []contract.SupportRecordDigest
	engine.installation.AdmitCustody = func(callctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
		owner, err := admitCustody(callctx, q, control, current, plain, support, witness, revision, before, warningBits, deadline)
		if err != nil || owner == nil {
			return owner, err
		}
		closeOwner := owner.Close
		owner.Close = func() {
			closeOwner()
			recorder.collect()
			if selectedOwner != nil || f.store.cas != beforeCAS+1 {
				t.Fatal("independent owner cut did not follow exactly one completed apply selection")
			}
			current, state := Open(callctx, f.admission, captureStore)
			if current == nil || !current.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("completed apply observation before independent owner", state)
			}
			recorder.collect()
			appliedRevision = current.head.Core.Revision
			reservation := generatedPlanInputWithCurrentGenerated(t, current, operation, []string{"secret"}, defaultGeneratedFixtureProfile())
			reservation.context.Expiry = uint64(deadline.UnixNano())
			recorder.collect()
			prepared, _ := preparePrivateGeneratedReservation(t, env, current, reservation, nil)
			recorder.collect()
			selected, state := current.selectCandidate(callctx, prepared.reservation.candidate)
			if selected == nil || state.Outcome != ObservedCurrent {
				t.Fatal("independent canonical owner selection", state)
			}
			recorder.collect()
			env.Custody.RetireGenerated()
			recorder.collect()
			selectedOwner = generatedLifecycleReopen(t, callctx, selected, env.Store)
			if selectedOwner.root.Generated.ActiveOwner != operation || !reflect.DeepEqual(current.currentEntryInputs(), selectedOwner.currentEntryInputs()) || current.root.OutputConfiguration != selectedOwner.root.OutputConfiguration {
				t.Fatal("reservation did not preserve current values and output configuration under its real owner")
			}
			ownerRevision = selectedOwner.head.Core.Revision
			ownerWork = installedApplyStableWork(t, callctx, selectedOwner)
			recorder.collect()
		}
		return owner, nil
	}
	engine, _ = publicOutputApplyReinstall(t, engine)
	owners := 0
	newOwner := private.NewOwner
	private.NewOwner = func(callctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
		owners++
		return newOwner(callctx, input)
	}
	publisher := installedPublicationEngine(t, f, private, recorder)
	joined := engine.ApplyAndPublish(ctx, fixtureID(env.Domain, "completed apply before independent owner"), fixtureID(env.Domain, "publication blocked by independent owner"), input, publisher, nil)
	receipt, err := contract.InspectCompactMutationReceipt(joined.Apply.Receipt)
	if selectedOwner == nil || appliedRevision.IsZero() || ownerRevision.IsZero() || appliedRevision == ownerRevision || joined.Apply.Result.Outcome != ObservedCurrent || joined.Apply.Result.ObservedRevision != appliedRevision || err != nil || receipt.OperationID != joined.Apply.OperationID || receipt.RequestIdentityDigest != joined.Apply.RequestIdentity || receipt.RequestedRevisionID != appliedRevision || receipt.ObservedRevisionID != appliedRevision {
		t.Fatal("independent owner changed the completed apply result or receipt", joined.Apply.Result, err)
	}
	result := applyPublicationAssertStage(t, joined, contract.PublicationSummaryFailed, 2)
	if result.Result.Outcome != AdmissionRefused || result.Result.Reason != AdmissionInvalid || owners != 0 {
		t.Fatal("independent active owner did not block private publication preparation", result.Result, owners)
	}
	for _, target := range result.Output.Entries {
		if len(target.Actions) != 1 {
			t.Fatal("blocked owner lost a requested action", target)
		}
		action := target.Actions[0]
		if action.Action != contract.PublicationCreateWithValue || action.Disposition != contract.PublicationNotSent || action.CoreReason != uint16(AdmissionInvalid) || !action.AttemptID.IsZero() || action.ProjectionCommitment.IsZero() || action.Evidence != (contract.PublicationEvidence{}) {
			t.Fatal("blocked action acquired an attempt or lost its exact unstarted fact", action)
		}
	}
	publicationEngineReopen(t, f)
	if f.store.cas != beforeCAS+2 || f.session.head.Core.Revision != ownerRevision || f.session.root.Generated.ActiveOwner != operation || !reflect.DeepEqual(ownerWork, installedApplyStableWork(t, ctx, f.session)) || !reflect.DeepEqual(selectedOwner.currentEntryInputs(), f.session.currentEntryInputs()) || selectedOwner.root.OutputConfiguration != f.session.root.OutputConfiguration {
		t.Fatal("blocked publication changed or took over the independent canonical owner")
	}
	publicOutputApplyAssertNoPublication(t, f.session)
	assertNativePublicationJoined(t, recorder, staging, 0)
}
