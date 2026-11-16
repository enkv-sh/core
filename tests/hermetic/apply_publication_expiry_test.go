package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

func waitApplyPublicationOriginalExpiry(t testing.TB, ctx context.Context, original time.Time, reached *bool) {
	t.Helper()
	deadline, finite := ctx.Deadline()
	if !finite || deadline != original || ctx.Err() != nil || *reached {
		t.Fatal("expiry cut did not reach its live original invocation boundary")
	}
	*reached = true
	<-ctx.Done()
	if ctx.Err() != context.DeadlineExceeded || time.Now().Before(original) {
		t.Fatal("cut did not observe actual expiration of the original context")
	}
}

// full_only: false
func TestApplyPublicationOriginalDeadlineExpiresDuringApplyAndBetweenStages(t *testing.T) {
	for _, cut := range []string{"during-apply", "between-stages"} {
		t.Run(cut, func(t *testing.T) {
			f, env, _, private, _ := nativePublicationFixture(t, true)
			recorder := newPublicationDiagnosticCapture()
			input := installedApplyCurrentInput(f.session)
			for i := range input {
				if input[i].Name == "secret" {
					input[i] = suppliedSecret(t, env, "secret", "expiry pending secret", custody.AlternateStandardValue, f.session.admission.recipient)
				}
			}
			beforeRevision, beforeCAS := f.session.head.Core.Revision, f.store.cas
			a := publicPublicationApplyFixture(env, f)
			engine := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
			engine.installation.Store = &installedPublicationCaptureStore{memoryStore: f.store, capture: recorder}
			admit := engine.installation.AdmitCustody
			var originalDeadline time.Time
			reached := false
			engine.installation.AdmitCustody = func(callctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
				if deadline != originalDeadline {
					t.Fatal("apply custody received a different absolute deadline")
				}
				if cut == "during-apply" {
					waitApplyPublicationOriginalExpiry(t, callctx, originalDeadline, &reached)
					return nil, callctx.Err()
				}
				owner, err := admit(callctx, q, control, current, plain, support, witness, revision, before, warningBits, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				closeOwner := owner.Close
				owner.Close = func() {
					closeOwner()
					if f.store.cas != beforeCAS+1 {
						t.Fatal("between-stage cut preceded confirmed apply selection")
					}
					waitApplyPublicationOriginalExpiry(t, callctx, originalDeadline, &reached)
				}
				return owner, nil
			}
			engine, _ = publicOutputApplyReinstall(t, engine)
			owners := 0
			newOwner := private.NewOwner
			private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
				owners++
				return newOwner(ctx, input)
			}
			publisher := installedPublicationEngine(t, f, private, recorder)
			// Artifact and source setup is complete. The operation gets one finite
			// budget; the selected boundary waits for its actual Done signal.
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), 10*time.Second)
			defer cancel()
			originalDeadline, _ = ctx.Deadline()
			joined := engine.ApplyAndPublish(ctx, fixtureID(env.Domain, "expiry apply "+cut), fixtureID(env.Domain, "expiry publication "+cut), input, publisher, nil)
			if !reached || ctx.Err() != context.DeadlineExceeded || owners != 0 || joined.Publication.Stage != "unstarted" || joined.Publication.Result != nil {
				t.Fatal("expired original invocation acquired publication work", reached, owners, joined.Publication)
			}
			current, state := Open(t.Context(), f.admission, f.store)
			if current == nil {
				t.Fatal("post-expiry authenticated observation", state)
			}
			if cut == "during-apply" {
				if joined.Apply.Result.Outcome == ObservedCurrent || joined.Apply.Result.Outcome == Unchanged || joined.Publication.Reason != "apply-incomplete" || len(joined.Apply.Receipt) != 0 || f.store.cas != beforeCAS || current.head.Core.Revision != beforeRevision {
					t.Fatal("expiry during apply invented a completed selection", joined.Apply.Result, joined.Publication)
				}
			} else {
				row, err := contract.InspectCompactMutationReceipt(joined.Apply.Receipt)
				if err != nil || joined.Apply.Result.Outcome != ObservedCurrent || joined.Publication.Reason != "deadline-expired" || f.store.cas != beforeCAS+1 || current.head.Core.Revision != joined.Apply.Result.ObservedRevision || row.OperationID != joined.Apply.OperationID || row.RequestIdentityDigest != joined.Apply.RequestIdentity || row.RequestedRevisionID != row.ObservedRevisionID {
					t.Fatal("between-stage expiry erased the completed apply or renewed the deadline", joined.Apply.Result, joined.Publication, err)
				}
			}
			publicOutputApplyAssertNoPublication(t, current)
			assertNativePublicationNoPrivateWork(t, recorder)
		})
	}
}

type applyPublicationExpiryOwner struct {
	publicationPrivateOwner
	cut      string
	wait     func(context.Context)
	prepared int
	armed    int
	sent     int
	retired  int
}

func (o *applyPublicationExpiryOwner) Prepare(ctx context.Context, id contract.ID, selection *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	o.prepared++
	rows, code := o.publicationPrivateOwner.Prepare(ctx, id, selection)
	if o.cut == "before-marker-arm" && code == contract.CryptoSuccess {
		o.wait(ctx)
	}
	return rows, code
}

func (o *applyPublicationExpiryOwner) Arm(ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	o.armed++
	return o.publicationPrivateOwner.Arm(ctx, id, dispatch)
}

func (o *applyPublicationExpiryOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	o.sent++
	result, code := o.publicationPrivateOwner.Send(ctx, id)
	if o.cut == "after-native-ack-before-close" {
		if code != contract.CryptoSuccess || result.Evidence.Class != contract.PublicationRequestAcknowledged {
			return result, code
		}
		o.wait(ctx)
	}
	return result, code
}

func (o *applyPublicationExpiryOwner) Retire(ctx context.Context) error {
	err := o.publicationPrivateOwner.Retire(ctx)
	o.retired++
	return err
}

type applyPublicationExpiryTrust struct {
	contract.Trust
	wait func(context.Context)
}

func (trust applyPublicationExpiryTrust) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	if request.Purpose() == contract.OutputClosePurpose {
		trust.wait(ctx)
	}
	return trust.Trust.Sign(ctx, request)
}

// full_only: false
func TestApplyPublicationOriginalDeadlineExpiresBeforeArmAfterSendAndDuringClose(t *testing.T) {
	for _, cut := range []string{"before-marker-arm", "after-native-ack-before-close", "during-close-signing"} {
		t.Run(cut, func(t *testing.T) {
			f, env, _, private, staging := nativePublicationFixture(t, false)
			recorder := newPublicationDiagnosticCapture()
			before := bytes.Clone(f.session.valueEntry(entrySlot(t, f.session, "plain")).ValueBytes)
			beforeCAS := f.store.cas
			a := publicPublicationApplyFixture(env, f)
			input := installedApplyCurrentInput(f.session)
			apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
			var originalDeadline time.Time
			reached := false
			wait := func(ctx context.Context) { waitApplyPublicationOriginalExpiry(t, ctx, originalDeadline, &reached) }
			newOwner := private.NewOwner
			var owner *applyPublicationExpiryOwner
			private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
				if owner != nil || input.Deadline != originalDeadline {
					t.Fatal("expiry acquired another owner or changed its deadline")
				}
				inner, err := newOwner(ctx, input)
				if err != nil {
					return nil, err
				}
				owner = &applyPublicationExpiryOwner{publicationPrivateOwner: inner, cut: cut, wait: wait}
				return owner, nil
			}
			publisher := installedPublicationEngine(t, f, private, recorder)
			if cut == "during-close-signing" {
				publisher.installation.Trust = applyPublicationExpiryTrust{Trust: publisher.installation.Trust, wait: wait}
			}
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), 10*time.Second)
			defer cancel()
			originalDeadline, _ = ctx.Deadline()
			joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "publication expiry apply "+cut), fixtureID(env.Domain, "publication expiry output "+cut), input, publisher, nil)
			if !reached || ctx.Err() != context.DeadlineExceeded || owner == nil || owner.prepared != 1 || owner.retired != 1 || joined.Apply.Result.Outcome != Unchanged || len(joined.Apply.Receipt) != 0 {
				t.Fatal("expiry missed its exact owner boundary or erased completed apply", reached, joined.Apply.Result)
			}
			wantSummary, sends := uint8(contract.PublicationSummaryUnknown), 1
			if cut == "before-marker-arm" {
				wantSummary, sends = contract.PublicationSummaryFailed, 0
			}
			result := applyPublicationAssertStage(t, joined, wantSummary, 1)
			if owner.sent != sends || owner.armed != sends || len(result.Output.Entries[0].Actions) != 1 {
				t.Fatal("expired owner sent again or lost its complete action row", owner.sent, owner.armed)
			}
			action := result.Output.Entries[0].Actions[0]
			selected := publicationEngineReopen(t, f)
			if !bytes.Equal(f.session.valueEntry(entrySlot(t, f.session, "plain")).ValueBytes, before) {
				t.Fatal("publication expiry changed canonical application content")
			}
			if sends == 0 {
				if action.Disposition != contract.PublicationNotSent || !action.AttemptID.IsZero() || action.Evidence != (contract.PublicationEvidence{}) || action.CoreReason != uint16(CustodyUnavailable) || len(selected.markers) != 0 || f.store.cas != beforeCAS {
					t.Fatal("pre-arm expiry invented remote uncertainty or a marker", action)
				}
			} else {
				marker, present := selected.markers[action.AttemptID]
				if action.Disposition != contract.PublicationOutcomeUnknown || action.AttemptID.IsZero() || action.Evidence.Class != contract.PublicationUnproved || action.Evidence.Entry != contract.PublicationMayHaveEnteredEntry || !present || marker.State != contract.PublicationMayHaveEntered || len(selected.markers) != 1 || f.store.cas != beforeCAS+1 {
					t.Fatal("post-send expiry hid an unresolved selected Attempt or invented its close", action)
				}
			}
			assertNativePublicationJoined(t, recorder, staging, sends)
		})
	}
}
