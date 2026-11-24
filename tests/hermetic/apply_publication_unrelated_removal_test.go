package core

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

// full_only: false
func TestApplyPublicationBetweenStagesUnroutedRemovalRespectsParticipatingGroup(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		name := "unrelated-unrouted-entry"
		if grouped {
			name = "unrouted-participating-group-member"
		}
		t.Run(name, func(t *testing.T) {
			f, env, _, private, staging := nativePublicationFixture(t, true)
			recorder := newPublicationDiagnosticCapture()
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
			defer cancel()
			entries := installedApplyCurrentInput(f.session)
			entries = append(entries, ApplyEntryInput{Name: "outside", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.session.admission.recipient}, InputBytes: []byte("unrouted value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			plain := slices.IndexFunc(entries, func(row ApplyEntryInput) bool { return row.Name == "plain" })
			if plain < 0 {
				t.Fatal("routed fixture entry absent")
			}
			output := nativePublicationOutput([]ApplyEntryInput{entries[plain]}, []uint64{1, 9})
			output.routes = []outputApplyRoute{{entryName: "plain", destinations: []string{"native"}}}
			if grouped {
				output.groups = [][]string{{"outside", "plain"}}
			}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
			recorder.collect()
			f.admission = OpenContext{admission: &f.session.admission}
			input := installedApplyCurrentInput(f.session)
			for i := range input {
				if input[i].Name == "secret" {
					input[i] = suppliedSecret(t, env, "secret", "between-stage selected secret", custody.AlternateStandardValue, f.session.admission.recipient)
				}
			}
			a := publicPublicationApplyFixture(env, f)
			engine := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
			engine.installation.Store = &installedPublicationCaptureStore{memoryStore: f.store, capture: recorder}
			admitCustody := engine.installation.AdmitCustody
			beforeCAS := f.store.cas
			var appliedRevision contract.ID
			removed := false
			engine.installation.AdmitCustody = func(callctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
				owner, err := admitCustody(callctx, q, control, current, plain, support, witness, revision, before, warningBits, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				closeOwner := owner.Close
				owner.Close = func() {
					closeOwner()
					recorder.collect()
					if removed || f.store.cas != beforeCAS+1 {
						t.Fatal("removal cut did not follow exactly one completed apply selection")
					}
					current, state := Open(callctx, f.admission, f.store)
					if current == nil {
						t.Fatal("authenticated observation before unrelated removal", state)
					}
					appliedRevision = current.head.Core.Revision
					remaining := slices.DeleteFunc(installedApplyCurrentInput(current), func(row ApplyEntryInput) bool { return row.Name == "outside" })
					if grouped {
						afterOutput := ownOutputApplyInput(output)
						afterOutput.groups = nil
						f.session = selectAdmittedOutputConfiguration(t, callctx, current, env, env.Custody, remaining, afterOutput)
					} else {
						parent := admitSuppliedComparison(t, current, env.Custody, remaining)
						comparison, state := current.Compare(callctx, remaining, parent)
						if comparison == nil {
							t.Fatal("unrelated removal comparison", state)
						}
						candidate, state := current.Prepare(callctx, comparison, admit(t, current, comparison), env.Trust)
						if candidate == nil {
							t.Fatal("unrelated removal preparation", state)
						}
						selected, state := current.selectCandidate(callctx, candidate)
						if selected == nil || state.Outcome != ObservedCurrent {
							t.Fatal("unrelated removal selection", state)
						}
						env.Custody.RetireApply()
						f.session = generatedLifecycleReopen(t, callctx, selected, env.Store)
					}
					f.admission = OpenContext{admission: &f.session.admission}
					recorder.collect()
					removed = true
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
			joined := engine.ApplyAndPublish(ctx, fixtureID(env.Domain, "between-stage removal apply"), fixtureID(env.Domain, "between-stage removal publication"), input, publisher, nil)
			receipt, err := contract.InspectCompactMutationReceipt(joined.Apply.Receipt)
			if !removed || appliedRevision.IsZero() || joined.Apply.Result.Outcome != ObservedCurrent || joined.Apply.Result.ObservedRevision != appliedRevision || err != nil || receipt.OperationID != joined.Apply.OperationID || receipt.RequestIdentityDigest != joined.Apply.RequestIdentity || receipt.ObservedRevisionID != appliedRevision || receipt.RequestedRevisionID != appliedRevision {
				t.Fatal("later removal rewrote completed apply facts", joined.Apply.Result, err)
			}
			publicationEngineReopen(t, f)
			for _, row := range f.session.root.Names {
				if row.Name == "outside" {
					t.Fatal("controlled removal did not select")
				}
			}
			if !bytes.Equal(f.session.valueEntry(entrySlot(t, f.session, "plain")).ValueBytes, []byte("private data")) {
				t.Fatal("unrelated removal changed the routed value")
			}
			if grouped {
				if joined.Publication.Stage != "unstarted" || joined.Publication.Reason != "selection-conflict" || joined.Publication.Result != nil || owners != 0 {
					t.Fatal("participating group removal did not refuse before publication", joined.Publication, owners)
				}
				publicOutputApplyAssertNoPublication(t, f.session)
				assertNativePublicationNoPrivateWork(t, recorder)
				return
			}
			result := applyPublicationAssertStage(t, joined, contract.PublicationSummaryComplete, 1)
			if owners != 1 || len(result.Output.Entries[0].Actions) != 1 || result.Output.Entries[0].Actions[0].Action != contract.PublicationCreateWithValue || result.Output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
				t.Fatal("unrelated unrouted removal blocked the captured target", joined.Publication, owners)
			}
			assertNativePublicationJoined(t, recorder, staging, 1)
		})
	}
}
