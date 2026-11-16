package core

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledAccessMutationsRetainInterruptionFacts(t *testing.T) {
	for _, operation := range []string{"rekey", "retire"} {
		for _, stage := range []string{"cancelled-entry", "expired-entry", "acknowledged-create"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				base, finish := context.WithTimeout(t.Context(), time.Minute)
				defer finish()
				f := newInstalledApplyTestFixture(t, base, contract.AWS, false)
				authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
				members := []contract.ID{authority, reader}
				slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				input := []ApplyEntryInput{sharingSecretNamed(t, f.env, "target", "interrupted access source", members)}
				setup := f.engine(t, f.selected, input, nil)
				if got := setup.Apply(base, fixtureID(f.env.Domain, "interrupted access setup"), input); got.Result.Outcome != ObservedCurrent {
					t.Fatal("access interruption setup did not select", got.Result)
				}
				setup.Close()
				selected := f.open(t, base)
				memory := requireAdmittedMemoryStore(t, f.env.Store)
				store := &installedApplyInterruptionStore{Store: f.env.Store, memory: memory}
				f.env.Store = store
				ctx, cancel := context.WithCancel(base)
				defer cancel()
				installedCloses, custodyCloses, admitted := 0, 0, 0
				wrapCustody := func(owner *InstalledApplyCustody, err error) (*InstalledApplyCustody, error) {
					admitted++
					if err == nil && owner != nil {
						closeOwner := owner.Close
						owner.Close = sync.OnceFunc(func() { closeOwner(); custodyCloses++ })
					}
					return owner, err
				}
				var invoke func(context.Context, contract.ID) PublicApplyResult
				var closeEngine func()
				if operation == "rekey" {
					i := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, nil)
					i.CloseInstalled = func() { installedCloses++ }
					admit := i.AdmitCustody
					i.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, windows contract.MutationReceiptWindows, warning uint8, deadline time.Time) (*InstalledApplyCustody, error) {
						return wrapCustody(admit(ctx, q, control, current, plain, support, witness, revision, windows, warning, deadline))
					}
					engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: i.AccessMutationInstallation, Name: "target", AdmitCustody: i.AdmitCustody})
					if err != nil {
						t.Fatal(err)
					}
					invoke, closeEngine = engine.Rekey, engine.Close
				} else {
					i := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, reader), nil)
					i.CloseInstalled = func() { installedCloses++ }
					admit := i.AdmitCustody
					i.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, slot uint16, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, windows contract.MutationReceiptWindows, warning uint8, deadline time.Time) (*InstalledApplyCustody, error) {
						return wrapCustody(admit(ctx, q, control, current, slot, plain, support, witness, revision, windows, warning, deadline))
					}
					engine, err := NewInstalledRecipientRetirement(i)
					if err != nil {
						t.Fatal(err)
					}
					invoke, closeEngine = engine.Retire, engine.Close
				}
				t.Cleanup(closeEngine)
				beforePublic, beforePrivate := f.keys.Calls()
				wantOutcome, wantReason := AdmissionRefused, contract.ReasonCancelled
				switch stage {
				case "cancelled-entry":
					cancel()
				case "expired-entry":
					var stop context.CancelFunc
					ctx, stop = context.WithDeadline(base, time.Unix(1, 0))
					defer stop()
					wantReason = contract.ReasonExpired
				case "acknowledged-create":
					wantOutcome = EvidenceUnavailable
					store.created = func(result contract.WriteResult) {
						if result.Status != contract.WriteAcknowledged {
							t.Fatal("interrupted immutable create was not acknowledged", result)
						}
						cancel()
					}
				}
				request := fixtureID(f.env.Domain, "access interruption "+operation+" "+stage)
				got := invoke(ctx, request)
				closeEngine()
				if got.RequestID != request || got.Result.Outcome != wantOutcome || got.Result.CommitMayHaveOccurred || len(got.Receipt) != 0 || got.Payload != nil || store.sends != 0 {
					t.Fatalf("access interruption changed its actual stage: %+v", got)
				}
				if len(got.Diagnostics) != 1 || got.Diagnostics[0].Subject.Kind != contract.SubjectObservation || got.Diagnostics[0].Outcome != contract.DiagnosticUnable || got.Diagnostics[0].Reason != wantReason || !slices.Equal(got.Diagnostics[0].Path, []contract.DiagnosticField{contract.FieldPresence}) {
					t.Errorf("access interruption lost its exact cause: %+v", got.Diagnostics)
				}
				if got.Preparation == nil || got.Preparation.PossibleUnacknowledgedCreate || got.Preparation.VerifiedPreparations != 0 || installedCloses != 1 {
					t.Fatal("access interruption lost owned preparation or installation cleanup", got.Preparation, installedCloses)
				}
				if stage == "acknowledged-create" {
					if store.puts != 1 || got.Preparation.AcknowledgedCreates != 1 || admitted != 1 || custodyCloses != 1 || got.DomainID != f.env.Domain || got.OperationID.IsZero() || !got.RequestIdentity.IsZero() || got.Result.ObservedRevision != selected.head.Core.Revision || got.Result.ObservedSnapshotID != selected.root.Snapshot || got.Result.Evidence != AuthenticatedClosure {
						t.Fatal("acknowledged access preparation lost exact facts or repeated work", got, store.puts, admitted, custodyCloses)
					}
				} else {
					public, private := f.keys.Calls()
					if store.reads != 0 || store.puts != 0 || admitted != 0 || custodyCloses != 0 || got.Preparation.AcknowledgedCreates != 0 || !got.OperationID.IsZero() || !got.RequestIdentity.IsZero() || public != beforePublic || private != beforePrivate {
						t.Fatal("entry interruption entered state or private work", got, store.reads, store.puts, admitted, custodyCloses)
					}
				}
			})
		}
	}
}
