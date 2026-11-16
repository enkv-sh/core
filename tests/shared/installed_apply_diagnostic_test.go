package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestInstalledApplyRetainsRejectedSealedBindingSubject(t *testing.T) {
	for _, generated := range []bool{false, true} {
		t.Run(fmt.Sprintf("generated=%t", generated), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
			original := suppliedSecret(t, f.env, "secret", "sealed binding original", custody.StandardValue, authority)
			first := f.engine(t, f.selected, []ApplyEntryInput{original}, nil)
			selected := first.Apply(ctx, testID("sealed binding predecessor"), []ApplyEntryInput{original})
			first.Close()
			if selected.Result.Outcome != ObservedCurrent {
				t.Fatal("exact supplied predecessor was not selected", selected.Result)
			}
			before := f.open(t, ctx)
			proposed := original
			proposed.Recipients = []contract.ID{authority, reader}
			slices.SortFunc(proposed.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			input := []ApplyEntryInput{proposed}
			var engine *InstalledApply
			if generated {
				process, _ := configurationRecoveryLocalGeneratedProcess(t)
				f.env.GeneratedProcess = process
				generation := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
					ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
				input = append(input, ApplyEntryInput{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Recipients: []contract.ID{authority}, Generated: &generation})
				callbacks := installedGeneratedTestCallbacks(t, f, process)
				callbacks.AdmitReservation = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedReservationInput, time.Time) (*InstalledGeneratedCustody, error) {
					t.Fatal("rejected sealed binding reached private reservation")
					return nil, nil
				}
				engine = installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
			} else {
				engine = f.engine(t, before, input, func(contract.CryptoKind) { t.Error("rejected sealed binding reached private comparison") })
			}
			store := requireAdmittedMemoryStore(t, f.env.Store)
			writes, cas := store.creates, store.cas
			got := engine.Apply(ctx, testID("sealed binding rejected addition"), input)
			engine.Close()
			if got.Result.Outcome != AdmissionRefused || len(got.Diagnostics) != 1 || got.Payload != nil || got.Generated != nil || len(got.Receipt) != 0 || store.creates != writes || store.cas != cas {
				t.Fatal("binding refusal lost its no-effect result or diagnostic handoff", got.Result, got.Diagnostics)
			}
			row := got.Diagnostics[0]
			if row.Subject.Kind != contract.SubjectEntry || row.Subject.Name != "secret" || row.Reason != contract.ReasonStaleSealedInputBinding || row.Outcome != contract.DiagnosticUnable || !slices.Equal(row.Path, []contract.DiagnosticField{contract.FieldSource}) {
				t.Fatal("installed result lost exact rejected source subject", row)
			}
		})
	}
}
