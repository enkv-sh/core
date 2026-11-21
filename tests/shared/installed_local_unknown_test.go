package core

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestInstalledLocalUnknownFinalReleasesDomain(t *testing.T) {
	for _, tc := range []struct {
		name           string
		reason, stored uint8
	}{
		{"malformed", contract.GeneratorReasonMalformed, 133},
		{"overflow", contract.GeneratorReasonOverflow, 134},
		{"rejected", contract.GeneratorReasonRejected, 135},
		{"transport", contract.GeneratorReasonTransport, 136},
		{"deadline", contract.GeneratorReasonDeadline, 137},
		{"identity-conflict", contract.GeneratorReasonIdentityConflict, 138},
	} {
		t.Run(tc.name, func(t *testing.T) {
			author := installedLocalAuthor{config: custody.BuildInstalledUnknownLocalAuthor(t, installedLocalPublicRoot(t), tc.reason)}
			checkInstalledLocalUnknown(t, author, tc.stored, "")
			if tc.reason == contract.GeneratorReasonTransport {
				t.Run("before-record", func(t *testing.T) { checkInstalledLocalUnknown(t, author, tc.stored, "before-record") })
				t.Run("after-record", func(t *testing.T) { checkInstalledLocalUnknown(t, author, tc.stored, "after-record") })
			}
		})
	}
}

func checkInstalledLocalUnknown(t *testing.T, author installedLocalAuthor, stored uint8, stop string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	row := author.config.Artifact
	declaration := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: row.ConfigContractID, Intent: installedLocalCanonicalIntent()}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: declaration}}
	admissions := 0
	var calls atomic.Int32
	engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions, func(bool) { calls.Add(1) })
	callbacks := engine.installation.Generated
	if stop == "before-record" {
		admit := callbacks.AdmitProducer
		callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
			owner, err := admit(ctx, q, control, in, implementation, deadline)
			if err == nil && owner != nil {
				// Lose the receiver's recording capability before any durable transition.
				owner.AdmitLocalFailure = nil
			}
			return owner, err
		}
	}
	if stop == "after-record" {
		callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
			return nil, contract.ErrRecord
		}
	}
	got := engine.Apply(ctx, testID("native unknown local create"), input)
	engine.Close()
	if admissions != 1 || calls.Load() != 1 || got.OperationID.IsZero() || got.RequestIdentity.IsZero() {
		t.Fatal("expected one completed native invocation", admissions, calls.Load(), got.Result)
	}
	if stop != "" {
		cold := f.open(t, ctx)
		work := mustSelectedGeneratedWork(t, cold)
		if len(got.Receipt) != 0 || cold.root.Generated.ActiveOwner != got.OperationID || len(work.attempts) != 1 {
			t.Fatal("interrupted operation lost its checkpoint", got.Result)
		}
		for _, a := range work.attempts {
			if len(a.result) != 0 || a.record.RetryUsed != 0 {
				t.Fatal("Unknown acquired a result or retry")
			}
			if stop == "before-record" {
				if a.record.State != contract.GeneratedEffectTransmitted || a.record.FailureReason != 0 {
					t.Fatal("missing return evidence acquired a terminal reason")
				}
			} else if a.record.State != contract.GeneratedEffectFailedTerminal || a.record.FailureReason != stored || a.record.Stage != contract.GeneratedStageTerminal {
				t.Fatal("cold checkpoint lost its exact qualified Unknown reason", a.record.State, a.record.FailureReason)
			}
		}
		continued := installedLocalEngine(t, ctx, f, cold, input, author, &admissions)
		observed := continued.Continue(ctx, testID("resume local unknown"), got.OperationID)
		continued.Close()
		if observed.OperationID != got.OperationID || observed.RequestIdentity != got.RequestIdentity || admissions != 1 {
			t.Fatal("cold continuation changed the operation or repeated CREATE")
		}
		if stop == "before-record" {
			if observed.Result.Outcome != EvidenceUnavailable || len(observed.Receipt) != 0 || f.open(t, ctx).root.Generated.ActiveOwner != got.OperationID {
				t.Fatal("cold continuation released a slot without durable evidence", observed.Result)
			}
			reopened := installedLocalEngine(t, ctx, f, f.open(t, ctx), input, author, &admissions)
			again := reopened.Continue(ctx, testID("recheck unresolved local unknown"), got.OperationID)
			reopened.Close()
			if again.Result.Outcome != EvidenceUnavailable || len(again.Receipt) != 0 || admissions != 1 || calls.Load() != 1 || f.open(t, ctx).root.Generated.ActiveOwner != got.OperationID {
				t.Fatal("second continuation changed unresolved work", again.Result)
			}
			return
		}
		got = observed
	}
	receipt, err := contract.InspectCompactMutationReceipt(got.Receipt)
	if err != nil || got.Result.Outcome != ObservedCurrent || receipt.OperationID != got.OperationID || receipt.RequestIdentityDigest != got.RequestIdentity ||
		receipt.StateResult != contract.ReceiptStateEffectTerminalFailure || receipt.CanonicalOutcome != contract.ReceiptCanonicalNotSelected ||
		receipt.EffectSummary != contract.ReceiptEffectFailed || receipt.SummaryCounts[contract.ReceiptSummaryFailureCount] != 1 || receipt.SummaryCounts[contract.ReceiptEffectCount] != 1 {
		t.Fatal("checked local Unknown did not close with a nonselecting failure receipt", got.Result, err)
	}
	if got.Generated == nil || len(got.Generated.Effects) != 1 || len(got.Generated.Duties) != 0 || len(got.Generated.Hazards) != 0 {
		t.Fatal("unexpected local terminal effects or owners")
	}
	effect := got.Generated.Effects[0]
	if effect.Reason != stored || effect.Record.FailureReason != stored || effect.Record.State != contract.GeneratedEffectFailedTerminal ||
		effect.EvidenceCeiling != contract.ReceiptEvidenceCanonical || effect.Warnings != (GeneratedResultWarnings{}) || effect.Target != nil || effect.Record.RetryUsed != 0 {
		t.Fatal("terminal evidence lost the distinction between SDK Unknown and a callback failure", effect.Reason, effect.Record.State)
	}
	cold := f.open(t, ctx)
	g := cold.root.Generated
	if cold.root.ValueEntryCount != 0 || !g.ActiveOwner.IsZero() || !g.ActivePhase.IsZero() || !g.ActiveGraph.IsZero() || g.Hazards != 0 || g.Retiring != 0 || g.GeneratedCurrent != 0 || len(mustSelectedGeneratedWork(t, cold).releases) != 0 {
		t.Fatal("terminal local Unknown selected a value or kept an owner")
	}
	observer := installedLocalEngine(t, ctx, f, cold, input, author, &admissions)
	observed := observer.Continue(ctx, testID("observe local unknown receipt"), got.OperationID)
	observer.Close()
	if observed.Result.Outcome != ObservedCurrent || !bytes.Equal(observed.Receipt, got.Receipt) {
		t.Fatal("reopened receipt differs from terminal failure", observed.Result)
	}
	nextInput := []ApplyEntryInput{{Name: "next", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: input[0].Recipients, InputBytes: []byte("after"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}}
	next := f.engine(t, cold, nextInput, nil)
	progress := next.Apply(ctx, testID("after local unknown"), nextInput)
	next.Close()
	if progress.Result.Outcome != ObservedCurrent || len(progress.Receipt) == 0 || admissions != 1 || calls.Load() != 1 {
		t.Fatal("next mutation failed or repeated CREATE", progress.Result)
	}
}
