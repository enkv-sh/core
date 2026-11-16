package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestInstalledLocalUnknownKeepsOriginalActiveWorkWithoutCallbackRepeat(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	author := installedLocalAuthor{config: custody.BuildInstalledUnknownLocalAuthor(t, installedLocalPublicRoot(t))}
	row := author.config.Artifact
	declaration := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: row.ConfigContractID, Intent: installedLocalCanonicalIntent()}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: declaration}}
	admissions := 0
	engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions)
	first := engine.Apply(ctx, testID("native unknown local create"), input)
	engine.Close()
	if first.Result.Outcome != ObservedCurrent || first.Result.Evidence != AuthenticatedClosure || first.Result.RequestedRevision.IsZero() || first.Result.ObservedRevision != first.Result.RequestedRevision || first.OperationID.IsZero() || first.RequestIdentity.IsZero() || first.Payload != nil || len(first.Receipt) != 0 || first.Generated == nil || len(first.Diagnostics) != 1 || first.Diagnostics[0].Reason != contract.ReasonSelectedObjectUnavailable {
		t.Fatal("unknown local return lost its selected reservation or invented completion", first)
	}
	revision, identity := first.Result.ObservedRevision, first.RequestIdentity
	for round := range 3 {
		selected := f.open(t, ctx)
		work := mustSelectedGeneratedWork(t, selected)
		if selected.head.Core.Revision != revision || selected.root.Generated.ActiveOwner != first.OperationID || selected.root.ValueEntryCount != 0 || work.parent == nil || work.parent.OperationID != first.OperationID || work.parent.RequestIdentityDigest != identity || len(work.attempts) != 1 {
			t.Fatal("unknown local result ended or replaced original work", selected.head.Core.Revision, selected.root.Generated.ActiveOwner)
		}
		for _, attempt := range work.attempts {
			if attempt.record.LifecycleMode != contract.GeneratorLifecycleNone || attempt.record.State != contract.GeneratedEffectTransmitted || len(attempt.result) != 0 {
				t.Fatal("unknown local return acquired a usable value or a terminal claim", attempt.record)
			}
			body, found, result := selected.ReadGeneratedResult(ctx, attempt.record.AttemptID)
			if len(body) != 0 || found || result.Outcome != 0 {
				t.Fatal("unknown local return acquired protected result evidence", found, result)
			}
		}
		if round == 2 {
			break
		}
		continued := installedLocalEngine(t, ctx, f, selected, input, author, &admissions)
		got := continued.Continue(ctx, testID("native unknown continuation "+string(rune('a'+round))), first.OperationID)
		continued.Close()
		if got.Result.Outcome != EvidenceUnavailable || got.Result.CommitMayHaveOccurred || got.OperationID != first.OperationID || got.RequestIdentity != identity || got.Payload != nil || len(got.Receipt) != 0 || got.Generated == nil {
			t.Fatal("fresh Continue invented recovery of unknown local result", got)
		}
	}
	if admissions != 1 {
		t.Fatal("fresh Continue repeated original native callback admission", admissions)
	}
}
