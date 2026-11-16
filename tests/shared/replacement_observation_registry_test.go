package core

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledReplacementObservationAcceptsRegistryChangesBeforeSuccession(t *testing.T) {
	for _, condition := range []string{"authority-signer", "recovery-signer"} {
		for _, change := range []string{"display", "creation"} {
			t.Run(fmt.Sprintf("%s/%s", condition, change), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				applied := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
				desired := currentApplyRecipients(applied.selected.registry())
				if change == "creation" {
					desired = installedApplyPreparedRecipient(t, applied.selected, "registry before successor nonce")
				} else {
					desired[0].Recipient.DisplayName = "current registry before successor"
				}
				engine := applied.engineWithRecipients(t, applied.selected, nil, desired, nil)
				result := engine.Apply(ctx, fixtureID(applied.env.Domain, "registry before successor apply"), nil)
				engine.Close()
				if result.Result.Outcome != ObservedCurrent {
					t.Fatal("actual predecessor registry apply", result.Result)
				}
				selected := applied.open(t, ctx)
				replacement := replacementObservationPrepareSelected(t, condition, applied.env, applied.keys, selected, applied.admitted)
				source, reason := qualifyReaderPublicBasis(replacement.installation.SourceBasis, applied.env.Domain, applied.env.Store.Descriptor())
				if reason != "" {
					t.Fatal("independent source basis", reason)
				}
				successor, reason := qualifyReaderPublicBasis(replacement.installation.SuccessorBasis, applied.env.Domain, applied.env.Store.Descriptor())
				if reason != "" || slices.Equal(source.enrollment, successor.enrollment) {
					t.Fatal("fixture did not retain historical source enrollment and actual successor registry", reason)
				}
				replacement.selectCandidate(t)
				observed, _ := replacement.query(t, condition+" existing output after "+change)
				if observed.StateResult != contract.ReaderSuccess || observed.Query == nil || observed.Query.Observation == nil {
					t.Fatal("historical registry facts rejected exact existing replacement output", observed.Result)
				}
				if replacement.installation.Correlation.Target == ReplacementTargetAuthority {
					if observed.Selection == nil || !observed.Selection.CandidateSelected || !observed.Selection.SuccessorSourceUsable || observed.Receipt != nil {
						t.Fatal("exact Authority selection/usability facts changed")
					}
				} else if observed.Receipt == nil || !observed.Receipt.CandidateSelected || observed.Receipt.Receipt.OperationKind != contract.OperationReplaceRecoveryKeysAndRoot {
					t.Fatal("exact Recovery replacement receipt unavailable")
				}
			})
		}
	}
}
