package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestSuppliedSharingUsesReaderRouteInReaderPhases(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, true)
	execution, known := catalog.ExecutionFor("secret.complete-supplied-sharing-preserves-current-access/plain1_secret1_grant_exclude", "live")
	if !known {
		t.Fatal("sharing execution facts unavailable")
	}
	steps := execution.WriterSteps()
	stepIndex, readerCalls := 0, 0
	role := ""
	env.Phase = func(name string) {
		if stepIndex >= len(steps) || steps[stepIndex].Name != name {
			t.Fatal("sharing execution differs from its declared phases")
		}
		role = steps[stepIndex].Role
		stepIndex++
	}
	env.ReaderConsume = func(selection contract.ConsumerSelection, choice uint8) custody.ConsumerCheck {
		if role != "reader" || selection.Binding.SubjectID != fixtureID(env.Domain, "reader") {
			t.Fatal("reader consumption used another actor phase or recipient")
		}
		readerCalls++
		return keys.Consume(context.Background(), selection, choice)
	}
	runSuppliedSharingScenario(t, context.Background(), env)
	if readerCalls != 3 || stepIndex != len(steps) {
		t.Fatal("sharing omitted an independent reader attempt or declared phase")
	}
}
