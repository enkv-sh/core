package core

import (
	"enkv.sh/core/contract"
	"testing"
)

func generatedRetirementFactsFixture(t testing.TB, state *StateSession, a generatedAttempt, disposition uint8) contract.GeneratorSafeFacts {
	t.Helper()
	selected, err := state.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("retirement fixture selected state", err)
	}
	bundle, err := selected.retainedGraph(a.record.OperationID)
	if err != nil {
		t.Fatal("retirement fixture selected graph", err)
	}
	source, err := selected.generatedDeleteSource(a.record.OwnerID)
	if err != nil {
		t.Fatal("retirement fixture selected source", err)
	}
	target, err := selected.generatedCleanupTarget(source.Record.Kind, source.SourceID, source.Target)
	if err != nil {
		t.Fatal("retirement fixture selected target", err)
	}
	if err := selected.validateDeleteTarget(t.Context(), bundle, a.record, target); err != nil {
		t.Fatal("retirement fixture target relation", err)
	}
	original, err := selected.createTargetEvidence(t.Context(), target)
	if err != nil {
		t.Fatal("retirement fixture original facts", err)
	}
	facts, err := original.Own()
	if err != nil {
		t.Fatal("retirement fixture original fact ownership", err)
	}
	facts.Action, facts.Disposition, facts.Reason = contract.GeneratorActionDelete, disposition, contract.GeneratorReasonNone
	facts.RequestDigest, facts.IntentDigest = a.expected.RequestDigest, a.expected.Template.IntentDigest
	if disposition == contract.GeneratorDispositionUnknown {
		facts.Reason = contract.GeneratorReasonTransport
	}
	return facts
}
