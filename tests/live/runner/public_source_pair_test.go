package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

func publicParsedSourceFacts(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, path string) nativeprocess.SourcePairFacts {
	t.Helper()
	child := publicCLI(t, ctx, inv, input, budget, "reader", true, nativeprocess.Policy{NoKMS: true, MaxRequests: 1, MaxBytes: 1}, nil, "--inspect-source-pair", "--source", path, "--source-format", "json")
	defer clear(child.Body)
	var facts nativeprocess.SourcePairFacts
	if child.Code != 0 || child.DiagnosticBytes != 0 || len(child.Body) > nativeprocess.SourcePairFactsLimit || operatorStrictJSON(child.Body, &facts) != nil || facts.Schema != "PublicSourcePairFacts/v1" || !facts.Resolved || facts.DomainID == ([32]byte{}) || !publicParsedSourcePins(facts).Valid() || len(child.Capture.Events) != 1 || child.Capture.Events[0].Kind != "footer" || child.Capture.Events[0].Code != 0 {
		t.Fatal("public source pair parser did not return exact public facts without SDK construction or use")
	}
	return facts
}
func publicParsedSourcePins(facts nativeprocess.SourcePairFacts) AdministrativeSourcePins {
	return AdministrativeSourcePins{FileID: contract.ID(facts.FileID), Format: facts.Format, EditableDigest: contract.ID(facts.EditableDigest), GeneratedDigest: contract.ID(facts.GeneratedDigest), EditableLength: facts.EditableLength, GeneratedLength: facts.GeneratedLength, HasGenerated: true}
}
func publicParsedSourceBasis(facts nativeprocess.SourcePairFacts) PublicBasis {
	basis := PublicBasis{Descriptor: facts.Basis.Descriptor, Control: facts.Basis.Control, Selection: facts.Basis.Selection}
	for _, row := range facts.Basis.Enrollment {
		basis.Enrollment = append(basis.Enrollment, PublicEnrollment{RecipientID: contract.ID(row.ID), Status: row.Status, DisplayName: row.DisplayName})
	}
	return basis
}
