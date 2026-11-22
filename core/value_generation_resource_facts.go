package core

import "enkv.sh/core/contract"

func generatedResourceFactsMatch(facts contract.GeneratorSafeFacts, digest contract.ID) bool {
	actual, err := contract.GeneratorResourceDigest(facts)
	return err == nil && actual == digest
}

func generatedFactsMatchTemplate(facts contract.GeneratorSafeFacts, x contract.GeneratorAttemptTemplate) bool {
	return facts.Action == x.Action && facts.LifecycleMode == x.LifecycleMode && facts.ResourceContractID == x.ResourceContractID && facts.IntentDigest == x.IntentDigest
}

// Inspect a bodyless DELETE observation against the selected original.
// A host rejection must identify a different resource. A provider Unknown
// must still name the exact admitted resource, even if the provider disputes it.
func inspectRetirementAttemptFacts(body []byte, a generatedAttempt) (contract.GeneratorAttemptFacts, error) {
	f, err := contract.InspectGeneratorAttemptFacts(body)
	if err != nil || a.expected.Template.Action != contract.GeneratorActionDelete || uint32(len(body)) > a.expected.Use.MaxFacts ||
		!generatedFactsMatchTemplate(f.GeneratorSafeFacts, a.expected.Template) || f.RequestDigest != a.record.RequestDigest ||
		!f.RetirementRejected && f.Disposition != contract.GeneratorDispositionUnknown {
		return contract.GeneratorAttemptFacts{}, contract.ErrRecord
	}
	digest, err := contract.GeneratorResourceDigest(f.GeneratorSafeFacts)
	if err != nil || a.expected.TargetResourceDigest.IsZero() || (digest == a.expected.TargetResourceDigest) == f.RetirementRejected {
		return contract.GeneratorAttemptFacts{}, contract.ErrRecord
	}
	return f, nil
}
