package core

import "enkv.sh/core/contract"

func generatedResourceFactsMatch(facts contract.GeneratorSafeFacts, digest contract.ID) bool {
	actual, err := contract.GeneratorResourceDigest(facts)
	return err == nil && actual == digest
}

func generatedFactsMatchTemplate(facts contract.GeneratorSafeFacts, x contract.GeneratorAttemptTemplate) bool {
	return facts.Action == x.Action && facts.LifecycleMode == x.LifecycleMode && facts.ResourceContractID == x.ResourceContractID && facts.IntentDigest == x.IntentDigest
}
