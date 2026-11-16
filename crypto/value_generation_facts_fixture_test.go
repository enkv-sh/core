package crypto

import (
	"enkv.sh/core/contract"
	"testing"
)

func generatedFixtureResourceDigest(t testing.TB, facts contract.GeneratorSafeFacts) contract.ID {
	t.Helper()
	digest, err := contract.GeneratorResourceDigest(facts)
	if err != nil {
		t.Fatal("fixture resource identity", err)
	}
	return digest
}
