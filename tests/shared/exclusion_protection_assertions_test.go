package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// This checks the public recipient-exclusion evidence independently of production admission.
// Actual D/C byte distinction is established by the private-owner tests.
func assertPublicExclusionProtection(t testing.TB, before, after contract.ValueEntry) {
	t.Helper()
	if before.Name != after.Name || before.ConfidentialityClass != contract.Secret || after.ConfidentialityClass != contract.Secret ||
		before.ValueState == after.ValueState || before.OriginSnapshot == after.OriginSnapshot || before.OriginTransition == after.OriginTransition {
		t.Fatal("exclusion did not change current value and origin identities")
	}
	oldPayload, oldErr := contract.InspectCanonicalPayload(before.ValueBytes)
	newPayload, newErr := contract.InspectCanonicalPayload(after.ValueBytes)
	if oldErr != nil || newErr != nil || bytes.Equal(oldPayload.Ciphertext, newPayload.Ciphertext) || oldPayload.SemanticCommitment == newPayload.SemanticCommitment {
		t.Fatal("exclusion did not change ciphertext and semantic evidence", oldErr, newErr)
	}
	for _, oldKey := range []contract.ID{oldPayload.DataKeyID, oldPayload.CommitmentKeyID} {
		for _, newKey := range []contract.ID{newPayload.DataKeyID, newPayload.CommitmentKeyID} {
			if oldKey == newKey {
				t.Fatal("exclusion reused an old public key identity")
			}
		}
	}
	metadata := before.Generated
	if before.ValueSource == contract.Generated {
		metadata.GenerationID = after.ValueState
	}
	if before.Incarnation != after.Incarnation || before.ValueSource != after.ValueSource || metadata != after.Generated {
		t.Fatal("protection-only exclusion changed source or generated metadata")
	}
}
