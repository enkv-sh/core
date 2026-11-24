package recovery

import (
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type ResponderPolicy struct {
	DenyNormal, DenyRecovery, DenyAuthority bool
	DenySecretOrdinal                       uint64
	RemoveObjectAfterPublic                 string
}

func configureCondition(t testing.TB, condition string, input *installedarchive.RecoveryInput, resourcesNormal, resourcesRecovery string, recoveryRegion string) (ResponderPolicy, *ObservedResult) {
	t.Helper()
	var policy ResponderPolicy
	var refused *ObservedResult
	refuse := func(outcome, reason uint8) { refused = &ObservedResult{Outcome: outcome, Reason: reason} }
	both := func() { input.RecoverySigner, input.RecoveryRegion = resourcesRecovery, recoveryRegion }
	switch condition {
	case "", "complete", "mixed-generated", "unused-recipient-denied", "zero-secret-genesis", "reader-replacement", "generated-active", "generated-retiring", "generated-uncertain", "new-domain-no-pin":
	case "prior-domain-pin":
		refuse(5, 2)
	case "matching-domain-pin":
		// The independent resource owner supplies this pin before setup.
	case "matching-kek-pin":
	case "adequate-anchor-fallback":
		both()
		policy.DenyNormal = true
	case "recovery-proof-recovery-only":
		both()
		input.NormalSigner, input.NormalRegion = "", ""
	case "recovery-proof-both":
		both()
	case "recovery-proof-normal-only":
		refuse(6, 12)
	case "recovery-proof-two-normal":
		input.RecoverySigner, input.RecoveryRegion = resourcesNormal, input.NormalRegion
		refuse(5, 4)
	case "both-anchors":
		both()
	case "unused-recovery-denied":
		both()
		policy.DenyRecovery = true
	case "recovery-only-inadequate":
		both()
		input.NormalSigner, input.NormalRegion = "", ""
		refuse(6, 12)
	case "required-public-denied":
		policy.DenyNormal = true
		refuse(6, 12)
	case "required-authority-denied", "recovery-key-only":
		policy.DenyAuthority = true
		refuse(6, 17)
	case "later-secret-denied":
		policy.DenySecretOrdinal = 5
		refuse(6, 17)
	case "selected-object-disappears":
		refuse(6, 7)
	case "copied-location":
		input.Prefix += "-copied"
		refuse(5, 2)
	case "wrong-domain-pin":
		id := contract.Hash([]byte("independent different DomainID"))
		input.ExpectedDomain = &id
		refuse(5, 2)
	case "wrong-kek-pin":
		input.ExpectedKEK = resourcesNormal
		refuse(8, 2) // AdmissionRefused, ConstructionMismatch
	case "wrong-owner":
		input.Owner = "999999999999"
		refuse(6, 8)
	case "wrong-locator":
		input.Prefix += "-absent"
		refuse(7, 7)
	case "wrong-anchor":
		input.NormalSigner, input.NormalRegion = resourcesRecovery, recoveryRegion
		refuse(5, 4)
	default:
		history, ok := installedarchive.ReplacementFor(condition)
		if !ok {
			t.Fatal("recovery parent condition refused", condition)
		}
		if len(history.Steps) > 0 && history.Steps[len(history.Steps)-1].Approval == 2 && history.Steps[len(history.Steps)-1].Mask&1 == 0 {
			both()
		}
	}
	if input.NormalSigner != "" && resourcesNormal == "" || input.RecoverySigner != "" && resourcesRecovery == "" {
		t.Fatal("independent signing resource missing")
	}
	return policy, refused
}
