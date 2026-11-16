package telemetry

import "testing"

// full_only: false
func TestReconstructionVerifyOperationHasOnlyCryptoOwner(t *testing.T) {
	if !ValidOperationOwner(ProviderCrypto, OpCryptoReconstructionVerify) ||
		!AllowedAttribute("operation", string(OpCryptoReconstructionVerify)) {
		t.Fatal("private verify/discard operation was not registered")
	}
	for _, provider := range []Provider{ProviderCore, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderApplication} {
		if ValidOperationOwner(provider, OpCryptoReconstructionVerify) {
			t.Fatal("non-Crypto provider owns private verify/discard")
		}
	}
}

// full_only: false
func TestReconstructionOperationHasOnlyCoreOwner(t *testing.T) {
	if !ValidOperationOwner(ProviderCore, OpCoreReconstruct) ||
		!AllowedAttribute("operation", string(OpCoreReconstruct)) ||
		!validDiagnosticStageFor(ProviderCore, OpCoreReconstruct, DiagnosticAdmission) ||
		validDiagnosticStageFor(ProviderCore, OpCoreReconstruct, DiagnosticProviderCall) {
		t.Fatal("complete reconstruction operation was not registered")
	}
	for _, provider := range []Provider{ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderApplication} {
		if ValidOperationOwner(provider, OpCoreReconstruct) {
			t.Fatal("non-Core provider owns complete reconstruction")
		}
	}
}
