package telemetry

import "testing"

// full_only: false
func TestGeneratedLifecycleOperationsKeepCoreMutationStages(t *testing.T) {
	for _, operation := range []Operation{"core.generated.retire", "core.generated.accept_retirement_risk", "core.generated.cleanup"} {
		if !AllowedAttribute("operation", string(operation)) || !ValidOperationOwner(ProviderCore, operation) {
			t.Fatal("generated lifecycle operation is not registered", operation)
		}
		for _, provider := range []Provider{ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
			if ValidOperationOwner(provider, operation) {
				t.Fatal("generated lifecycle operation has another owner", provider, operation)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticCommitObservation} {
			if !validDiagnosticStageFor(ProviderCore, operation, stage) {
				t.Fatal("lifecycle stage refused", operation, stage)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticPrivateCustody, DiagnosticCandidatePersistence, DiagnosticProviderCall} {
			if validDiagnosticStageFor(ProviderCore, operation, stage) {
				t.Fatal("unowned lifecycle stage admitted", operation, stage)
			}
		}
	}
}
