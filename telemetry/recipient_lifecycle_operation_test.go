package telemetry

import "testing"

// full_only: false
func TestRecipientLifecycleOperationsHaveOnlyCoreAdmission(t *testing.T) {
	for _, operation := range []Operation{"core.rekey_envelope", "core.retire_recipient"} {
		if !AllowedAttribute("operation", string(operation)) || !ValidOperationOwner(ProviderCore, operation) {
			t.Fatal("recipient lifecycle operation is not registered", operation)
		}
		for _, provider := range []Provider{ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
			if ValidOperationOwner(provider, operation) {
				t.Fatal("recipient lifecycle operation admits another owner", provider)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall} {
			if validDiagnosticStageFor(ProviderCore, operation, stage) != (stage == DiagnosticAdmission) {
				t.Fatal("recipient lifecycle parent admits incorrect stage", operation, stage)
			}
		}
	}
	if AllowedAttribute("operation", "core.exclude_recipients") || ValidOperationOwner(ProviderCore, Operation("core.exclude_recipients")) {
		t.Fatal("withdrawn standalone exclusion operation remains registered")
	}
}
