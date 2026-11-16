package telemetry

import "testing"

// full_only: false
func TestPluginOperationsHaveOnlyApplicationAdmission(t *testing.T) {
	for _, operation := range []Operation{OpPluginResolve, OpPluginCapture, OpPluginAcquire, OpPluginSelect, OpPluginRetained} {
		if !AllowedAttribute("operation", string(operation)) {
			t.Fatal("operation missing", operation)
		}
		for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
			if ValidOperationOwner(provider, operation) != (provider == ProviderApplication) {
				t.Fatal("incorrect owner", provider, operation)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticProviderCall, DiagnosticLocalStaging, DiagnosticLocalReplacement, DiagnosticLocalCompletion} {
			if validDiagnosticStageFor(ProviderApplication, operation, stage) != (stage == DiagnosticAdmission) {
				t.Fatal("incorrect stage", operation, stage)
			}
		}
	}
}
