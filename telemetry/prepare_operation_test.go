package telemetry

import "testing"

// full_only: false
func TestPrepareOperationsHaveOnlyLocalApplicationAdmission(t *testing.T) {
	for _, operation := range []Operation{OpConfigurationPrepare, OpConfigurationPrepareDependencies} {
		if !AllowedAttribute("operation", string(operation)) || !ValidOperationOwner(ProviderApplication, operation) {
			t.Fatal("prepare operation is not registered", operation)
		}
		for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderWorker} {
			if ValidOperationOwner(provider, operation) {
				t.Fatal("prepare admits another owner", provider, operation)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall, DiagnosticLocalStaging, DiagnosticLocalReplacement, DiagnosticLocalCompletion} {
			if validDiagnosticStageFor(ProviderApplication, operation, stage) != (stage == DiagnosticAdmission) {
				t.Fatal("prepare admits a nonlocal stage", operation, stage)
			}
		}
	}
}
