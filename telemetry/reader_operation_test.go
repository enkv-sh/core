package telemetry

import "testing"

// full_only: false
func TestReaderOperationsHaveOnlyPublicCoreStages(t *testing.T) {
	for _, operation := range []Operation{"core.reader.compare", "core.reader.manifest", "core.reader.recipients", "core.generated.list", "core.receipt.list", "core.receipt.detail", "core.inspect", "core.inspect_recipient", "core.inspect_capacity", "core.gc_plan", "core.gc_validate_plan"} {
		if !AllowedAttribute("operation", string(operation)) || !ValidOperationOwner(ProviderCore, operation) {
			t.Fatal("Reader operation is not registered", operation)
		}
		for _, provider := range []Provider{ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
			if ValidOperationOwner(provider, operation) {
				t.Fatal("Reader operation admits another owner", provider)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication} {
			if !validDiagnosticStageFor(ProviderCore, operation, stage) {
				t.Fatal("public stage refused", stage)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticPrivateCustody, DiagnosticProviderCall, DiagnosticCandidatePersistence, DiagnosticCommitObservation} {
			if validDiagnosticStageFor(ProviderCore, operation, stage) {
				t.Fatal("Reader admits an effect stage", stage)
			}
		}
	}
}
