package telemetry

import "testing"

// full_only: false
func TestConfigurationOperationsHaveOnlyLocalApplicationStages(t *testing.T) {
	for _, operation := range []Operation{"configuration.capture", "configuration.parse", "configuration.write", "configuration.initialization_manifest"} {
		if !AllowedAttribute("operation", string(operation)) || !ValidOperationOwner(ProviderApplication, operation) {
			t.Fatal("local configuration operation is not registered", operation)
		}
		for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderWorker} {
			if ValidOperationOwner(provider, operation) {
				t.Fatal("configuration operation admits another owner", provider)
			}
		}
		read := operation == OpConfigurationCapture || operation == OpConfigurationParse
		for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall} {
			want := read && stage == DiagnosticAdmission || !read && (stage == DiagnosticCandidatePersistence || stage == DiagnosticCommitObservation)
			if validDiagnosticStageFor(ProviderApplication, operation, stage) != want {
				t.Fatal("configuration stage permission differs", operation, stage)
			}
		}
	}
}
