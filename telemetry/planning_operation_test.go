package telemetry

import "testing"

// full_only: false
func TestPlanningOperationsHaveReadOnlyStages(t *testing.T) {
	for _, item := range []struct {
		provider  Provider
		operation Operation
	}{{ProviderCore, OpCorePlanning}, {ProviderCrypto, OpCryptoPlanning}, {ProviderCrypto, OpCryptoPlanningDisplay}} {
		if !AllowedAttribute("operation", string(item.operation)) || !ValidOperationOwner(item.provider, item.operation) {
			t.Fatal("planning operation is not registered", item)
		}
		for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderApplication, ProviderWorker, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost} {
			if ValidOperationOwner(provider, item.operation) != (provider == item.provider) {
				t.Fatal("planning operation admits a different owner", provider, item.operation)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticProviderCall, DiagnosticCandidatePersistence, DiagnosticCommitObservation} {
			if validDiagnosticStageFor(item.provider, item.operation, stage) {
				t.Fatal("planning admits a mutation stage", stage)
			}
		}
	}
	for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticPrivateCustody} {
		if !validDiagnosticStageFor(ProviderCore, OpCorePlanning, stage) {
			t.Fatal("Core planning refuses a read stage", stage)
		}
	}
	for _, operation := range []Operation{OpCryptoPlanning, OpCryptoPlanningDisplay} {
		if !validDiagnosticStageFor(ProviderCrypto, operation, DiagnosticPrivateCustody) {
			t.Fatal("Crypto planning refuses custody stage", operation)
		}
	}
}
