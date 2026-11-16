package telemetry

import "testing"

// full_only: false
func TestAdministrativePlanDeliveryOperationHasOnlyApplicationOwner(t *testing.T) {
	if OpAdministrativePlanWrite != "administrative.plan.write" || !AllowedAttribute("operation", string(OpAdministrativePlanWrite)) {
		t.Fatal("plan delivery operation is not closed")
	}
	for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderApplication, ProviderWorker, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost} {
		if ValidOperationOwner(provider, OpAdministrativePlanWrite) != (provider == ProviderApplication) {
			t.Fatal("plan delivery has incorrect owner", provider)
		}
	}
	for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall} {
		if validDiagnosticStageFor(ProviderApplication, OpAdministrativePlanWrite, stage) != (stage == DiagnosticCandidatePersistence) {
			t.Fatal("plan delivery stage is not closed", stage)
		}
	}
}
