package telemetry

import "testing"

// full_only: false
func TestGCPlanDeliveryHasOnlyLocalApplicationPersistence(t *testing.T) {
	if !AllowedAttribute("operation", string(OpGCPlanWrite)) || !ValidOperationOwner(ProviderApplication, OpGCPlanWrite) {
		t.Fatal("GC artifact operation unregistered")
	}
	for _, owner := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderWorker} {
		if ValidOperationOwner(owner, OpGCPlanWrite) {
			t.Fatal("GC artifact operation granted another owner", owner)
		}
	}
	for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall} {
		if validDiagnosticStageFor(ProviderApplication, OpGCPlanWrite, stage) != (stage == DiagnosticCandidatePersistence) {
			t.Fatal("GC artifact operation granted another stage", stage)
		}
	}
}
