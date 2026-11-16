package telemetry

import "testing"

// full_only: false
func TestCoreObservationOfferKeepsClosedOwnerAndResults(t *testing.T) {
	if !AllowedAttribute("operation", string(OpCoreObservationOffer)) || !ValidOperationOwner(ProviderCore, OpCoreObservationOffer) {
		t.Fatal("observation offer operation unregistered")
	}
	for _, provider := range []Provider{ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
		if ValidOperationOwner(provider, OpCoreObservationOffer) {
			t.Fatal("observation signal admitted another owner", provider)
		}
	}
	for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall} {
		if validDiagnosticStageFor(ProviderCore, OpCoreObservationOffer, stage) {
			t.Fatal("storage offer acquired product stage", stage)
		}
	}
	for _, result := range []Result{ResultSuccess, ResultContention, ResultCapacityExceeded, ResultInvalid} {
		recorder := NewRecorder()
		call := Start(testDiagnosticContext(recorder), ProviderCore, OpCoreObservationOffer)
		call.Finish(result)
		records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
		if len(records) != 2 || records[0].Event != DiagnosticStart || records[1].Event != DiagnosticReturn || records[1].Result != result {
			t.Fatal("offer signal incomplete", records)
		}
		for _, r := range records {
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
