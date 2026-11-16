package telemetry

import "testing"

// full_only: false
func TestCorePublicationOperationsKeepClosedOwnerAndStage(t *testing.T) {
	for _, test := range []struct {
		operation Operation
		stage     DiagnosticStage
	}{
		{OpCorePublicationPlan, DiagnosticAdmission},
		{OpCorePublicationExecute, DiagnosticCommitObservation},
		{OpCorePublicationPrepareReservation, DiagnosticAdmission},
		{OpCorePublicationPrepareClose, DiagnosticCommitObservation},
	} {
		t.Run(string(test.operation), func(t *testing.T) {
			if !AllowedAttribute("operation", string(test.operation)) || !ValidOperationOwner(ProviderCore, test.operation) {
				t.Fatal("Core publication operation is not registered")
			}
			for _, provider := range []Provider{ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
				if ValidOperationOwner(provider, test.operation) {
					t.Fatal("publication operation admitted another owner", provider)
				}
			}
			for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall} {
				if validDiagnosticStageFor(ProviderCore, test.operation, stage) != (stage == test.stage) {
					t.Fatal("publication operation admitted an incorrect stage", stage)
				}
			}
			recorder := NewRecorder()
			call := Start(testDiagnosticContext(recorder), ProviderCore, test.operation)
			call.Checkpoint(test.stage, DiagnosticReasonNone)
			call.Finish(ResultAdmissionRefused)
			records := recorder.Drain(make([]DiagnosticRecord, 0, 3))
			if len(records) != 3 || records[1].Stage != test.stage {
				t.Fatal("publication operation records are incomplete")
			}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
