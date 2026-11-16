package telemetry

import "testing"

// full_only: false
func TestManifestHostOperationsHaveClosedOwnerAndStages(t *testing.T) {
	for _, operation := range []Operation{OpManifestHostCheck, OpManifestHostRender, OpManifestHostJoin, OpManifestHostCancel} {
		if !AllowedAttribute("provider", "manifesthost") || !AllowedAttribute("operation", string(operation)) {
			t.Fatal("manifest host vocabulary missing", operation)
		}
		for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
			if ValidOperationOwner(provider, operation) != (provider == ProviderManifestHost) {
				t.Fatal("incorrect operation owner", provider, operation)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticPrivateCustody, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticProviderCall, DiagnosticLocalStaging, DiagnosticLocalReplacement, DiagnosticLocalCompletion} {
			want := stage == DiagnosticProviderCall
			if operation == OpManifestHostCheck {
				want = stage == DiagnosticAdmission
			}
			if validDiagnosticStageFor(ProviderManifestHost, operation, stage) != want {
				t.Fatal("incorrect diagnostic stage", operation, stage)
			}
		}
		recorder := NewRecorder()
		call := Start(testDiagnosticContext(recorder), ProviderManifestHost, operation)
		call.FinishReason(ResultEvidenceUnavailable, DiagnosticReasonEvidenceUnavailable)
		records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
		if len(records) != 2 || records[1].Event != DiagnosticReturn || records[1].Result != ResultEvidenceUnavailable {
			t.Fatal("terminal failure missing", records)
		}
		for _, record := range records {
			if record.Validate() != nil || record.Path != "" || record.ErrorDetail != "" {
				t.Fatal("invalid or unsafe diagnostic", record)
			}
		}
	}
}
