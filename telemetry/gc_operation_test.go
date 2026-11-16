package telemetry

import "testing"

// full_only: false
func TestGCOperationsKeepCheckpointFreeCoreParents(t *testing.T) {
	stages := []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall}
	for _, operation := range []Operation{OpCoreGCApply, OpCoreGCContinue} {
		t.Run(string(operation), func(t *testing.T) {
			if !AllowedAttribute("operation", string(operation)) || !ValidOperationOwner(ProviderCore, operation) {
				t.Fatal("GC parent is not a registered Core operation")
			}
			for _, owner := range []Provider{ProviderCrypto, ProviderAWS, ProviderGCP, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost, ProviderApplication, ProviderWorker} {
				if ValidOperationOwner(owner, operation) {
					t.Fatal("GC parent has another owner", owner)
				}
			}
			for _, stage := range stages {
				if validDiagnosticStageFor(ProviderCore, operation, stage) {
					t.Fatal("GC parent acquired a checkpoint stage", stage)
				}
			}
			returns := []struct {
				result Result
				reason DiagnosticReason
			}{
				{ResultObservedCurrent, DiagnosticReasonNone},
				{ResultAdmissionRefused, DiagnosticReasonAdmissionInvalid},
				{ResultUnresolvedCommit, DiagnosticReasonWriteUncertain},
			}
			if operation == OpCoreGCApply {
				returns = append(returns, struct {
					result Result
					reason DiagnosticReason
				}{ResultUnchanged, DiagnosticReasonNone})
			}
			for _, outcome := range returns {
				t.Run(string(outcome.result), func(t *testing.T) {
					recorder := NewRecorder()
					parent := Start(testDiagnosticContext(recorder), ProviderCore, operation)
					for _, stage := range stages {
						parent.Checkpoint(stage, DiagnosticReasonNone)
					}
					child := Start(parent.Context(), ProviderCore, OpCoreStoreDeleteIfToken)
					child.Checkpoint(DiagnosticCommitObservation, DiagnosticReasonNone)
					child.FinishReason(ResultWriteUnknown, DiagnosticReasonUncertain)
					parent.FinishReason(outcome.result, outcome.reason)
					records := recorder.Drain(make([]DiagnosticRecord, 0, 5))
					if len(records) != 5 || recorder.Status().Rejected != uint64(len(stages)) {
						t.Fatal("parent stage leaked into capture or normal events were lost", records, recorder.Status())
					}
					if records[0].Event != DiagnosticStart || records[0].Operation != operation || records[0].ParentCall != 0 || records[4].Event != DiagnosticReturn || records[4].Operation != operation || records[4].Call != records[0].Call || records[4].Stage != "" || records[4].Result != outcome.result || records[4].Reason != outcome.reason {
						t.Fatal("GC parent did not retain its normal start/return facts", records)
					}
					if records[1].Event != DiagnosticStart || records[1].Operation != OpCoreStoreDeleteIfToken || records[1].ParentCall != records[0].Call || records[2].Call != records[1].Call || records[2].Event != DiagnosticCheckpoint || records[2].Stage != DiagnosticCommitObservation || records[3].Call != records[1].Call || records[3].Event != DiagnosticReturn || records[3].Result != ResultWriteUnknown || records[3].Reason != DiagnosticReasonUncertain {
						t.Fatal("Store delete lost its parent or owned checkpoint", records)
					}
					for _, record := range records {
						if err := record.Validate(); err != nil {
							t.Fatal("accepted invalid GC diagnostic record", err)
						}
					}
				})
			}
		})
	}
}
