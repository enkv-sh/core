package telemetry

import (
	"context"
	"testing"
)

// full_only: false
func TestManifestFileOperationAdmitsOnlyNativeApplicationStages(t *testing.T) {
	operation := Operation("manifest.file.write")
	if !AllowedAttribute("operation", string(operation)) {
		t.Fatal("native operation not registered")
	}
	for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderApplication, ProviderWorker, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost} {
		if ValidOperationOwner(provider, operation) != (provider == ProviderApplication) {
			t.Fatal("native operation owner differs", provider)
		}
	}
	for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticLocalStaging, DiagnosticLocalReplacement, DiagnosticLocalCompletion, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticPrivateCustody, DiagnosticProviderCall, DiagnosticCommitObservation, DiagnosticCandidatePersistence} {
		want := stage == DiagnosticAdmission || stage == DiagnosticLocalStaging || stage == DiagnosticLocalReplacement || stage == DiagnosticLocalCompletion
		if validDiagnosticStageFor(ProviderApplication, operation, stage) != want {
			t.Fatal("native stage permission differs", stage)
		}
	}
}

// full_only: false
func TestManifestCountsKeepCompleteBoundedPartitionAndDisabledPath(t *testing.T) {
	var disabled *Call
	disabled.ManifestEntries(512, 400, 112)
	for _, tc := range []struct {
		name                         string
		selected, included, excluded int
		result                       Result
		want                         bool
	}{
		{"empty", 0, 0, 0, ResultSuccess, true}, {"maximum", 512, 400, 112, ResultSuccess, true},
		{"over", 513, 400, 113, ResultSuccess, false}, {"negative", 1, -1, 2, ResultSuccess, false},
		{"incomplete", 3, 1, 1, ResultSuccess, false}, {"failed", 3, 1, 2, ResultFailure, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			points := make(chan MetricPoint, 16)
			ctx := WithCapability(context.Background(), NewCapability(points, nil))
			call := Start(ctx, ProviderCore, OpCoreReaderManifest)
			call.ManifestEntries(tc.selected, tc.included, tc.excluded)
			call.Finish(tc.result)
			got := map[string]int64{}
			for len(points) > 0 {
				p := <-points
				if p.Name == ManifestSelectedEntries || p.Name == ManifestIncludedEntries || p.Name == ManifestExcludedEntries {
					if !validMetricPoint(p) {
						t.Fatal("invalid manifest point", p)
					}
					got[p.Name] = p.IntValue
				}
			}
			if tc.want {
				if len(got) != 3 || got["enkv.manifest.selected_entries"] != int64(tc.selected) || got["enkv.manifest.included_entries"] != int64(tc.included) || got["enkv.manifest.excluded_entries"] != int64(tc.excluded) {
					t.Fatal("partition counters differ", got)
				}
			} else if len(got) != 0 {
				t.Fatal("incomplete partition emitted", got)
			}
		})
	}
	for _, p := range []MetricPoint{{Name: ManifestSelectedEntries, Provider: ProviderCore, Operation: OpCoreReaderManifest, Result: ResultSuccess, IntValue: 513}, {Name: ManifestSelectedEntries, Provider: ProviderApplication, Operation: OpManifestFileWrite, Result: ResultSuccess, IntValue: 2}, {Name: ManifestSelectedEntries, Provider: ProviderCore, Operation: OpCoreReaderManifest, Result: ResultFailure, IntValue: 2}} {
		if validMetricPoint(p) {
			t.Fatal("counter accepts wrong owner/result/bound", p)
		}
	}
	if Start(context.Background(), ProviderApplication, OpManifestFileWrite) != nil {
		t.Fatal("disabled telemetry started a call")
	}
}

// full_only: false
func TestManifestNativeFailureRetainsClosedDiagnosticReturn(t *testing.T) {
	recorder := NewRecorder()
	call := Start(testDiagnosticContext(recorder), ProviderApplication, OpManifestFileWrite)
	call.Checkpoint(DiagnosticAdmission, DiagnosticReasonNone)
	call.Checkpoint(DiagnosticLocalStaging, DiagnosticReasonNone)
	call.Checkpoint(DiagnosticLocalReplacement, DiagnosticReasonUncertain)
	call.Checkpoint(DiagnosticLocalCompletion, DiagnosticReasonEvidenceUnavailable)
	call.FinishReason(ResultFailure, DiagnosticReasonEvidenceUnavailable)
	records := recorder.Drain(make([]DiagnosticRecord, 0, 6))
	if len(records) != 6 || records[5].Event != DiagnosticReturn || records[5].Result != ResultFailure || records[5].Reason != DiagnosticReasonEvidenceUnavailable || records[5].SeverityNumber != SeverityError {
		t.Fatal("native failure lost terminal", records)
	}
	for _, record := range records {
		if record.Validate() != nil || record.Path != "" || record.EntryName != "" || record.KeyID != "" || record.ErrorDetail != "" {
			t.Fatal("native diagnostic contains unbounded facts", record)
		}
	}
}
