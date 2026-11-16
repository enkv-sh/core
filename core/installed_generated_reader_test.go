package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestGeneratedListRefusalRetainsOperationAndPublicTelemetry(t *testing.T) {
	var reader *InstalledGeneratedReader
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	request := contract.ID{1}
	got := reader.List(ctx, request)
	if got.Context.Operation != "generated-list" || got.Context.RequestID != request || got.Result != refused(AdmissionInvalid) ||
		got.StateResult != contract.ReaderRefused || got.FailureReason != contract.ReasonInvalidInput || got.View != nil {
		t.Fatal("list refusal lost its closed public operation", got)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
	if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint ||
		records[2].Event != telemetry.DiagnosticReturn || records[2].Operation != telemetry.OpCoreGeneratedList ||
		records[2].Result != telemetry.ResultAdmissionRefused {
		t.Fatal("list refusal did not complete exact public telemetry", records)
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
