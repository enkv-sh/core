package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestInstalledPublicationRefusalCompletesClosedTelemetry(t *testing.T) {
	var engine *InstalledPublication
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	request := contract.ID{1}
	result := engine.Publish(ctx, request, PublicationRequest{Names: []string{"entry"}})
	if result.RequestID != request || result.Result != refused(AdmissionInvalid) || result.Output != nil {
		t.Fatal("invalid public publication admitted work", result.Result)
	}
	status := recorder.Status()
	if status.Accepted != 3 || status.Rejected != 0 || status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 {
		t.Fatal("public publication emitted an unaccepted diagnostic", status)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
	if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint ||
		records[1].Stage != telemetry.DiagnosticCommitObservation || records[2].Event != telemetry.DiagnosticReturn ||
		records[2].Operation != telemetry.OpCorePublicationExecute || records[2].Result != telemetry.ResultAdmissionRefused {
		t.Fatal("public publication lost its closed diagnostic sequence", records)
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
