package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestInspectionReaderRefusalRetainsSafeTelemetry(t *testing.T) {
	var reader *InstalledInspectionReader
	for _, recipient := range []bool{false, true} {
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
		if recipient {
			got := reader.InspectRecipient(ctx, RecipientInspectionRequest{RequestNonce: publicationRelationID(1), RecipientID: publicationRelationID(2)})
			if got.Operation != InspectRecipientOperation || got.StateResult != PublicQueryRefused || got.View != nil || got.FailureReason != contract.ReasonInvalidInput || got.Validate() != nil {
				t.Fatal("recipient refusal lost closed safe result", got)
			}
		} else {
			got := reader.Inspect(ctx, DomainInspectionRequest{RequestNonce: publicationRelationID(1)})
			if got.Operation != InspectOperation || got.StateResult != PublicQueryRefused || got.View != nil || got.FailureReason != contract.ReasonInvalidInput || got.ValidateMetadataWorkOutput() != nil {
				t.Fatal("domain refusal lost closed safe result", got)
			}
		}
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
		if len(records) != 3 || records[2].Event != telemetry.DiagnosticReturn || records[2].Result != telemetry.ResultAdmissionRefused {
			t.Fatal("inspection refusal telemetry incomplete", records)
		}
		for _, row := range records {
			if err := row.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
