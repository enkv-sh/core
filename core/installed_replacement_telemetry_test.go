package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestInstalledReplacementTelemetryOwnsEveryAdmissionRefusal(t *testing.T) {
	var authority *InstalledAuthorityReplacement
	var recovery *InstalledRecoveryReplacement
	var recipient *InstalledRecipientReplacement
	for _, check := range []struct {
		operation telemetry.Operation
		invoke    func(context.Context) PublicReplacementResult
	}{
		{telemetry.OpCoreReplaceAuthorityKeys, func(ctx context.Context) PublicReplacementResult { return authority.Replace(ctx, contract.ID{1}) }},
		{telemetry.OpCoreReplaceRecoveryKeys, func(ctx context.Context) PublicReplacementResult { return recovery.Replace(ctx, contract.ID{2}) }},
		{telemetry.OpCoreReplaceRecipientKey, func(ctx context.Context) PublicReplacementResult { return recipient.Replace(ctx, contract.ID{3}) }},
	} {
		t.Run(string(check.operation), func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			result := check.invoke(ctx)
			if result.Result != refused(AdmissionInvalid) {
				t.Fatal(result.Result)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
			if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint || records[2].Event != telemetry.DiagnosticReturn || records[2].Operation != check.operation || records[2].Result != telemetry.ResultAdmissionRefused || records[2].Reason != telemetry.DiagnosticReasonAdmissionInvalid {
				t.Fatal("closed replacement telemetry boundary", records)
			}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
