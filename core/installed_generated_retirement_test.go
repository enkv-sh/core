package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestGeneratedRetirementFormsRefuseMissingSelectors(t *testing.T) {
	var engine *InstalledApply
	request := contract.ID{1}
	for _, call := range []func() PublicApplyResult{
		func() PublicApplyResult {
			return engine.RetireGenerated(context.Background(), request, GeneratedRetirementRequest{})
		},
		func() PublicApplyResult {
			return engine.ContinueGeneratedRetirement(context.Background(), request, GeneratedRetirementContinuationRequest{})
		},
		func() PublicApplyResult {
			return engine.AcceptGeneratedRetirementRisk(context.Background(), request, GeneratedRetirementRiskRequest{DutyID: contract.ID{2}})
		},
		func() PublicApplyResult {
			return engine.AcceptGeneratedRetirementRisk(context.Background(), request, GeneratedRetirementRiskRequest{AttemptID: contract.ID{3}})
		},
	} {
		result := call()
		if result.RequestID != request || result.Result != refused(AdmissionInvalid) || result.Generated != nil || len(result.Receipt) != 0 {
			t.Fatal("missing exact selector did not refuse before admission", result)
		}
	}
}

// full_only: false
func TestGeneratedRetirementTelemetryOwnsAdmissionRefusals(t *testing.T) {
	var engine *InstalledApply
	for _, item := range []struct {
		operation telemetry.Operation
		invoke    func(context.Context) PublicApplyResult
	}{
		{telemetry.OpCoreGeneratedRetire, func(ctx context.Context) PublicApplyResult {
			return engine.RetireGenerated(ctx, contract.ID{1}, GeneratedRetirementRequest{DutyID: contract.ID{2}})
		}},
		{telemetry.OpCoreGeneratedAcceptRetirementRisk, func(ctx context.Context) PublicApplyResult {
			return engine.AcceptGeneratedRetirementRisk(ctx, contract.ID{1}, GeneratedRetirementRiskRequest{DutyID: contract.ID{2}, AttemptID: contract.ID{3}})
		}},
	} {
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
		if result := item.invoke(ctx); result.Result != refused(AdmissionInvalid) {
			t.Fatal(result)
		}
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
		if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint ||
			records[2].Event != telemetry.DiagnosticReturn || records[2].Operation != item.operation || records[2].Result != telemetry.ResultAdmissionRefused {
			t.Fatal("generated lifecycle refusal lost its closed telemetry", records)
		}
		for _, record := range records {
			if err := record.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
