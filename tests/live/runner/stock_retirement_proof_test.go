package core

import (
	"context"
	"encoding/hex"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

func (r *stockPluginRun) retire(ctx context.Context, phase, actor, source string, duty stockGeneratedFact) {
	r.t.Helper()
	spec := r.input.PublicConfiguration.Stock
	var before *StateSession
	var reader stockOriginalReader
	dutyID := publicReplacementID(r.t, duty.Facts.Duty)
	if spec.Fixture.Purpose == records.StockRetirementProofPurpose {
		before = r.selected(ctx, source)
		work := mustSelectedGeneratedWork(r.t, before)
		row, ok := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}]
		if !ok {
			r.t.Fatal("stock Reader could not freeze the selected retirement Duty")
		}
		original, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || original.Kind != contract.GeneratedDutyRetirement || original.ExecutorID != publicReplacementID(r.t, duty.Facts.Executor) {
			r.t.Fatal("stock frozen retirement executor differs")
		}
		target, err := work.retirementTarget(ctx, original)
		if err != nil {
			r.t.Fatal("stock Reader could not freeze the retirement target")
		}
		facts, err := work.createTargetEvidence(ctx, target)
		at := len(r.evidence.Retirements)
		if err != nil || at >= len(r.evidence.ProviderTokenIDs) || string(facts.Target) != spec.CloudflareAccount || string(facts.ResourceData) != r.evidence.ProviderTokenIDs[at] {
			r.t.Fatal("stock frozen retirement target differs from the original verified token")
		}
		reader, err = openStockVersionReader(ctx, r.input, r.inv.StateDir, r.budget, before.root.Domain)
		if err != nil {
			r.t.Fatal("stock historical Reader unavailable")
		}
	}
	result := r.generated(ctx, phase, actor, source, "success", "generated", "retire", "--duty", duty.Facts.Duty)
	if !stockRetirementMatches(result, duty) {
		r.t.Fatal("stock retirement support or target differs", phase)
	}
	record := stockRetirementEvidence(phase, result, duty)
	if before != nil {
		after := r.selected(ctx, source)
		closeDigest, resultDigest, length := stockHistoricalRetirement(r.t, ctx, before, after, publicReplacementID(r.t, result.OperationID), publicReplacementID(r.t, result.Revision), dutyID, publicReplacementID(r.t, duty.Facts.Executor), reader)
		record.CloseDigest = hex.EncodeToString(closeDigest[:])
		record.ResultDigest = hex.EncodeToString(resultDigest[:])
		record.ResultLength = length
	}
	r.evidence.Retirements = append(r.evidence.Retirements, record)
}
