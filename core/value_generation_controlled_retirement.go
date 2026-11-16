package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

type generatedControlledProgress struct {
	ack           generatedAttempt
	rows          [][]byte
	contradiction bool
}

// Derive each prefix from its exact sealed results, never from a mutable latest
// status. A pending replacement is used only while building its record CAS.
func (g *generatedSelection) controlledRetirementProgress(d contract.GeneratedDutyRecord, pending *generatedAttempt, validate bool) (generatedControlledProgress, error) {
	if d.CompletionClass != contract.GeneratedCompletionConfirmed || d.Kind != contract.GeneratedDutyRetirement {
		return generatedControlledProgress{}, contract.ErrRecord
	}
	row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, d.DutyID}]
	if !ok {
		return generatedControlledProgress{}, contract.ErrRecord
	}
	source, err := contract.InspectGeneratedDeleteSource(row)
	if err != nil || source.Duty != d {
		return generatedControlledProgress{}, contract.ErrRecord
	}
	return g.controlledDeleteSourceProgress(source, pending, validate)
}

func (g *generatedSelection) controlledDeleteSourceProgress(source contract.GeneratedDeleteSource, pending *generatedAttempt, validate bool) (generatedControlledProgress, error) {
	var out generatedControlledProgress
	if source.CompletionClass != contract.GeneratedCompletionConfirmed {
		return out, contract.ErrRecord
	}
	history, err := g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorHistory, source.History)
	if err != nil {
		return out, err
	}
	var createPrefix uint32
	if original, present := g.attempts[source.OriginalAttemptID]; present && original.expected.Template.Action == contract.GeneratorActionCreate {
		createPrefix = original.record.History.Count
		if createPrefix > uint32(len(history)) {
			return out, contract.ErrRecord
		}
	}
	var attempts []generatedAttempt
	acks := make(map[contract.ID]generatedAttempt)
	for ordinal, body := range history {
		if uint32(ordinal) < createPrefix {
			continue // Immutable create ancestry is validated separately.
		}
		h, err := contract.InspectGeneratorHistory(body)
		if err != nil {
			return out, err
		}
		a, ok := g.attempts[h.PredecessorAttemptID]
		if !ok {
			return out, contract.ErrRecord
		}
		if a.expected.Template.Action == contract.GeneratorActionCreate {
			continue
		}
		if a.expected.Template.Action != contract.GeneratorActionDelete || a.record.OwnerID != source.OwnerID || a.record.ResourceID != source.ResourceID {
			return out, contract.ErrRecord
		}
		if pending != nil && pending.record.AttemptID == a.record.AttemptID {
			a = *pending
		}
		attempts = append(attempts, a)
		if len(a.result) != 0 {
			r, err := contract.InspectGeneratedResultRecord(a.result)
			if err != nil {
				return out, err
			}
			if r.SafeFacts.Disposition == contract.GeneratorDispositionRetirementAcknowledged {
				acks[a.record.ResultID] = a
			}
		}
	}
	for _, a := range attempts {
		rows, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorProgress, a.record.Progress)
		if err != nil || len(rows) > 2 {
			return out, contract.ErrRecord
		}
		var admittedAck generatedAttempt
		completed := false
		for _, body := range rows {
			progress, err := contract.InspectGeneratorProgress(body)
			if err != nil || progress.CompletionClass != source.CompletionClass || progress.RequiredSteps != contract.GeneratorConfirmedRequiredSteps {
				return out, contract.ErrRecord
			}
			switch progress.CompletedSteps {
			case contract.GeneratorProgressAcknowledged:
				ack, ok := acks[progress.ResultID]
				if !ok || !admittedAck.record.AttemptID.IsZero() {
					return out, contract.ErrRecord
				}
				want, err := generatedControlledProgressRow(ack, contract.GeneratorProgressAcknowledged)
				if err != nil || !bytes.Equal(body, want) {
					return out, contract.ErrRecord
				}
				admittedAck = ack
			case contract.GeneratorProgressConfirmed:
				if completed || progress.AttemptID != a.record.AttemptID {
					return out, contract.ErrRecord
				}
				want, err := generatedControlledProgressRow(a, contract.GeneratorProgressConfirmed)
				if err != nil || !bytes.Equal(body, want) {
					return out, contract.ErrRecord
				}
				completed = true
			default:
				return out, contract.ErrRecord
			}
		}
		if completed && admittedAck.record.AttemptID.IsZero() {
			return out, contract.ErrRecord
		}
		if !admittedAck.record.AttemptID.IsZero() && admittedAck.record.AttemptID != a.record.AttemptID {
			scope := contract.GeneratorControlledRetirementScope(a.record.DescriptorID, a.record.ConfigContractID, a.record.ResultContractID)
			want := contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, a.expected.TargetResourceDigest,
				scope, admittedAck.record.ResultID, contract.Hash(admittedAck.result))
			if a.record.RequestDigest != want {
				return out, contract.ErrRecord
			}
		}
		recorded, err := g.deleteResultRecorded(a)
		if err != nil {
			return out, err
		}
		if pending != nil && pending.record.AttemptID == a.record.AttemptID {
			recorded = false
		}
		if len(a.result) != 0 {
			r, err := contract.InspectGeneratedResultRecord(a.result)
			if err != nil {
				return out, err
			}
			f := r.SafeFacts
			switch f.Disposition {
			case contract.GeneratorDispositionRetirementAcknowledged:
				if recorded && (a.record.State != contract.GeneratedEffectSucceeded || admittedAck.record.AttemptID != a.record.AttemptID || completed) ||
					!recorded && admittedAck.record.AttemptID == a.record.AttemptID {
					return out, contract.ErrRecord
				}
				if out.ack.record.AttemptID.IsZero() {
					out.ack = a
					row, err := generatedControlledProgressRow(a, contract.GeneratorProgressAcknowledged)
					if err != nil {
						return out, err
					}
					out.rows = [][]byte{row}
				}
			case contract.GeneratorDispositionScopedUnusability, contract.GeneratorDispositionContinuedUsability, contract.GeneratorDispositionConflictingBinding:
				if admittedAck.record.AttemptID.IsZero() || f.PrecedingResultID != admittedAck.record.ResultID ||
					f.PrecedingResultBodyDigest != contract.Hash(admittedAck.result) ||
					f.ScopeID != contract.GeneratorControlledRetirementScope(a.record.DescriptorID, a.record.ConfigContractID, a.record.ResultContractID) ||
					recorded && (f.Disposition == contract.GeneratorDispositionScopedUnusability && a.record.State != contract.GeneratedEffectSucceeded ||
						f.Disposition != contract.GeneratorDispositionScopedUnusability && a.record.State != contract.GeneratedEffectFailedTerminal || completed != (f.Disposition == contract.GeneratorDispositionScopedUnusability)) ||
					!recorded && completed {
					return out, contract.ErrRecord
				}
				if f.Disposition != contract.GeneratorDispositionScopedUnusability {
					out.contradiction = true
				} else if !out.contradiction && len(out.rows) < 2 {
					row, err := generatedControlledProgressRow(a, contract.GeneratorProgressConfirmed)
					if err != nil {
						return out, err
					}
					ackRow, err := generatedControlledProgressRow(admittedAck, contract.GeneratorProgressAcknowledged)
					if err != nil {
						return out, err
					}
					out.ack = admittedAck
					out.rows = [][]byte{ackRow, row}
					slices.SortFunc(out.rows, func(a, b []byte) int { return bytes.Compare(a[2:66], b[2:66]) })
				}
			default:
				return out, contract.ErrRecord
			}
		}
		if pending == nil || pending.record.AttemptID != a.record.AttemptID {
			bad, err := g.validateDeleteFacts(a)
			if err != nil {
				return out, err
			}
			out.contradiction = out.contradiction || bad
		}
		if validate && recorded && len(a.result) == 0 {
			return out, contract.ErrRecord
		}
	}
	if validate && source.Record.Kind == contract.GeneratedDutySupportKind {
		d := source.Duty
		rows, err := g.vectors.resolve(contract.GeneratedDutySupportKind, source.SourceID, contract.GeneratorVectorProgress, d.Progress)
		step := uint8(1)
		if len(out.rows) > 0 {
			step = 2
		}
		if err != nil || d.Step != step || !slices.EqualFunc(rows, out.rows, bytes.Equal) {
			return out, contract.ErrRecord
		}
	}
	return out, nil
}

func generatedControlledProgressRow(a generatedAttempt, completed uint8) ([]byte, error) {
	return contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1, AttemptID: a.record.AttemptID, ResultID: a.record.ResultID,
		Evidence: contract.GeneratorDescriptor{Digest: contract.Hash(a.result), Length: uint64(len(a.result)), Count: 1}, RequiredSteps: contract.GeneratorConfirmedRequiredSteps, CompletedSteps: completed, CompletionClass: contract.GeneratedCompletionConfirmed})
}

func (g *generatedSelection) generatedControlledRetirementClose(_ context.Context, a generatedAttempt, revision contract.ID) (generatedRetirementClose, error) {
	var out generatedRetirementClose
	d, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.record.OwnerID}].Body)
	if err != nil || d.Status != a.record.State || a.record.Stage != contract.GeneratedStageTerminal || len(a.result) == 0 {
		return out, contract.ErrRecord
	}
	progress, err := g.controlledRetirementProgress(d, nil, true)
	if err != nil {
		return out, err
	}
	final := len(progress.rows) == 2 && !progress.contradiction && a.record.State == contract.GeneratedEffectSucceeded
	out = generatedRetirementClose{duty: d, attempt: a, nonfinal: !final,
		release: contract.PendingInboxReleaseRecord{Schema: 1, DomainID: a.record.DomainID, InboxID: a.record.InboxID, OriginalResultID: a.record.ResultID,
			SelectedHandoffDigest: contract.Hash(a.result), HandoffRevisionID: revision, CapacityReservation: d.CapacityReservation, ObjectLength: uint32(len(a.result)), State: contract.GeneratedReleasePending}}
	remove := map[generatedRecordKey]bool{{contract.GeneratedParentSupportKind, a.record.OperationID}: true, {contract.GeneratedPhaseSupportKind, a.record.OperationID}: true}
	operations := map[contract.ID]bool{a.record.OperationID: true}
	if final {
		row := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, d.DutyID}]
		source, err := contract.InspectGeneratedDeleteSource(row)
		if err != nil {
			return out, err
		}
		target, err := g.generatedCleanupTarget(row.Kind, d.DutyID, d.Target)
		if err != nil {
			return out, err
		}
		closed, err := g.generatedDeleteSourceClosure(a, source, target, a.result, revision)
		if err != nil {
			return out, err
		}
		return generatedRetirementClose{duty: d, attempt: closed.attempt, release: closed.release,
			material: a.material.Core.OperationMaterialID, materials: closed.materials,
			slices: closed.slices, locations: closed.locations, rows: closed.rows}, nil
	}
	for _, row := range g.image.supportRecords() {
		if remove[generatedRecordKey{row.Kind, row.RecordID}] && !generatedSelectionAnchored(g) {
			continue
		}
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return out, err
			}
			if v.VectorKind == contract.GeneratorVectorSlices || v.OwnerKind == contract.GeneratedParentSupportKind && operations[v.OwnerID] && !generatedSelectionAnchored(g) && v.VectorKind != contract.GeneratorVectorSupport {
				continue
			}
		}
		out.rows = append(out.rows, row)
	}
	out.rows, out.locations, out.slices, err = g.generatedCloseContent(out.rows)
	return out, err
}
