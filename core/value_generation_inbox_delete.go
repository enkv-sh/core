package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

type generatedInboxDeleteOutcome uint8

const (
	generatedInboxDeletePending generatedInboxDeleteOutcome = iota + 1
	generatedInboxDeleteClean
	generatedInboxDeleteUnknown
	generatedInboxDeleteExpired
	generatedInboxDeleteInvalidObject
)

// deleteGeneratedInbox verifies the selected handoff bytes before it asks an
// optional store capability to delete that exact observed object version. It
// does not alter authenticated state; a separate signed transition removes the
// pending release only after this function reports clean.
func (s *StateSession) deleteGeneratedInbox(ctx context.Context, inboxID contract.ID) generatedInboxDeleteOutcome {
	if s == nil || ctx == nil || inboxID.IsZero() || s.store == nil {
		return generatedInboxDeleteUnknown
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return generatedInboxDeleteUnknown
	}
	row, ok := g.records[generatedRecordKey{kind: contract.PendingInboxReleaseSupportKind, id: inboxID}]
	if !ok {
		return generatedInboxDeleteUnknown
	}
	release, err := contract.InspectPendingInboxReleaseRecord(row.Body)
	if err != nil || release.InboxID != inboxID ||
		(release.State != contract.GeneratedReleasePending && release.State != contract.GeneratedReleaseUnknown) {
		return generatedInboxDeleteUnknown
	}
	key, err := format.GeneratedResultKey(s.admission.store.Prefix, release.DomainID, release.InboxID)
	if err != nil {
		return generatedInboxDeleteUnknown
	}
	read := s.storeRead(ctx, key, release.ObjectLength)
	switch read.Status {
	case contract.ReadMissing:
		return generatedInboxDeleteClean
	case contract.ReadOK:
		if uint32(len(read.Body)) != release.ObjectLength || contract.Hash(read.Body) != release.SelectedHandoffDigest {
			return generatedInboxDeleteInvalidObject
		}
		if !read.Token.Valid() || read.Token.Family != s.admission.store.Family {
			return generatedInboxDeleteUnknown
		}
	case contract.ReadInvalid:
		if read.Reason == contract.ReasonLimit {
			return generatedInboxDeleteInvalidObject
		}
		return generatedInboxDeleteUnknown
	default:
		return generatedInboxDeleteUnknown
	}
	deleter, ok := s.store.(contract.ConditionalDeleteStore)
	if !ok {
		// The exact object was observed present, and this Store cannot send
		// a conditional deletion. Its existing mapping still applies.
		return generatedInboxDeletePending
	}
	if ctx.Err() != nil {
		return generatedInboxDeleteExpired
	}
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderCore, telemetry.OpCoreStoreDeleteIfToken,
		(telemetry.DiagnosticDetails{}).WithPathKind("state_object"))
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	result := deleter.DeleteIfToken(telemetry.CallContext(ctx, call), key, read.Token)
	finishWrite(call, 0, result)
	switch result.Status {
	case contract.WriteAcknowledged:
		return generatedInboxDeleteClean
	case contract.WritePrecondition, contract.WriteConflict:
		return generatedInboxDeletePending
	default:
		return generatedInboxDeleteUnknown
	}
}
