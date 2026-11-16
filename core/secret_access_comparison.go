package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The complete public image remains current-derived. Only the exact target
// enters private comparison; untouched secrets need no synthetic equality row.
func (s *StateSession) compareEntryInputsForMutation(ctx context.Context, input []ApplyEntryInput, recipients []contract.ApplyRecipientInput, access *contract.CryptoSecretAccessIntent, retirement *contract.RecipientRetirementRow, refusalDiagnostic **contract.Diagnostic) (*Comparison, Result) {
	c, result := s.compareEntryInputsWithRetirement(ctx, input, recipients, retirement, refusalDiagnostic)
	if c != nil && retirement != nil {
		if access != nil {
			return nil, refused(InvalidIntent)
		}
		return s.compareRecipientRetirement(c, *retirement)
	}
	if c == nil || access == nil {
		return c, result
	}
	old := s.valueEntry(access.Target.Slot)
	if old == nil || old.Name != access.Target.Name || old.ConfidentialityClass != contract.Secret || old.Incarnation != access.Target.Incarnation || old.ValueState != access.Target.Material || publicEntryDigest(s.root.Domain, access.Target.Slot, old) != access.Target.BeforePublicEntryDigest || len(c.desiredEntries) != len(s.root.Names) || len(c.added)+len(c.removed)+len(c.recipientChanges) != 0 {
		return nil, refused(InvalidIntent)
	}
	if access.OperationKind != contract.OperationEnvelopeRekey || len(access.RemovedRecipients) != 0 {
		return nil, refused(InvalidIntent)
	}
	for at, after := range c.desiredEntries {
		before := s.valueEntry(c.slots[at])
		if before == nil || after.Name != before.Name || after.ValueSource != before.ValueSource || after.ConfidentialityClass != before.ConfidentialityClass || !bytes.Equal(after.InputBytes, before.ValueBytes) {
			return nil, refused(InvalidIntent)
		}
		members := before.Recipients
		if !slices.Equal(after.Recipients, members) {
			return nil, refused(InvalidIntent)
		}
	}
	descriptor, err := contract.SecretAccessIntentDescriptor(s.root.Domain, c.intent, c.recipients, *access)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	owned := *access
	c.secretAccess, c.operationKind = &owned, owned.OperationKind
	c.desired, c.desiredLength = descriptor.Digest, descriptor.Length
	// Re-key changes protected material even when private comparison is equal.
	if !slices.Contains(c.changed, owned.Target.Slot) {
		c.changed = append(c.changed, owned.Target.Slot)
		slices.Sort(c.changed)
	}
	c.touched[owned.Target.Slot/format.PageSlots] = true
	return c, result
}

func (s *StateSession) compareResolvedEntryInputsForPurpose(ctx context.Context, input []ApplyEntryInput, recipients []contract.ApplyRecipientInput, access *contract.CryptoSecretAccessIntent) (*Comparison, Result) {
	return s.compareResolvedEntryInputsForMutation(ctx, input, recipients, access, nil)
}

func (s *StateSession) compareResolvedEntryInputsForMutation(ctx context.Context, input []ApplyEntryInput, recipients []contract.ApplyRecipientInput, access *contract.CryptoSecretAccessIntent, retirement *contract.RecipientRetirementRow) (*Comparison, Result) {
	request := slices.Clone(input)
	for at := range request {
		if request[at].Retained != nil {
			request[at].InputBytes = nil
		}
	}
	return s.compareEntryInputsForMutation(ctx, request, recipients, access, retirement, nil)
}

func comparisonPrivateSourceCount(q contract.CryptoCompareRequest) uint32 {
	if q.SecretAccess != nil {
		return 1
	}
	if q.Retirement != nil {
		var count uint32
		for _, row := range q.Current {
			entry, err := contract.DecodeValueEntry(row.EntryBytes)
			if err == nil && slices.Contains(entry.Recipients, q.Retirement.RecipientID) {
				count++
			}
		}
		return count
	}
	return uint32(len(q.SealedInputs) + len(q.Current))
}

func secretAccessComparisonMatches(c *Comparison, got contract.CryptoCompareResult) bool {
	if c == nil || c.secretAccess == nil || got.OperationRef.IsZero() || len(got.Rows) != 1 {
		return false
	}
	target := c.secretAccess.Target
	at := slices.IndexFunc(c.intent, func(row contract.CryptoIntentRow) bool { return row.Name == target.Name })
	if at < 0 {
		return false
	}
	intent, row := c.intent[at], got.Rows[0]
	want := contract.CryptoComparisonRow{Name: target.Name, BeforePresent: true, AfterPresent: true, BeforePublicEntryDigest: target.BeforePublicEntryDigest, SourceDigest: intent.PayloadDigest, AfterRawLength: intent.ContentLength, Relation: contract.CryptoEqual}

	return row == want
}
