package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

func currentApplyRecipients(rows []contract.RecipientRecord) []contract.ApplyRecipientInput {
	inputs := make([]contract.ApplyRecipientInput, len(rows))
	for i, row := range rows {
		inputs[i].Recipient = row
	}
	slices.SortFunc(inputs, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	return inputs
}

type applyRecipientProposal struct {
	inputs  []contract.ApplyRecipientInput
	records []contract.RecipientRecord
	changed []contract.ID
}

func (s *StateSession) admitApplyRecipients(ctx context.Context, desired []contract.ApplyRecipientInput) (*applyRecipientProposal, error) {
	return s.admitRecipientProposal(ctx, desired, nil)
}

func (s *StateSession) admitRecipientProposal(ctx context.Context, desired []contract.ApplyRecipientInput, retirement *contract.RecipientRetirementRow) (*applyRecipientProposal, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || len(desired) == 0 {
		return nil, contract.ErrRecord
	}
	if len(desired) > contract.CryptoMaxRecipients {
		return nil, contract.ErrRecordCapacity
	}
	if retirement != nil && !s.authenticatedRecipientRetirement(*retirement) {
		return nil, contract.ErrRecord
	}
	var length uint64
	for i, input := range desired {
		row := input.Recipient
		if i > 0 && bytes.Compare(desired[i-1].Recipient.RecipientID[:], row.RecipientID[:]) >= 0 {
			return nil, contract.ErrRecord
		}
		n, err := contract.RecipientRecordLength(row)
		if err != nil {
			return nil, err
		}
		length += uint64(n)
		if length > contract.MaxPublicRegistryBytes {
			return nil, contract.ErrRecordCapacity
		}
	}
	current := s.registry()
	before := make(map[contract.ID]contract.RecipientRecord, len(current))
	for _, row := range current {
		before[row.RecipientID] = row
	}
	proposal := &applyRecipientProposal{inputs: desired, records: make([]contract.RecipientRecord, len(desired))}
	for i, input := range desired {
		row := input.Recipient
		if retirement != nil && (input.Creation != nil || row.RecipientID == retirement.RecipientID) {
			return nil, contract.ErrRecord
		}
		if row.Status != contract.CurrentRecipient || row.CurrentBinding == nil || row.CurrentBinding.Provider != s.root.CurrentAccess.Core.Provider {
			return nil, contract.ErrRecord
		}
		if _, err := contract.EncodeRecipientRecord(row); err != nil {
			return nil, err
		}
		if old, exists := before[row.RecipientID]; exists {
			if old.Status != contract.CurrentRecipient || old.CurrentBinding == nil || !kmsBindingEqual(*old.CurrentBinding, *row.CurrentBinding) {
				return nil, contract.ErrRecord
			}
			delete(before, row.RecipientID)
			if row.DisplayName != old.DisplayName {
				if retirement != nil {
					return nil, contract.ErrRecord
				}
				proposal.changed = append(proposal.changed, row.RecipientID)
			}
		} else {
			if retirement != nil {
				return nil, contract.ErrRecord
			}
			if input.Creation == nil || input.Creation.Snapshot != s.root.Snapshot {
				return nil, contract.ErrRecord
			}
			id, err := contract.RecipientCreationID(s.root.Domain, input.Creation.Snapshot, input.Creation.Nonce)
			if err != nil || id != row.RecipientID {
				return nil, contract.ErrRecord
			}
			binding, incarnation, err := contract.RecipientInitialBindingIDs(s.root.Domain, id)
			if err != nil || binding != row.CurrentBinding.BindingID || incarnation != row.CurrentBinding.BindingIncarnationID || row.CurrentBinding.BindingSerial != 1 {
				return nil, contract.ErrRecord
			}
			proposal.changed = append(proposal.changed, id)
		}
		proposal.records[i] = row
	}
	if retirement != nil {
		if len(before) != 1 {
			return nil, contract.ErrRecord
		}
		if _, present := before[retirement.RecipientID]; !present {
			return nil, contract.ErrRecord
		}
		delete(before, retirement.RecipientID)
		proposal.changed = append(proposal.changed, retirement.RecipientID)
	}
	if len(before) != 0 {
		return nil, contract.ErrRecord
	}
	return proposal, nil
}

func (c *Comparison) proposedRecipient(id contract.ID) *contract.RecipientRecord {
	i := slices.IndexFunc(c.recipients, func(row contract.ApplyRecipientInput) bool { return row.Recipient.RecipientID == id })
	if i < 0 {
		return nil
	}
	return &c.recipients[i].Recipient
}

func (c *Comparison) proposedRegistry() []contract.RecipientRecord {
	rows := make([]contract.RecipientRecord, len(c.recipients))
	for i, row := range c.recipients {
		rows[i] = row.Recipient
	}
	return rows
}

func (s *StateSession) validateApplyRecipientIdentities(ctx context.Context, c *Comparison) error {
	if c == nil || c.session != s {
		return contract.ErrRecord
	}
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return err
	}
	for _, row := range c.recipients {
		if s.recipientRecord(row.Recipient.RecipientID) != nil {
			continue
		}
		binding := row.Recipient.CurrentBinding
		for _, id := range []contract.ID{row.Recipient.RecipientID, binding.BindingID, binding.BindingIncarnationID} {
			if id.IsZero() || used[id] {
				return contract.ErrRecord
			}
			used[id] = true
		}
	}
	return nil
}

func ownApplyRecipients(inputs []contract.ApplyRecipientInput) ([]contract.ApplyRecipientInput, error) {
	owned := make([]contract.ApplyRecipientInput, len(inputs))
	for i, input := range inputs {
		body, err := contract.EncodeRecipientRecord(input.Recipient)
		if err != nil {
			return nil, err
		}
		owned[i].Recipient, err = contract.DecodeRecipientRecord(body)
		if err != nil {
			return nil, err
		}
		if input.Creation != nil {
			proof := *input.Creation
			owned[i].Creation = &proof
		}
	}
	return owned, nil
}
func (c *Comparison) qualificationCounts() map[contract.ID]uint32 {
	counts := make(map[contract.ID]uint32)
	for _, row := range c.recipients {
		if c.session.recipientRecord(row.Recipient.RecipientID) == nil {
			counts[row.Recipient.CurrentBinding.BindingID] = contract.PublicKeyQualificationUseCount(row.Recipient.CurrentBinding.Provider)
		}
	}
	return counts
}
func (c *Comparison) requiresCrypto() bool {
	return c.retirement != nil || c.session.root.SecretCount != 0 || slices.ContainsFunc(c.desiredEntries, func(v ApplyEntryInput) bool { return v.ConfidentialityClass == contract.Secret }) || slices.ContainsFunc(c.recipients, func(v contract.ApplyRecipientInput) bool {
		return c.session.recipientRecord(v.Recipient.RecipientID) == nil
	})
}
