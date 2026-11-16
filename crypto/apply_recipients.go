package crypto

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
)

func sameApplyRecipient(a, b contract.RecipientRecord) bool {
	return a.RecipientID == b.RecipientID && a.Status == b.Status && a.DisplayName == b.DisplayName &&
		a.CurrentBinding != nil && b.CurrentBinding != nil && sameApplyBinding(*a.CurrentBinding, *b.CurrentBinding)
}

// The selected predecessor supplies current rows independently of the request.
// Ordinary apply preserves every current identity and binding; only absent rows
// need creation evidence and an independently installed public qualifier.
func applyRecipientAdmission(q contract.CryptoCompareRequest, current []contract.RecipientRecord, public map[contract.ID]PublicKeyQualifier, control contract.ControlCore) (bool, map[contract.ID]PublicKeyQualifier, bool) {
	if !validApplyCurrentRecipients(current, control) || len(q.Recipients) < len(current) || len(q.Recipients) > contract.CryptoMaxRecipients || len(public) > contract.CryptoMaxRecipients {
		return false, nil, false
	}
	predecessor, err := contract.DecodeRef(q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		return false, nil, false
	}
	return applyRecipientAdmissionAtSnapshot(q, current, public, control, predecessor.Object)
}

func applyRecipientAdmissionAtSnapshot(q contract.CryptoCompareRequest, current []contract.RecipientRecord, public map[contract.ID]PublicKeyQualifier, control contract.ControlCore, snapshot contract.ID) (bool, map[contract.ID]PublicKeyQualifier, bool) {
	if snapshot.IsZero() || !validApplyCurrentRecipients(current, control) || len(q.Recipients) < len(current) || len(q.Recipients) > contract.CryptoMaxRecipients || len(public) > contract.CryptoMaxRecipients {
		return false, nil, false
	}
	changed, before := false, 0
	qualified := make(map[contract.ID]PublicKeyQualifier, len(public))
	for _, input := range q.Recipients {
		row := input.Recipient
		bindingIndex := applyBindingIndex(q.Bindings, row.RecipientID)
		if row.Status != contract.CurrentRecipient || row.CurrentBinding == nil || bindingIndex < 0 || !sameApplyBinding(*row.CurrentBinding, q.Bindings[bindingIndex].Binding) {
			return false, nil, false
		}
		if before < len(current) && bytes.Compare(current[before].RecipientID[:], row.RecipientID[:]) < 0 {
			return false, nil, false
		}
		if before < len(current) && current[before].RecipientID == row.RecipientID {
			if !sameApplyBinding(*current[before].CurrentBinding, *row.CurrentBinding) {
				return false, nil, false
			}
			changed = changed || !sameApplyRecipient(current[before], row)
			before++
			continue
		}
		proof := input.Creation
		if proof == nil || proof.Snapshot != snapshot {
			return false, nil, false
		}
		id, err := contract.RecipientCreationID(q.Context.DomainID, proof.Snapshot, proof.Nonce)
		if err != nil || id != row.RecipientID {
			return false, nil, false
		}
		binding, incarnation, err := contract.RecipientInitialBindingIDs(q.Context.DomainID, id)
		if err != nil || row.CurrentBinding.BindingID != binding || row.CurrentBinding.BindingIncarnationID != incarnation || row.CurrentBinding.BindingSerial != 1 {
			return false, nil, false
		}
		route := public[id]
		if route == nil || route.Family() != control.Provider || route.CredentialRoute().IsZero() {
			return false, nil, false
		}
		qualified[id] = route
		changed = true
	}
	if before != len(current) || len(qualified) != len(public) {
		return false, nil, false
	}
	return changed, qualified, true
}

func validApplyCurrentRecipients(current []contract.RecipientRecord, control contract.ControlCore) bool {
	if len(current) == 0 || len(current) > contract.CryptoMaxRecipients {
		return false
	}
	registryBytes := 0
	authorityPresent := false
	for i, row := range current {
		n, err := contract.RecipientRecordLength(row)
		if err != nil || row.Status != contract.CurrentRecipient || row.CurrentBinding.Provider != control.Provider || i > 0 && bytes.Compare(current[i-1].RecipientID[:], row.RecipientID[:]) >= 0 || n > contract.MaxPublicRegistryBytes-registryBytes {
			return false
		}
		registryBytes += n
		if row.RecipientID == control.AuthorityRecipientID {
			authorityPresent = sameApplyBinding(*row.CurrentBinding, control.AuthorityKMSBinding)
		}
	}
	return authorityPresent
}

func (a *applyAdmission) qualifyRecipients(ctx context.Context, reply *contract.CryptoResponse) contract.CryptoResultCode {
	for _, input := range a.request.Recipients {
		id := input.Recipient.RecipientID
		route, created := a.recipientPublic[id]
		if !created {
			continue
		}
		if ctx.Err() != nil {
			return contract.CryptoCancelled
		}
		binding := a.request.Bindings[applyBindingIndex(a.request.Bindings, id)]
		result := route.Qualify(ctx, binding.Binding)
		expected := contract.PublicKeyQualificationUseCount(binding.Binding.Provider)
		if expected == 0 || !appendKeyUses(reply, binding, contract.KeyUsePublicKeyRead, result.Uses, uint64(expected)) {
			return contract.CryptoResponseUnknown
		}
		if ctx.Err() != nil {
			return contract.CryptoCancelled
		}
		if result.Status != KeyOK {
			return keyResultCode(result.Status)
		}
		if result.Uses != (KeyUses{Completed: expected}) {
			return contract.CryptoResponseUnknown
		}
	}
	return contract.CryptoSuccess
}

func (a *applyAdmission) candidateRecipientsEqual(rows []contract.RecipientRecord) bool {
	if len(rows) != len(a.request.Recipients) {
		return false
	}
	for i, row := range rows {
		if !sameApplyRecipient(row, a.request.Recipients[i].Recipient) {
			return false
		}
	}
	return true
}
