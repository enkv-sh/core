package configuration

import (
	"context"
	"errors"
	"slices"

	"enkv.sh/core/contract"
)

// MergeReconstructedCompanion consumes both models, including on failure.
// Success transfers the surviving declaration and recovered backing into the
// returned model. The caller must independently authenticate recovered facts;
// this join grants no domain authority and changes no source bytes.
func MergeReconstructedCompanion(ctx context.Context, source, recovered *Model) (merged *Model, resultErr error) {
	defer func() {
		if resultErr != nil {
			releaseReconstructionModel(source)
		}
		releaseReconstructionModel(recovered)
	}()
	if ctx == nil || source == nil || recovered == nil || source == recovered || source.Resolved || !recovered.Resolved || recovered.FileID.IsZero() || recovered.DomainID.IsZero() {
		return nil, ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	if err := source.parsedPair.validateCaptured(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	if source.parsedPair.Generated != nil || source.Generated == "" || source.Generated != recovered.Generated || source.DomainName != recovered.DomainName {
		return nil, sourceError("generated", "domain-name-reference-mismatch")
	}
	if source.Provider != recovered.Provider || source.Store != recovered.Store {
		return nil, sourceError("domain.store", "store-mismatch")
	}
	if source.Authority.SigningSelector != recovered.Authority.SigningSelector || source.Authority.EncryptionSelector != recovered.Authority.EncryptionSelector {
		return nil, sourceError("domain.authority", "prepare-selected-key")
	}
	if source.RecoveryEnabled != recovered.RecoveryEnabled {
		return nil, sourceError("domain.recovery", "recovery-mode-mismatch")
	}
	if source.RecoveryEnabled && (source.Recovery.SigningSelector != recovered.Recovery.SigningSelector || source.Recovery.EncryptionSelector != recovered.Recovery.EncryptionSelector) {
		return nil, sourceError("domain.recovery", "prepare-selected-key")
	}
	for i := range source.Recipients {
		row := &source.Recipients[i]
		match := func(candidate Recipient) bool { return !row.ID.IsZero() && candidate.ID == row.ID }
		var current Recipient
		if at := slices.IndexFunc(recovered.Recipients, match); at >= 0 {
			current = recovered.Recipients[at]
		} else {
			at := slices.IndexFunc(recovered.GeneratedRecipients, func(candidate Recipient) bool {
				return candidate.Creation != nil && match(candidate)
			})
			if at < 0 {
				return nil, spanDiagnostic(source, row.EditableSpan, "recipients", "missing-prepared-recipient", nil)
			}
			current = recovered.GeneratedRecipients[at]
			id, err := contract.RecipientCreationID(recovered.DomainID, current.Creation.Snapshot, current.Creation.Nonce)
			binding, incarnation, bindingErr := contract.RecipientInitialBindingIDs(recovered.DomainID, row.ID)
			if err != nil || bindingErr != nil || id != row.ID || current.Encryption.Binding.ID != binding ||
				current.Encryption.Binding.Incarnation != incarnation || current.Encryption.Binding.Serial != 1 {
				return nil, spanDiagnostic(source, row.EditableSpan, "recipients", "missing-prepared-recipient", nil)
			}
		}
		if row.Selector != current.Encryption.Selector {
			return nil, spanDiagnostic(source, row.SelectorSpan, "recipients.item.encryption_key", "prepare-selected-key", nil)
		}
		row.Encryption, row.Creation = current.Encryption, current.Creation
	}
	for i := range source.Entries {
		entry := &source.Entries[i]
		at := slices.IndexFunc(recovered.Entries, func(current Entry) bool { return current.Name == entry.Name })
		if entry.Secret && entry.Generated == nil {
			if at < 0 {
				if source.MissingInputs == nil {
					source.MissingInputs = make([]string, 0, len(source.Entries))
				}
				source.MissingInputs = append(source.MissingInputs, entry.Name)
				continue
			}
			current := recovered.Entries[at]
			if current.InputEncoding != entry.InputEncoding || !current.Secret || current.Generated != nil || current.Retained == nil || current.Retained.Incarnation.IsZero() || current.Retained.Material.IsZero() || len(current.Sealed) != 0 {
				return nil, spanDiagnostic(source, entry.EntrySpan, "entries.source", "sealed-context-mismatch", nil)
			}
			entry.Retained, entry.Sealed = current.Retained, nil
		}
		if entry.Generated != nil && entry.Generated.canonicalSettings != nil {
			if at < 0 || recovered.Entries[at].Generated == nil {
				return nil, spanDiagnostic(source, entry.EntrySpan, "entries.source.canonical", "missing-required-field", nil)
			}
			current := recovered.Entries[at].Generated
			entry.Generated.canonicalRecord = current.canonicalRecord
			if entry.Generated.canonicalRecord == nil {
				entry.Generated.canonicalRecord = current.Intent
			}
		}
	}
	for i := range source.Outputs {
		binding := &source.Outputs[i]
		if binding.canonicalSettings == nil {
			continue
		}
		at := slices.IndexFunc(recovered.Outputs, func(current OutputBinding) bool { return current.DestinationID == binding.DestinationID })
		if at < 0 {
			return nil, sourceError("outputs.destinations.canonical", "missing-required-field")
		}
		current := recovered.Outputs[at]
		binding.canonicalRecord = current.canonicalRecord
		if binding.canonicalRecord == nil {
			var err error
			binding.canonicalRecord, err = contract.EncodeNormalOutputBinding(current.Binding)
			if err != nil {
				return nil, errors.Join(ErrEdit, err)
			}
		}
		binding.Binding = current.Binding
	}
	source.FileID, source.DomainID = recovered.FileID, recovered.DomainID
	source.Authority.ID, source.Authority.Signing, source.Authority.Encryption = recovered.Authority.ID, recovered.Authority.Signing, recovered.Authority.Encryption
	if source.RecoveryEnabled {
		source.Recovery.ID, source.Recovery.Signing, source.Recovery.Encryption = recovered.Recovery.ID, recovered.Recovery.Signing, recovered.Recovery.Encryption
	}
	source.Basis, recovered.Basis = recovered.Basis, Basis{}
	source.Observation, recovered.Observation = recovered.Observation, nil
	source.Resolved = true
	source.preparation = true
	if err := resolveCanonicalSettings(source); err != nil {
		return nil, err
	}
	if err := RefreshPublic(source); err != nil {
		return nil, err
	}
	slices.Sort(source.MissingInputs)
	return source, nil
}
