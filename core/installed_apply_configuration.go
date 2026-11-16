package core

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// installedApplyInputs consumes the installation's owned public proposal before
// private admission. Only authenticated current payloads can fill generated input.
func (s *StateSession) installedApplyInputs(ctx context.Context, i ApplyInstallation, input []ApplyEntryInput) ([]ApplyEntryInput, *outputApplyInput, Result) {
	if ctx == nil || ctx.Err() != nil || s == nil || i.Store == nil || i.ConfigurationValidator == nil {
		return nil, nil, refused(InvalidIntent)
	}
	if !publicConfigurationBounded(i.PublicConfiguration) || !publicConfigurationBackingBounded(i.PublicConfiguration) {
		return nil, nil, refused(CapacityExceeded)
	}
	limits := publicConfigurationCheck{ctx: ctx, result: PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}}
	if !publicConfigurationInputLimits(&limits, i.PublicConfiguration) {
		return nil, nil, refused(CapacityExceeded)
	}
	desired := i.ConfigurationValidator.validateOwned(ctx, i.PublicConfiguration)
	if !desired.Valid || !desired.Complete || !desired.DiagnosticsComplete || !installedApplyConfigurationCarriers(desired.Configuration, input, i.DesiredRecipients) {
		return nil, nil, refused(InvalidIntent)
	}
	configured, ok := i.Store.(contract.StoreConfigurationSource)
	if !ok || i.Store.Descriptor() != s.admission.store {
		return nil, nil, refused(ConstructionMismatch)
	}
	stored := configured.StoreConfiguration()
	identity, err := contract.StoreConfigurationID(stored)
	if err != nil || identity != s.head.Core.Store || identity != s.admission.store.Identity || stored.DomainID != s.root.Domain || stored.Provider != s.admission.store.Family || stored.PrefixBeforeHEAD != s.admission.store.Prefix {
		return nil, nil, refused(ConstructionMismatch)
	}
	actual, failed := projectSelectedPublicConfiguration(ctx, s.selectedImage(), s.selectedObjectReader(), stored, s.admission.recipient, i.ConfigurationValidator)
	if failed.Outcome != 0 {
		return nil, nil, failed.Result
	}
	if !actual.Valid || !actual.Complete || !actual.DiagnosticsComplete {
		return nil, nil, refused(InvalidIntent)
	}
	comparison := comparePublicConfigurations(ctx, desired, actual)
	if !comparison.DiagnosticsComplete || comparison.Verdict == contract.ComparisonUnable {
		return nil, nil, refused(InvalidIntent)
	}
	for _, change := range comparison.Changes {
		switch change.Subject.Kind {
		case contract.SubjectRecipient, contract.SubjectEntry, contract.SubjectOutputBinding, contract.SubjectOutputTarget, contract.SubjectRoutingRule:
		case contract.SubjectConfiguration:
			if len(change.Path) != 1 || change.Path[0] != contract.FieldGroups {
				return nil, nil, refused(InvalidIntent)
			}
		default:
			return nil, nil, refused(InvalidIntent)
		}
	}
	mapped := slices.Clone(input)
	for at := range mapped {
		entry := &mapped[at]
		if entry.ValueSource != contract.Generated {
			continue
		}
		named := slices.IndexFunc(s.root.Names, func(row format.NameEntry) bool { return row.Name == entry.Name })
		if entry.Retained != nil || entry.Generated == nil {
			return nil, nil, refused(InvalidIntent)
		}
		var current *contract.ValueEntry
		if named >= 0 {
			current = s.valueEntry(s.root.Names[named].Slot)
			if current == nil || current.ConfidentialityClass != contract.Secret {
				return nil, nil, refused(InvalidIntent)
			}
		}
		intent, err := contract.GeneratorIntentDigest(entry.Generated.Intent)
		if err != nil {
			return nil, nil, refused(InvalidIntent)
		}
		plan := contract.GeneratorValueEntryPlan{Epoch: entry.Generated.Epoch, IntentDigest: intent, InputEncoding: entry.InputEncoding}
		if current == nil || current.ValueSource != contract.Generated || plan.Epoch > current.Generated.Epoch {
			plan.ChangeMask = contract.GeneratorValueChangeContent
		}
		if !generatedEpochValid(current, plan, *entry.Generated) {
			if current != nil && current.ValueSource == contract.Generated {
				if plan.Epoch < current.Generated.Epoch {
					return nil, nil, refused(StaleGeneratedEpoch)
				}
				if plan.Epoch == current.Generated.Epoch {
					return nil, nil, refused(GeneratedIntentConflict)
				}
			}
			return nil, nil, refused(InvalidIntent)
		}
		if plan.ChangeMask&contract.GeneratorValueChangeContent != 0 {
			if len(entry.InputBytes) != 0 {
				return nil, nil, refused(InvalidIntent)
			}
			continue
		}
		if len(entry.InputBytes) != 0 && !bytes.Equal(entry.InputBytes, current.ValueBytes) {
			return nil, nil, refused(InvalidIntent)
		}
		entry.InputBytes = current.ValueBytes
	}
	return mapped, publicOutputApplyInput(desired.Configuration), Result{}
}

func installedApplyConfigurationCarriers(configuration contract.PublicConfiguration, input []ApplyEntryInput, recipients []contract.ApplyRecipientInput) bool {
	if len(configuration.Entries.Value) != len(input) || len(configuration.Recipients.Value) != len(recipients) {
		return false
	}
	entries := slices.Clone(input)
	slices.SortFunc(entries, func(a, b ApplyEntryInput) int { return strings.Compare(a.Name, b.Name) })
	for at, row := range configuration.Entries.Value {
		entry := entries[at]
		if row.Name != entry.Name || row.Class.Value != entry.ConfidentialityClass || row.Source.Value != entry.ValueSource || row.InputEncoding.Value != entry.InputEncoding || row.OutputEncoding.Value != entry.OutputEncoding || !slices.Equal(row.Memberships.Value, entry.Recipients) || row.Class.Value == contract.Plain && !bytes.Equal(row.PlainValue.Value, entry.InputBytes) {
			return false
		}
		if row.Generated == nil {
			if entry.Generated != nil {
				return false
			}
			continue
		}
		g, public := entry.Generated, row.Generated
		if g == nil || g.ConfigContractID != public.ConfigContractID.Value || g.ResourceContractID != public.ResourceContractID.Value || g.LifecycleMode != public.LifecycleMode.Value ||
			g.Epoch != public.Epoch.Value || g.RetirementMode != public.Retirement.Value ||
			g.CompletionClass != public.Completion.Value || !bytes.Equal(g.Intent, public.ContentIntent.Value) {
			return false
		}
	}
	registry := slices.Clone(recipients)
	slices.SortFunc(registry, func(a, b contract.ApplyRecipientInput) int {
		return comparePublicIDs(a.Recipient.RecipientID, b.Recipient.RecipientID)
	})
	for at, public := range configuration.Recipients.Value {
		row := registry[at].Recipient
		if row.RecipientID != public.RecipientID || row.Status != contract.CurrentRecipient || row.DisplayName != public.DisplayName.Value || row.CurrentBinding == nil {
			return false
		}
		binding, encryption := row.CurrentBinding, public.Encryption
		if binding.Provider != encryption.Provider.Value || binding.KeySelector != encryption.Selector.Value || !bytes.Equal(binding.SPKI, encryption.PublicKey.Value) || binding.Fingerprint != encryption.Fingerprint.Value || binding.WrapProfile != encryption.WrapProfile.Value || binding.ProtectionClass != encryption.ProtectionClass.Value {
			return false
		}
	}
	return true
}
