package core

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func installedApplyTestConfiguration(t testing.TB, ctx context.Context, selected *StateSession, input []ApplyEntryInput, desired []contract.ApplyRecipientInput, validator *PublicConfigurationValidator) contract.PublicConfiguration {
	t.Helper()
	source, ok := selected.store.(contract.StoreConfigurationSource)
	if !ok {
		t.Fatal("installed apply fixture has no Store configuration")
	}
	projected, failure := projectSelectedPublicConfiguration(ctx, selected.selectedImage(), selected.selectedObjectReader(), source.StoreConfiguration(), selected.admission.recipient, validator)
	if failure.Outcome != 0 || !projected.Valid || !projected.Complete {
		t.Fatal("installed apply fixture projection", failure.Result, projected.Diagnostics)
	}
	configuration := projected.Configuration
	prior := configuration.Entries.Value
	entries := make([]contract.PublicEntry, len(input))
	for i, row := range input {
		entry := contract.PublicEntry{Name: row.Name, Class: observedPublicField(row.ConfidentialityClass), Source: observedPublicField(row.ValueSource), InputEncoding: observedPublicField(row.InputEncoding), OutputEncoding: observedPublicField(row.OutputEncoding), Memberships: observedPublicField(slices.Clone(row.Recipients))}
		if row.ConfidentialityClass == contract.Plain {
			entry.PlainValue = observedPublicField(slices.Clone(row.InputBytes))
		}
		if row.Generated != nil {
			entry.Generated = installedGeneratedPublicSettings(row.Generated)
		} else if row.ValueSource == contract.Generated {
			for _, old := range prior {
				if old.Name == row.Name {
					entry.Generated = old.Generated
				}
			}
		}
		entries[i] = entry
	}
	configuration.Entries = observedPublicField(entries)
	recipients := make([]contract.PublicRecipient, len(desired))
	for i, input := range desired {
		row := input.Recipient
		recipients[i] = contract.PublicRecipient{RecipientID: row.RecipientID, DisplayName: observedPublicField(row.DisplayName), Encryption: observedPublicEncryption(*row.CurrentBinding)}
	}
	configuration.Recipients = observedPublicField(recipients)
	return configuration
}
