package core

import (
	"context"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"slices"
	"strings"
)

func observedPublicField[T any](value T) contract.PublicField[T] {
	return contract.PublicField[T]{State: contract.PublicPresent, Value: value}
}
func observedPublicEncryption(b contract.KMSBinding) contract.PublicEncryptionSettings {
	return contract.PublicEncryptionSettings{Provider: observedPublicField(b.Provider), Selector: observedPublicField(strings.Clone(b.KeySelector)), PublicKey: observedPublicField(ownPublicSlice(b.SPKI)), Fingerprint: observedPublicField(b.Fingerprint), WrapProfile: observedPublicField(b.WrapProfile), ProtectionClass: observedPublicField(b.ProtectionClass)}
}
func observedPublicSigning(b contract.PublicSigningBinding) contract.PublicSigningSettings {
	return contract.PublicSigningSettings{Provider: observedPublicField(b.Provider), Selector: observedPublicField(strings.Clone(b.KeySelector)), PublicKey: observedPublicField(ownPublicSlice(b.SPKI)), Fingerprint: observedPublicField(b.Fingerprint), Role: observedPublicField(b.Role), Profile: observedPublicField(b.SigningProfile)}
}

// projectPublicConfiguration owns one semantic projection. Selected pages stay
// immutable; output visitor policy backing transfers directly into this owner.
func (e *ReaderEngine) projectPublicConfiguration(ctx context.Context, selected publicSelection) (PublicConfigurationValidation, readerFailure) {
	if !selected.complete {
		return PublicConfigurationValidation{}, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
	}
	return projectSelectedPublicConfiguration(ctx, &selected.image, selected.basis.reader, selected.basis.anchor.configuration, selected.authorityID, e.validator)
}

func projectSelectedPublicConfiguration(ctx context.Context, image *selectedImage, reader selectedObjectReader, stored contract.StoreConfiguration, authorityID contract.ID, validator *PublicConfigurationValidator) (PublicConfigurationValidation, readerFailure) {
	var empty PublicConfigurationValidation
	input := contract.PublicConfiguration{
		Store:      contract.PublicStoreSettings{DomainID: observedPublicField(stored.DomainID), Provider: observedPublicField(stored.Provider), ConstructionProfile: observedPublicField(stored.ConstructionProfile), Region: observedPublicField(strings.Clone(stored.Region)), Bucket: observedPublicField(strings.Clone(stored.Bucket)), Prefix: observedPublicField(strings.Clone(stored.PrefixBeforeHEAD)), ExpectedOwner: observedPublicField(strings.Clone(stored.ExpectedOwner))},
		Authority:  contract.PublicAuthoritySettings{RecipientID: observedPublicField(authorityID), Signing: observedPublicSigning(image.root.CurrentAccess.Core.NormalSigning)},
		Recovery:   contract.PublicRecoverySettings{Enabled: observedPublicField(image.root.CurrentAccess.Core.Recovery != nil)},
		Entries:    observedPublicField(make([]contract.PublicEntry, len(image.root.Names))),
		Recipients: observedPublicField(make([]contract.PublicRecipient, 0, image.root.RecipientCount)),
	}
	if r := image.root.CurrentAccess.Core.Recovery; r != nil {
		signing, encryption := observedPublicSigning(r.Signing), observedPublicEncryption(r.KMS)
		input.Recovery.Signing = &signing
		input.Recovery.Encryption = &encryption
	}
	names := make(map[contract.ID]string, len(image.root.Names))
	var content *generatedContent
	for i, row := range image.root.Names {
		if ctx.Err() != nil {
			return empty, readerRefusal(contract.ReasonCancelled)
		}
		entry := image.valueEntry(row.Slot)
		if entry == nil {
			return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
		}
		names[entry.Incarnation] = row.Name
		projected := contract.PublicEntry{Name: strings.Clone(row.Name), Class: observedPublicField(entry.ConfidentialityClass), Source: observedPublicField(entry.ValueSource), InputEncoding: observedPublicField(entry.InputEncoding), OutputEncoding: observedPublicField(entry.OutputEncoding), Memberships: observedPublicField(ownPublicSlice(entry.Recipients))}
		if entry.ConfidentialityClass == contract.Plain {
			projected.PlainValue = observedPublicField(ownPublicSlice(entry.ValueBytes))
		}
		if entry.ValueSource == contract.Generated {
			g := entry.Generated
			if content == nil {
				var err error
				content, err = selectedGeneratedContent(image)
				if err != nil {
					return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
				}
			}
			var readResult Result
			intent, err := content.readSelectedSlice(ctx, contract.GeneratorContentIntent, g.IntentDigest, contract.GeneratorIntentMaxLength, func(ctx context.Context, loc format.FragmentLocation, consume func([]byte) error) (Result, error) {
				r, err := withSelectedFragmentFromImage(ctx, image, reader, loc, consume)
				if r.Outcome != 0 {
					readResult = r
				}
				return r, err
			})
			if readResult.Outcome != 0 {
				return empty, readerSelectionFailure(readResult)
			}
			if err != nil {
				return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
			}
			projected.Generated = &contract.PublicGeneratedSettings{Epoch: observedPublicField(g.Epoch), ConfigContractID: observedPublicField(g.ConfigContractID), ResourceContractID: observedPublicField(g.ResourceContractID), LifecycleMode: observedPublicField(g.LifecycleMode), ContentIntent: observedPublicField(intent)}
			if g.LifecycleMode == contract.GeneratorLifecycleManaged {
				projected.Generated.Retirement = observedPublicField(g.RetirementMode)
				projected.Generated.Completion = observedPublicField(g.CompletionClass)
			}

		}
		input.Entries.Value[i] = projected
	}
	for _, page := range image.recipients {
		if page == nil {
			continue
		}
		for _, r := range page.Slots {
			if r == nil {
				continue
			}
			if r.Status != contract.CurrentRecipient || r.CurrentBinding == nil {
				return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
			}
			input.Recipients.Value = append(input.Recipients.Value, contract.PublicRecipient{RecipientID: r.RecipientID, DisplayName: observedPublicField(strings.Clone(r.DisplayName)), Encryption: observedPublicEncryption(*r.CurrentBinding)})
		}
	}
	counts := make(map[string]int, int(image.root.OutputConfiguration.BindingCount))
	routeCount, groupCount := 0, 0
	count := contract.OutputConfigurationVisit{Target: func(_, entry, _ contract.ID, destination string) error {
		if _, ok := names[entry]; !ok {
			return contract.ErrRecord
		}
		counts[destination]++
		return nil
	}, Group: func(_ []contract.ID) error {
		groupCount++
		return nil
	}, Route: func(entry contract.ID, _ []string) error {
		if !entry.IsZero() {
			if _, ok := names[entry]; !ok {
				return contract.ErrRecord
			}
		}
		routeCount++
		return nil
	}}
	if _, r := selectedOutputConfigurationWithReader(ctx, image.root, image.supportFacts, reader, false, &count); r.Outcome != 0 {
		return empty, readerSelectionFailure(r)
	}
	input.OutputBindings = observedPublicField(make([]contract.PublicOutputBinding, 0, image.root.OutputConfiguration.BindingCount))
	input.Groups = observedPublicField(make([][]string, 0, groupCount))
	input.Routing = observedPublicField(make([]contract.PublicRoutingRule, 0, routeCount))
	visit := contract.OutputConfigurationVisit{
		Binding: func(_ contract.ID, destination string, facts contract.OutputDestination) error {
			row := contract.PublicOutputBinding{DestinationID: destination, Destination: observedPublicField(facts), Targets: observedPublicField(make([]contract.PublicOutputTarget, 0, counts[destination]))}

			input.OutputBindings.Value = append(input.OutputBindings.Value, row)
			return nil
		},
		Group: func(members []contract.ID) error {
			group := make([]string, len(members))
			for i, member := range members {
				name, present := names[member]
				if !present {
					return contract.ErrRecord
				}
				group[i] = strings.Clone(name)
			}
			slices.Sort(group)
			input.Groups.Value = append(input.Groups.Value, group)
			return nil
		},
		TargetFields: func(_ contract.ID, destination string, target contract.OutputTarget) error {
			name, ok := names[target.EntryIncarnationID]
			if !ok {
				return contract.ErrRecord
			}
			if len(input.OutputBindings.Value) == 0 || input.OutputBindings.Value[len(input.OutputBindings.Value)-1].DestinationID != destination {
				input.OutputBindings.Value = append(input.OutputBindings.Value, contract.PublicOutputBinding{DestinationID: destination, Targets: observedPublicField(make([]contract.PublicOutputTarget, 0, counts[destination]))})
			}
			binding := &input.OutputBindings.Value[len(input.OutputBindings.Value)-1]
			binding.Targets.Value = append(binding.Targets.Value, publicOutputTarget(name, target))
			return nil
		},
		Route: func(entry contract.ID, destinations []string) error {
			key := contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}
			if !entry.IsZero() {
				name, ok := names[entry]
				if !ok {
					return contract.ErrRecord
				}
				key.EntrySelector = contract.PublicNamedEntry
				key.EntryName = strings.Clone(name)
			}
			input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: key, Destinations: observedPublicField(destinations)})
			return nil
		},
	}
	if _, r := selectedOutputConfigurationWithReader(ctx, image.root, image.supportFacts, reader, false, &visit); r.Outcome != 0 {
		return empty, readerSelectionFailure(r)
	}
	slices.SortFunc(input.Groups.Value, func(a, b []string) int { return slices.Compare(a, b) })
	slices.SortFunc(input.Recipients.Value, func(a, b contract.PublicRecipient) int { return comparePublicIDs(a.RecipientID, b.RecipientID) })
	for i := range input.OutputBindings.Value {
		slices.SortFunc(input.OutputBindings.Value[i].Targets.Value, func(a, b contract.PublicOutputTarget) int { return strings.Compare(a.EntryName, b.EntryName) })
	}
	slices.SortFunc(input.Routing.Value, func(a, b contract.PublicRoutingRule) int { return comparePublicRoutingKeys(a.Key, b.Key) })
	if !publicConfigurationBounded(input) || !publicConfigurationBackingBounded(input) {
		return empty, readerRefusal(contract.ReasonLimitExceeded)
	}
	result := validator.validateOwned(ctx, input, false)
	for i := range result.Diagnostics {
		d := &result.Diagnostics[i]
		if d.Reason != contract.ReasonPublicFactUnavailable && d.Reason != contract.ReasonUnsupportedProfile && d.Reason != contract.ReasonUnsupportedSchema && d.Reason != contract.ReasonCancelled && d.Reason != contract.ReasonExpired && d.Reason != contract.ReasonSelectedRelationInvalid {
			return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
		}
	}
	slices.SortFunc(result.Diagnostics, comparePublicDiagnostics)
	return result, readerFailure{}
}
