package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

var ErrReconstructionConfiguration = errors.New("reconstruction configuration refused")

// ReconstructionConfigurationOptions supplies local syntax and a fresh sealing
// identity. These fields cannot select or authenticate a domain or a key.
type ReconstructionConfigurationOptions struct {
	Name   string
	FileID contract.ID
}

// ReconstructionConfiguration normalizes a complete authenticated observation
// with separately retained trust. The caller owns projection and basis. It
// installs no files, credentials, dependencies or operation capability. Emit the
// returned model only through the shared configuration writer's staging path.
func ReconstructionConfiguration(ctx context.Context, projection *core.ReconstructionProjection, basis core.PublicBasis, options ReconstructionConfigurationOptions) (*configuration.Model, error) {
	owned, err := basis.OwnedCopy()
	if err != nil {
		call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationParse)
		call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
		call.Finish(telemetry.ResultWriteRefused)
		return nil, errors.Join(ErrReconstructionConfiguration, err)
	}
	return reconstructionConfigurationOwned(ctx, projection, owned, options)
}

// Ownership transfers at entry, including failure. Success transfers the basis
// directly into the returned model; failure clears its byte backing.
func reconstructionConfigurationOwned(ctx context.Context, projection *core.ReconstructionProjection, basis core.PublicBasis, options ReconstructionConfigurationOptions) (model *configuration.Model, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationParse)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	defer func() {
		result := telemetry.ResultSuccess
		if resultErr != nil {
			result = telemetry.ResultWriteRefused
			clearReconstructionBasis(&basis)
		}
		call.Finish(result)
	}()
	if ctx == nil || ctx.Err() != nil || options.FileID.IsZero() {
		return nil, ErrReconstructionConfiguration
	}
	ctx = telemetry.CallContext(ctx, call)
	if err := projection.CheckPublicBasis(ctx, basis); err != nil {
		return nil, errors.Join(ErrReconstructionConfiguration, err)
	}
	before, ok := projection.Provenance()
	if !ok {
		return nil, ErrReconstructionConfiguration
	}
	reference, err := configuration.GeneratedPath(options.Name)
	if err != nil {
		return nil, ErrReconstructionConfiguration
	}
	m := &configuration.Model{DomainID: before.Domain, FileID: options.FileID, DomainName: options.Name, Generated: reference, Resolved: true,
		Basis: configurationReplacementBasis(basis), Observation: &configuration.Observation{}}
	var root format.Root
	var entries []contract.ValueEntry
	var recipients []contract.RecipientRecord
	outputs := map[uint16]int{}
	count := projection.PartCount()
	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, ok := projection.PartInfo(i)
		if !ok {
			return nil, ErrReconstructionConfiguration
		}
		switch info.Kind {
		case core.ReconstructionAccessPagePart, core.ReconstructionIndexPagePart:
			continue
		case core.ReconstructionSupportRowPart:
			if info.SupportKind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
		}
		part, ok := projection.CopyPart(i)
		if !ok {
			return nil, ErrReconstructionConfiguration
		}
		var err error
		switch part.Kind {
		case core.ReconstructionConfigurationPart:
			m.Observation.StoreConfiguration = part.Body
			var stored contract.StoreConfiguration
			stored, err = contract.DecodeStoreConfiguration(part.Body)
			m.Provider = stored.Provider
			m.Store = contract.StoreLocation{Provider: stored.Provider, Region: stored.Region, Bucket: stored.Bucket, PrefixBeforeHEAD: stored.PrefixBeforeHEAD, ExpectedOwner: stored.ExpectedOwner}
		case core.ReconstructionHEADPart:
			m.Observation.Head = part.Body
		case core.ReconstructionRootPart:
			root, err = format.DecodeRoot(part.Body)
		case core.ReconstructionValuePagePart:
			var page format.ValueEntryPage
			page, err = format.DecodeValueEntryPage(part.Body)
			for _, row := range page.Slots {
				if row != nil {
					if row.ConfidentialityClass == contract.Secret {
						row.ValueBytes = nil
					}
					entries = append(entries, *row)
				}
			}
		case core.ReconstructionRecipientPagePart:
			var page format.RecipientPage
			page, err = format.DecodeRecipientPage(part.Body)
			for _, row := range page.Slots {
				if row != nil {
					recipients = append(recipients, *row)
				}
			}
		case core.ReconstructionSupportRowPart:
			switch part.SupportKind {
			case contract.OutputConfigurationSliceSupportKind:
				var slice contract.OutputConfigurationSlice
				slice, err = contract.InspectOutputConfigurationSlice(part.Body)
				if _, duplicate := outputs[slice.SliceIndex]; duplicate {
					return nil, ErrReconstructionConfiguration
				}
				outputs[slice.SliceIndex] = i

			}
		}
		if err != nil {
			return nil, errors.Join(ErrReconstructionConfiguration, err)
		}
	}
	slices.SortFunc(recipients, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	refs := map[contract.ID]string{}
	current := root.CurrentAccess.Core.CurrentControl
	m.Authority.ID = current.AuthorityRecipientID
	m.Authority.SigningSelector = current.NormalSigning.KeySelector
	m.Authority.Signing = reconstructionSigningKey(current.NormalSigning)
	m.RecoveryEnabled = current.Recovery != nil
	if current.Recovery != nil {
		r := current.Recovery
		m.Recovery.SigningSelector = r.Signing.KeySelector
		m.Recovery.Signing = reconstructionSigningKey(r.Signing)
		m.Recovery.EncryptionSelector = r.KMS.KeySelector
		m.Recovery.Encryption = reconstructionEncryptionKey(r.KMS)
	}
	publicRecipients := make([]contract.PublicRecipient, 0, len(recipients))
	for _, row := range recipients {
		if row.Status != contract.CurrentRecipient || row.CurrentBinding == nil {
			return nil, ErrReconstructionConfiguration
		}
		key := reconstructionEncryptionKey(*row.CurrentBinding)
		publicRecipients = append(publicRecipients, contract.PublicRecipient{RecipientID: row.RecipientID, DisplayName: reconstructionField(row.DisplayName), Encryption: reconstructionPublicEncryption(*row.CurrentBinding)})
		if row.RecipientID == m.Authority.ID {
			m.Authority.DisplayName = row.DisplayName
			m.Authority.Encryption = key
			m.Authority.EncryptionSelector = key.Selector
			continue
		}
		ref := "r" + strconv.Itoa(len(m.Recipients))
		refs[row.RecipientID] = ref
		m.Recipients = append(m.Recipients, configuration.Recipient{Reference: ref, DisplayName: row.DisplayName, Selector: key.Selector, ID: row.RecipientID, Encryption: key})
	}
	m.GeneratedRecipients = slices.Clone(m.Recipients)
	names := map[contract.ID]string{}
	publicEntries := make([]contract.PublicEntry, 0, len(entries))
	for _, e := range entries {
		names[e.Incarnation] = e.Name
		local := configuration.Entry{Name: e.Name, InputEncoding: e.InputEncoding, OutputEncoding: e.OutputEncoding, ContentLength: e.ContentLength, Secret: e.ConfidentialityClass == contract.Secret}
		public := contract.PublicEntry{Name: e.Name, InputEncoding: reconstructionField(e.InputEncoding), OutputEncoding: reconstructionField(e.OutputEncoding), Class: reconstructionField(e.ConfidentialityClass), Source: reconstructionField(e.ValueSource), Memberships: reconstructionField(slices.Clone(e.Recipients))}
		for _, id := range e.Recipients {
			if id == m.Authority.ID {
				continue
			}
			ref, ok := refs[id]
			if !ok {
				return nil, ErrReconstructionConfiguration
			}
			local.Recipients = append(local.Recipients, ref)
		}
		if e.ValueSource == contract.Generated {
			g := e.Generated
			intent, err := projection.CopyGeneratedIntent(ctx, g.IntentDigest)
			if err != nil {
				return nil, err
			}
			canonical, err := contract.InspectGeneratorIntent(intent)
			if err != nil || canonical.ConfigContractID != g.ConfigContractID || canonical.ResourceContractID != g.ResourceContractID || canonical.LifecycleMode != g.LifecycleMode {
				return nil, ErrReconstructionConfiguration
			}
			retirement := ""
			if g.LifecycleMode == contract.GeneratorLifecycleManaged {
				retirement = "manual"
				if g.RetirementMode == contract.GeneratedRetirementAuto {
					retirement = "auto"
				}
			}
			local.Generated = &configuration.Generator{Epoch: g.Epoch, Retirement: retirement, Intent: intent}
			public.Generated = &contract.PublicGeneratedSettings{Epoch: reconstructionField(g.Epoch), ConfigContractID: reconstructionField(g.ConfigContractID), ResourceContractID: reconstructionField(g.ResourceContractID), LifecycleMode: reconstructionField(g.LifecycleMode), ContentIntent: reconstructionField(intent)}
			if g.LifecycleMode == contract.GeneratorLifecycleManaged {
				public.Generated.Retirement = reconstructionField(g.RetirementMode)
				public.Generated.Completion = reconstructionField(g.CompletionClass)
			}
		} else if local.Secret {
			local.Retained = &configuration.Pin{Incarnation: e.Incarnation, Material: e.ValueState}
		} else {
			if len(e.ValueBytes) != 0 {
				local.Plain = e.ValueBytes
			}
			public.PlainValue = reconstructionField(local.Plain)
		}
		m.Entries = append(m.Entries, local)
		publicEntries = append(publicEntries, public)
	}
	m.Public = contract.PublicConfiguration{Store: contract.PublicStoreSettings{DomainID: reconstructionField(m.DomainID), Provider: reconstructionField(m.Provider), ConstructionProfile: reconstructionField(contract.StoreConstructionProfile), Region: reconstructionField(m.Store.Region), Bucket: reconstructionField(m.Store.Bucket), Prefix: reconstructionField(m.Store.PrefixBeforeHEAD), ExpectedOwner: reconstructionField(m.Store.ExpectedOwner)}, Authority: contract.PublicAuthoritySettings{RecipientID: reconstructionField(m.Authority.ID), Signing: reconstructionPublicSigning(current.NormalSigning)}, Recovery: contract.PublicRecoverySettings{Enabled: reconstructionField(m.RecoveryEnabled)}, Recipients: reconstructionField(publicRecipients), Entries: reconstructionField(publicEntries), OutputBindings: reconstructionField([]contract.PublicOutputBinding{}), Groups: reconstructionField[[][]string](nil), Routing: reconstructionField([]contract.PublicRoutingRule{})}
	if current.Recovery != nil {
		signing, encryption := reconstructionPublicSigning(current.Recovery.Signing), reconstructionPublicEncryption(current.Recovery.KMS)
		m.Public.Recovery.Signing = &signing
		m.Public.Recovery.Encryption = &encryption
	}
	if err := reconstructionOutputs(m, root.OutputConfiguration, projection, outputs, names); err != nil {
		return nil, err
	}
	validated := validateInstalledConfiguration(ctx, m.Public)
	if !validated.Valid || !validated.Complete || !validated.DiagnosticsComplete {
		return nil, ErrReconstructionConfiguration
	}
	m.Public = validated.Configuration
	// Stage enforces the pair limit on the generated companion and the
	// requested editable representation, including a preserved source file.
	after, ok := projection.Provenance()
	if !ok || after != before || ctx.Err() != nil {
		return nil, ErrReconstructionConfiguration
	}
	return m, nil
}

func reconstructionField[T any](value T) contract.PublicField[T] {
	return contract.PublicField[T]{State: contract.PublicPresent, Value: value}
}
func reconstructionEncryptionKey(b contract.KMSBinding) configuration.Key {
	return configuration.Key{Selector: b.KeySelector, PublicKey: bytes.Clone(b.SPKI), Binding: configuration.Binding{ID: b.BindingID, Incarnation: b.BindingIncarnationID, Serial: b.BindingSerial, Protection: b.ProtectionClass}}
}
func reconstructionSigningKey(b contract.PublicSigningBinding) configuration.Key {
	return configuration.Key{Selector: b.KeySelector, PublicKey: bytes.Clone(b.SPKI)}
}
func reconstructionPublicEncryption(b contract.KMSBinding) contract.PublicEncryptionSettings {
	return contract.PublicEncryptionSettings{Provider: reconstructionField(b.Provider), Selector: reconstructionField(b.KeySelector), PublicKey: reconstructionField(b.SPKI), Fingerprint: reconstructionField(b.Fingerprint), WrapProfile: reconstructionField(b.WrapProfile), ProtectionClass: reconstructionField(b.ProtectionClass)}
}
func reconstructionPublicSigning(b contract.PublicSigningBinding) contract.PublicSigningSettings {
	return contract.PublicSigningSettings{Provider: reconstructionField(b.Provider), Selector: reconstructionField(b.KeySelector), PublicKey: reconstructionField(b.SPKI), Fingerprint: reconstructionField(b.Fingerprint), Role: reconstructionField(b.Role), Profile: reconstructionField(b.SigningProfile)}
}

func reconstructionOutputs(m *configuration.Model, descriptor contract.OutputConfigurationDescriptor, projection *core.ReconstructionProjection, parts map[uint16]int, names map[contract.ID]string) error {
	name := func(id contract.ID) (string, error) {
		value, ok := names[id]
		if !ok {
			return "", ErrReconstructionConfiguration
		}
		return value, nil
	}
	visit := contract.OutputConfigurationVisit{
		Binding: func(_ contract.ID, id string, d contract.OutputDestination) error {
			row := contract.PublicOutputBinding{DestinationID: id, Destination: reconstructionField(d), Targets: reconstructionField([]contract.PublicOutputTarget{})}
			m.Public.OutputBindings.Value = append(m.Public.OutputBindings.Value, row)
			m.Outputs = append(m.Outputs, configuration.OutputBinding{DestinationID: id, Binding: contract.NormalOutputBinding{DestinationID: id, Destination: d, Targets: []contract.NormalOutputTarget{}}})
			return nil
		},
		TargetFields: func(_ contract.ID, destination string, target contract.OutputTarget) error {
			entry, err := name(target.EntryIncarnationID)
			if err != nil || len(m.Public.OutputBindings.Value) == 0 {
				return ErrReconstructionConfiguration
			}
			binding := &m.Public.OutputBindings.Value[len(m.Public.OutputBindings.Value)-1]
			if binding.DestinationID != destination {
				return ErrReconstructionConfiguration
			}
			binding.Targets.Value = append(binding.Targets.Value, reconstructionPublicTarget(entry, target))
			target.EntryIncarnationID = contract.ID{}
			local := &m.Outputs[len(m.Outputs)-1]
			if local.DestinationID != destination {
				return ErrReconstructionConfiguration
			}
			local.Binding.Targets = append(local.Binding.Targets, contract.NormalOutputTarget{Name: entry, Target: target})
			return nil
		},
		Group: func(ids []contract.ID) error {
			members := make([]string, len(ids))
			for i, id := range ids {
				value, err := name(id)
				if err != nil {
					return err
				}
				members[i] = value
			}
			slices.Sort(members)
			m.Public.Groups.Value = append(m.Public.Groups.Value, members)
			return nil
		},
		Route: func(entry contract.ID, destinations []string) error {
			local := configuration.Route{Default: entry.IsZero(), Destinations: slices.Clone(destinations)}
			key := contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}
			if !entry.IsZero() {
				value, err := name(entry)
				if err != nil {
					return err
				}
				key.EntrySelector = contract.PublicNamedEntry
				key.EntryName = value
				local.EntryName = value
			}
			m.Routes = append(m.Routes, local)
			m.Public.Routing.Value = append(m.Public.Routing.Value, contract.PublicRoutingRule{Key: key, Destinations: reconstructionField(slices.Clone(destinations))})
			return nil
		},
	}
	err := contract.VisitOutputConfigurationSource(m.DomainID, descriptor, func(index uint16) (contract.OutputConfigurationSlice, error) {
		partIndex, ok := parts[index]
		if !ok {
			return contract.OutputConfigurationSlice{}, ErrReconstructionConfiguration
		}
		part, ok := projection.CopyPart(partIndex)
		if !ok {
			return contract.OutputConfigurationSlice{}, ErrReconstructionConfiguration
		}
		return contract.InspectOutputConfigurationSlice(part.Body)
	}, visit)
	if err != nil {
		return err
	}
	for i := range m.Outputs {
		slices.SortFunc(m.Outputs[i].Binding.Targets, func(a, b contract.NormalOutputTarget) int { return strings.Compare(a.Name, b.Name) })
	}
	return nil
}

func reconstructionPublicTarget(name string, target contract.OutputTarget) contract.PublicOutputTarget {
	return contract.PublicOutputTarget{EntryName: name, ServiceContractID: reconstructionField(target.ServiceContractID), TargetContractID: reconstructionField(target.TargetContractID), CanonicalTarget: reconstructionField(target.CanonicalTarget), ConsumerLocator: reconstructionField(target.ConsumerLocator), TargetData: reconstructionField(target.TargetData), PayloadEncoding: reconstructionField(target.PayloadEncoding), LocatorRequiresCreation: reconstructionField(target.LocatorRequiresCreation), Capabilities: reconstructionField(target.Capabilities), CreateValueBounds: reconstructionField(target.CreateValueBounds), WriteValueBounds: reconstructionField(target.WriteValueBounds), ConsumerPolicy: reconstructionField(target.Policy)}
}

func clearReconstructionBasis(basis *core.PublicBasis) {
	for _, body := range [][]byte{basis.Descriptor, basis.Control, basis.Selection, basis.SigningAnchor, basis.StoreConfiguration, basis.HEAD, basis.Root} {
		clear(body)
	}
	for _, page := range basis.RecipientPages {
		clear(page)
	}
	clear(basis.Enrollment)
	*basis = core.PublicBasis{}
}
