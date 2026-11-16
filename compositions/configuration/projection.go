package configuration

import (
	"slices"

	"enkv.sh/core/contract"
)

func encryption(provider contract.Family, key Key) contract.PublicEncryptionSettings {
	return contract.PublicEncryptionSettings{Provider: present(provider), Selector: present(key.Selector), PublicKey: present(key.PublicKey), Fingerprint: present(contract.Hash(key.PublicKey)), WrapProfile: present(contract.RSAOAEPWrapProfile), ProtectionClass: present(key.Binding.Protection)}
}
func signing(provider contract.Family, key Key, role uint8) contract.PublicSigningSettings {
	return contract.PublicSigningSettings{Provider: present(provider), Selector: present(key.Selector), PublicKey: present(key.PublicKey), Fingerprint: present(contract.Hash(key.PublicKey)), Role: present(role), Profile: present(contract.P256SigningProfile)}
}

// RefreshPublic projects available source and normalized facts. It grants no
// installation trust or operation permission. Canonical carriers need no plugin.
func RefreshPublic(m *Model) error {
	if m == nil || len(m.Entries) > contract.CryptoMaxValueEntries || len(m.Outputs) > contract.MaxOutputBindings {
		return ErrCapture
	}
	bindings, err := publicOutputBindings(m)
	if err != nil {
		return err
	}
	public := m.Public
	public.OutputBindings = present(bindings)
	if !m.Resolved {
		m.Public = public
		return nil
	}
	p := &public
	p.Store = contract.PublicStoreSettings{DomainID: present(m.DomainID), Provider: present(m.Provider), ConstructionProfile: present(contract.StoreConstructionProfile), Region: present(m.Store.Region), Bucket: present(m.Store.Bucket), Prefix: present(m.Store.PrefixBeforeHEAD), ExpectedOwner: present(m.Store.ExpectedOwner)}
	p.Authority = contract.PublicAuthoritySettings{RecipientID: present(m.Authority.ID), Signing: signing(m.Provider, m.Authority.Signing, contract.NormalSigningRole)}
	p.Recovery = contract.PublicRecoverySettings{Enabled: present(m.RecoveryEnabled)}
	if m.RecoveryEnabled {
		s := signing(m.Provider, m.Recovery.Signing, contract.RecoverySigningRole)
		e := encryption(m.Provider, m.Recovery.Encryption)
		p.Recovery.Signing = &s
		p.Recovery.Encryption = &e
	}
	recipients := make([]contract.PublicRecipient, 0, len(m.Recipients)+1)
	recipients = append(recipients, contract.PublicRecipient{RecipientID: m.Authority.ID, DisplayName: present(m.Authority.DisplayName), Encryption: encryption(m.Provider, m.Authority.Encryption)})
	references := map[string]contract.ID{}
	for _, r := range m.Recipients {
		references[r.Reference] = r.ID
		recipients = append(recipients, contract.PublicRecipient{RecipientID: r.ID, DisplayName: present(r.DisplayName), Encryption: encryption(m.Provider, r.Encryption)})
	}
	p.Recipients = present(recipients)
	entries := make([]contract.PublicEntry, 0, len(m.Entries))
	intentBytes := 0
	for _, e := range m.Entries {
		class, source := contract.Plain, contract.Supplied
		if e.Secret {
			class = contract.Secret
		}
		if e.Generated != nil {
			source = contract.Generated
		}
		members := make([]contract.ID, 0, len(e.Recipients)+1)
		members = append(members, m.Authority.ID)
		for _, ref := range e.Recipients {
			members = append(members, references[ref])
		}
		row := contract.PublicEntry{Name: e.Name, Class: present(class), Source: present(source), InputEncoding: present(e.InputEncoding), OutputEncoding: present(e.OutputEncoding), Memberships: present(members)}
		if !e.Secret {
			row.PlainValue = present(e.Plain)
		}
		if e.Generated != nil {
			g := e.Generated
			intentBytes += len(g.Intent)
			if intentBytes > contract.MaxPublicGeneratedIntents {
				return sourceError("entries.source", "generator-declaration-limit")
			}
			retirement := contract.GeneratedRetirementManual
			if g.Retirement == "auto" {
				retirement = contract.GeneratedRetirementAuto
			}
			if err := ValidateGeneratorSource(g); err != nil {
				return sourceError("entries.source", "invalid-generator-input")
			}
			row.Generated = &contract.PublicGeneratedSettings{Epoch: present(g.Epoch)}
			if len(g.Intent) == 0 {
				row.Generated.ConfigContractID = unavailable[contract.ID]()
				row.Generated.ResourceContractID = unavailable[contract.ID]()
				row.Generated.LifecycleMode = unavailable[contract.GeneratorLifecycleMode]()
				row.Generated.ContentIntent = unavailable[[]byte]()
				row.Generated.Completion = unavailable[uint8]()
				if g.Retirement != "" {
					row.Generated.Retirement = present(retirement)
				}
			} else {
				intent, err := contract.InspectGeneratorIntent(g.Intent)
				if err != nil {
					return err
				}
				row.Generated.ConfigContractID = present(intent.ConfigContractID)
				row.Generated.ResourceContractID = present(intent.ResourceContractID)
				row.Generated.LifecycleMode = present(intent.LifecycleMode)
				row.Generated.ContentIntent = present(g.Intent)
				if intent.LifecycleMode == contract.GeneratorLifecycleManaged {
					row.Generated.Retirement = present(retirement)
					row.Generated.Completion = present(contract.GeneratedCompletionAcknowledged)
				}
			}
		}
		entries = append(entries, row)
	}
	p.Entries = present(entries)
	routes := make([]contract.PublicRoutingRule, 0, len(m.Routes))
	for _, r := range m.Routes {
		k := contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: r.EntryName}
		if r.Default {
			k.EntrySelector = contract.PublicDefaultRoute
		}
		routes = append(routes, contract.PublicRoutingRule{Key: k, Destinations: present(r.Destinations)})
	}
	p.Routing = present(routes)
	m.Public = public
	return nil
}

func publicOutputBindings(m *Model) ([]contract.PublicOutputBinding, error) {
	var needed map[string]map[string]bool
	if slices.ContainsFunc(m.Outputs, func(source OutputBinding) bool { return source.canonicalRecord != nil }) {
		var err error
		needed, err = outputTargetEntries(m)
		if err != nil {
			return nil, err
		}
	}
	bindings := make([]contract.PublicOutputBinding, 0, len(m.Outputs))
	decoded, targets := 6, 0
	for _, group := range m.Public.Groups.Value {
		decoded += 2 + 32*len(group)
	}
	for _, source := range m.Outputs {
		binding := source.Binding
		targets += len(binding.Targets)
		if len(binding.Targets) > contract.MaxOutputTargetsPerBinding || targets > contract.MaxOutputTargets {
			return nil, sourceError("outputs", "output-target-limit")
		}
		if source.DestinationID != binding.DestinationID || !pluginSelectionValid(source.Plugin) {
			return nil, sourceError("outputs", "binding-name-mismatch")
		}
		row := contract.PublicOutputBinding{DestinationID: source.DestinationID}
		if source.Settings == nil {
			length, err := contract.NormalOutputBindingDeclarationLength(binding)
			if err != nil {
				return nil, sourceError("outputs", "invalid-canonical-binding")
			}
			decoded += length
			row.Destination = present(binding.Destination)
			currentTargets := true
			if source.canonicalRecord != nil {
				// Saved targets describe the earlier route set, not edits to its source.
				currentTargets = len(binding.Targets) == len(needed[source.DestinationID])
				for _, target := range binding.Targets {
					if !needed[source.DestinationID][target.Name] {
						currentTargets = false
						break
					}
				}
			}
			if source.settingsEdited && binding.Targets == nil || !currentTargets {
				row.Targets = unavailable[[]contract.PublicOutputTarget]()
			} else {
				row.Targets = present(publicOutputTargets(binding.Targets))
			}
		} else {
			if source.Plugin == "" || !pluginSelectionValid(source.Plugin) || len(source.Settings) > contract.MaxOutputDestinationSettings || !settingsValid(source.Settings) {
				return nil, sourceError("outputs", "invalid-output-input")
			}
			if binding.Destination.ConfigContractID == "" {
				row.Destination = unavailable[contract.OutputDestination]()
			} else {
				length, err := contract.OutputDestinationLength(binding.Destination)
				if err != nil {
					return nil, err
				}
				decoded += length
				row.Destination = present(binding.Destination)
			}
			row.Targets = unavailable[[]contract.PublicOutputTarget]()
			if binding.Targets != nil {
				row.Targets = present(publicOutputTargets(binding.Targets))
			}
		}
		if decoded > contract.MaxOutputDeclarationBytes {
			return nil, sourceError("outputs", "output-declaration-limit")
		}
		bindings = append(bindings, row)
	}
	return bindings, nil
}

func unavailable[T any]() contract.PublicField[T] {
	return contract.PublicField[T]{State: contract.PublicUnavailable}
}

func publicOutputTargets(targets []contract.NormalOutputTarget) []contract.PublicOutputTarget {
	out := make([]contract.PublicOutputTarget, 0, len(targets))
	for _, named := range targets {
		t := named.Target
		out = append(out, contract.PublicOutputTarget{EntryName: named.Name, ServiceContractID: present(t.ServiceContractID), TargetContractID: present(t.TargetContractID), CanonicalTarget: present(t.CanonicalTarget), ConsumerLocator: present(t.ConsumerLocator), TargetData: present(t.TargetData), PayloadEncoding: present(t.PayloadEncoding), LocatorRequiresCreation: present(t.LocatorRequiresCreation), Capabilities: present(t.Capabilities), CreateValueBounds: present(t.CreateValueBounds), WriteValueBounds: present(t.WriteValueBounds), ConsumerPolicy: present(t.Policy)})
	}
	return out
}
