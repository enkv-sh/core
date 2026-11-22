package configuration

import (
	"bytes"
	"enkv.sh/core/contract"
)

func parseGenerated(p *parser, m *Model) {
	p.provider = m.Provider
	seen := 0
	recipientRows := make(map[string]Recipient)
	secretRows := make(map[string]Entry)
	sealedRaw := 0
	for _, e := range m.Entries {
		sealedRaw += len(e.Plain)
	}
	rootSpan := p.mark(SpanRoot, 0)
	p.object(10, func(k string) {
		switch k {
		case "schema":
			seen |= 1
			if p.text(32, false, false) != "enkv/generated/v2" {
				p.failValue("unsupported-schema")
			}
		case "canonical_records":
			parseCanonicalRecords(p, m)
		case "file_id":
			seen |= 2
			m.FileID = id(p)
		case "domain":
			seen |= 4
			parseGeneratedDomain(p, m)
		case "recipients":
			seen |= 8
			container := p.mark(SpanRecipients, 0)
			p.object(255, func(ref string) {
				span := p.mark(SpanRecipient, uint32(len(recipientRows)))
				span.SourceOffset, span.SourceLength = p.member.SourceOffset, p.member.SourceLength
				r := Recipient{Reference: ref}
				declared := false
				for _, want := range m.Recipients {
					if want.Reference == ref {
						r = want
						declared = true
						break
					}
				}
				mask := 0
				p.object(3, func(k string) {
					switch k {
					case "id":
						mask |= 1
						generatedID := id(p)
						if declared && (r.ID.IsZero() || r.ID != generatedID) {
							p.failValue("recipient-id-mismatch")
						}
						r.ID = generatedID
					case "encryption":
						mask |= 2
						selector := r.Selector
						if m.selectedRecipient != nil && ref == *m.selectedRecipient {
							selector = ""
						}
						r.Encryption = parseKey(p, selector, false)
					case "creation":
						r.Creation = &Creation{}
						s := 0
						p.object(2, func(k string) {
							switch k {
							case "snapshot":
								s |= 1
								r.Creation.Snapshot = id(p)
							case "nonce":
								s |= 2
								r.Creation.Nonce = id(p)
							default:
								p.failMember("unknown-field")
							}
						})
						required(p, s, 3)
					default:
						p.failMember("unknown-field")
					}
				})
				required(p, mask, 3)
				r.GeneratedSpan = p.record(span)
				recipientRows[ref] = r
				generated := r
				generated.Selector = r.Encryption.Selector
				m.GeneratedRecipients = append(m.GeneratedRecipients, generated)
			})
			m.GeneratedRecipientsSpan = p.record(container)
		case "secrets":
			seen |= 16
			secretsSpan := p.mark(SpanSecrets, 0)
			p.object(512, func(name string) {
				m.SecretRowsCount++
				span := p.mark(SpanSecret, uint32(len(secretRows)))
				member := p.member
				e := Entry{Name: name}
				active := false
				for _, wanted := range m.Entries {
					if wanted.Name == name && wanted.Secret && wanted.Generated == nil {
						active = true
						break
					}
				}
				mask := 0
				p.object(1, func(k string) {
					switch k {
					case "sealed":
						mask |= 1
						limit := contract.CryptoMaxSealedInputLength
						e.Sealed = p.base64(limit)
					case "retained":
						mask |= 2
						e.Retained = &Pin{}
						s := 0
						p.object(2, func(k string) {
							switch k {
							case "incarnation":
								s |= 1
								e.Retained.Incarnation = id(p)
							case "material":
								s |= 2
								e.Retained.Material = id(p)
							default:
								p.failMember("unknown-field")
							}
						})
						required(p, s, 3)
					default:
						p.failMember("unknown-field")
					}
				})
				if mask != 1 && mask != 2 {
					p.failContext("missing-secret-input")
				}
				if mask == 1 && p.err == nil {
					if view, err := contract.InspectSealedInputEnvelope(e.Sealed); err != nil {
						p.fail("invalid-sealed-input")
					} else {
						if !bytes.Equal(view.Core.Name, []byte(name)) {
							p.fail("sealed-context-mismatch")
						}
						if active {
							if int(view.Core.ContentLength) > (8<<20)-sealedRaw {
								p.fail("sealed-input-limit")
							} else {
								sealedRaw += int(view.Core.ContentLength)
							}
						}
					}
				}
				if p.err != nil {
					return
				}

				span.SourceOffset = member.Offset
				span.SourceLength = p.end - member.Offset
				e.SecretSpan = p.record(span)
				if m.selected != nil && name == *m.selected {
					m.SelectedSecretSpan, m.SelectedSecretPresent = e.SecretSpan, true
				}
				for _, wanted := range m.Entries {
					if wanted.Name == name && wanted.Secret && wanted.Generated == nil {
						secretRows[name] = e
						break
					}
				}
			})
			m.SecretsSpan = p.record(secretsSpan)
		case "public_basis":
			seen |= 32
			span := p.mark(0, 0)
			parseBasis(p, &m.Basis)
			m.BasisSpan = p.record(span)
		case "replacement":
			span := p.mark(0, 0)
			m.Replacement = parseReplacementMetadata(p)
			m.ReplacementSpan = p.record(span)
		case "maintenance":
			span := p.mark(0, 0)
			m.Maintenance = parseMaintenanceMetadata(p)
			m.MaintenanceSpan = p.record(span)
		case "observation":
			m.Observation = &Observation{}
			s := 0
			p.object(3, func(k string) {
				switch k {
				case "kind":
					s |= 1
					if p.text(32, false, false) != "selected-closure/v1" {
						p.failContext("invalid-observation")
					}
				case "store_configuration":
					s |= 2
					m.Observation.StoreConfiguration = p.base64(4096)
				case "head":
					s |= 4
					m.Observation.Head = p.base64(65536)
				default:
					p.failMember("unknown-field")
				}
			})
			required(p, s, 7)
		default:
			p.failMember("unknown-field")
		}
	})
	m.GeneratedRootSpan = p.record(rootSpan)
	if m.Replacement != nil && !m.Replacement.Request.valid(m.Provider, m.RecoveryEnabled) {
		p.failContext("invalid-replacement")
	}
	required(p, seen, 63)
	ids := map[contract.ID]bool{m.Authority.ID: true}
	for i, r := range m.Recipients {
		row, ok := recipientRows[r.Reference]
		if !ok {
			if m.selectedRecipient != nil && r.Reference == *m.selectedRecipient || m.acceptedWork && r.ID.IsZero() {
				continue
			}
			if p.err == nil {
				p.err = spanDiagnostic(m, r.EditableSpan, "recipients", "missing-prepared-recipient", nil)
			}
			continue
		}
		if ids[row.ID] {
			p.fail("duplicate-recipient-id")
		}
		ids[row.ID] = true
		m.Recipients[i] = row
	}
	for i, e := range m.Entries {
		if e.Secret && e.Generated == nil {
			row, ok := secretRows[e.Name]
			if !ok {
				if m.preparation || m.acceptedWork {
					if m.MissingInputs == nil {
						m.MissingInputs = make([]string, 0, len(m.Entries))
					}
					m.MissingInputs = append(m.MissingInputs, e.Name)
					continue
				}
				if p.err == nil {
					p.err = spanDiagnostic(m, e.EntrySpan, "entries.source", "missing-prepared-secret", nil)
				}
				continue
			}
			m.Entries[i].SecretSpan = row.SecretSpan
			m.Entries[i].Sealed = row.Sealed
			m.Entries[i].Retained = row.Retained
		}
	}
}
func parseGeneratedDomain(p *parser, m *Model) {
	seen := 0
	p.object(3, func(k string) {
		switch k {
		case "id":
			seen |= 1
			m.DomainID = id(p)
		case "authority":
			seen |= 2
			s := 0
			p.object(3, func(k string) {
				switch k {
				case "id":
					s |= 1
					m.Authority.ID = id(p)
				case "signing":
					s |= 2
					m.Authority.Signing = parseKey(p, m.Authority.SigningSelector, true)
				case "encryption":
					s |= 4
					m.Authority.Encryption = parseKey(p, m.Authority.EncryptionSelector, false)
				default:
					p.failMember("unknown-field")
				}
			})
			required(p, s, 7)
		case "recovery":
			seen |= 4
			s := 0
			enabled := false
			p.object(3, func(k string) {
				switch k {
				case "enabled":
					s |= 1
					enabled = p.boolean()
				case "signing":
					s |= 2
					m.Recovery.Signing = parseKey(p, m.Recovery.SigningSelector, true)
				case "encryption":
					s |= 4
					m.Recovery.Encryption = parseKey(p, m.Recovery.EncryptionSelector, false)
				default:
					p.failMember("unknown-field")
				}
			})
			want := 1
			if enabled {
				want = 7
			}
			required(p, s, want)
			if enabled != m.RecoveryEnabled {
				p.failContext("recovery-mode-mismatch")
			}
		default:
			p.failMember("unknown-field")
		}
	})
	required(p, seen, 7)
}
func parseKey(p *parser, selector string, signing bool) Key {
	span := p.mark(SpanKey, 0)
	var k Key
	k.Selector = selector
	seen := 0
	var publicKeyToken Span
	p.object(3, func(field string) {
		switch field {
		case "selector":
			seen |= 1
			actual := p.text(1024, false, false)
			k.Selector = actual
			if !contract.PublicKeySelectorValid(p.provider, actual, signing) {
				p.failValue("invalid-key-selector")
			}
			if selector != "" && actual != selector {
				p.failValue("prepare-selected-key")
			}
		case "public_key":
			seen |= 2
			limit := contract.KMSPublicKeyLength
			if signing {
				limit = contract.MaxPublicKey
			}
			publicKeyToken = p.mark(0, 0)
			k.PublicKey = p.base64(limit)
		case "binding":
			if signing {
				p.failMember("unknown-field")
				return
			}
			seen |= 4
			k.Binding = parseBinding(p)
		default:
			p.failMember("unknown-field")
		}
	})
	want := 7
	if signing {
		want = 3
	}
	required(p, seen, want)
	var err error
	if signing {
		err = contract.ValidateSigningPublicKey(k.PublicKey)
	} else {
		err = contract.ValidateEncryptionPublicKey(k.PublicKey)
	}
	if err != nil {
		p.failFieldValue("invalid-public-key", "public_key", publicKeyToken)
	}
	k.GeneratedSpan = p.record(span)
	return k
}
func parseBinding(p *parser) Binding {
	var b Binding
	seen := 0
	p.object(4, func(k string) {
		switch k {
		case "id":
			seen |= 1
			b.ID = id(p)
		case "incarnation":
			seen |= 2
			b.Incarnation = id(p)
		case "serial":
			seen |= 4
			b.Serial = p.integer()
			if b.Serial == 0 {
				p.failValue("invalid-binding-serial")
			}
		case "protection":
			seen |= 8
			switch p.text(8, false, false) {
			case "hardware":
				b.Protection = contract.HardwareProtection
			case "software":
				b.Protection = contract.SoftwareProtection
			default:
				p.failValue("invalid-protection")
			}
		default:
			p.failMember("unknown-field")
		}
	})
	required(p, seen, 15)
	return b
}
func parseBasis(p *parser, b *Basis) {
	seen := 0
	kind := ""
	p.object(10, func(k string) {
		switch k {
		case "kind":
			seen |= 1
			kind = p.text(11, false, false)
		case "descriptor":
			seen |= 2
			b.Descriptor = p.base64(contract.GenesisDescriptorLimit)
		case "control":
			seen |= 4
			b.Control = p.base64(contract.ControlCoreMaxLength)
		case "selection":
			seen |= 8
			b.Selection = p.base64(contract.MaxHeadLength)
		case "anchor":
			seen |= 32
			b.SigningAnchor = p.base64(contract.PublicSigningBindingMaxLength)
		case "store_configuration":
			seen |= 64
			b.StoreConfiguration = p.base64(contract.MaxStoreConfigurationLength)
		case "head":
			seen |= 128
			b.HEAD = p.base64(contract.MaxHeadLength)
		case "root":
			seen |= 256
			b.Root = p.base64(contract.MaxRootLength)
		case "recipient_pages":
			seen |= 512
			p.array(contract.MaxRecipientPages, func(_ int) {
				page := p.base64(contract.MaxRecipientPageLength)
				if len(page) == 0 {
					p.failContext("empty-basis")
				}
				if p.err == nil {
					b.RecipientPages = append(b.RecipientPages, page)
				}
			})
		case "enrollment":
			seen |= 16
			ids := map[contract.ID]bool{}
			p.array(256, func(_ int) {
				row := Enrollment{}
				mask := 0
				p.object(3, func(k string) {
					switch k {
					case "id":
						mask |= 1
						row.ID = id(p)
					case "status":
						mask |= 2
						switch p.text(7, false, false) {
						case "current":
							row.Status = contract.CurrentRecipient
						case "retired":
							row.Status = contract.RetiredRecipient
						default:
							p.failValue("invalid-enrollment-status")
						}
					case "display_name":
						mask |= 4
						row.DisplayName = p.text(256, false, false)
					default:
						p.failMember("unknown-field")
					}
				})
				required(p, mask, 7)
				if ids[row.ID] {
					p.fail("duplicate-enrollment-id")
				}
				ids[row.ID] = true
				b.Enrollment = append(b.Enrollment, row)
			})
		default:
			p.failMember("unknown-field")
		}
	})
	switch kind {
	case "genesis":
		required(p, seen, 3)
		if len(b.Descriptor) == 0 {
			p.failContext("empty-basis")
		}
	case "successor":
		required(p, seen, 29)
		if len(b.Control) == 0 || len(b.Selection) == 0 || len(b.Enrollment) == 0 {
			p.failContext("empty-basis")
		}
	case "observation":
		required(p, seen, 993)
		if len(b.SigningAnchor) == 0 || len(b.StoreConfiguration) == 0 || len(b.HEAD) == 0 || len(b.Root) == 0 || len(b.RecipientPages) == 0 {
			p.failContext("empty-basis")
		}
	default:
		p.fail("invalid-basis")
	}
}
func join(m *Model) error {
	sortedEntries(m)
	if err := resolveCanonicalSettings(m); err != nil {
		return err
	}
	if !m.Resolved {
		return RefreshPublic(m)
	}
	var raw int
	for _, e := range m.Entries {
		raw += int(e.ContentLength)
		if len(e.Sealed) > 0 {
			v, err := contract.InspectSealedInputEnvelope(e.Sealed)
			if err != nil || v.Core.DomainID != m.DomainID || v.Core.FileIdentity != m.FileID || v.Core.InputEncoding != e.InputEncoding || !bytes.Equal(v.Core.Name, []byte(e.Name)) {
				return sourceError("entries.source", "sealed-context-mismatch")
			}
			raw += int(v.Core.ContentLength)
		}
	}
	if raw > 8<<20 {
		return sourceError("entries", "raw-value-limit")
	}
	if m.Observation != nil {
		s, e := contract.DecodeStoreConfiguration(m.Observation.StoreConfiguration)
		if e != nil || s.DomainID != m.DomainID || s.Provider != m.Provider || s.Region != m.Store.Region || s.Bucket != m.Store.Bucket || s.PrefixBeforeHEAD != m.Store.PrefixBeforeHEAD || s.ExpectedOwner != m.Store.ExpectedOwner {
			return sourceError("observation.store_configuration", "store-mismatch")
		}
	}
	return RefreshPublic(m)
}
