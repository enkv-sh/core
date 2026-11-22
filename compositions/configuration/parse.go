package configuration

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// ErrSourceInvalid records a positive grammar, shape or native source-layout
// refusal. Unknown intake premises and reader failures do not establish it.
var ErrSourceInvalid = errors.New("configuration source invalid")

func parseEditModel(ctx context.Context, pair *Pair, model *Model) (*Model, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationParse)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	next := telemetry.CallContext(ctx, call)
	if ctx == nil {
		next = nil
	}
	var err error
	if model.selectedRecipient != nil && !referenceValid(*model.selectedRecipient) {
		err = sourceError("recipients", "invalid-selected-reference")
	} else {
		model, err = parsePairModel(next, pair, model)
	}
	if err == nil && (model.selectedRecipient != nil || model.acceptedWork) && !model.Resolved {
		err = sourceError("generated", "restore-exact-generated-file")
		model = nil
	}
	if pair != nil && pair.Editable != nil {
		call.InputBytes(pair.Editable.Size())
		if pair.Generated != nil {
			call.InputBytes(pair.Generated.Size())
		}
	}
	finishSource(call, ctx, err, telemetry.DiagnosticReasonInvalidFormat)
	return model, err
}

func parsePairModel(ctx context.Context, pair *Pair, m *Model) (_ *Model, resultErr error) {
	defer func() {
		var diagnostic *Diagnostic
		if pair != nil && errors.As(resultErr, &diagnostic) {
			image := pair.Editable
			if diagnostic.Generated {
				image = pair.Generated
			}
			resultErr = bindCapturedSourceError(resultErr, image)
		}
	}()
	if ctx == nil || pair == nil || pair.Editable == nil || (pair.Format != JSON && pair.Format != YAML) {
		return nil, ErrCapture
	}
	if err := pair.validateCaptured(); err != nil {
		return nil, err
	}
	if pair.Editable.Size() < 0 || pair.Editable.Size() > MaxPairBytes || pair.Generated != nil && (pair.Generated.Size() < 0 || pair.Generated.Size() > MaxPairBytes-pair.Editable.Size()) {
		return nil, sourceError("generated", "pair-size-limit")
	}
	e := parseEditableModel(ctx, pair.Editable, pair.Format, m)
	if e != nil {
		return nil, e
	}
	if m.Generated == "" && pair.Generated != nil {
		return nil, sourceError("generated", "undeclared-generated-file")
	}
	if m.Generated != "" {
		if pair.Generated == nil {
			return nil, spanDiagnostic(m, m.GeneratedSpan, "generated", "restore-exact-generated-file", nil)
		}
		p := newParser(ctx, io.NewSectionReader(pair.Generated, 0, pair.Generated.Size()), JSON)
		p.generatedImage = true
		p.spans = &m.Spans
		p.provider = m.Provider
		parseGenerated(p, m)
		if e = p.done(); e != nil {
			return nil, e
		}
		m.Resolved = true
	}
	if e = join(m); e != nil {
		return nil, e
	}
	sort.Strings(m.MissingInputs)
	m.parsedPair = pair
	return m, nil
}
func parseEditableMode(ctx context.Context, image *Image, format Format, discardPayloads bool, selected *string) (*Model, error) {
	m := &Model{discardPayloads: discardPayloads, selected: selected}
	if err := parseEditableModel(ctx, image, format, m); err != nil {
		return nil, err
	}
	return m, nil
}

func parseEditableModel(ctx context.Context, image *Image, format Format, m *Model) (resultErr error) {
	defer func() { resultErr = bindCapturedSourceError(resultErr, image) }()
	p := newParser(ctx, io.NewSectionReader(image, 0, image.Size()), format)
	p.spans = &m.Spans
	p.layoutEnabled = format == YAML
	p.beginDocument()
	seen := uint8(0)
	rootSpan := p.mark(SpanRoot, 0)
	rootLayout := p.layout
	p.object(7, func(k string) {
		switch k {
		case "schema":
			seen |= 1
			if p.text(32, false, false) != "enkv/configuration/v3" {
				p.failValue("unsupported-schema")
			}
		case "domain":
			seen |= 2
			parseDomain(p, m)
		case "recipients":
			seen |= 4
			container := p.mark(SpanRecipients, 0)
			p.object(255, func(ref string) {
				if ref == "" {
					p.fail("empty-reference")
					return
				}
				span := p.mark(SpanRecipient, uint32(len(m.Recipients)))
				span.SourceOffset, span.SourceLength = p.member.SourceOffset, p.member.SourceLength
				r := Recipient{Reference: ref, IDSpan: MaxSpans}
				mask := 0
				p.object(3, func(k string) {
					switch k {
					case "id":
						token := p.mark(0, 0)
						r.ID = id(p)
						r.IDSpan = p.record(token)
						for _, previous := range m.Recipients {
							if previous.ID == r.ID {
								p.failValue("duplicate-recipient-id")
							}
						}
					case "display_name":
						mask |= 1
						r.DisplayName = p.text(256, false, false)
					case "encryption_key":
						mask |= 2
						token := p.mark(0, 0)
						r.Selector = p.text(1024, false, false)
						r.SelectorSpan = p.record(token)
					default:
						p.failMember("unknown-field")
					}
				})
				required(p, mask, 3)
				r.EditableSpan = p.record(span)
				m.Recipients = append(m.Recipients, r)
			})
			m.RecipientsSpan = p.record(container)
		case "entries":
			seen |= 8
			span := p.mark(SpanEntries, 0)
			before := p.layout
			parseEntries(p, m)
			m.layoutEntries = p.layoutEnd.since(before)
			m.EntriesSpan = p.record(span)
		case "outputs":
			seen |= 16
			parseOutputs(p, m)
		case "plugins":
			parsePlugins(p, m)
		case "generated":
			span := p.mark(SpanGeneratedReference, 0)
			m.Generated = p.text(85, false, false)
			m.GeneratedSpan = p.record(span)
			if !generatedPathValid(m.Generated) {
				p.failValue("invalid-generated-reference")
			}
		default:
			p.failMember("unknown-field")
		}
	})
	m.RootSpan = p.record(rootSpan)
	m.layoutRoot = p.layoutEnd.since(rootLayout)
	required(p, int(seen), 31)
	if e := p.done(); e != nil {
		return e
	}
	if e := validateEditable(m); e != nil {
		return e
	}
	if m.Generated != "" && m.Generated != generatedPath(m.DomainName) {
		return spanDiagnostic(m, m.GeneratedSpan, "generated", "domain-name-reference-mismatch", nil)
	}
	return nil
}
func required(p *parser, seen, want int) {
	if seen != want {
		p.failContext("missing-required-field")
	}
}
func generatedPathValid(path string) bool {
	if len(path) < 22 || len(path) > 85 || !strings.HasPrefix(path, ".enkv/") || !strings.HasSuffix(path, ".generated.json") {
		return false
	}
	return domainNameValid(path[6 : len(path)-15])
}
func generatedPath(name string) string { return ".enkv/" + name + ".generated.json" }
func domainNameValid(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for i, c := range []byte(name) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_') {
			continue
		}
		return false
	}
	return true
}
func parseDomain(p *parser, m *Model) {
	span := p.mark(SpanDomain, 0)
	defer func() { p.record(span) }()
	seen := 0
	p.object(5, func(k string) {
		switch k {
		case "name":
			seen |= 16
			token := p.mark(0, 0)
			m.DomainName = p.text(64, false, false)
			m.DomainNameSpan = p.record(token)
			if !domainNameValid(m.DomainName) {
				p.failValue("invalid-domain-name")
			}
		case "provider":
			seen |= 1
			switch p.text(3, false, false) {
			case "aws":
				m.Provider = contract.AWS
			case "gcp":
				m.Provider = contract.GCP
			default:
				p.failValue("unsupported-provider")
			}
		case "store":
			seen |= 2
			parseStore(p, &m.Store)
		case "authority":
			seen |= 4
			parseRole(p, &m.Authority, false, nil)
		case "recovery":
			seen |= 8
			parseRole(p, &m.Recovery, true, &m.RecoveryEnabled)
		default:
			p.failMember("unknown-field")
		}
	})
	required(p, seen, 31)
	m.Store.Provider = m.Provider
}
func parseStore(p *parser, s *contract.StoreLocation) {
	span := p.mark(SpanDomain, 1)
	defer func() { p.record(span) }()
	seen := 0
	var ownerToken Span
	p.object(4, func(k string) {
		switch k {
		case "region":
			seen |= 1
			s.Region = p.text(64, false, false)
		case "bucket":
			seen |= 2
			s.Bucket = p.text(222, false, false)
		case "prefix":
			seen |= 4
			s.PrefixBeforeHEAD = p.text(contract.MaxStorePrefixLength, false, false)
		case "expected_owner":
			seen |= 8
			ownerToken = p.mark(0, 0)
			s.ExpectedOwner = p.text(12, false, false)
		default:
			p.failMember("unknown-field")
		}
	})
	if seen&7 != 7 {
		p.failContext("missing-required-field")
	}
	if seen&8 != 0 && s.ExpectedOwner == "" {
		p.failFieldValue("invalid-owner", "expected_owner", ownerToken)
	}
}
func parseRole(p *parser, r *Role, recovery bool, enabled *bool) {
	span := p.mark(SpanRole, 0)
	defer func() { p.record(span) }()
	seen := 0
	p.object(3, func(k string) {
		switch k {
		case "display_name":
			if recovery {
				p.failMember("unknown-field")
				return
			}
			seen |= 1
			r.DisplayName = p.text(256, false, false)
		case "enabled":
			if !recovery {
				p.failMember("unknown-field")
				return
			}
			seen |= 1
			*enabled = p.boolean()
		case "signing_key":
			seen |= 2
			token := p.mark(0, 0)
			r.SigningSelector = p.text(1024, false, false)
			r.SigningSpan = p.record(token)
		case "encryption_key":
			seen |= 4
			token := p.mark(0, 0)
			r.EncryptionSelector = p.text(1024, false, false)
			r.EncryptionSpan = p.record(token)
		default:
			p.failMember("unknown-field")
		}
	})
	want := 7
	if recovery && !*enabled {
		want = 1
	}
	required(p, seen, want)
}
func parseEntries(p *parser, m *Model) {
	raw, members, generated, intents := 0, 0, 0, 0
	p.object(512, func(name string) {
		if members == 4096 {
			p.fail("aggregate-limit")
			return
		}
		members++ // Authority is present exactly once in every entry.
		span := p.mark(SpanEntry, uint32(len(m.Entries)))
		entryLayout := p.layout
		e := Entry{Name: name, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
		mask := 0
		conf, kind := "", ""
		var confidentialityToken Span
		sourceMask := 0
		reservedGenerated := false
		reserveGenerated := func() {
			if reservedGenerated {
				return
			}
			reservedGenerated = true
			if generated == 128 {
				p.fail("generated-limit")
				return
			}
			generated++
		}
		p.object(4, func(k string) {
			switch k {
			case "confidentiality":
				mask |= 1
				token := p.mark(0, 0)
				confidentialityToken = token
				conf = p.text(6, false, false)
				if m.selected != nil && name == *m.selected {
					m.SelectedConfidentialityOffset = uint32(token.Offset)
					m.SelectedConfidentialityLength = uint32(max(0, p.end-token.Offset))
				}
			case "recipients":
				mask |= 2
				seen := map[string]bool{}
				container := p.mark(0, 0)
				ownerColumn := uint64(0)
				if p.valueOwner.kind == blockKeyOwner {
					ownerColumn = p.valueOwner.col
				}
				var items []Span
				selected := -1
				p.array(63, func(index int) {
					if members == 4096 {
						p.fail("aggregate-limit")
						return
					}
					members++
					token := p.mark(SpanRecipientReference, uint32(len(m.Entries)))
					s := p.text(256, false, false)
					if m.selectedReference != nil && s == *m.selectedReference {
						p.record(token)
					}
					if s == "" || seen[s] {
						p.failValue("duplicate-or-empty-reference")
					}
					seen[s] = true
					if m.maintenance {
						item := p.arrayItem
						item.Length = max(0, p.end-item.Offset)
						items = append(items, item)
						if m.selectedReference != nil && s == *m.selectedReference {
							selected = index
						}
					}
					e.Recipients = append(e.Recipients, s)
				})
				if selected >= 0 {
					container.Length = max(0, p.end-container.Offset)
					m.maintenanceRemovals = append(m.maintenanceRemovals, maintenanceRemoval{container: container, items: items, selected: selected, array: true, ownerColumn: ownerColumn})
				}
			case "output_encoding":
				e.OutputEncoding = parseOutputEncoding(p)
			case "source":
				sourceSpan := p.mark(0, 0)
				sourceLayout := p.layout
				mask |= 4
				p.object(8, func(k string) {
					switch k {
					case "kind":
						sourceMask |= 1
						kind = p.text(9, false, false)
						if kind == "generated" {
							reserveGenerated()
						}
					case "encoding":
						e.InputEncoding = parseInputEncoding(p)
					case "value":
						sourceMask |= 2
						valueSpan := p.mark(0, 0)
						e.Plain = p.bytes(contract.CryptoMaxRetainedValue, true)
						span.ValueOffset, span.ValueLength = uint32(valueSpan.Offset), uint32(max(0, p.end-valueSpan.Offset))
						span.ValueFlow = valueSpan.Flow
					case "bytes":
						e.PlainBase64 = true
						sourceMask |= 4
						valueSpan := p.mark(0, 0)
						e.Plain = p.base64(min(contract.CryptoMaxRawValue, contract.CryptoMaxRawSet-raw))
						span.ValueOffset, span.ValueLength = uint32(valueSpan.Offset), uint32(max(0, p.end-valueSpan.Offset))
						span.ValueFlow = valueSpan.Flow
					case "plugin", "settings", "canonical", "epoch", "retirement":
						reserveGenerated()
						if p.err != nil {
							return
						}
						if e.Generated == nil {
							e.Generated = &Generator{}
						}
						g := e.Generated
						switch k {
						case "plugin":
							sourceMask |= 8
							g.Plugin = parsePluginSelection(p)
						case "epoch":
							sourceMask |= 16
							g.Epoch = p.integer()
						case "retirement":
							sourceMask |= 32
							g.Retirement = p.text(6, false, false)
						case "settings":
							sourceMask |= 64
							g.Settings = parseSettings(p, maxGeneratorSettings)
						case "canonical":
							sourceMask |= 128
							g.canonicalSettings = parseCanonicalSettings(p, maxCanonicalGeneratorSettings)
						}

					default:
						p.failMember("unknown-field")
					}
				})
				span.SourceOffset, span.SourceLength = sourceSpan.Offset, max(0, p.end-sourceSpan.Offset)
				if m.selected != nil && *m.selected == name {
					m.layoutSource = p.layoutEnd.since(sourceLayout)
				}
			default:
				p.failMember("unknown-field")
			}
		})
		if m.selected != nil && *m.selected == name {
			m.layoutEntry = p.layoutEnd.since(entryLayout)
		}
		required(p, mask, 7)
		if conf != "plain" && conf != "secret" {
			p.failFieldValue("invalid-confidentiality", "confidentiality", confidentialityToken)
		}
		e.Secret = conf == "secret"
		want := 1
		if kind == "supplied" {
			if !e.Secret {
				if sourceMask&2 != 0 {
					want |= 2
				} else {
					want |= 4
				}
			}
		} else if kind == "generated" && e.Secret {
			want = 1 | 8 | 16
			if sourceMask&32 != 0 {
				want |= 32
			}
			if sourceMask&64 != 0 {
				want |= 64
			} else {
				want |= 128
			}
			if e.Generated == nil {
				p.failContext("missing-required-field")
				return
			}
			if e.Generated.Settings != nil {
				if err := ValidateGeneratorSource(e.Generated); err != nil {
					p.failContext("invalid-generator-input")
				}
			} else if e.Generated.Retirement != "" && e.Generated.Retirement != "manual" && e.Generated.Retirement != "auto" {
				p.failContext("invalid-generator-input")
			}
			intents += len(e.Generated.Intent)
			if intents > contract.MaxPublicGeneratedIntents {
				p.fail("generator-declaration-limit")
			}
			if m.discardPayloads {
				e.Generated.Settings, e.Generated.Intent, e.Generated.canonicalSettings = nil, nil, nil
			}

		} else {
			p.failContext("invalid-source")
		}
		if !e.Secret {
			content, err := contract.InputContentLength(e.InputEncoding, e.Plain)
			if err != nil || e.PlainBase64 && e.InputEncoding != contract.InputEncodingRaw {
				p.failContext("invalid-input-representation")
			} else {
				e.ContentLength = content
				raw += int(content)
				if raw > contract.CryptoMaxRawSet {
					p.fail("raw-value-limit")
				}
			}
			if m.discardPayloads {
				e.Plain = nil
			}
		}
		required(p, sourceMask, want)
		if p.err != nil {
			return
		}
		e.EntrySpan = p.record(span)
		m.Entries = append(m.Entries, e)
	})
}
func id(p *parser) contract.ID {
	s := p.text(64, false, false)
	var out contract.ID
	if len(s) != 64 || strings.ToLower(s) != s {
		p.failValue("invalid-id")
		return out
	}
	n, e := hex.Decode(out[:], []byte(s))
	if e != nil || n != 32 || out.IsZero() {
		p.failValue("invalid-id")
	}
	return out
}
func sourceError(field, reason string) error {
	return &Diagnostic{Field: field, Reason: reason, cause: ErrSourceInvalid}
}
func spanDiagnostic(m *Model, index uint32, field, reason string, cause error) *Diagnostic {
	if cause == nil {
		cause = ErrSourceInvalid
	}
	d := &Diagnostic{Field: field, Reason: reason, Context: true, cause: cause}
	if int(index) < len(m.Spans) {
		s := m.Spans[index]
		d.Offset, d.Line, d.Column = s.Offset, s.Line, s.Column
	}
	return d
}
func validateEditable(m *Model) error {
	if !contract.StoreLocationValid(m.Store) || m.Provider == contract.AWS && m.Store.ExpectedOwner == "" {
		return sourceError("domain.store", "invalid-store")
	}
	roles := []Role{m.Authority}
	if m.RecoveryEnabled {
		roles = append(roles, m.Recovery)
	}
	for _, r := range roles {
		if !contract.PublicKeySelectorValid(m.Provider, r.SigningSelector, true) || !contract.PublicKeySelectorValid(m.Provider, r.EncryptionSelector, false) {
			return sourceError("domain", "invalid-key-selector")
		}
	}
	known := make(map[string]bool, len(m.Recipients))
	for _, r := range m.Recipients {
		if !contract.PublicKeySelectorValid(m.Provider, r.Selector, false) {
			return sourceError("recipients", "invalid-key-selector")
		}
		known[r.Reference] = true
	}
	for _, e := range m.Entries {
		for _, r := range e.Recipients {
			if !known[r] {
				return sourceError("entries.recipients", "unresolved-reference")
			}
		}
	}
	return validateOutputReferences(m)
}
func sortedEntries(m *Model) {
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Name < m.Entries[j].Name })
	sort.Slice(m.Recipients, func(i, j int) bool { return m.Recipients[i].Reference < m.Recipients[j].Reference })
}

func parseInputEncoding(p *parser) uint8 {
	switch p.text(6, false, false) {
	case "raw":
		return contract.InputEncodingRaw
	case "base64":
		return contract.InputEncodingBase64
	default:
		p.failValue("invalid-encoding")
		return 0
	}
}

func parseOutputEncoding(p *parser) uint8 {
	switch p.text(6, false, false) {
	case "raw":
		return contract.OutputEncodingRaw
	case "base64":
		return contract.OutputEncodingBase64
	default:
		p.failValue("invalid-encoding")
		return 0
	}
}
