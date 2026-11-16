package configuration

import (
	"bytes"
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

func parseCanonicalRecords(p *parser, m *Model) {
	seen, intents, declaration, targets := 0, 0, 6, 0
	for _, group := range m.Public.Groups.Value {
		declaration += 2 + 32*len(group)
	}
	p.object(2, func(kind string) {
		switch kind {
		case "generators":
			seen |= 1
			var pending Span
			var previousEnd, lastEnd int64
			rows := 0
			p.object(contract.GeneratedCurrentEntryLimit, func(name string) {
				member := p.member
				body := p.base64(contract.GeneratorIntentMaxLength)
				if _, err := contract.InspectGeneratorIntent(body); err != nil {
					p.fail("invalid-canonical-intent")
					return
				}
				intents += len(body)
				if intents > contract.MaxPublicGeneratedIntents {
					p.fail("generator-declaration-limit")
					return
				}
				at := slices.IndexFunc(m.Entries, func(e Entry) bool {
					return e.Name == name
				})
				entrySpan := uint32(MaxSpans)
				if at >= 0 {
					entrySpan = m.Entries[at].EntrySpan
					g := m.Entries[at].Generated
					if g != nil && g.canonicalSettings != nil && g.Settings == nil {
						g.canonicalRecord = body
					}
				}
				if rows > 0 {
					pending.Length = member.Offset - pending.Offset
					p.addSpan(pending)
				}
				previousEnd, lastEnd = lastEnd, p.end
				pending = Span{Offset: member.Offset, Length: p.end - member.Offset, Kind: SpanCanonicalGenerator, Index: entrySpan}
				rows++
			})
			if p.err == nil && rows > 0 {
				// A final row owns its preceding comma; other rows own the next.
				if rows > 1 {
					pending.Offset, pending.Length = previousEnd, lastEnd-previousEnd
				}
				p.addSpan(pending)
			}
		case "outputs":
			seen |= 2
			p.object(contract.MaxOutputBindings, func(name string) {
				body := p.base64(contract.MaxNormalOutputBindingBytes)
				binding, err := contract.InspectNormalOutputBinding(body)
				if err != nil || binding.DestinationID != name {
					p.fail("invalid-canonical-binding")
					return
				}
				targets += len(binding.Targets)
				if targets > contract.MaxOutputTargets {
					p.fail("output-target-limit")
					return
				}
				length, err := contract.NormalOutputBindingDeclarationLength(binding)
				if err != nil {
					p.fail("invalid-canonical-binding")
					return
				}
				declaration += length
				if declaration > contract.MaxOutputDeclarationBytes {
					p.fail("output-declaration-limit")
					return
				}
				at := slices.IndexFunc(m.Outputs, func(v OutputBinding) bool {
					return v.DestinationID == name && v.canonicalSettings != nil && v.Settings == nil
				})
				if at >= 0 {
					m.Outputs[at].canonicalRecord = body
					m.Outputs[at].Binding = binding
				}
			})
		default:
			p.failMember("unknown-field")
		}
	})
	required(p, seen, 3)
}

func resolveCanonicalSettings(m *Model) error {
	for i := range m.Entries {
		g := m.Entries[i].Generated
		if g == nil || g.canonicalSettings == nil {
			continue
		}
		if g.Settings != nil {
			return sourceError("entries.source.canonical", "invalid-generator-input")
		}
		if g.canonicalRecord == nil {
			return sourceError("canonical_records.generators", "missing-required-field")
		}
		intent, err := contract.InspectGeneratorIntent(g.canonicalRecord)
		if err != nil {
			return sourceError("canonical_records.generators", "invalid-canonical-intent")
		}
		settings, err := editedCanonicalSettings(intent.Settings, g.canonicalSettings, maxCanonicalGeneratorSettings)
		if err != nil {
			return err
		}
		g.Intent = g.canonicalRecord
		if !bytes.Equal(settings, intent.Settings) {
			intent.Settings = settings
			g.Intent, err = contract.EncodeGeneratorIntent(intent)
			if err != nil {
				return err
			}
		}
		if err := ValidateGeneratorSource(g); err != nil {
			return sourceError("entries.source.canonical", "invalid-generator-input")
		}
	}
	for i := range m.Outputs {
		source := &m.Outputs[i]
		if source.canonicalSettings == nil {
			continue
		}
		if source.Settings != nil {
			return sourceError("outputs.destinations.canonical", "invalid-output-input")
		}
		if source.canonicalRecord == nil {
			return sourceError("canonical_records.outputs", "missing-required-field")
		}
		settings, err := editedCanonicalSettings(source.Binding.Destination.CanonicalSettings, source.canonicalSettings, contract.MaxOutputDestinationSettings)
		if err != nil {
			return err
		}
		source.settingsEdited = !bytes.Equal(settings, source.Binding.Destination.CanonicalSettings)
		source.Binding.Destination.CanonicalSettings = settings
		if source.settingsEdited {
			source.Binding.Targets = nil
		}
	}
	return nil
}

func (w *generatedWriter) canonicalRecords(m *Model) {
	generators := make([]int, 0, len(m.Entries))
	outputs := make([]int, 0, len(m.Outputs))
	for i, e := range m.Entries {
		if e.Generated != nil && e.Generated.Settings == nil {
			generators = append(generators, i)
		}
	}
	for i, b := range m.Outputs {
		if b.Settings == nil {
			outputs = append(outputs, i)
		}
	}
	if len(generators) == 0 && len(outputs) == 0 {
		return
	}
	slices.SortFunc(generators, func(a, b int) int { return strings.Compare(m.Entries[a].Name, m.Entries[b].Name) })
	slices.SortFunc(outputs, func(a, b int) int { return strings.Compare(m.Outputs[a].DestinationID, m.Outputs[b].DestinationID) })
	w.write(`,"canonical_records":{"generators":{`)
	for j, i := range generators {
		e := m.Entries[i]
		g := e.Generated
		if j > 0 {
			w.write(",")
		}
		if j > 0 && m.Entries[generators[j-1]].Name == e.Name {
			w.err = ErrCapture
			return
		}
		record := g.canonicalRecord
		if record == nil {
			record = g.Intent
		}
		if _, err := contract.InspectGeneratorIntent(record); err != nil {
			w.err = err
			return
		}
		w.quote(e.Name, contract.CryptoMaxName)
		w.write(":")
		w.blob(record, contract.GeneratorIntentMaxLength)
	}
	w.write(`},"outputs":{`)
	for j, i := range outputs {
		b := m.Outputs[i]
		if j > 0 {
			w.write(",")
		}
		if j > 0 && m.Outputs[outputs[j-1]].DestinationID == b.DestinationID {
			w.err = ErrCapture
			return
		}
		record := b.canonicalRecord
		if record == nil {
			var err error
			record, err = contract.EncodeNormalOutputBinding(b.Binding)
			if err != nil {
				w.err = err
				return
			}
		}
		w.quote(b.DestinationID, 256)
		w.write(":")
		w.blob(record, contract.MaxNormalOutputBindingBytes)
	}
	w.write("}}")
}
