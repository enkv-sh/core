package configuration

import (
	"encoding/hex"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
)

// GeneratedPath returns the one stable satellite reference for a local name.
func GeneratedPath(name string) (string, error) {
	if !domainNameValid(name) {
		return "", ErrCapture
	}
	return generatedPath(name), nil
}

// EmitEditable streams a fresh normalized declaration. Existing files use the
// span editor instead. Stage must parse the complete pair and enforce its bound.
func EmitEditable(out io.Writer, m *Model, format Format) error {
	if out == nil || m == nil || !m.Resolved || !domainNameValid(m.DomainName) || m.Generated != generatedPath(m.DomainName) || format != JSON && format != YAML || len(m.Entries) > contract.CryptoMaxValueEntries || len(m.Recipients) > 255 || len(m.Plugins) > maxPluginRequirements {
		return ErrCapture
	}
	plugins := slices.Clone(m.Plugins)
	slices.SortFunc(plugins, func(a, b PluginRequirement) int { return strings.Compare(a.Name, b.Name) })
	for i, requirement := range plugins {
		if !artifact.ValidPluginID(requirement.Name) || i > 0 && plugins[i-1].Name == requirement.Name || requirement.Version != "" && !artifact.ValidVersion(requirement.Version) {
			return ErrCapture
		}
	}
	for i, recipient := range m.Recipients {
		if recipient.ID.IsZero() || recipient.ID == m.Authority.ID {
			return ErrCapture
		}
		for _, previous := range m.Recipients[:i] {
			if previous.ID == recipient.ID {
				return ErrCapture
			}
		}
	}
	w := &editableWriter{generatedWriter: generatedWriter{out: out}, format: format}
	count := 6
	if len(plugins) > 0 {
		count++
	}
	w.object("", count, func() {
		w.text("schema", "enkv/configuration/v3")
		w.object("domain", 5, func() {
			w.text("name", m.DomainName)
			provider := "aws"
			if m.Provider == contract.GCP {
				provider = "gcp"
			} else if m.Provider != contract.AWS {
				w.err = ErrCapture
			}
			w.text("provider", provider)
			count := 3
			if m.Provider == contract.AWS {
				count++
			}
			w.object("store", count, func() {
				w.text("region", m.Store.Region)
				w.text("bucket", m.Store.Bucket)
				w.text("prefix", m.Store.PrefixBeforeHEAD)
				if m.Provider == contract.AWS {
					w.text("expected_owner", m.Store.ExpectedOwner)
				}
			})
			w.object("authority", 3, func() {
				w.text("display_name", m.Authority.DisplayName)
				w.text("signing_key", m.Authority.SigningSelector)
				w.text("encryption_key", m.Authority.EncryptionSelector)
			})
			count = 1
			if m.RecoveryEnabled {
				count = 3
			}
			w.object("recovery", count, func() {
				w.boolean("enabled", m.RecoveryEnabled)
				if m.RecoveryEnabled {
					w.text("signing_key", m.Recovery.SigningSelector)
					w.text("encryption_key", m.Recovery.EncryptionSelector)
				}
			})
		})
		recipients := slices.Clone(m.Recipients)
		slices.SortFunc(recipients, func(a, b Recipient) int { return strings.Compare(a.Reference, b.Reference) })
		w.object("recipients", len(recipients), func() {
			for _, r := range recipients {
				w.object(r.Reference, 3, func() {
					w.text("id", hex.EncodeToString(r.ID[:]))
					w.text("display_name", r.DisplayName)
					w.text("encryption_key", r.Selector)
				})
			}
		})
		entries := slices.Clone(m.Entries)
		slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
		w.object("entries", len(entries), func() {
			for _, e := range entries {
				entryFields := 3
				if e.OutputEncoding == contract.OutputEncodingBase64 {
					entryFields++
				}
				w.object(e.Name, entryFields, func() {
					class := "plain"
					if e.Secret {
						class = "secret"
					}
					w.text("confidentiality", class)
					members := slices.Clone(e.Recipients)
					slices.Sort(members)
					w.texts("recipients", members)
					if e.OutputEncoding == contract.OutputEncodingBase64 {
						w.text("output_encoding", "base64")
					}
					count := 1
					if e.Generated != nil {
						count = 4
						if e.Generated.Retirement != "" {
							count++
						}
					} else if !e.Secret {
						count = 2
					}
					if e.InputEncoding == contract.InputEncodingBase64 {
						count++
					}
					w.object("source", count, func() {
						if e.InputEncoding == contract.InputEncodingBase64 {
							w.text("encoding", "base64")
						}
						if e.Generated != nil {
							g := e.Generated
							w.text("kind", "generated")
							w.plugin(g.Plugin)
							w.number("epoch", g.Epoch)
							if g.Retirement != "" {
								w.text("retirement", g.Retirement)
							}
							if err := ValidateGeneratorSource(g); err != nil {
								w.err = err
								return
							}
							if g.Settings != nil {
								w.settings(g.Settings, maxGeneratorSettings)
							} else {
								settings := g.canonicalSettings
								if settings == nil {
									intent, err := contract.InspectGeneratorIntent(g.Intent)
									if err != nil {
										w.err = err
										return
									}
									settings = intent.Settings
								}
								w.object("canonical", 1, func() { w.settings(settings, maxCanonicalGeneratorSettings) })
							}
							return
						}
						w.text("kind", "supplied")
						if !e.Secret {
							if e.InputEncoding == contract.InputEncodingBase64 || !e.PlainBase64 && utf8.Valid(e.Plain) {
								w.text("value", string(e.Plain))
							} else {
								w.item("bytes")
								w.scalarStart()
								if w.format == YAML {
									w.yamlBlob(e.Plain, contract.CryptoMaxRawValue)
								} else {
									w.blob(e.Plain, contract.CryptoMaxRawValue)
								}
								w.scalarEnd()
							}
						}
					})
				})
			}
		})
		w.outputs(m)
		if len(plugins) > 0 {
			w.object("plugins", len(plugins), func() {
				for _, requirement := range plugins {
					count := 0
					if requirement.Version != "" {
						count = 1
					}
					w.object(requirement.Name, count, func() {
						if requirement.Version != "" {
							w.text("version", requirement.Version)
						}
					})
				}
			})
		}
		w.text("generated", m.Generated)
	})
	if format == JSON {
		w.raw("\n")
	}
	if w.err != nil {
		return captureCause(w.err)
	}
	return nil
}

type editableFrame struct{ array, first bool }
type editableWriter struct {
	generatedWriter
	format Format
	level  int
	frames [MaxDepth]editableFrame
}

func (w *editableWriter) item(key string) {
	if w.level == 0 || w.err != nil {
		return
	}
	frame := &w.frames[w.level-1]
	if w.format == JSON {
		if !frame.first {
			w.raw(",")
		}
		w.raw("\n")
		w.raw(strings.Repeat("  ", w.level))
	} else {
		w.raw(strings.Repeat("  ", w.level-1))
	}
	frame.first = false
	if frame.array {
		if w.format == YAML {
			w.raw("-")
		}
		return
	}
	if w.format == YAML {
		w.yamlString(key, 1024, true, false)
	} else {
		w.quote(key, 1024)
	}
	w.raw(":")
	if w.format == JSON {
		w.raw(" ")
	}
}
func (w *editableWriter) scalarStart() {
	if w.format == YAML {
		w.raw(" ")
	}
}
func (w *editableWriter) scalarEnd() {
	if w.format == YAML {
		w.raw("\n")
	}
}
func (w *editableWriter) text(key, value string) {
	w.item(key)
	w.scalarStart()
	if w.format == YAML {
		w.yamlString(value, len(value), false, false)
	} else {
		w.quote(value, len(value))
	}
	w.scalarEnd()
}
func (w *editableWriter) number(key string, value uint64) {
	w.item(key)
	w.scalarStart()
	w.raw(strconv.FormatUint(value, 10))
	w.scalarEnd()
}
func (w *editableWriter) boolean(key string, value bool) {
	w.item(key)
	w.scalarStart()
	w.raw(strconv.FormatBool(value))
	w.scalarEnd()
}
func (w *editableWriter) container(key string, count int, array bool, emit func()) {
	if w.err != nil {
		return
	}
	root := w.level == 0
	if !root {
		w.item(key)
	}
	open, close := "{", "}"
	if array {
		open, close = "[", "]"
	}
	if count == 0 {
		w.scalarStart()
		w.raw(open + close)
		w.scalarEnd()
		return
	}
	if w.level == MaxDepth {
		w.err = ErrCapture
		return
	}
	if w.format == JSON {
		w.raw(open)
	} else if !root {
		w.raw("\n")
	}
	w.frames[w.level] = editableFrame{array: array, first: true}
	w.level++
	emit()
	w.level--
	if w.format == JSON {
		w.raw("\n" + strings.Repeat("  ", w.level) + close)
	}
}
func (w *editableWriter) object(key string, count int, emit func()) {
	w.container(key, count, false, emit)
}
func (w *editableWriter) array(key string, count int, emit func()) {
	w.container(key, count, true, emit)
}
func (w *editableWriter) texts(key string, values []string) {
	w.array(key, len(values), func() {
		for _, v := range values {
			w.text("", v)
		}
	})
}
func (w *editableWriter) plugin(name string) {
	w.item("plugin")
	w.scalarStart()
	if name == "" {
		w.raw("null")
	} else if artifact.ValidPluginID(name) {
		if w.format == YAML {
			w.yamlString(name, 255, false, false)
		} else {
			w.quote(name, 255)
		}
	} else {
		w.err = ErrCapture
	}
	w.scalarEnd()
}
func (w *editableWriter) settings(body []byte, limit int) {
	w.item("settings")
	w.settingsValueIterative(body, limit)
}

func (w *editableWriter) outputs(m *Model) {
	bindings := slices.Clone(m.Outputs)
	if len(bindings) > contract.MaxOutputBindings || len(bindings) == 0 && len(m.Public.OutputBindings.Value) > 0 {
		w.err = ErrCapture
		return
	}
	slices.SortFunc(bindings, func(a, b OutputBinding) int { return strings.Compare(a.DestinationID, b.DestinationID) })
	w.object("outputs", 3, func() {
		w.object("destinations", len(bindings), func() {
			for _, source := range bindings {
				if source.DestinationID != source.Binding.DestinationID {
					w.err = ErrCapture
					return
				}
				count := 2

				w.object(source.DestinationID, count, func() {
					w.plugin(source.Plugin)
					if source.Settings == nil {
						if _, err := contract.NormalOutputBindingDeclarationLength(source.Binding); err != nil {
							w.err = err
							return
						}
						settings := source.canonicalSettings
						if settings == nil {
							settings = source.Binding.Destination.CanonicalSettings
						}
						w.object("canonical", 1, func() { w.settings(settings, contract.MaxOutputDestinationSettings) })
						return
					}
					if source.Plugin == "" {
						w.err = ErrCapture
						return
					}
					w.settings(source.Settings, contract.MaxOutputDestinationSettings)

				})
			}
		})
		w.routing(m.Routes)
		groups := slices.Clone(m.Public.Groups.Value)
		slices.SortFunc(groups, func(a, b []string) int { return slices.Compare(a, b) })
		w.array("groups", len(groups), func() {
			for _, g := range groups {
				members := slices.Clone(g)
				slices.Sort(members)
				w.texts("", members)
			}
		})
	})
}

func (w *editableWriter) routing(routes []Route) {
	var defaults []string
	hasDefault := false
	entries := make([]Route, 0, len(routes))
	for _, route := range routes {
		if route.Default {
			hasDefault = true
			defaults = route.Destinations
		} else {
			entries = append(entries, route)
		}
	}
	slices.SortFunc(entries, func(a, b Route) int { return strings.Compare(a.EntryName, b.EntryName) })
	count := 1
	if hasDefault {
		count++
	}
	w.object("routing", count, func() {
		if hasDefault {
			values := slices.Clone(defaults)
			slices.Sort(values)
			w.texts("default", values)
		}
		w.object("entries", len(entries), func() {
			for _, route := range entries {
				values := slices.Clone(route.Destinations)
				slices.Sort(values)
				w.texts(route.EntryName, values)
			}
		})
	})
}
