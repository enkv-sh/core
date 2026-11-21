package configuration

import (
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

func parseOutputs(p *parser, m *Model) {
	seen := 0
	targets := 0
	declaration, routing := uint64(6), uint64(5)
	p.object(3, func(key string) {
		switch key {
		case "destinations":
			seen |= 1
			m.Outputs = []OutputBinding{}
			p.object(contract.MaxOutputBindings, func(id string) {
				if id == "" {
					p.fail("empty-destination")
					return
				}
				binding, length := parseOutputBinding(p, id)
				binding.SourceIndex = uint16(len(m.Outputs))
				targets += len(binding.Binding.Targets)
				if targets > contract.MaxOutputTargets {
					p.fail("output-target-limit")
					return
				}
				declaration += uint64(length)
				if declaration > contract.MaxOutputDeclarationBytes {
					p.fail("output-declaration-limit")
					return
				}
				if m.discardPayloads {
					binding.Settings, binding.canonicalSettings = nil, nil
					binding.Binding = contract.NormalOutputBinding{DestinationID: id}
				}
				m.Outputs = append(m.Outputs, binding)
			})
		case "routing":
			seen |= 2
			p.object(2, func(key string) {
				switch key {
				case "default":
					parseRoute(p, m, Route{Default: true}, &routing)
				case "entries":
					p.object(contract.CryptoMaxValueEntries, func(name string) {
						parseRoute(p, m, Route{EntryName: name}, &routing)
					})
				default:
					p.fail("unknown-field")
				}
			})
		case "groups":
			grouped := make(map[string]bool)
			p.array(contract.CryptoMaxValueEntries, func(_ int) {
				span := p.mark(SpanGroup, uint32(len(m.Public.Groups.Value)))
				var group []string
				p.array(contract.CryptoMaxValueEntries, func(_ int) {
					if len(grouped) >= contract.CryptoMaxValueEntries {
						p.fail("group-member-limit")
						return
					}
					name := p.text(contract.CryptoMaxName, false, false)
					if grouped[name] {
						p.fail("duplicate-group-member")
						return
					}
					grouped[name] = true
					group = append(group, name)
				})
				if len(group) == 0 {
					p.fail("empty-group")
				}
				declaration += uint64(2 + 32*len(group))
				if declaration > contract.MaxOutputDeclarationBytes {
					p.fail("output-declaration-limit")
				}
				slices.Sort(group)
				p.record(span)
				m.Public.Groups.Value = append(m.Public.Groups.Value, group)
			})
		default:
			p.fail("unknown-field")
		}
	})
	required(p, seen, 3)
	if declaration+4+routing > contract.MaxOutputConfigurationBytes {
		p.fail("output-configuration-limit")
	}
	m.Public.Groups.State = contract.PublicPresent
	slices.SortFunc(m.Outputs, func(a, b OutputBinding) int {
		return strings.Compare(a.DestinationID, b.DestinationID)
	})
	slices.SortFunc(m.Public.Groups.Value, func(a, b []string) int { return slices.Compare(a, b) })
}

func parseOutputBinding(p *parser, id string) (OutputBinding, int) {
	span := p.mark(SpanDestination, 0)
	defer func() { p.record(span) }()
	out := OutputBinding{DestinationID: id, Binding: contract.NormalOutputBinding{DestinationID: id}}
	seen := 0
	decoded := 0
	p.object(3, func(key string) {
		switch key {
		case "plugin":
			seen |= 1
			out.Plugin = parsePluginSelection(p)
		case "settings":
			seen |= 2
			out.Settings = parseSettings(p, contract.MaxOutputDestinationSettings)
			decoded = len(out.Settings) + len(id) + 10
		case "canonical":
			seen |= 4
			out.canonicalSettings = parseCanonicalSettings(p, contract.MaxOutputDestinationSettings)
			decoded = len(out.canonicalSettings) + len(id) + 10

		default:
			p.fail("unknown-field")
		}
	})
	if seen&2 != 0 {
		want := 3

		required(p, seen, want)
		if out.Plugin == "" {
			p.fail("missing-plugin")
		}

	} else {
		required(p, seen, 5)
	}
	return out, decoded
}

func parseRoute(p *parser, m *Model, route Route, charge *uint64) {
	span := p.mark(SpanRoute, uint32(len(m.Routes)))
	if len(m.Routes) >= contract.MaxPublicRoutingRules {
		p.fail("routing-count-limit")
		return
	}
	p.array(contract.MaxOutputRouteDestinations, func(_ int) {
		id := p.text(256, false, false)
		if id == "" || slices.Contains(route.Destinations, id) {
			p.fail("duplicate-or-empty-destination")
			return
		}
		route.Destinations = append(route.Destinations, id)
	})
	if !route.Default {
		*charge += 33
	}
	for _, id := range route.Destinations {
		*charge += uint64(4 + len(id))
	}
	if *charge > contract.MaxOutputRoutingBytes {
		p.fail("routing-byte-limit")
		return
	}
	slices.Sort(route.Destinations)
	p.record(span)
	m.Routes = append(m.Routes, route)
}

// OutputTargetEncodings returns the effective entry encodings for each destination.
func (m *Model) OutputTargetEncodings() (map[string]map[string]uint8, error) {
	invalid := func() error { return sourceError("outputs", "invalid-output-reference") }
	entries := make(map[string]bool, len(m.Entries))
	for _, entry := range m.Entries {
		entries[entry.Name] = true
	}
	destinations := make(map[string]bool, len(m.Outputs))
	for _, binding := range m.Outputs {
		destinations[binding.DestinationID] = true
	}
	type routeKey struct {
		defaultRoute bool
		entry        string
	}
	routes := make(map[routeKey][]string, len(m.Routes))
	for _, route := range m.Routes {
		if route.Default && route.EntryName != "" || !route.Default && !entries[route.EntryName] || len(route.Destinations) > contract.MaxOutputRouteDestinations {
			return nil, invalid()
		}
		seen := make(map[string]bool, len(route.Destinations))
		for _, id := range route.Destinations {
			if !destinations[id] || seen[id] {
				return nil, invalid()
			}
			seen[id] = true
		}
		key := routeKey{route.Default, route.EntryName}
		if _, duplicate := routes[key]; duplicate {
			return nil, invalid()
		}
		routes[key] = route.Destinations
	}
	needed := make(map[string]map[string]uint8, len(destinations))
	for id := range destinations {
		needed[id] = make(map[string]uint8)
	}
	targetCount := 0
	for _, entry := range m.Entries {
		selected, present := routes[routeKey{entry: entry.Name}]
		if !present {
			selected = routes[routeKey{defaultRoute: true}]
		}
		for _, id := range selected {
			targetCount++
			if targetCount > contract.MaxOutputTargets {
				return nil, invalid()
			}
			needed[id][entry.Name] = entry.OutputEncoding
		}
	}
	return needed, nil
}

func validateOutputReferences(m *Model) error {
	_, err := m.OutputTargetEncodings()
	if err != nil {
		return err
	}
	invalid := func() error { return sourceError("outputs", "invalid-output-reference") }
	entries := make(map[string]bool, len(m.Entries))
	for _, entry := range m.Entries {
		entries[entry.Name] = true
	}

	for _, group := range m.Public.Groups.Value {
		for _, name := range group {
			if !entries[name] {
				return invalid()
			}
		}
	}
	return nil
}
