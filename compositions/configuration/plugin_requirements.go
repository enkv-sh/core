package configuration

import "enkv.sh/sdk/artifact"

const maxPluginRequirements = 64

func parsePlugins(p *parser, m *Model) {
	p.object(maxPluginRequirements, func(name string) {
		if !artifact.ValidPluginID(name) {
			p.fail("invalid-plugin")
			return
		}
		requirement := PluginRequirement{Name: name}
		p.object(1, func(field string) {
			if field != "version" {
				p.fail("unknown-field")
				return
			}
			requirement.Version = p.text(128, false, false)
			if !artifact.ValidVersion(requirement.Version) {
				p.fail("invalid-plugin-version")
			}
		})
		if p.err == nil {
			m.Plugins = append(m.Plugins, requirement)
		}
	})
}
