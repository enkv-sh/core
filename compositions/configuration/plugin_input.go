package configuration

import (
	"encoding/json"
	"io"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	generator "enkv.sh/sdk/protocols/generator"
)

const maxGeneratorSettings = generator.MaximumSettingsInputLength
const maxCanonicalGeneratorSettings = generator.MaximumSettingsLength

func parsePluginSelection(p *parser) string {
	p.skip()
	var name string
	if p.format == YAML {
		var value []byte
		p.scalar(func(b byte) {
			var ok bool
			value, ok = boundedAppend(value, b, 255)
			if !ok {
				p.fail("scalar-limit")
			}
		}, false, false)
		if p.plain {
			switch string(value) {
			case "null", "Null", "NULL", "~":
				p.layoutRaw(4)
				return ""
			}
		}
		p.validateText(value, false)
		name = string(value)
	} else if p.peek() == '"' {
		name = p.text(255, false, false)
	} else {
		if p.atom() != "null" {
			p.failValue("invalid-plugin")
		}
		return ""
	}
	if !artifact.ValidPluginID(name) {
		p.failValue("invalid-plugin")
	}
	return name
}

func parseCanonicalSettings(p *parser, limit int) []byte {
	var body []byte
	seen := 0
	p.object(1, func(key string) {
		if key != "settings" {
			p.failMember("unknown-field")
			return
		}
		seen = 1
		body = parseSettings(p, limit)
	})
	required(p, seen, 1)
	return body
}

// ValidateGeneratorSource checks the common source arms and the retirement rule
// of any present canonical intent. Plugin-owned semantics remain separate.
func ValidateGeneratorSource(g *Generator) error {
	if g == nil || g.Plugin != "" && !artifact.ValidPluginID(g.Plugin) || g.Retirement != "" && g.Retirement != "manual" && g.Retirement != "auto" {
		return ErrCapture
	}
	if g.Settings != nil {
		if g.Plugin == "" || len(g.Settings) > maxGeneratorSettings || !settingsValid(g.Settings) {
			return ErrCapture
		}
		if len(g.Intent) == 0 {
			return nil
		}
	}
	intent, err := contract.InspectGeneratorIntent(g.Intent)
	if err != nil {
		return err
	}
	if intent.LifecycleMode == contract.GeneratorLifecycleNone && g.Retirement != "" || intent.LifecycleMode == contract.GeneratorLifecycleManaged && g.Retirement == "" {
		return ErrCapture
	}
	return nil
}

type settingsBuffer struct {
	body  []byte
	limit int
}

func (w *settingsBuffer) Write(p []byte) (int, error) { return w.WriteString(string(p)) }
func (w *settingsBuffer) WriteString(s string) (int, error) {
	if len(s) > w.limit-len(w.body) {
		return 0, io.ErrShortWrite
	}
	for i := range len(s) {
		var ok bool
		w.body, ok = boundedAppend(w.body, s[i], w.limit)
		if !ok {
			return i, io.ErrShortWrite
		}
	}
	return len(s), nil
}

func parseSettings(p *parser, limit int) []byte { return parseSettingsIterative(p, limit) }

func pluginSelectionValid(name string) bool { return name == "" || artifact.ValidPluginID(name) }
func settingsValid(body []byte) bool        { return utf8.Valid(body) && json.Valid(body) }
