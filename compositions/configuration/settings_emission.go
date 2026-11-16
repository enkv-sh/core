package configuration

import (
	"encoding/json"
	"strings"
)

// Count the readable expansion before emitting it. Deeply nested public JSON
// can be much larger in the editable view than in its exact companion record.
func (w *editableWriter) settingsValueIterative(body []byte, limit int) {
	if len(body) > limit {
		w.err = ErrCapture
		return
	}
	tokens, err := inspectSettingsTokens(body)
	if err != nil {
		w.err = err
		return
	}
	depths := make([]uint16, len(tokens.values))
	stringValue := func(token settingsToken) string {
		var text string
		if err := json.Unmarshal(body[token.start:token.end], &text); err != nil {
			w.err = ErrCapture
		}
		return text
	}
	var length int64
	for i, token := range tokens.values {
		depth := uint16(w.level)
		if token.parent != 0 {
			depth = depths[token.parent-1] + 1
		}
		depths[i] = depth
		if token.parent != 0 {
			parent := tokens.values[token.parent-1]
			if w.format == JSON {
				if parent.first != uint32(i+1) {
					length++
				}
				length += 1 + 2*int64(depth)
				if parent.kind == '{' {
					length += int64(token.keyEnd-token.keyStart) + 2
				}
			} else {
				length += 2 * int64(depth-1)
				if parent.kind == '{' {
					length += yamlStringLength(token.name, true, false) + 1
				} else {
					length++
				}
			}
		}
		collection := token.kind == '{' || token.kind == '['
		if collection && token.first != 0 {
			if w.format == JSON {
				length += 3 + 2*int64(depth)
			} else {
				length++
			}
		} else {
			if collection {
				length += 2
			} else {
				if w.format == YAML && token.kind == '"' {
					length += yamlStringLength(stringValue(token), false, false)
				} else {
					length += int64(token.end - token.start)
				}
			}
			if w.format == YAML {
				length += 2
			}
		}
		if length > MaxPairBytes-w.count {
			w.err = sourceError("canonical.settings", "pair-size-limit")
			return
		}
	}
	type frame struct {
		node  uint32
		depth uint16
	}
	stack := make([]frame, 0, 10000)
	closeFrame := func() {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if w.format == JSON {
			close := "}"
			if tokens.values[current.node-1].kind == '[' {
				close = "]"
			}
			w.raw("\n" + strings.Repeat("  ", int(current.depth)) + close)
		}
	}
	for i, token := range tokens.values {
		if w.err != nil {
			return
		}
		for len(stack) > 0 && stack[len(stack)-1].node != token.parent {
			closeFrame()
		}
		depth := int(depths[i])
		if token.parent != 0 {
			parent := tokens.values[token.parent-1]
			if w.format == JSON {
				if parent.first != uint32(i+1) {
					w.raw(",")
				}
				w.raw("\n" + strings.Repeat("  ", depth))
			} else {
				w.raw(strings.Repeat("  ", depth-1))
			}
			if parent.kind == '{' {
				if w.format == YAML {
					w.yamlString(token.name, limit, true, false)
				} else {
					w.raw(string(body[token.keyStart:token.keyEnd]))
				}
				w.raw(":")
				if w.format == JSON {
					w.raw(" ")
				}
			} else if w.format == YAML {
				w.raw("-")
			}
		}
		collection := token.kind == '{' || token.kind == '['
		if collection && token.first != 0 {
			if w.format == JSON {
				w.raw(string(token.kind))
			} else {
				w.raw("\n")
			}
			stack = append(stack, frame{node: uint32(i + 1), depth: depths[i]})
		} else {
			if w.format == YAML {
				w.raw(" ")
			}
			if collection {
				if token.kind == '{' {
					w.raw("{}")
				} else {
					w.raw("[]")
				}
			} else {
				if w.format == YAML && token.kind == '"' {
					w.yamlString(stringValue(token), limit, false, false)
				} else {
					w.raw(string(tokens.raw(uint32(i + 1))))
				}
			}
			if w.format == YAML {
				w.raw("\n")
			}
		}
	}
	for len(stack) > 0 {
		closeFrame()
	}
}
