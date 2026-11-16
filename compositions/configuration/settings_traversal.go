package configuration

import (
	"encoding/json"
	"strings"

	generator "enkv.sh/sdk/protocols/generator"
)

// Settings use the existing scalar, indentation and flow rules, with their own
// iterative collection lifetime. Their admitted depth is independent of the
// configuration envelope's sixteen structural frames.
func parseSettingsIterative(p *parser, limit int) []byte {
	type frame struct {
		kind        byte
		flow, after bool
		col         uint64
		count       int
		first       *parsedObjectKey
		owner       valueOwner
		indent      uint64
	}
	out := settingsBuffer{limit: limit}
	writer := generatedWriter{out: &out}
	stack := make([]frame, 0, 10000)
	outerOwner, outerFlow, outerDepth := p.valueOwner, p.flowDepth, p.depth
	// Standalone settings still need one scanner indentation slot for scalar
	// folding. Collection depth remains in stack, and the outer depth is restored.
	if p.depth == 0 {
		p.depth = 1
	}
	indentIndex := max(0, p.depth-1)
	originalIndent := p.indents[indentIndex]
	origin := p.mark(0, 0)
	defer func() {
		p.valueOwner = outerOwner
		p.flowDepth = outerFlow
		p.depth = outerDepth
		p.indents[indentIndex] = originalIndent
		p.collection = origin
	}()
	prefix := func(first, array bool) {
		if !p.layoutEnabled {
			return
		}
		depth := p.depth + len(stack)
		if depth > 1 || !first {
			p.layout.bytes += 1 + int64(2*(depth-1))
			p.layout.lines++
		}
		if array {
			p.layout.bytes++
		}
	}
	closeFrame := func() {
		current := stack[len(stack)-1]
		if current.flow {
			p.flowDepth--
		}
		p.indents[indentIndex] = current.indent
		p.valueOwner = current.owner
		close := byte('}')
		if current.kind == '[' {
			close = ']'
		}
		writer.raw(string(close))
		stack = stack[:len(stack)-1]
	}
	openFrame := func(kind byte, first *parsedObjectKey) {
		p.skip()
		if len(stack) == 10000 {
			p.fail("depth-limit")
			return
		}
		col := p.col
		if first != nil {
			col = first.span.Column
		}
		flow := first == nil && (p.peek() == '{' || p.peek() == '[')
		owner := p.valueOwner
		if p.format == YAML && kind == '{' && (owner.kind == blockKeyOwner && p.line == owner.line && !flow || (owner.kind == blockKeyOwner || owner.kind == sequenceItemOwner) && p.line > owner.line && col <= owner.col) {
			p.fail("invalid-indentation")
			return
		}
		current := frame{kind: kind, flow: flow, col: col, first: first, owner: owner, indent: p.indents[indentIndex]}
		stack = append(stack, current)
		writer.raw(string(kind))
		if flow {
			p.flowDepth++
			p.take()
		} else {
			p.indents[indentIndex] = col
		}
	}
	needValue := true
	for p.err == nil && writer.err == nil {
		if needValue {
			p.skip()
			needValue = false
			switch {
			case p.peek() == '{':
				openFrame('{', nil)
				continue
			case p.peek() == '[' || p.format == YAML && p.peek() == '-' && p.separated(1):
				openFrame('[', nil)
				continue
			}
			scalar, quoted, first := readSettingsScalar(p, limit)
			p.skip()
			if p.format == YAML && p.peek() == ':' && p.separated(1) {
				p.validateText(scalar, true)
				if p.err != nil {
					break
				}
				openFrame('{', &parsedObjectKey{text: string(scalar), span: first})
				continue
			}
			if quoted {
				writer.quote(string(scalar), limit)
			} else {
				text := string(scalar)
				if p.format == YAML {
					switch text {
					case "Null", "NULL", "~":
						text = "null"
					}
				}
				if json.Valid([]byte(text)) {
					p.layoutRaw(len(text))
					writer.raw(text)
				} else if p.format == YAML && !typedPlain(scalar) {
					writer.quote(text, limit)
				} else {
					p.fail("invalid-settings-value")
				}
			}
			if len(stack) == 0 {
				break
			}
		}
		if len(stack) == 0 {
			break
		}
		current := &stack[len(stack)-1]
		p.skip()
		close := byte('}')
		if current.kind == '[' {
			close = ']'
		}
		if current.after {
			p.valueOwner = current.owner
			if current.flow {
				if p.peek() == close {
					p.layoutEnd = p.layout
					p.take()
					closeFrame()
					continue
				}
				p.expect(',')
				p.skip()
				if p.peek() == close {
					if p.format == YAML {
						p.take()
						closeFrame()
						continue
					}
					p.fail("trailing-comma")
					break
				}
			} else if p.col < current.col || p.peek() == 0 {
				closeFrame()
				continue
			}
			current.after = false
		} else if current.flow && p.peek() == close {
			if p.layoutEnabled {
				p.layout.bytes += 2
				if p.depth+len(stack) > 1 {
					p.layout.bytes++
				}
				p.layoutEnd = p.layout
			}
			p.take()
			closeFrame()
			continue
		}
		if p.peek() == 0 {
			if current.flow {
				p.fail("unexpected-end")
			} else {
				closeFrame()
			}
			continue
		}
		if current.count >= limit {
			p.fail("collection-limit")
			break
		}
		if current.kind == '{' {
			if current.first == nil && !current.flow {
				if p.col < current.col {
					closeFrame()
					continue
				}
				if p.col != current.col {
					p.fail("invalid-indentation")
					break
				}
			}
			member := p.mark(0, 0)
			prefix(current.count == 0, false)
			keyLine := p.line
			var key string
			if current.first != nil {
				key, member, keyLine = current.first.text, current.first.span, current.first.span.Line
				current.first = nil
			} else {
				key = p.text(limit, true, false)
			}
			p.skip()
			if p.format == YAML && p.line != keyLine {
				p.fail("complex-key")
				break
			}
			p.expect(':')
			if p.layoutEnabled {
				p.layout.bytes++
			}
			if p.format == YAML && !current.flow && !p.separated(0) {
				p.fail("block-value-separation")
			}
			p.skip()
			if current.count > 0 {
				writer.raw(",")
			}
			writer.quote(key, limit)
			writer.raw(":")
			p.valueOwner = valueOwner{kind: blockKeyOwner, line: member.Line, col: member.Column}
			if current.flow {
				p.valueOwner.kind = flowCollectionOwner
			}
		} else {
			if !current.flow && (p.col != current.col || p.peek() != '-') {
				closeFrame()
				continue
			}
			item := p.mark(0, 0)
			prefix(current.count == 0, true)
			if !current.flow {
				p.take()
				if p.peek() != ' ' && p.peek() != '\n' && p.peek() != '\r' {
					p.fail("invalid-sequence")
					break
				}
				p.skip()
				if p.line > item.Line && p.col <= item.Column {
					p.fail("invalid-indentation")
					break
				}
			}
			if current.count > 0 {
				writer.raw(",")
			}
			p.valueOwner = valueOwner{kind: sequenceItemOwner, line: item.Line, col: item.Column}
			if current.flow {
				p.valueOwner.kind = flowCollectionOwner
			}
		}
		current.count++
		current.after = true
		needValue = true
	}
	if p.err != nil || writer.err != nil || !generator.ValidCanonicalSettings(out.body) {
		if p.err == nil {
			p.fail("invalid-settings-value")
		}
		return nil
	}
	return out.body
}

func readSettingsScalar(p *parser, limit int) ([]byte, bool, Span) {
	var scalar []byte
	first := p.mark(0, 0)
	quoted := p.peek() == '"' || p.format == YAML && p.peek() == '\''
	emit := func(b byte) {
		var ok bool
		scalar, ok = boundedAppend(scalar, b, limit)
		if !ok {
			p.fail("settings-limit")
		}
	}
	if p.format == JSON && !quoted {
		for p.err == nil {
			b := p.peek()
			if b == 0 || strings.ContainsRune(" \t\r\n,]}", rune(b)) {
				break
			}
			p.take()
			emit(b)
		}
	} else {
		p.scalarValue(emit, false, true, p.format == YAML)
	}
	first.Length = max(0, p.end-first.Offset)
	return scalar, quoted, first
}
