package configuration

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"sort"
	"strings"

	generator "enkv.sh/sdk/protocols/generator"
)

type settingsToken struct {
	name                                              string
	start, end, first, next, keyStart, keyEnd, parent uint32
	kind                                              byte
}
type settingsTokens struct {
	body   []byte
	values []settingsToken
	keys   []uint32
}

// Spans borrow one bounded settings record. They do not retain decoded numbers
// or a second copy of the baseline. Index zero is represented by the link 1.
func inspectSettingsTokens(body []byte) (settingsTokens, error) {
	if !generator.ValidCanonicalSettings(body) {
		return settingsTokens{}, ErrCapture
	}
	result := settingsTokens{body: body, values: make([]settingsToken, 0, (len(body)+1)/2), keys: make([]uint32, 0, len(body)/4)}
	type frame struct {
		node, last       uint32
		name             string
		keyStart, keyEnd uint32
		key              bool
	}
	stack := make([]frame, 0, min(10000, len(body)/2))
	add := func(start, end int, kind byte) uint32 {
		value := settingsToken{start: uint32(start), end: uint32(end), kind: kind}
		if len(stack) > 0 {
			parent := &stack[len(stack)-1]
			value.parent = parent.node
			if result.values[parent.node-1].kind == '{' {
				value.name, value.keyStart, value.keyEnd = parent.name, parent.keyStart, parent.keyEnd
			}
		}
		result.values = append(result.values, value)
		link := uint32(len(result.values))
		if len(stack) > 0 {
			parent := &stack[len(stack)-1]
			if parent.last == 0 {
				result.values[parent.node-1].first = link
			} else {
				result.values[parent.last-1].next = link
			}
			parent.last = link
			if result.values[parent.node-1].kind == '{' {
				result.keys = append(result.keys, link)
			}
		}
		return link
	}
	for i := 0; i < len(body); {
		switch body[i] {
		case ' ', '\t', '\r', '\n':
			i++
		case '{', '[':
			link := add(i, 0, body[i])
			stack = append(stack, frame{node: link, key: body[i] == '{'})
			i++
		case '}', ']':
			result.values[stack[len(stack)-1].node-1].end = uint32(i + 1)
			stack = stack[:len(stack)-1]
			i++
		case ':':
			stack[len(stack)-1].key = false
			i++
		case ',':
			stack[len(stack)-1].key = result.values[stack[len(stack)-1].node-1].kind == '{'
			i++
		case '"':
			end := settingsStringEnd(body, i)
			if len(stack) > 0 && stack[len(stack)-1].key {
				parent := &stack[len(stack)-1]
				if json.Unmarshal(body[i:end], &parent.name) != nil {
					return settingsTokens{}, ErrCapture
				}
				parent.keyStart, parent.keyEnd = uint32(i), uint32(end)
			} else {
				add(i, end, '"')
			}
			i = end
		default:
			end := i + 1
			for end < len(body) && !strings.ContainsRune(" \t\r\n,]}", rune(body[end])) {
				end++
			}
			kind := body[i]
			if kind == '-' || kind >= '0' && kind <= '9' {
				kind = '#'
			}
			add(i, end, kind)
			i = end
		}
	}
	slices.SortFunc(result.keys, func(a, b uint32) int {
		x, y := result.values[a-1], result.values[b-1]
		if x.parent < y.parent {
			return -1
		}
		if x.parent > y.parent {
			return 1
		}
		return strings.Compare(x.name, y.name)
	})
	return result, nil
}
func settingsStringEnd(body []byte, start int) int {
	for i := start + 1; i < len(body); i++ {
		if body[i] == '\\' {
			i++
			continue
		}
		if body[i] == '"' {
			return i + 1
		}
	}
	return len(body)
}
func (v settingsTokens) raw(link uint32) []byte {
	token := v.values[link-1]
	return v.body[token.start:token.end]
}
func (v settingsTokens) member(parent uint32, name string) uint32 {
	at := sort.Search(len(v.keys), func(i int) bool {
		token := v.values[v.keys[i]-1]
		return token.parent > parent || token.parent == parent && token.name >= name
	})
	if at < len(v.keys) {
		token := v.values[v.keys[at]-1]
		if token.parent == parent && token.name == name {
			return v.keys[at]
		}
	}
	return 0
}

// Formatting and key ordering do not change meaning. Numeric spellings remain
// exact tokens, and strings compare by their decoded Unicode scalar sequence.
func compareSettingsTokens(original, edited settingsTokens) ([]uint32, []bool, error) {
	matches := make([]uint32, len(edited.values))
	matches[0] = 1
	for i, token := range edited.values {
		old := matches[i]
		if old == 0 || token.kind != original.values[old-1].kind {
			continue
		}
		switch token.kind {
		case '{':
			for child := token.first; child != 0; child = edited.values[child-1].next {
				matches[child-1] = original.member(old, edited.values[child-1].name)
			}
		case '[':
			oldChild := original.values[old-1].first
			for child := token.first; child != 0 && oldChild != 0; child = edited.values[child-1].next {
				matches[child-1] = oldChild
				oldChild = original.values[oldChild-1].next
			}
		}
	}
	equal := make([]bool, len(edited.values))
	for i := len(edited.values) - 1; i >= 0; i-- {
		token := edited.values[i]
		old := matches[i]
		if old == 0 || token.kind != original.values[old-1].kind {
			continue
		}
		switch token.kind {
		case '{', '[':
			oldCount, newCount := 0, 0
			unchanged := true
			for child := original.values[old-1].first; child != 0; child = original.values[child-1].next {
				oldCount++
			}
			for child := token.first; child != 0; child = edited.values[child-1].next {
				newCount++
				unchanged = unchanged && equal[child-1]
			}
			equal[i] = oldCount == newCount && unchanged
		case '"':
			var a, b string
			if json.Unmarshal(original.raw(old), &a) != nil || json.Unmarshal(edited.raw(uint32(i+1)), &b) != nil {
				return nil, nil, ErrCapture
			}
			equal[i] = a == b
		default:
			equal[i] = bytes.Equal(original.raw(old), edited.raw(uint32(i+1)))
		}
	}
	return matches, equal, nil
}

type settingsTokenWriter struct {
	body          []byte
	length, limit int
	retain        bool
}

func (w *settingsTokenWriter) Write(body []byte) (int, error) {
	if len(body) > w.limit-w.length {
		return 0, io.ErrShortWrite
	}
	if w.retain {
		w.body = append(w.body, body...)
	}
	w.length += len(body)
	return len(body), nil
}

func emitEditedSettings(out io.Writer, original, edited settingsTokens, matches []uint32, equal []bool) error {
	write := func(body []byte) error {
		n, err := out.Write(body)
		if err == nil && n != len(body) {
			return io.ErrShortWrite
		}
		return err
	}
	if err := write(original.body[:original.values[0].start]); err != nil {
		return err
	}
	type frame struct {
		node, cursor uint32
		phase        byte
		count        int
	}
	stack := make([]frame, 1, 10000)
	stack[0].node = 1
	for len(stack) > 0 {
		at := len(stack) - 1
		current := &stack[at]
		node := edited.values[current.node-1]
		old := matches[current.node-1]
		if current.phase == 0 {
			if equal[current.node-1] {
				if err := write(original.raw(old)); err != nil {
					return err
				}
				stack = stack[:at]
				continue
			}
			if old == 0 || node.kind != original.values[old-1].kind || node.kind != '{' && node.kind != '[' {
				if err := write(edited.raw(current.node)); err != nil {
					return err
				}
				stack = stack[:at]
				continue
			}
			if err := write([]byte{node.kind}); err != nil {
				return err
			}
			current.phase = 1
			current.cursor = node.first
			if node.kind == '{' {
				current.cursor = original.values[old-1].first
			}
		}
		child := uint32(0)
		if node.kind == '[' {
			child = current.cursor
			if child != 0 {
				current.cursor = edited.values[child-1].next
			}
		} else {
			for current.phase == 1 && current.cursor != 0 && child == 0 {
				prior := original.values[current.cursor-1]
				current.cursor = prior.next
				child = edited.member(current.node, prior.name)
			}
			if child == 0 && current.phase == 1 {
				current.phase = 2
				current.cursor = node.first
			}
			for current.phase == 2 && current.cursor != 0 && child == 0 {
				candidate := current.cursor
				current.cursor = edited.values[candidate-1].next
				if matches[candidate-1] == 0 {
					child = candidate
				}
			}
		}
		if child == 0 {
			close := byte('}')
			if node.kind == '[' {
				close = ']'
			}
			if err := write([]byte{close}); err != nil {
				return err
			}
			stack = stack[:at]
			continue
		}
		if current.count > 0 {
			if err := write([]byte{','}); err != nil {
				return err
			}
		}
		current.count++
		if node.kind == '{' {
			token := edited.values[child-1]
			body := edited.body
			if prior := matches[child-1]; prior != 0 {
				token = original.values[prior-1]
				body = original.body
			}
			if err := write(body[token.keyStart:token.keyEnd]); err != nil {
				return err
			}
			if err := write([]byte{':'}); err != nil {
				return err
			}
		}
		if equal[child-1] {
			if err := write(original.raw(matches[child-1])); err != nil {
				return err
			}
			continue
		}
		childToken, prior := edited.values[child-1], matches[child-1]
		if prior == 0 || childToken.kind != original.values[prior-1].kind || childToken.kind != '{' && childToken.kind != '[' {
			if err := write(edited.raw(child)); err != nil {
				return err
			}
			continue
		}
		stack = append(stack, frame{node: child})
	}
	return write(original.body[original.values[0].end:])
}

func editedCanonicalSettings(original, edited []byte, limit int) ([]byte, error) {
	if len(original) > limit || len(edited) > limit {
		return nil, sourceError("canonical.settings", "settings-limit")
	}
	before, err := inspectSettingsTokens(original)
	if err != nil {
		return nil, err
	}
	after, err := inspectSettingsTokens(edited)
	if err != nil {
		return nil, err
	}
	matches, equal, err := compareSettingsTokens(before, after)
	if err != nil {
		return nil, err
	}
	if equal[0] {
		return original, nil
	}
	count := &settingsTokenWriter{limit: limit}
	if err := emitEditedSettings(count, before, after, matches, equal); err != nil {
		return nil, sourceError("canonical.settings", "settings-limit")
	}
	writer := &settingsTokenWriter{body: make([]byte, 0, count.length), limit: count.length, retain: true}
	if err := emitEditedSettings(writer, before, after, matches, equal); err != nil {
		return nil, err
	}
	if !generator.ValidCanonicalSettings(writer.body) {
		return nil, ErrCapture
	}
	return writer.body, nil
}
