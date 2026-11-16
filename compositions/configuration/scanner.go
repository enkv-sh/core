package configuration

import (
	"bufio"
	"context"
	"io"

	"enkv.sh/core/contract"
)

type parser struct {
	provider                                  contract.Family
	end                                       int64
	trivia                                    bool
	ctx                                       context.Context
	ctxDone                                   <-chan struct{}
	r                                         *bufio.Reader
	format                                    Format
	off                                       int64
	line, col                                 uint64
	depth, flowDepth                          int
	indents                                   [MaxDepth]uint64
	field                                     string
	err                                       error
	spans                                     *[]Span
	plain                                     bool
	scalarMultiline                           bool
	generatedImage                            bool
	unicodeRemaining, unicodeLow, unicodeHigh byte
	indentation                               bool
	previousCR                                bool
	onComment                                 func(int64, int64) error
	member                                    Span
	arrayItem                                 Span
	valueOwner                                valueOwner
	token                                     Span
	collection                                Span
	document                                  bool
	layoutEnabled                             bool
	layout, layoutEnd                         layoutSize
	tokenLayout                               int64
}

type layoutSize struct{ bytes, lines int64 }

func (s layoutSize) since(before layoutSize) layoutSize {
	return layoutSize{s.bytes - before.bytes, s.lines - before.lines}
}
func (p *parser) layoutPrefix(first, array bool) {
	if !p.layoutEnabled {
		return
	}
	indent := int64(2 * (p.depth - 1))
	if p.depth > 1 || !first {
		p.layout.bytes += 1 + indent
		p.layout.lines++
	}
	if array {
		p.layout.bytes++
	}
}
func (p *parser) layoutRaw(length int) {
	if p.layoutEnabled {
		p.layout.bytes += int64(length) + 1 - p.tokenLayout
		p.layoutEnd = p.layout
	}
}

type valueOwnerKind uint8

const (
	noValueOwner valueOwnerKind = iota
	blockKeyOwner
	sequenceItemOwner
	flowCollectionOwner
)

type valueOwner struct {
	kind      valueOwnerKind
	line, col uint64
}

func newParser(ctx context.Context, r io.Reader, f Format) *parser {
	p := &parser{ctx: ctx, r: bufio.NewReaderSize(r, WindowBytes), format: f, line: 1, col: 1, indentation: true}
	if ctx == nil {
		p.fail("invalid-context")
	} else {
		p.ctxDone = ctx.Done()
	}
	return p
}
func (p *parser) fail(reason string) {
	var cause error
	switch reason {
	case "read-failed", "invalid-context":
	case "cancelled":
		if p.ctx != nil {
			cause = p.ctx.Err()
		}
	default:
		cause = ErrSourceInvalid
	}
	p.failCause(reason, cause)
}
func (p *parser) failRead(cause error) { p.failCause("read-failed", cause) }
func (p *parser) failCause(reason string, cause error) {
	if p.err == nil {
		p.err = &Diagnostic{Field: p.field, Generated: p.generatedImage, Offset: p.off, Line: p.line, Column: p.col, Reason: reason, cause: cause}
	}
}
func (p *parser) failPosition(reason string, at Span) {
	if p.err != nil {
		return
	}
	p.fail(reason)
	if d, ok := p.err.(*Diagnostic); ok {
		d.Offset, d.Line, d.Column = at.Offset, at.Line, at.Column
	}
}
func (p *parser) failFieldValue(reason, field string, at Span) {
	if p.err != nil {
		return
	}
	if p.field == "" {
		p.field = safeField(field)
	} else {
		p.field += "." + safeField(field)
	}
	p.token = at
	p.failValue(reason)
}
func (p *parser) failValue(reason string) {
	if p.err != nil {
		return
	}
	p.fail(reason)
	if d, ok := p.err.(*Diagnostic); ok && p.token.Line != 0 {
		d.Offset, d.Line, d.Column = p.token.Offset, p.token.Line, p.token.Column
	}
}
func (p *parser) failContext(reason string) {
	if p.err != nil {
		return
	}
	p.fail(reason)
	if d, ok := p.err.(*Diagnostic); ok {
		d.Context = true
		if p.collection.Line != 0 {
			d.Offset, d.Line, d.Column = p.collection.Offset, p.collection.Line, p.collection.Column
		}
	}
}
func (p *parser) failMember(reason string) {
	if p.err != nil {
		return
	}
	p.fail(reason)
	if d, ok := p.err.(*Diagnostic); ok && p.member.Line != 0 {
		d.Offset, d.Line, d.Column = p.member.Offset, p.member.Line, p.member.Column
	}
}
func (p *parser) marker(marker string) bool {
	if p.format != YAML || p.col != 1 || p.flowDepth != 0 {
		return false
	}
	v, err := p.r.Peek(4)
	if err != nil && err != io.EOF {
		p.failRead(err)
		return false
	}
	return len(v) >= 3 && string(v[:3]) == marker && (len(v) == 3 || v[3] == ' ' || v[3] == '\t' || v[3] == '\r' || v[3] == '\n')
}
func (p *parser) beginDocument() {
	p.document = p.format == YAML
	p.skip()
	if !p.document {
		return
	}
	if p.col == 1 && p.peek() == '%' {
		p.fail("directive-forbidden")
		return
	}
	if p.marker("---") {
		p.take()
		p.take()
		p.take()
		p.skip()
	}
	if p.marker("---") {
		p.fail("additional-document")
	}
	if p.col == 1 && p.peek() == '%' {
		p.fail("directive-forbidden")
	}
}
func safeField(key string) string {
	switch key {
	case "plugins", "plugin", "settings", "canonical", "canonical_records", "generators":
		return key
	case "schema", "domain", "provider", "store", "region", "bucket", "prefix", "expected_owner", "authority", "recovery", "enabled", "display_name", "signing_key", "encryption_key", "recipients", "entries", "source", "confidentiality", "kind", "value", "bytes", "generator", "epoch", "retirement", "spec", "account", "name", "policies", "effect", "permission_groups", "resources", "id", "request_ip", "in", "not_in", "not_before", "expires_on", "outputs", "destinations", "profile", "version", "encodings", "project_number", "owner", "repository", "environment", "visibility", "repositories", "routing", "default", "fallback", "groups", "generated", "file_id", "signing", "encryption", "selector", "public_key", "binding", "incarnation", "serial", "protection", "creation", "snapshot", "nonce", "secrets", "sealed", "retained", "material", "public_basis", "descriptor", "control", "selection", "enrollment", "status", "observation", "store_configuration", "head", "anchor", "root", "recipient_pages":
		return key
	default:
		return "item"
	}
}
func (p *parser) peek() byte {
	if p.err != nil {
		return 0
	}
	v, e := p.r.Peek(1)
	if e == io.EOF {
		if p.unicodeRemaining != 0 {
			p.fail("invalid-unicode")
		}
		return 0
	}
	if e != nil {
		p.failRead(e)
		return 0
	}
	if v[0] == 0 {
		p.fail("invalid-control")
		return 0
	}
	return v[0]
}
func (p *parser) take() byte {
	if p.err != nil {
		return 0
	}
	select {
	case <-p.ctxDone:
		p.fail("cancelled")
		return 0
	default:
	}
	v, e := p.r.ReadByte()
	if e != nil {
		if e == io.EOF {
			p.fail("unexpected-end")
		} else {
			p.failRead(e)
		}
		return 0
	}
	p.off++
	if !p.trivia {
		p.end = p.off
	}
	if p.unicodeRemaining > 0 {
		if v < p.unicodeLow || v > p.unicodeHigh {
			p.fail("invalid-unicode")
		}
		p.unicodeRemaining--
		p.unicodeLow, p.unicodeHigh = 0x80, 0xbf
	} else {
		switch {
		case v < 0x20 && v != '\t' && v != '\r' && v != '\n':
			p.fail("invalid-control")
		case v < 0x80:
		case v >= 0xc2 && v <= 0xdf:
			p.unicodeRemaining = 1
			p.unicodeLow, p.unicodeHigh = 0x80, 0xbf
		case v >= 0xe0 && v <= 0xef:
			p.unicodeRemaining = 2
			p.unicodeLow, p.unicodeHigh = 0x80, 0xbf
			if v == 0xe0 {
				p.unicodeLow = 0xa0
			}
			if v == 0xed {
				p.unicodeHigh = 0x9f
			}
		case v >= 0xf0 && v <= 0xf4:
			p.unicodeRemaining = 3
			p.unicodeLow, p.unicodeHigh = 0x80, 0xbf
			if v == 0xf0 {
				p.unicodeLow = 0x90
			}
			if v == 0xf4 {
				p.unicodeHigh = 0x8f
			}
		default:
			p.fail("invalid-unicode")
		}
	}
	if v == '\r' || v == '\n' {
		if v == '\r' || !p.previousCR {
			p.line++
		}
		p.col = 1
		p.indentation = true
	} else {
		p.col++
		if v != ' ' && v != '\t' {
			p.indentation = false
		}
	}
	p.previousCR = v == '\r'
	return v
}

func (p *parser) consumeLineBreak() bool {
	b := p.peek()
	if b != '\r' && b != '\n' {
		return false
	}
	p.take()
	if b == '\r' && p.peek() == '\n' {
		p.take()
	}
	return true
}
func (p *parser) skip() {
	old := p.trivia
	p.trivia = true
	defer func() { p.trivia = old }()
	for p.err == nil {
		switch p.peek() {
		case ' ':
			p.spaces()
		case '\r', '\n':
			p.take()
		case '\t':
			if p.format == YAML && p.indentation {
				p.fail("tab-indentation")
				return
			}
			p.take()
		case '#':
			if p.format != YAML {
				return
			}
			p.skipComment()
		default:
			return
		}
	}
}

func (p *parser) skipComment() {
	start := p.off
	for p.err == nil && p.peek() != 0 && p.peek() != '\n' && p.peek() != '\r' {
		p.take()
	}
	if p.layoutEnabled {
		p.layout.bytes += p.off - start + 2 + int64(4*p.depth)
		p.layout.lines += 2
	}
	if p.err == nil && p.onComment != nil {
		p.err = p.onComment(start, p.off-start)
	}
}
func (p *parser) expect(c byte) {
	if p.peek() != c {
		p.fail("unexpected-token")
		return
	}
	p.take()
}
func (p *parser) frame() func() {
	p.depth++
	if p.depth > MaxDepth {
		p.fail("depth-limit")
	}
	return func() {
		if p.depth <= MaxDepth {
			p.indents[p.depth-1] = 0
		}
		p.depth--
	}
}
func (p *parser) indent() uint64 {
	for i := min(p.depth, MaxDepth) - 1; i >= 0; i-- {
		if p.indents[i] != 0 {
			return p.indents[i]
		}
	}
	return 1
}
func (p *parser) object(limit int, fn func(string)) {
	p.objectFields(limit, 256, nil, fn)
}

type parsedObjectKey struct {
	text string
	span Span
}

func (p *parser) objectFields(limit, keyLimit int, first *parsedObjectKey, fn func(string)) {
	defer p.frame()()
	p.skip()
	origin := Span{Offset: p.off, Line: p.line, Column: p.col}
	defer func() { p.collection = origin }()
	if p.err != nil {
		return
	}
	col := p.col
	if first != nil {
		col = first.span.Column
	}
	flow := first == nil && p.peek() == '{'
	if p.format == YAML {
		if p.peek() == 0 {
			p.fail("object-required")
			return
		}
		owner := p.valueOwner
		// Flow keys impose no block indentation floor on their values.
		if owner.kind == blockKeyOwner && p.line == owner.line && !flow ||
			(owner.kind == blockKeyOwner || owner.kind == sequenceItemOwner) && p.line > owner.line && col <= owner.col {
			p.fail("invalid-indentation")
			return
		}
	}
	if flow {
		p.flowDepth++
		defer func() { p.flowDepth-- }()
		p.take()
		p.skip()
		if p.peek() == '}' {
			if p.layoutEnabled {
				p.layout.bytes += 2
				if p.depth > 1 {
					p.layout.bytes++
				}
				p.layoutEnd = p.layout
			}
			p.take()
			return
		}
	} else if p.format != YAML {
		p.fail("object-required")
		return
	} else {
		p.indents[p.depth-1] = col
	}
	seen := make(map[string]struct{}, min(limit, 16))
	count := 0
	for p.err == nil {
		p.skip()
		if p.document && p.depth == 1 && !flow && p.col == 1 && (p.marker("---") || p.marker("...") || p.peek() == '%') {
			break
		}
		if first == nil && !flow && p.col < col {
			break
		}
		if first == nil && !flow && p.col != col {
			p.fail("invalid-indentation")
			break
		}
		if p.peek() == 0 {
			if flow {
				p.fail("unexpected-end")
			}
			break
		}
		if count == limit {
			p.fail("collection-limit")
			break
		}
		member := p.mark(0, 0)
		p.layoutPrefix(count == 0, false)
		keyLine := p.line
		var key string
		if first != nil {
			key, member, keyLine = first.text, first.span, first.span.Line
			first = nil
		} else {
			key = p.text(keyLimit, true, false)
		}
		member.SourceOffset, member.SourceLength = member.Offset, max(0, p.end-member.Offset)
		if p.err != nil {
			break
		}
		if _, ok := seen[key]; ok {
			p.token = member
			part := safeField(key)
			if p.field == "" {
				p.field = part
			} else {
				p.field += "." + part
			}
			p.failValue("duplicate-key")
			break
		}
		seen[key] = struct{}{}
		count++
		p.skip()
		if p.format == YAML && p.line != keyLine {
			p.fail("complex-key")
			break
		}
		p.expect(':')
		if p.layoutEnabled {
			p.layout.bytes++
		}
		if p.format == YAML && !flow && !p.separated(0) {
			p.fail("block-value-separation")
		}
		p.skip()
		old := p.field
		part := safeField(key)
		if old == "" {
			p.field = part
		} else {
			p.field = old + "." + part
		}
		previousMember := p.member
		p.member = member
		previousOwner := p.valueOwner
		p.valueOwner = valueOwner{kind: blockKeyOwner, line: member.Line, col: member.Column}
		if flow {
			p.valueOwner.kind = flowCollectionOwner
		}
		fn(key)
		p.valueOwner = previousOwner
		p.member = previousMember
		p.field = old
		if flow {
			p.skip()
			if p.peek() == '}' {
				if p.layoutEnabled {
					p.layoutEnd = p.layout
				}
				p.take()
				break
			}
			p.expect(',')
			p.skip()
			if p.peek() == '}' {
				if p.format == YAML {
					p.take()
					break
				}
				p.fail("trailing-comma")
			}
		} else {
			p.skip()
			if p.col < col || p.peek() == 0 {
				break
			}
		}
	}
}
func (p *parser) array(limit int, fn func(int)) {
	defer p.frame()()
	p.skip()
	origin := Span{Offset: p.off, Line: p.line, Column: p.col}
	defer func() { p.collection = origin }()
	if p.err != nil {
		return
	}
	flow := p.peek() == '['
	col := p.col
	if flow {
		p.flowDepth++
		defer func() { p.flowDepth-- }()
		p.take()
		p.skip()
		if p.peek() == ']' {
			if p.layoutEnabled {
				p.layout.bytes += 2
				if p.depth > 1 {
					p.layout.bytes++
				}
				p.layoutEnd = p.layout
			}
			p.take()
			return
		}
	} else if p.format != YAML || p.peek() != '-' {
		p.fail("array-required")
		return
	} else {
		p.indents[p.depth-1] = col
	}
	n := 0
	for p.err == nil {
		p.skip()
		if !flow && (p.col != col || p.peek() != '-') {
			break
		}
		if n == limit {
			p.fail("collection-limit")
			return
		}
		item := p.mark(0, 0)
		p.layoutPrefix(n == 0, true)
		if !flow {
			p.take()
			if p.peek() != ' ' && p.peek() != '\n' && p.peek() != '\r' {
				p.fail("invalid-sequence")
				return
			}
			p.skip()
			if p.line > item.Line && p.col <= item.Column {
				p.fail("invalid-indentation")
				return
			}
		}
		previousItem := p.arrayItem
		p.arrayItem = item
		previousOwner := p.valueOwner
		p.valueOwner = valueOwner{kind: sequenceItemOwner, line: item.Line, col: item.Column}
		if flow {
			p.valueOwner.kind = flowCollectionOwner
		}
		fn(n)
		p.valueOwner = previousOwner
		p.arrayItem = previousItem
		n++
		p.skip()
		if flow {
			if p.peek() == ']' {
				if p.layoutEnabled {
					p.layoutEnd = p.layout
				}
				p.take()
				return
			}
			p.expect(',')
			p.skip()
			if p.peek() == ']' {
				if p.format == YAML {
					p.take()
					return
				}
				p.fail("trailing-comma")
				return
			}
		} else if p.col < col || p.peek() == 0 {
			return
		}
	}
}
func (p *parser) done() error {
	if p.ctx != nil && p.ctx.Err() != nil {
		p.fail("cancelled")
	}
	p.skip()
	if p.document {
		if p.marker("...") {
			p.take()
			p.take()
			p.take()
			p.skip()
		}
		if p.marker("---") {
			p.fail("additional-document")
		}
		if p.col == 1 && p.peek() == '%' {
			p.fail("directive-forbidden")
		}
	}
	if p.peek() != 0 {
		p.fail("trailing-content")
	}
	return p.err
}
func (p *parser) addSpan(s Span) uint32 {
	if p.spans == nil {
		return 0
	}
	if len(*p.spans) >= MaxSpans {
		p.fail("span-limit")
		return 0
	}
	if len(*p.spans) == cap(*p.spans) {
		next := min(MaxSpans, max(16, 2*cap(*p.spans)))
		grown := make([]Span, len(*p.spans), next)
		copy(grown, *p.spans)
		*p.spans = grown
	}
	index := uint32(len(*p.spans))
	*p.spans = append(*p.spans, s)
	return index
}

func (p *parser) mark(kind uint16, index uint32) Span {
	p.skip()
	return Span{Offset: p.off, Line: p.line, Column: p.col, Kind: kind, Index: index, Flow: p.format == YAML && p.flowDepth > 0}
}
func (p *parser) record(s Span) uint32 {
	if p.err != nil {
		return 0
	}
	s.Length = max(0, p.end-s.Offset)
	return p.addSpan(s)
}

// Spaces can fill the complete image. Consume only the current scanner window.
func (p *parser) spaces() {
	if p.unicodeRemaining != 0 {
		p.take()
		return
	}
	for p.err == nil && p.peek() == ' ' {
		if p.ctx.Err() != nil {
			p.fail("cancelled")
			return
		}
		buffer, e := p.r.Peek(p.r.Buffered())
		if e != nil {
			p.failRead(e)
			return
		}
		n := 0
		for n < len(buffer) && buffer[n] == ' ' {
			n++
		}
		if n == 0 {
			return
		}
		used, e := p.r.Discard(n)
		if e != nil || used != n {
			if e == nil {
				e = io.ErrUnexpectedEOF
			}
			p.failRead(e)
			return
		}
		p.off += int64(n)
		p.col += uint64(n)
		p.previousCR = false
	}
}
