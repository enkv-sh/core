package configuration

import (
	"bytes"
	"encoding/base64"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func boundedAppend(dst []byte, b byte, limit int) ([]byte, bool) {
	if len(dst) >= limit {
		return dst, false
	}
	if len(dst) == cap(dst) {
		n := min(limit, max(32, 2*cap(dst)))
		v := make([]byte, len(dst), n)
		copy(v, dst)
		dst = v
	}
	return append(dst, b), true
}

var yamlNumber = regexp.MustCompile(`^(?:[+-]?(?:[0-9][0-9_]*(?::[0-9_]+)*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9]+)?|\.[0-9_]+(?:[eE][+-]?[0-9]+)?|0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+)|[+-]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)

func typedPlain(v []byte) bool {
	s := string(v)
	return s == "true" || s == "false" || s == "null" || s == "Null" || s == "NULL" || s == "~" || yamlNumber.Match(v)
}
func (p *parser) text(limit int, key, block bool) string {
	p.token = p.mark(0, 0)
	if value, ok := p.bufferedQuotedText(limit, key); ok {
		return value
	}
	var v []byte
	p.scalar(func(b byte) {
		var ok bool
		v, ok = boundedAppend(v, b, limit)
		if !ok {
			p.fail("scalar-limit")
		}
	}, key, block)
	p.validateText(v, key)
	return string(v)
}
func (p *parser) validateText(v []byte, key bool) {
	if !utf8.Valid(v) {
		p.fail("invalid-unicode")
	}
	if p.plain && key && string(v) == "<<" {
		p.failValue("merge-forbidden")
	}
	if p.plain && typedPlain(v) {
		p.failValue("string-required")
	}
}
func (p *parser) bufferedQuotedText(limit int, key bool) (string, bool) {
	if p.err != nil || p.unicodeRemaining != 0 || p.trivia || limit < 0 || p.format != JSON && p.format != YAML || p.r.Buffered() < 2 {
		return "", false
	}
	buffer, err := p.r.Peek(p.r.Buffered())
	if err != nil {
		p.plain = false
		p.failRead(err)
		return "", true
	}
	if buffer[0] != '"' {
		return "", false
	}
	windowEnd := min(limit, len(buffer)-2) + 2
	end := bytes.IndexByte(buffer[1:windowEnd], '"') + 1
	if end == 0 {
		return "", false
	}
	value := string(buffer[1:end])
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b <= ' ' || b >= 0x7f || b == '\\' {
			return "", false
		}
	}
	p.plain = false
	if p.layoutEnabled {
		p.tokenLayout = int64(len(value) + 2)
		if !key {
			p.tokenLayout++
		}
		p.layout.bytes += p.tokenLayout
		p.layoutEnd = p.layout
	}
	consumed := 0
	cancelled := false
	done := p.ctxDone
consume:
	for consumed <= end {
		select {
		case <-done:
			cancelled = true
			break consume
		default:
		}
		consumed++
	}
	decoded := min(end-1, max(0, consumed-1))
	if decoded < len(value) {
		value = strings.Clone(value[:decoded])
	}
	used, err := p.r.Discard(consumed)
	if err != nil || used != consumed {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		p.failRead(err)
		return value, true
	}
	if consumed != 0 {
		p.off += int64(consumed)
		p.col += uint64(consumed)
		p.end = p.off
		p.indentation = false
		p.previousCR = false
	}
	if cancelled {
		p.fail("cancelled")
	}
	return value, true
}

func (p *parser) bytes(limit int, block bool) []byte {
	var v []byte
	p.scalar(func(b byte) {
		var ok bool
		v, ok = boundedAppend(v, b, limit)
		if !ok {
			p.fail("scalar-limit")
		}
	}, false, block)
	if !utf8.Valid(v) {
		p.fail("invalid-unicode")
	}
	if p.plain && typedPlain(v) {
		p.failValue("string-required")
	}
	return v
}

// Base64 excludes '.', '-', ':', and '_'. These are the numeric forms that
// remain possible; state is independent of the scalar's encoded length.
type plainBase64Number byte

func (s plainBase64Number) next(b byte) plainBase64Number {
	digit := b >= '0' && b <= '9'
	hex := digit || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
	switch s {
	case 0, 1:
		if b == '+' && s == 0 {
			return 1
		}
		if b == '0' {
			return 2
		}
		if digit {
			return 3
		}
	case 2:
		if b == 'x' || b == 'X' {
			return 7
		}
		if b == 'o' || b == 'O' {
			return 9
		}
		if b == 'b' || b == 'B' {
			return 11
		}
		fallthrough
	case 3:
		if digit {
			return 3
		}
		if b == 'e' || b == 'E' {
			return 4
		}
	case 4:
		if b == '+' {
			return 5
		}
		if digit {
			return 6
		}
	case 5, 6:
		if digit {
			return 6
		}
	case 7, 8:
		if hex {
			return 8
		}
	case 9, 10:
		if b >= '0' && b <= '7' {
			return 10
		}
	case 11, 12:
		if b == '0' || b == '1' {
			return 12
		}
	}
	return 255
}
func (s plainBase64Number) complete() bool {
	return s == 2 || s == 3 || s == 6 || s == 8 || s == 10 || s == 12
}

func (p *parser) base64(limit int) []byte {
	var out []byte
	var group [4]byte
	var prefix [32]byte
	n, encoded := 0, 0
	ended := false
	number := plainBase64Number(0)
	p.scalar(func(b byte) {
		if encoded < len(prefix) {
			prefix[encoded] = b
		}
		number = number.next(b)
		encoded++
		if encoded > base64.StdEncoding.EncodedLen(limit) || ended {
			p.fail("base64-limit-or-padding")
			return
		}
		group[n] = b
		n++
		if n == 4 {
			var raw [3]byte
			k, e := base64.StdEncoding.Strict().Decode(raw[:], group[:])
			if e != nil {
				p.failValue("invalid-base64")
				return
			}
			if k < 3 {
				ended = true
			}
			for _, v := range raw[:k] {
				var ok bool
				out, ok = boundedAppend(out, v, limit)
				if !ok {
					p.fail("scalar-limit")
					return
				}
			}
			n = 0
		}
	}, false, false)
	if n != 0 {
		p.failValue("invalid-base64")
	}
	if p.plain && (number.complete() || encoded <= len(prefix) && typedPlain(prefix[:encoded])) {
		p.failValue("string-required")
	}
	return out
}
func (p *parser) scalar(emit func(byte), key, block bool) {
	p.scalarValue(emit, key, block, false)
}
func (p *parser) scalarValue(emit func(byte), key, block, mapping bool) {
	p.token = p.mark(0, 0)
	p.plain = false
	p.scalarMultiline = false
	if p.err != nil {
		return
	}
	scalarStart := p.off
	layoutBefore := p.layout.bytes
	if p.layoutEnabled {
		p.tokenLayout = 2
		if !key {
			p.tokenLayout++
		}
		p.layout.bytes += p.tokenLayout
	}
	defer func() {
		if p.layoutEnabled {
			if p.err == nil && !p.scalarMultiline {
				size := p.end - scalarStart
				if !key {
					size++
				}
				p.layout.bytes += size - (p.layout.bytes - layoutBefore)
				p.tokenLayout = size
			}
			p.layoutEnd = p.layout
		}
	}()
	sink := emit
	emit = func(b byte) {
		if p.layoutEnabled && p.err == nil {
			n := int64(1)
			if b == '"' || b == '\\' || b == '\n' || b == '\r' || b == '\t' || b == '\b' || b == '\f' {
				n = 2
			} else if b < 0x20 {
				n = 6
			}
			p.layout.bytes += n
			p.tokenLayout += n
		}
		if p.err == nil {
			sink(b)
		}
	}
	quote := p.peek()
	if quote == '"' || quote == '\'' && p.format == YAML {
		p.quoted(quote, emit, key)
		return
	}
	if p.format != YAML {
		p.failValue("string-required")
		return
	}
	if (quote == '|' || quote == '>') && block {
		p.scalarMultiline = true
		p.block(emit)
		return
	}
	if strings.ContainsRune("!&*%@`{}[]|>", rune(quote)) || quote == 0 {
		p.fail("unsupported-scalar")
		return
	}
	if (quote == '?' || quote == ':' || quote == '-') && p.separated(1) {
		p.fail("unsupported-scalar")
		return
	}
	p.plain = true
	var pending []byte
	pendingCount, count := 0, 0
	scalarEnd := p.off
	flush := func() {
		if pendingCount > WindowBytes {
			p.fail("scalar-limit")
			return
		}
		for _, b := range pending {
			emit(b)
		}
		pending = pending[:0]
		pendingCount = 0
	}
	for p.err == nil {
		b := p.peek()
		if b == 0 || p.flowDepth > 0 && (b == ',' || b == ']' || b == '}') {
			break
		}
		if p.flowDepth > 0 && (b == '[' || b == '{') {
			p.fail("flow-indicator-in-plain-scalar")
			break
		}
		if (key || mapping) && b == ':' && p.separated(1) {
			break
		}
		if b == ':' && p.separated(1) {
			p.fail("colon-separation")
			break
		}
		if b == '#' && (count == 0 || pendingCount > 0) {
			break
		}
		if b == '\n' || b == '\r' {
			if key {
				break
			}
			pending = pending[:0]
			pendingCount = 0
			breaks := p.breaks()
			if p.peek() == 0 || p.peek() == '#' || p.flowDepth > 0 && (p.peek() == ',' || p.peek() == ']' || p.peek() == '}') || p.flowDepth == 0 && p.col <= p.indent() {
				break
			}
			p.scalarMultiline = true
			if breaks == 1 {
				emit(' ')
			} else {
				for range breaks - 1 {
					emit('\n')
				}
			}
			continue
		}
		p.take()
		if b == ' ' || b == '\t' {
			pendingCount++
			if pendingCount <= WindowBytes {
				pending, _ = boundedAppend(pending, b, WindowBytes)
			}
			continue
		}
		flush()
		emit(b)
		scalarEnd = p.off
		count++
	}
	p.end = scalarEnd
	if count == 0 {
		p.fail("empty-scalar")
	}

}
func (p *parser) separated(ahead int) bool {
	v, e := p.r.Peek(ahead + 1)
	if e == io.EOF && len(v) <= ahead {
		return true
	}
	if e != nil && e != io.EOF {
		p.failRead(e)
		return true
	}
	if len(v) <= ahead {
		return true
	}
	b := v[ahead]
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || p.flowDepth > 0 && strings.ContainsRune(",[]{}", rune(b))
}
func (p *parser) breaks() int {
	n := 0
	for p.err == nil && p.consumeLineBreak() {
		n++
		for p.peek() == ' ' || p.peek() == '\t' {
			p.take()
		}
	}
	return n
}
func (p *parser) quoted(quote byte, emit func(byte), key bool) {
	p.take()
	var pending []byte
	pendingCount := 0
	flush := func() {
		if pendingCount > WindowBytes {
			p.fail("scalar-limit")
			return
		}
		for _, b := range pending {
			emit(b)
		}
		pending = pending[:0]
		pendingCount = 0
	}
	for p.err == nil {
		at := Span{Offset: p.off, Line: p.line, Column: p.col}
		b := p.take()
		if b == quote {
			flush()
			if quote == '\'' && p.peek() == '\'' {
				p.take()
				emit('\'')
				continue
			}
			return
		}
		if p.format == YAML && (b == ' ' || b == '\t') {
			pendingCount++
			if pendingCount <= WindowBytes {
				pending, _ = boundedAppend(pending, b, WindowBytes)
			}
			continue
		}
		if p.format == YAML && (b == '\n' || b == '\r') {
			p.scalarMultiline = true
			if key {
				p.fail("complex-key")
				return
			}
			pending = pending[:0]
			pendingCount = 0
			if b == '\r' && p.peek() == '\n' {
				p.take()
			}
			for p.peek() == ' ' || p.peek() == '\t' {
				p.take()
			}
			more := p.breaks()
			if more == 0 {
				emit(' ')
			} else {
				for range more {
					emit('\n')
				}
			}
			continue
		}
		flush()
		if b < ' ' {
			p.failPosition("unescaped-control", at)
			return
		}
		if b == '\\' && quote == '"' {
			e := p.take()
			if p.format == YAML && (e == '\n' || e == '\r') {
				p.scalarMultiline = true
				if e == '\r' && p.peek() == '\n' {
					p.take()
				}
				for p.peek() == ' ' || p.peek() == '\t' {
					p.take()
				}
				for range p.breaks() {
					emit('\n')
				}
				continue
			}
			switch e {
			case '"', '\\', '/':
				emit(e)
			case 'b':
				emit('\b')
			case 'f':
				emit('\f')
			case 'n':
				emit('\n')
			case 'r':
				emit('\r')
			case 't':
				emit('\t')
			case 'u':
				r := p.hexRune(4)
				if utf16.IsSurrogate(r) {
					if r < 0xd800 || r > 0xdbff || p.take() != '\\' || p.take() != 'u' {
						p.fail("invalid-surrogate")
						return
					}
					low := p.hexRune(4)
					if low < 0xdc00 || low > 0xdfff {
						p.fail("invalid-surrogate")
						return
					}
					r = utf16.DecodeRune(r, low)
				}
				p.rune(emit, r)
			default:
				if p.format != YAML {
					p.failPosition("invalid-escape", at)
					return
				}
				switch e {
				case '0':
					emit(0)
				case 'a':
					emit(7)
				case 'v':
					emit(11)
				case 'e':
					emit(27)
				case ' ', '\t':
					emit(e)
				case 'N':
					p.rune(emit, 0x85)
				case '_':
					p.rune(emit, 0xa0)
				case 'L':
					p.rune(emit, 0x2028)
				case 'P':
					p.rune(emit, 0x2029)
				case 'x':
					p.rune(emit, p.hexRune(2))
				case 'U':
					p.rune(emit, p.hexRune(8))
				default:
					p.failPosition("invalid-escape", at)
				}
			}
		} else {
			emit(b)
		}
	}
}
func (p *parser) rune(emit func(byte), r rune) {
	if !utf8.ValidRune(r) {
		p.fail("invalid-unicode-escape")
		return
	}
	var b [4]byte
	n := utf8.EncodeRune(b[:], r)
	for _, v := range b[:n] {
		emit(v)
	}
}
func (p *parser) hexRune(count int) rune {
	var n uint32
	for range count {
		at := Span{Offset: p.off, Line: p.line, Column: p.col}
		b := p.take()
		n <<= 4
		switch {
		case b >= '0' && b <= '9':
			n += uint32(b - '0')
		case b >= 'a' && b <= 'f':
			n += uint32(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			n += uint32(b - 'A' + 10)
		default:
			p.failPosition("invalid-unicode-escape", at)
		}
	}
	if n > utf8.MaxRune {
		p.fail("invalid-unicode-escape")
	}
	return rune(n)
}
func (p *parser) atom() string {
	p.token = p.mark(0, 0)
	var out []byte
	for p.err == nil {
		b := p.peek()
		if b == 0 || strings.ContainsRune(" \t\r\n,]}", rune(b)) {
			break
		}
		p.take()
		if len(out) >= 20 {
			p.fail("invalid-scalar")
			return ""
		}
		out = append(out, b)
	}
	if p.layoutEnabled {
		p.tokenLayout = int64(len(out) + 1)
		p.layout.bytes += p.tokenLayout
		p.layoutEnd = p.layout
	}
	return string(out)
}
func (p *parser) boolean() bool {
	s := p.atom()
	if s != "true" && s != "false" {
		p.failValue("boolean-required")
	}
	return s == "true"
}
func (p *parser) integer() uint64 {
	s := p.atom()
	if s == "" || len(s) > 1 && s[0] == '0' {
		p.failValue("integer-required")
		return 0
	}
	for _, b := range []byte(s) {
		if b < '0' || b > '9' {
			p.failValue("integer-required")
			return 0
		}
	}
	v, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		p.failValue("integer-range")
	}
	return v
}
func (p *parser) block(emit func(byte)) {
	consumeBreak := func() bool {
		end := p.off
		if !p.consumeLineBreak() {
			return false
		}
		p.end = end
		return true
	}
	style := p.take()
	chomp := byte(0)
	explicit := uint64(0)
	for range 2 {
		b := p.peek()
		if b == '+' || b == '-' {
			if chomp != 0 {
				p.fail("invalid-block-header")
				return
			}
			chomp = p.take()
		} else if b >= '1' && b <= '9' {
			if explicit != 0 {
				p.fail("invalid-block-header")
				return
			}
			explicit = uint64(p.take() - '0')
		} else {
			break
		}
	}
	for p.peek() == ' ' {
		p.take()
	}
	if p.peek() == '#' {
		p.skipComment()
	}
	if p.peek() == 0 {
		return
	}
	if !consumeBreak() {
		p.fail("unexpected-token")
		return
	}
	indent := uint64(0)
	if explicit != 0 {
		indent = p.indent() + explicit
	}
	pending := 0
	first := true
	previousMore := false
	for p.err == nil && p.peek() != 0 {
		previousEnd := p.end
		spaces := uint64(0)
		for p.peek() == ' ' {
			p.take()
			spaces++
		}
		if (p.peek() == '\n' || p.peek() == '\r') && (indent == 0 || spaces+1 <= indent) {
			consumeBreak()
			pending++
			continue
		}
		if indent == 0 {
			if spaces+1 <= p.indent() {
				p.end = previousEnd
				break
			}
			indent = spaces + 1
		}
		if spaces+1 < indent {
			p.end = previousEnd
			break
		}
		more := spaces+1 > indent || p.peek() == '\t'
		if first {
			for range pending {
				emit('\n')
			}
		} else if style == '>' && !previousMore && !more {
			if pending == 1 {
				emit(' ')
			} else {
				for range max(0, pending-1) {
					emit('\n')
				}
			}
		} else {
			for range pending {
				emit('\n')
			}
		}
		for n := indent - 1; n < spaces; n++ {
			emit(' ')
		}
		for p.peek() != 0 && p.peek() != '\n' && p.peek() != '\r' {
			emit(p.take())
		}
		first = false
		previousMore = more
		pending = 0
		if consumeBreak() {
			pending = 1
		}
	}
	if chomp == '+' {
		for range pending {
			emit('\n')
		}
	} else if chomp != '-' && !first && pending > 0 {
		emit('\n')
	}
}
