package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
)

var errResultJSONLayout = errors.New("result JSON layout refused")

type resultJSONFrame struct {
	close    byte
	nonempty bool
}

// Each owner supplies its complete compact ceiling. The layout keeps only the
// closed schema's structural stack; strings and encoded plugin bytes stream.
type resultJSONLayout struct {
	frames                  [32]resultJSONFrame
	depth                   int
	compact, compactLimit   uint64
	quoted, escaped, closed bool
}

func (l *resultJSONLayout) token(s string, emit func(string)) error {
	if uint64(len(s)) > l.compactLimit-l.compact {
		return errResultJSONLayout
	}
	l.compact += uint64(len(s))
	emit(s)
	return nil
}

func (l *resultJSONLayout) newline(emit func(string)) {
	const spaces = "                                                                "
	emit("\n")
	if l.depth != 0 {
		emit(spaces[:2*l.depth])
	}
}

func (l *resultJSONLayout) beforeValue(emit func(string)) {
	if l.depth != 0 && !l.frames[l.depth-1].nonempty {
		l.frames[l.depth-1].nonempty = true
		l.newline(emit)
	}
}

func (l *resultJSONLayout) write(s string, emit func(string)) error {
	for i := 0; i < len(s); {
		if l.quoted {
			start := i
			for i < len(s) {
				b := s[i]
				i++
				if l.escaped {
					l.escaped = false
				} else if b == '\\' {
					l.escaped = true
				} else if b == '"' {
					l.quoted = false
					break
				}
			}
			if err := l.token(s[start:i], emit); err != nil {
				return err
			}
			continue
		}
		b := s[i]
		if b == ' ' || b == '\n' || b == '\r' || b == '\t' {
			i++
			continue
		}
		if l.closed {
			return errResultJSONLayout
		}
		switch b {
		case '{', '[':
			if l.depth == len(l.frames) {
				return errResultJSONLayout
			}
			l.beforeValue(emit)
			if err := l.token(s[i:i+1], emit); err != nil {
				return err
			}
			close := byte('}')
			if b == '[' {
				close = ']'
			}
			l.frames[l.depth] = resultJSONFrame{close: close}
			l.depth++
		case '}', ']':
			if l.depth == 0 || l.frames[l.depth-1].close != b {
				return errResultJSONLayout
			}
			l.depth--
			if l.frames[l.depth].nonempty {
				l.newline(emit)
			}
			if err := l.token(s[i:i+1], emit); err != nil {
				return err
			}
			l.closed = l.depth == 0
		case ',':
			if l.depth == 0 || !l.frames[l.depth-1].nonempty {
				return errResultJSONLayout
			}
			if err := l.token(",", emit); err != nil {
				return err
			}
			l.newline(emit)
		case ':':
			if l.depth == 0 {
				return errResultJSONLayout
			}
			if err := l.token(":", emit); err != nil {
				return err
			}
			emit(" ")
		case '"':
			l.beforeValue(emit)
			if err := l.token("\"", emit); err != nil {
				return err
			}
			l.quoted = true
		default:
			if l.depth == 0 {
				return errResultJSONLayout
			}
			l.beforeValue(emit)
			start := i
			for i < len(s) && s[i] != ',' && s[i] != '}' && s[i] != ']' && s[i] != ':' && s[i] != '{' && s[i] != '[' && s[i] != '"' && s[i] != ' ' && s[i] != '\n' && s[i] != '\r' && s[i] != '\t' {
				i++
			}
			if err := l.token(s[start:i], emit); err != nil {
				return err
			}
			continue
		}
		i++
	}
	return nil
}

func (l *resultJSONLayout) finish(emit func(string)) error {
	if !l.closed || l.depth != 0 || l.quoted || l.escaped {
		return errResultJSONLayout
	}
	emit("\n")
	return nil
}

func renderReadableResultJSON(compactLimit uint64, limitError error, write func(*resultStreamWriter)) ([]byte, error) {
	if compactLimit == 0 || compactLimit > math.MaxUint64/67 {
		return nil, limitError
	}
	layout := resultJSONLayout{compactLimit: compactLimit}
	count := &resultStreamWriter{ctx: context.Background(), limit: 67 * compactLimit, limitError: limitError, layout: &layout}
	write(count)
	count.finishJSON()
	if count.err != nil || count.n > uint64(int(^uint(0)>>1)) {
		return nil, limitError
	}
	buffer := bytes.NewBuffer(make([]byte, 0, int(count.n)))
	layout = resultJSONLayout{compactLimit: compactLimit}
	stream := &resultStreamWriter{ctx: context.Background(), out: buffer, limit: count.n, limitError: limitError, layout: &layout}
	write(stream)
	stream.finishJSON()
	if stream.err != nil || stream.n != count.n || uint64(buffer.Len()) != count.n {
		clear(buffer.Bytes())
		return nil, limitError
	}
	return buffer.Bytes(), nil
}

func writeReadableResultJSON(ctx context.Context, out io.Writer, compactLimit uint64, limitError error, write func(*resultStreamWriter)) error {
	if ctx == nil || out == nil || compactLimit == 0 || compactLimit > math.MaxUint64/67 {
		return limitError
	}
	layout := resultJSONLayout{compactLimit: compactLimit}
	count := &resultStreamWriter{ctx: ctx, limit: 67 * compactLimit, limitError: limitError, layout: &layout}
	write(count)
	count.finishJSON()
	if count.err != nil {
		return count.err
	}
	layout = resultJSONLayout{compactLimit: compactLimit}
	stream := &resultStreamWriter{ctx: ctx, out: out, limit: count.n, limitError: limitError, layout: &layout}
	write(stream)
	stream.finishJSON()
	if stream.err != nil {
		return stream.err
	}
	if stream.n != count.n {
		return limitError
	}
	return nil
}
