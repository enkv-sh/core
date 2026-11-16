package crypto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

var (
	errMaterializationCapacity       = errors.New("materialization capacity exceeded")
	errMaterializationRepresentation = errors.New("unsupported materialization representation")
	errMaterializationMismatch       = errors.New("materialization bytes differ")
)

type materializationValue struct {
	name string
	raw  []byte
}

type materializationEnvRecord struct {
	materializationValue
	quote byte
}

// materializationEnv owns only sorted descriptors. Its raw backing belongs to
// the private value owner and must remain unchanged until all sink work joins.
type materializationEnv struct {
	records       []materializationEnvRecord
	encodedLength int
}

func prepareMaterializationEnv(values []materializationValue) (materializationEnv, error) {
	if len(values) == 0 || len(values) > contract.CryptoMaxValueEntries {
		return materializationEnv{}, errMaterializationCapacity
	}
	total := 0
	for _, value := range values {
		if len(value.name) > contract.CryptoMaxName || len(value.raw) > contract.CryptoMaxRetainedValue || len(value.raw) > contract.CryptoMaxRetainedSet-total {
			return materializationEnv{}, errMaterializationCapacity
		}
		total += len(value.raw)
		if !materializationEnvName(value.name) {
			return materializationEnv{}, errMaterializationRepresentation
		}
	}
	var quotes [contract.CryptoMaxValueEntries]byte
	encodedLength := total
	for i, value := range values {
		quote, ok := materializationEnvQuote(value.raw)
		if !ok {
			return materializationEnv{}, errMaterializationRepresentation
		}
		quotes[i] = quote
		encodedLength += len(value.name) + 2
		if quote != 0 {
			encodedLength += 2
		}
	}
	records := make([]materializationEnvRecord, len(values))
	for i, value := range values {
		records[i] = materializationEnvRecord{materializationValue: value, quote: quotes[i]}
	}
	slices.SortFunc(records, func(a, b materializationEnvRecord) int { return strings.Compare(a.name, b.name) })
	for i := 1; i < len(records); i++ {
		if records[i-1].name == records[i].name {
			return materializationEnv{}, errMaterializationRepresentation
		}
	}
	return materializationEnv{records: records, encodedLength: encodedLength}, nil
}

func materializationEnvName(name string) bool {
	if name == "" || name == "__proto__" {
		return false
	}
	for i := range len(name) {
		b := name[i]
		if b != '_' && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && (i <= 0 || b < '0' || b > '9') {
			return false
		}
	}
	return true
}

func materializationEnvQuote(raw []byte) (byte, bool) {
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 || bytes.IndexByte(raw, '\r') >= 0 || bytes.Contains(raw, []byte("\u2028")) || bytes.Contains(raw, []byte("\u2029")) {
		return 0, false
	}
	if len(raw) > 0 {
		first, _ := utf8.DecodeRune(raw)
		last, _ := utf8.DecodeLastRune(raw)
		if !materializationEnvTrim(first) && !materializationEnvTrim(last) && bytes.IndexByte(raw, '#') < 0 && bytes.IndexByte(raw, '\n') < 0 && raw[0] != '\'' && raw[0] != '`' && raw[0] != '"' {
			return 0, true
		}
		if raw[len(raw)-1] == '\\' {
			return 0, false
		}
	}
	for _, quote := range [...]byte{'\'', '`', '"'} {
		if bytes.IndexByte(raw, quote) >= 0 {
			continue
		}
		if quote == '"' && (bytes.Contains(raw, []byte(`\n`)) || bytes.Contains(raw, []byte(`\r`))) {
			continue
		}
		return quote, true
	}
	return 0, false
}

func materializationEnvTrim(r rune) bool {
	return r >= '\t' && r <= '\r' || r == ' ' || r == '\u00a0' || r == '\u1680' ||
		r >= '\u2000' && r <= '\u200a' || r == '\u2028' || r == '\u2029' ||
		r == '\u202f' || r == '\u205f' || r == '\u3000' || r == '\ufeff'
}

func (e materializationEnv) writeTo(ctx context.Context, w io.Writer) error {
	if ctx == nil || w == nil || e.encodedLength <= 0 || len(e.records) == 0 {
		return errMaterializationRepresentation
	}
	var prefix [contract.CryptoMaxName + 2]byte
	var suffix [2]byte
	defer clear(prefix[:])
	defer clear(suffix[:])
	for _, record := range e.records {
		n := copy(prefix[:], record.name)
		prefix[n] = '='
		n++
		suffixLength := 1
		suffix[0] = '\n'
		if record.quote != 0 {
			prefix[n] = record.quote
			n++
			suffix[0], suffix[1], suffixLength = record.quote, '\n', 2
		}
		for _, part := range [][]byte{prefix[:n], record.raw, suffix[:suffixLength]} {
			for len(part) > 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				chunk := part[:min(len(part), 4096)]
				written, err := w.Write(chunk)
				if err != nil {
					return err
				}
				if written != len(chunk) {
					return io.ErrShortWrite
				}
				part = part[len(chunk):]
			}
		}
	}
	return ctx.Err()
}

func (e materializationEnv) matches(ctx context.Context, r io.Reader) (bool, error) {
	if r == nil {
		return false, errMaterializationRepresentation
	}
	comparison := materializationEnvComparison{ctx: ctx, reader: r}
	defer clear(comparison.buffer[:])
	if err := e.writeTo(ctx, &comparison); err != nil {
		if errors.Is(err, errMaterializationMismatch) {
			return false, nil
		}
		return false, err
	}
	if comparison.eof {
		return true, nil
	}
	n, err := r.Read(comparison.buffer[:1])
	if contextErr := ctx.Err(); contextErr != nil {
		return false, contextErr
	}
	if err != nil && err != io.EOF {
		return false, err
	}
	if n != 0 {
		return false, nil
	}
	if err == nil {
		return false, io.ErrNoProgress
	}
	return true, nil
}

type materializationEnvComparison struct {
	ctx    context.Context
	reader io.Reader
	buffer [4096]byte
	eof    bool
}

func (c *materializationEnvComparison) Write(expected []byte) (int, error) {
	compared := 0
	for len(expected) > 0 {
		if err := c.ctx.Err(); err != nil {
			return compared, err
		}
		if c.eof {
			return compared, errMaterializationMismatch
		}
		chunk := expected[:min(len(expected), len(c.buffer))]
		n, err := c.reader.Read(c.buffer[:len(chunk)])
		if contextErr := c.ctx.Err(); contextErr != nil {
			return compared, contextErr
		}
		if n < 0 || n > len(chunk) {
			return compared, io.ErrShortBuffer
		}
		if err != nil && err != io.EOF {
			return compared + n, err
		}
		if !bytes.Equal(c.buffer[:n], chunk[:n]) {
			return compared + n, errMaterializationMismatch
		}
		if err == io.EOF {
			c.eof = true
		} else if n == 0 {
			return compared, io.ErrNoProgress
		}
		compared += n
		expected = expected[n:]
	}
	return compared, nil
}
