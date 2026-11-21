package configuration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

// SuppliedEdit retains only fixed target facts and borrowed frozen images. It
// does not retain the source model, public basis, diagnostics or plain values.
type SuppliedEdit struct {
	pair                                          *Pair
	name                                          string
	confidential                                  bool
	inputEncoding, wasInputEncoding               uint8
	present, wasSecret, wasGenerated, plainBase64 bool
	entries, source, value, secrets               Span
	canonicalRemoval                              Span
	confidentialityOffset, confidentialityLength  int64
	hasSecret                                     bool
	secretRows                                    uint32
	entryCount                                    int
	sourceColumn, valueColumn                     uint64
	layoutSpan                                    Span
	layoutIndent                                  uint64
	layoutBound                                   int64
	referencePath                                 string
	records                                       []suppliedSecretRecord
}

type suppliedSecretRecord struct {
	name           string
	offset, length int64
}

func PrepareSuppliedEdit(pair *Pair, m *Model, name string, confidential bool, inputEncoding uint8) (*SuppliedEdit, error) {
	if inputEncoding != contract.InputEncodingRaw && inputEncoding != contract.InputEncodingBase64 || pair == nil || pair.Editable == nil || pair.Generated == nil || m == nil || !m.Resolved || len(name) > contract.CryptoMaxName || !utf8.ValidString(name) {
		return nil, ErrEdit
	}
	if err := pair.validateCaptured(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	get := func(index uint32) (Span, error) {
		if int(index) >= len(m.Spans) {
			return Span{}, ErrEdit
		}
		return m.Spans[index], nil
	}
	p := &SuppliedEdit{pair: pair, name: strings.Clone(name), confidential: confidential, inputEncoding: inputEncoding, confidentialityOffset: int64(m.SelectedConfidentialityOffset), confidentialityLength: int64(m.SelectedConfidentialityLength), hasSecret: m.SelectedSecretPresent, secretRows: m.SecretRowsCount, entryCount: len(m.Entries), referencePath: m.Generated}
	if _, err := get(m.RootSpan); err != nil {
		return nil, err
	}
	var err error
	for _, selected := range []struct {
		index uint32
		out   *Span
	}{{m.EntriesSpan, &p.entries}, {m.SecretsSpan, &p.secrets}} {
		*selected.out, err = get(selected.index)
		if err != nil {
			return nil, err
		}
	}
	if confidential {
		p.records = make([]suppliedSecretRecord, 0, 512)
		scanner := newParser(context.Background(), strings.NewReader(""), JSON)
		for _, span := range m.Spans {
			if span.Kind != SpanSecret {
				continue
			}
			if len(p.records) == cap(p.records) || span.SourceOffset < p.secrets.Offset || span.SourceLength <= 0 || span.SourceOffset+span.SourceLength > p.secrets.Offset+p.secrets.Length {
				return nil, ErrEdit
			}
			scanner.r.Reset(io.NewSectionReader(pair.Generated, span.SourceOffset, span.SourceLength))
			name := scanner.text(256, true, false)
			if scanner.err != nil {
				return nil, errors.Join(ErrEdit, scanner.err)
			}
			p.records = append(p.records, suppliedSecretRecord{name: name, offset: span.SourceOffset, length: span.SourceLength})
		}
		sort.Slice(p.records, func(i, j int) bool { return p.records[i].name < p.records[j].name })
	}
	for _, entry := range m.Entries {
		if entry.Name == name {
			p.present, p.wasSecret, p.wasGenerated, p.plainBase64 = true, entry.Secret, entry.Generated != nil, entry.PlainBase64
			p.wasInputEncoding = entry.InputEncoding
			span, err := get(entry.EntrySpan)
			if err != nil {
				return nil, err
			}
			p.source = Span{Offset: span.SourceOffset, Length: span.SourceLength}
			p.layoutSpan = span
			p.value = Span{Offset: int64(span.ValueOffset), Length: int64(span.ValueLength), Flow: span.ValueFlow}
			for _, span := range m.Spans {
				if span.Kind == SpanCanonicalGenerator && span.Index == entry.EntrySpan {
					p.canonicalRemoval = span
					break
				}
			}
			break
		}
	}
	if p.present && p.confidentialityLength == 0 {
		return nil, ErrEdit
	}
	if p.present {
		p.sourceColumn, err = imageColumn(pair.Editable, p.source.Offset)
		if err != nil {
			return nil, err
		}
		if p.value.Length > 0 {
			p.valueColumn, err = imageColumn(pair.Editable, p.value.Offset)
			if err != nil {
				return nil, err
			}
		}
	}
	if !p.present && p.entryCount >= contract.CryptoMaxValueEntries || confidential && !p.hasSecret && p.secretRows >= 512 {
		return nil, ErrEditBounds
	}
	if pair.Format == YAML {
		scalarOnly := p.present && !confidential && !p.wasSecret && !p.wasGenerated && p.value.Length > 0 && p.inputEncoding == p.wasInputEncoding
		if confidential && p.wasSecret && !p.wasGenerated && p.inputEncoding == p.wasInputEncoding {
			scalarOnly = true
		}
		if !scalarOnly {
			candidates := []Span{m.Spans[m.RootSpan], p.entries}
			sizes := []layoutSize{m.layoutRoot, m.layoutEntries}
			if p.present {
				candidates = append(candidates, p.layoutSpan, p.source)
				sizes = append(sizes, m.layoutEntry, m.layoutSource)
			}
			p.layoutSpan = Span{}
			chosen := 0
			for index, span := range candidates {
				var first [1]byte
				if _, err := pair.Editable.ReadAt(first[:], span.Offset); err != nil {
					return nil, err
				}
				if first[0] == '{' {
					p.layoutSpan = span
					chosen = index
					break
				}
			}
			if p.layoutSpan.Length > 0 {
				if p.layoutSpan.Offset != m.Spans[m.RootSpan].Offset {
					indent, err := imageLineIndent(pair.Editable, p.layoutSpan.Offset)
					if err != nil {
						return nil, err
					}
					p.layoutIndent = indent + 2
				}
				size := sizes[chosen]
				p.layoutBound = size.bytes + (int64(p.layoutIndent)-int64(2*chosen))*size.lines
			}
		} else {
			p.layoutSpan = Span{}
		}
	}
	if pair.Format != YAML {
		p.layoutSpan = Span{}
	}
	return p, nil
}

// MaximumPairBytes counts a conservative complete replacement before stdin.
// Removed source bytes remain charged as the upper bound for preserved comments.
func (p *SuppliedEdit) MaximumPairBytes(raw uint32) (int64, error) {
	if p == nil || raw > contract.CryptoMaxRawValue {
		return 0, ErrEditBounds
	}
	if err := p.pair.validateCaptured(); err != nil {
		return 0, errors.Join(ErrEditBounds, err)
	}
	retained := raw
	if p.inputEncoding == contract.InputEncodingBase64 {
		retained = uint32(base64.StdEncoding.EncodedLen(int(raw)))
	}
	name, _ := json.Marshal(p.name)
	generated := p.pair.Generated.Size()
	if p.confidential {
		envelope := contract.SealedInputEnvelopeFixedLength + len(p.name) + int(retained)
		row := int64(len(name) + len(": {\n      \"sealed\": \"\"\n    }") + base64.StdEncoding.EncodedLen(envelope))
		count := 1
		for _, record := range p.records {
			if record.name != p.name {
				row += record.length
				count++
			}
		}
		generated += row + int64(len("{}")+count*len("\n    ")+(count-1)*len(",")+len("\n  ")) - p.secrets.Length
	}
	editable := p.pair.Editable.Size()
	if p.layoutSpan.Length > 0 {
		editable += p.layoutBound - p.layoutSpan.Length
	}
	source := int64(len(`{"kind":"supplied","encoding":"base64"}`)) + 64
	if !p.confidential {
		source = int64(len(`{"kind":"supplied","value":""}`)) + 6*int64(retained) + 64
	}
	if p.present {
		conf := int64(len(`"plain"`))
		if p.confidential {
			conf = int64(len(`"secret"`))
		}
		editable += conf - p.confidentialityLength
		if !p.confidential || !p.wasSecret || p.wasGenerated || p.inputEncoding != p.wasInputEncoding {
			editable += source
			if p.pair.Format == YAML {
				editable += int64(max(p.sourceColumn, p.valueColumn))
			}
		}
	} else {
		editable += int64(len(name)+len(`:{"confidentiality":"secret","recipients":[],"source":}`)) + source + 128
		if p.pair.Format == YAML {
			editable += int64(p.entries.Column) + 2
		}
	}
	if generated < 0 || editable < 0 || generated > MaxPairBytes || editable > MaxPairBytes-generated {
		return 0, ErrEditBounds
	}
	return generated + editable, nil
}

// ChangesGenerated reports whether the selected supplied edit changes its companion.
func (p *SuppliedEdit) ChangesGenerated() bool {
	return p != nil && (p.confidential || p.canonicalRemoval.Length > 0)
}

func (p *SuppliedEdit) EmitGenerated(ctx context.Context, out io.Writer, envelope []byte) error {
	if !p.ChangesGenerated() || len(envelope) > contract.CryptoMaxSealedInputLength || !p.confidential && len(envelope) != 0 {
		return ErrEdit
	}
	if err := p.pair.validateCaptured(); err != nil {
		return errors.Join(ErrEdit, err)
	}
	var edits []Edit
	if p.canonicalRemoval.Length > 0 {
		edits = append(edits, Edit{Offset: p.canonicalRemoval.Offset, Length: p.canonicalRemoval.Length})
	}
	if p.confidential {
		edit := Edit{Offset: p.secrets.Offset, Length: p.secrets.Length, Emit: func(out io.Writer) error {
			w := &generatedWriter{out: out}
			w.write("{")
			first, inserted := true, false
			prefix := func() {
				if !first {
					w.write(",")
				}
				first = false
				w.write("\n    ")
			}
			row := func() {
				prefix()
				formatted := &generatedWriter{out: writerAdapter{w}, multiline: true, baseDepth: 2}
				formatted.quote(p.name, contract.CryptoMaxName)
				formatted.write(`:{"sealed":`)
				formatted.blob(envelope, contract.CryptoMaxSealedInputLength)
				formatted.write(`}`)
				if formatted.err != nil {
					w.err = formatted.err
				}
				inserted = true
			}
			buffer := make([]byte, WindowBytes)
			for _, record := range p.records {
				if !inserted && record.name >= p.name {
					row()
				}
				if record.name == p.name {
					continue
				}
				prefix()
				if w.err == nil {
					w.err = copyEditRange(ctx, writerAdapter{w}, p.pair.Generated, record.offset, record.length, buffer)
				}
			}
			if !inserted {
				row()
			}
			w.write("\n  }")
			return w.err
		}}
		edits = append(edits, edit)
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
	return CopyEdits(ctx, out, p.pair.Generated, edits)
}

func (p *SuppliedEdit) EmitEditable(ctx context.Context, out io.Writer, reference string, plain []byte) error {
	if p == nil || reference != p.referencePath || !generatedPathValid(reference) || len(plain) > contract.CryptoMaxRetainedValue {
		return ErrEdit
	}
	if !p.confidential {
		if _, err := contract.InputContentLength(p.inputEncoding, plain); err != nil {
			return errors.Join(ErrEdit, err)
		}
	}
	if err := p.pair.validateCaptured(); err != nil {
		return errors.Join(ErrEdit, err)
	}
	if p.layoutSpan.Length > 0 {
		edit := Edit{Offset: p.layoutSpan.Offset, Length: p.layoutSpan.Length, Emit: func(out io.Writer) error { return p.emitFlowLayout(ctx, out, plain) }}
		return CopyEdits(ctx, out, p.pair.Editable, []Edit{edit})
	}
	var edits []Edit
	conf := "plain"
	if p.confidential {
		conf = "secret"
	}
	if p.present {
		if p.confidential != p.wasSecret {
			quoted, err := editableStringBytes(conf, p.pair.Format, Span{}, false)
			if err != nil {
				return err
			}
			edits = append(edits, Edit{Offset: p.confidentialityOffset, Length: p.confidentialityLength, Replacement: quoted})
		}
		if !p.confidential || !p.wasSecret || p.wasGenerated || p.inputEncoding != p.wasInputEncoding {
			if !p.confidential && !p.wasSecret && !p.wasGenerated && p.value.Length > 0 && p.inputEncoding == p.wasInputEncoding && p.plainBase64 == !utf8.Valid(plain) {
				value := func(out io.Writer) error {
					if p.pair.Format == YAML {
						return emitYAMLPlainScalar(out, plain, p.plainBase64, p.value.Flow)
					}
					return emitPlainScalar(out, plain, p.plainBase64)
				}
				edits = append(edits, Edit{Offset: p.value.Offset, Length: p.value.Length, Emit: func(w io.Writer) error { return p.emitReplacement(ctx, w, p.value, value) }})
			} else {
				edits = append(edits, Edit{Offset: p.source.Offset, Length: p.source.Length, Emit: func(w io.Writer) error {
					return p.emitReplacement(ctx, w, p.source, func(w io.Writer) error { return p.emitChangedSource(w, plain) })
				}})
			}
		}
	} else {
		separator := ","
		blockPrefix := ""
		if p.entryCount == 0 {
			separator = ""
		}
		offset := p.entries.Offset + p.entries.Length - 1
		if p.pair.Format == YAML && p.entries.Length > 0 {
			var first [1]byte
			if _, err := p.pair.Editable.ReadAt(first[:], p.entries.Offset); err != nil {
				return err
			}
			if first[0] != '{' {
				offset = p.entries.Offset + p.entries.Length
				var err error
				offset, err = afterEditLine(p.pair.Editable, offset)
				if err != nil {
					return err
				}
				separator = "block"
				blockPrefix, err = editLinePrefix(p.pair.Editable, offset)
				if err != nil {
					return err
				}
				// A new EOF separator can change a keep-chomped scalar's value.
				if offset == p.pair.Editable.Size() && blockPrefix != "" {
					offset = p.entries.Offset - int64(p.entries.Column-1)
					blockPrefix = ""
				}
			} else {
				var err error
				separator, err = YAMLFlowMappingSeparator(ctx, p.pair.Editable, p.entries)
				if err != nil {
					return err
				}
			}
		}
		edits = append(edits, Edit{Offset: offset, Emit: func(w io.Writer) error {
			prefix := separator
			if separator == "block" {
				prefix = blockPrefix
			}
			if _, err := io.WriteString(w, prefix); err != nil {
				return err
			}
			if separator == "block" {
				if err := emitSuppliedEntryYAML(w, p.name, p.confidential, plain, p.inputEncoding, p.entries.Column-1); err != nil {
					return err
				}
				_, err := io.WriteString(w, "\n")
				return err
			}
			if p.pair.Format == JSON {
				formatted := &generatedWriter{out: w, multiline: true, baseDepth: 2}
				formatted.raw("\n    ")
				formatted.quote(p.name, contract.CryptoMaxName)
				formatted.write(`:{"confidentiality":` + strconv.Quote(conf) + `,"recipients":[],"source":`)
				if err := emitSuppliedSource(writerAdapter{formatted}, p.confidential, plain, p.inputEncoding); err != nil {
					return err
				}
				formatted.write("}")
				formatted.raw("\n  ")
				return formatted.err
			}
			return ErrEdit
		}})
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
	return CopyEdits(ctx, out, p.pair.Editable, edits)
}

func emitSuppliedSource(out io.Writer, confidential bool, plain []byte, inputEncoding uint8) error {
	if confidential {
		_, err := io.WriteString(out, `{"kind":"supplied"`+inputEncodingField(inputEncoding)+`}`)
		return err
	}
	field := "value"
	binary := !utf8.Valid(plain)
	if binary {
		field = "bytes"
	}
	if _, err := io.WriteString(out, `{"kind":"supplied"`+inputEncodingField(inputEncoding)+`,"`+field+`":`); err != nil {
		return err
	}
	if err := emitPlainScalar(out, plain, binary); err != nil {
		return err
	}
	_, err := io.WriteString(out, "}")
	return err
}

func emitPlainScalar(out io.Writer, plain []byte, binary bool) error {
	if binary {
		if _, err := io.WriteString(out, `"`); err != nil {
			return err
		}
		encoder := base64.NewEncoder(base64.StdEncoding, out)
		_, writeErr := encoder.Write(plain)
		if err := errors.Join(writeErr, encoder.Close()); err != nil {
			return err
		}
		_, err := io.WriteString(out, `"`)
		return err
	}
	if _, err := io.WriteString(out, `"`); err != nil {
		return err
	}
	for len(plain) > 0 {
		n := min(4096, len(plain))
		for n < len(plain) && !utf8.RuneStart(plain[n]) {
			n--
		}
		encoded, err := json.Marshal(string(plain[:n]))
		if err != nil {
			return err
		}
		part := encoded[1 : len(encoded)-1]
		if written, err := out.Write(part); err != nil || written != len(part) {
			return errors.Join(err, io.ErrShortWrite)
		}
		plain = plain[n:]
	}
	_, err := io.WriteString(out, `"`)
	return err
}

func emitYAMLPlainScalar(out io.Writer, plain []byte, binary, flow bool) error {
	w := &generatedWriter{out: out}
	if binary {
		w.yamlBlob(plain, contract.CryptoMaxRawValue)
	} else {
		w.yamlString(string(plain), contract.CryptoMaxRetainedValue, false, flow)
	}
	return w.err
}

func (p *SuppliedEdit) emitReplacement(ctx context.Context, out io.Writer, span Span, emit func(io.Writer) error) error {
	if p.pair.Format == YAML {
		column, err := imageColumn(p.pair.Editable, span.Offset)
		if err != nil {
			return err
		}
		if err := copyEditComments(ctx, out, p.pair.Editable, span, column, p.sourceColumn); err != nil {
			return err
		}
	}
	return emit(out)
}

func imageColumn(image *Image, offset int64) (uint64, error) {
	var buffer [256]byte
	column := uint64(1)
	for offset > 0 {
		n := int(min(offset, int64(len(buffer))))
		offset -= int64(n)
		if _, err := image.ReadAt(buffer[:n], offset); err != nil {
			return 0, err
		}
		for i := n - 1; i >= 0; i-- {
			if buffer[i] == '\n' {
				return column, nil
			}
			column++
		}
	}
	return column, nil
}

// Only lexical state is visited here: no names, values or source meanings are
// reconstructed. Quoted/block scalar content cannot become a YAML comment.
func copyEditComments(ctx context.Context, out io.Writer, image *Image, span Span, column, indent uint64) error {
	p := newParser(ctx, io.NewSectionReader(image, span.Offset, span.Length), YAML)
	p.col = column
	p.indentation = false
	p.depth = 1
	p.indents[0] = indent
	buffer := make([]byte, 256)
	seen := false
	p.onComment = func(offset, length int64) error {
		if seen {
			commentColumn, err := imageColumn(image, span.Offset+offset)
			if err != nil {
				return err
			}
			start := span.Offset + offset - int64(commentColumn-1)
			for start < span.Offset+offset {
				var b [1]byte
				if _, err := image.ReadAt(b[:], start); err != nil {
					return err
				}
				if b[0] != ' ' && b[0] != '\t' {
					break
				}
				if n, err := out.Write(b[:]); err != nil || n != 1 {
					return errors.Join(err, io.ErrShortWrite)
				}
				start++
			}
		}
		if err := copyEditRange(ctx, out, image, span.Offset+offset, length, buffer); err != nil {
			return err
		}
		if _, err := io.WriteString(out, "\n"); err != nil {
			return err
		}
		seen = true
		return nil
	}
	scanEditTokens(p)
	if p.err != nil {
		return p.err
	}
	if seen {
		return writeEditIndent(out, column-1)
	}
	return nil
}

// YAMLFlowMappingSeparator returns the insertion separator for an admitted map.
func YAMLFlowMappingSeparator(ctx context.Context, image *Image, span Span) (string, error) {
	if image == nil || span.Offset < 0 || span.Length < 2 || span.Offset > image.Size() || span.Length > image.Size()-span.Offset {
		return "", ErrEdit
	}
	p := newParser(ctx, io.NewSectionReader(image, span.Offset, span.Length), YAML)
	p.col, p.depth = span.Column, 1
	p.indents[0], p.indentation = span.Column, false
	if p.peek() != '{' {
		return "", errors.Join(ErrEdit, p.err)
	}
	last := scanEditTokens(p)
	if p.err != nil {
		return "", p.err
	}
	if last == 0 || last == ',' {
		return "", nil
	}
	return ",", nil
}

func scanEditTokens(p *parser) byte {
	var last byte
	for p.err == nil {
		p.skip()
		b := p.peek()
		if b == 0 {
			break
		}
		if p.indentation && b != '|' && b != '>' {
			p.indents[0] = p.col
		}
		switch b {
		case '{', '[':
			p.flowDepth++
			p.take()
		case '}', ']':
			p.flowDepth--
			p.take()
			if p.flowDepth == 1 {
				last = b
			}
		case ':', ',':
			if p.flowDepth == 1 {
				last = b
			}
			p.take()
		case '-':
			if p.flowDepth == 0 && p.separated(1) {
				p.take()
				break
			}
			fallthrough
		default:
			p.scalarValue(func(byte) {}, false, true, true)
			if p.flowDepth == 1 {
				last = 'v'
			}
		}
	}
	return last
}

func writeEditIndent(out io.Writer, count uint64) error {
	var spaces [256]byte
	for i := range spaces {
		spaces[i] = ' '
	}
	for count > 0 {
		n := int(min(count, uint64(len(spaces))))
		if written, err := out.Write(spaces[:n]); err != nil || written != n {
			return errors.Join(err, io.ErrShortWrite)
		}
		count -= uint64(n)
	}
	return nil
}

func editLinePrefix(image *Image, offset int64) (string, error) {
	if offset == 0 {
		return "", nil
	}
	var previous [1]byte
	if _, err := image.ReadAt(previous[:], offset-1); err != nil {
		return "", err
	}
	if previous[0] == '\n' || previous[0] == '\r' {
		return "", nil
	}
	return "\n", nil
}

func afterEditLine(image *Image, offset int64) (int64, error) {
	currentBreak := false
	if offset < image.Size() {
		var current [1]byte
		if _, err := image.ReadAt(current[:], offset); err != nil {
			return 0, err
		}
		currentBreak = current[0] == '\n' || current[0] == '\r'
	}
	if offset > 0 && !currentBreak {
		var previous [1]byte
		if _, err := image.ReadAt(previous[:], offset-1); err != nil {
			return 0, err
		}
		if previous[0] == '\n' || previous[0] == '\r' {
			return offset, nil
		}
	}
	var buffer [256]byte
	for offset < image.Size() {
		n := int(min(int64(len(buffer)), image.Size()-offset))
		if _, err := image.ReadAt(buffer[:n], offset); err != nil {
			return 0, err
		}
		for i, b := range buffer[:n] {
			if b == '\n' || b == '\r' {
				end := offset + int64(i) + 1
				if b == '\r' && end < image.Size() {
					var next [1]byte
					if _, err := image.ReadAt(next[:], end); err != nil {
						return 0, err
					}
					if next[0] == '\n' {
						end++
					}
				}
				return end, nil
			}
		}
		offset += int64(n)
	}
	return offset, nil
}

func imageLineIndent(image *Image, offset int64) (uint64, error) {
	column, err := imageColumn(image, offset)
	if err != nil {
		return 0, err
	}
	start := offset - int64(column-1)
	var b [1]byte
	indent := uint64(0)
	for start < offset {
		if _, err := image.ReadAt(b[:], start); err != nil {
			return 0, err
		}
		if b[0] != ' ' {
			break
		}
		indent++
		start++
	}
	return indent, nil
}
func emitSuppliedEntryYAML(out io.Writer, name string, confidential bool, plain []byte, inputEncoding uint8, indent uint64) error {
	w := &generatedWriter{out: out}
	w.raw(strings.Repeat(" ", int(indent)))
	w.yamlString(name, contract.CryptoMaxName, true, false)
	w.raw(":\n" + strings.Repeat(" ", int(indent+2)) + "confidentiality: ")
	conf := "plain"
	if confidential {
		conf = "secret"
	}
	w.yamlString(conf, 6, false, false)
	w.raw("\n" + strings.Repeat(" ", int(indent+2)) + "recipients: []" + "\n" + strings.Repeat(" ", int(indent+2)) + "source:")
	if w.err != nil {
		return w.err
	}
	return emitSuppliedSourceYAML(out, confidential, plain, inputEncoding, indent+4, true)
}
func emitSuppliedSourceYAML(out io.Writer, confidential bool, plain []byte, inputEncoding uint8, indent uint64, newline bool) error {
	w := &generatedWriter{out: out}
	if newline {
		w.raw("\n" + strings.Repeat(" ", int(indent)))
	}
	w.raw("kind: supplied")
	if inputEncoding == contract.InputEncodingBase64 {
		w.raw("\n" + strings.Repeat(" ", int(indent)) + "encoding: base64")
	}
	if !confidential {
		field := "value"
		binary := !utf8.Valid(plain)
		if binary {
			field = "bytes"
		}
		w.raw("\n" + strings.Repeat(" ", int(indent)) + field + ": ")
		if w.err != nil {
			return w.err
		}
		if err := emitYAMLPlainScalar(out, plain, binary, false); err != nil {
			return err
		}
	}
	return w.err
}
func (p *SuppliedEdit) emitChangedSource(out io.Writer, plain []byte) error {
	if p.pair.Format == JSON {
		w := &generatedWriter{out: out, multiline: true, baseDepth: 3}
		if err := emitSuppliedSource(writerAdapter{w}, p.confidential, plain, p.inputEncoding); err != nil {
			return err
		}
		return w.err
	}
	indent, err := imageLineIndent(p.pair.Editable, p.source.Offset)
	if err != nil {
		return err
	}
	return emitSuppliedSourceYAML(out, p.confidential, plain, p.inputEncoding, indent, false)
}

func (edit *SuppliedEdit) emitFlowLayout(ctx context.Context, out io.Writer, plain []byte) error {
	replace := func(p *parser, w *generatedWriter, depth uint64, offset int64) bool {
		if !edit.present {
			return false
		}
		if offset == edit.source.Offset {
			skipEditableValue(p)
			if err := emitSuppliedSourceYAML(writerAdapter{w}, edit.confidential, plain, edit.inputEncoding, depth, true); err != nil {
				w.err = err
			}
			return true
		}
		if offset == edit.confidentialityOffset && edit.confidential != edit.wasSecret {
			skipEditableValue(p)
			conf := "plain"
			if edit.confidential {
				conf = "secret"
			}
			w.raw(" ")
			w.yamlString(conf, 6, false, false)
			return true
		}
		return false
	}
	appendEntry := func(offset int64, depth uint64, count int, w *generatedWriter) bool {
		if edit.present || offset != edit.entries.Offset {
			return false
		}
		if count > 0 || edit.layoutSpan.Column != 1 {
			w.raw("\n")
		}
		if w.err == nil {
			w.err = emitSuppliedEntryYAML(writerAdapter{w}, edit.name, edit.confidential, plain, edit.inputEncoding, depth)
		}
		return true
	}
	return emitFlowSection(ctx, out, edit.pair.Editable, edit.layoutSpan, edit.layoutIndent, replace, appendEntry)
}
func skipEditableValue(p *parser) {
	if sourceSettingsPath(p.field) {
		parseSettings(p, maxGeneratorSettings)
		return
	}
	p.skip()
	switch p.peek() {
	case '{':
		p.objectFields(int(MaxPairBytes), maxGeneratorSettings, nil, func(string) { skipEditableValue(p) })
	case '[':
		p.array(int(MaxPairBytes), func(int) { skipEditableValue(p) })
	default:
		p.scalarValue(func(byte) {}, false, true, false)
	}
}

func emitFlowSection(ctx context.Context, out io.Writer, image *Image, span Span, indent uint64,
	replace func(*parser, *generatedWriter, uint64, int64) bool,
	appendMember func(int64, uint64, int, *generatedWriter) bool) error {
	p := newParser(ctx, io.NewSectionReader(image, span.Offset, span.Length), YAML)
	p.col = span.Column
	p.indentation = false
	switch span.Kind {
	case SpanEntries:
		p.field = "entries"
	case SpanEntry:
		p.field = "entries.item"
	case SpanRecipients:
		p.field = "recipients"
	case 0:
		p.field = "entries.item.source"
	}
	w := &generatedWriter{out: out}
	commentIndent := indent
	commentPending := false
	buffer := make([]byte, WindowBytes)
	p.onComment = func(offset, length int64) error {
		w.raw("\n" + strings.Repeat(" ", int(commentIndent)))
		if w.err != nil {
			return w.err
		}
		if err := copyEditRange(ctx, writerAdapter{w}, image, span.Offset+offset, length, buffer); err != nil {
			return err
		}
		commentPending = true
		return w.err
	}
	var value func(uint64, bool)
	value = func(depth uint64, root bool) {
		p.skip()
		if p.err != nil || w.err != nil {
			return
		}
		commentIndent = depth
		if commentPending {
			w.raw("\n" + strings.Repeat(" ", int(depth)))
			commentPending = false
		}
		offset := span.Offset + p.off
		if replace != nil && replace(p, w, depth, offset) {
			return
		}
		kind := p.peek()
		settings := sourceSettingsPath(p.field)
		if settings && (kind == '{' || kind == '[') {
			start := p.off
			onComment := p.onComment
			p.onComment = nil
			parseSettings(p, maxGeneratorSettings)
			p.onComment = onComment
			if p.err == nil {
				w.raw(" ")
				if w.err == nil {
					w.err = copyEditRange(ctx, writerAdapter{w}, image, span.Offset+start, p.end-start, buffer)
				}
			}
			return
		}
		if kind != '{' && kind != '[' {
			start := p.off
			binary := strings.HasPrefix(p.field, "entries.") && strings.HasSuffix(p.field, ".source.bytes")
			var decoded []byte
			if binary {
				// One logical value fits the existing copy buffer even when its
				// Base64 source crosses the scanner window.
				decoded = p.base64Into(buffer[:0], contract.CryptoMaxRawValue)
			} else {
				p.scalarValue(func(b byte) {
					var ok bool
					decoded, ok = boundedAppend(decoded, b, maxGeneratorSettings)
					if !ok {
						p.fail("scalar-limit")
					}
				}, false, true, false)
			}
			if p.err != nil {
				return
			}
			w.raw(" ")
			if w.err != nil {
				return
			}
			switch {
			case !p.scalarMultiline:
				w.err = copyEditRange(ctx, writerAdapter{w}, image, span.Offset+start, p.end-start, buffer)
			case binary:
				w.yamlBlob(decoded, contract.CryptoMaxRawValue)
			default:
				w.yamlString(string(decoded), maxGeneratorSettings, false, false)
			}
			return
		}
		count := 0
		prefix := func() {
			if count > 0 || !root {
				w.raw("\n" + strings.Repeat(" ", int(depth)))
			}
			count++
			commentPending = false
			if kind == '{' {
				if w.err == nil {
					w.err = copyEditRange(ctx, writerAdapter{w}, image, span.Offset+p.member.SourceOffset, p.member.SourceLength, buffer)
				}
				w.raw(":")
			} else {
				w.raw("-")
			}
		}
		if kind == '{' {
			p.objectFields(int(MaxPairBytes), maxGeneratorSettings, nil, func(string) { prefix(); value(depth+2, false); commentIndent = depth })
			if appendMember != nil && appendMember(offset, depth, count, w) {
				count++
			}
		} else {
			p.array(int(MaxPairBytes), func(int) { prefix(); value(depth+2, false); commentIndent = depth })
		}
		if count == 0 {
			if commentPending {
				w.raw("\n" + strings.Repeat(" ", int(depth)))
				commentPending = false
			}
			if !root {
				w.raw(" ")
			}
			if kind == '{' {
				w.raw("{}")
			} else {
				w.raw("[]")
			}
		}
	}
	value(indent, span.Column == 1)
	if err := p.done(); err != nil {
		return err
	}
	return w.err
}

func sourceSettingsPath(field string) bool {
	parts := strings.Split(field, ".")
	if len(parts) < 4 {
		return false
	}
	if parts[0] == "entries" && parts[2] == "source" {
		return parts[3] == "settings" || len(parts) > 4 && parts[3] == "canonical" && parts[4] == "settings"
	}
	return parts[0] == "outputs" && parts[1] == "destinations" && (parts[3] == "settings" || len(parts) > 4 && parts[3] == "canonical" && parts[4] == "settings")
}

func inputEncodingField(encoding uint8) string {
	if encoding == contract.InputEncodingBase64 {
		return `,"encoding":"base64"`
	}
	return ""
}
