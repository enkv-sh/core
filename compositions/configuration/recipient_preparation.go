package configuration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

type RecipientDeclaration struct {
	DisplayName, EncryptionSelector string
}

type RecipientPreparationMaterial struct {
	RecipientID contract.ID
	Encryption  contract.KMSBinding
	Creation    *Creation
}

// RecipientEdit borrows its captured pair and retains no source model or values.
type RecipientEdit struct{ edits capturedEdits }

type capturedEdits struct {
	pair       *Pair
	reference  string
	editable   []Edit
	recipients Span
	records    []recipientRecord
}

func (e *capturedEdits) emitEditable(ctx context.Context, out io.Writer, reference string) error {
	if e == nil || e.pair == nil || reference != e.reference {
		return ErrEdit
	}
	if err := e.pair.validateCaptured(); err != nil {
		return errors.Join(ErrEdit, err)
	}
	return CopyEdits(ctx, out, e.pair.Editable, e.editable)
}

func (e *capturedEdits) emitGenerated(ctx context.Context, out io.Writer) error {
	if e == nil || e.pair == nil || e.pair.Generated == nil {
		return ErrEdit
	}
	if err := e.pair.validateCaptured(); err != nil {
		return errors.Join(ErrEdit, err)
	}
	return CopyEdits(ctx, out, e.pair.Generated, []Edit{recipientContainerEdit(ctx, e.pair.Generated, e.recipients, e.records)})
}

func referenceValid(reference string) bool {
	return reference != "" && len(reference) <= 256 && utf8.ValidString(reference)
}

// ParseForRecipientPreparation permits only the selected recipient's missing
// generated row or old selector. The completed candidate still requires Parse.
func ParseForRecipientPreparation(ctx context.Context, pair *Pair, reference string) (*Model, error) {
	return parseEditModel(ctx, pair, &Model{selectedRecipient: &reference})
}

func PrepareRecipientEdit(ctx context.Context, pair *Pair, model *Model, reference string, declaration *RecipientDeclaration, material RecipientPreparationMaterial) (*RecipientEdit, error) {
	if pair == nil || model == nil || model.parsedPair != pair || !model.Resolved || !referenceValid(reference) || material.RecipientID.IsZero() || model.selectedRecipient != nil && *model.selectedRecipient != reference {
		return nil, ErrEdit
	}
	if err := pair.validateCaptured(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	var selected *Recipient
	for i := range model.Recipients {
		row := &model.Recipients[i]
		if row.Reference == reference {
			selected = row
		} else if row.ID == material.RecipientID {
			return nil, ErrEdit
		}
	}
	if material.RecipientID == model.Authority.ID || declaration == nil && selected == nil || declaration != nil && (selected != nil || len(model.Recipients) == 255) {
		return nil, ErrEdit
	}
	if selected != nil && !selected.ID.IsZero() && selected.ID != material.RecipientID {
		if material.Creation == nil {
			return nil, ErrEdit
		}
		created, err := contract.RecipientCreationID(model.DomainID, material.Creation.Snapshot, material.Creation.Nonce)
		if err != nil || created != material.RecipientID {
			return nil, errors.Join(ErrEdit, err)
		}
	}
	selector := ""
	if declaration != nil {
		if len(declaration.DisplayName) > 256 || !utf8.ValidString(declaration.DisplayName) {
			return nil, ErrEdit
		}
		selector = declaration.EncryptionSelector
	} else {
		selector = selected.Selector
	}
	if material.Encryption.Provider != model.Provider || material.Encryption.KeySelector != selector || !contract.PublicKeySelectorValid(model.Provider, selector, false) {
		return nil, ErrEdit
	}
	if _, err := contract.KMSBindingLength(material.Encryption); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	if material.Creation != nil && (material.Creation.Snapshot.IsZero() || material.Creation.Nonce.IsZero()) {
		return nil, ErrEdit
	}
	body, err := preparedRecipientBytes(reference, material)
	if err != nil {
		return nil, err
	}
	edit := &RecipientEdit{edits: capturedEdits{pair: pair, reference: model.Generated}}
	if declaration != nil {
		span, err := modelSpan(model, model.RecipientsSpan)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(struct {
			ID            string `json:"id"`
			DisplayName   string `json:"display_name"`
			EncryptionKey string `json:"encryption_key"`
		}{hex.EncodeToString(material.RecipientID[:]), declaration.DisplayName, declaration.EncryptionSelector})
		if err != nil {
			return nil, err
		}
		root, err := modelSpan(model, model.RootSpan)
		if err != nil {
			return nil, err
		}
		insertion, err := recipientDeclarationInsertion(ctx, pair, root, span, len(model.Recipients), reference, value)
		if err != nil {
			return nil, err
		}
		edit.edits.editable = []Edit{insertion}
	} else {
		prepared := *selected
		prepared.ID = material.RecipientID
		if !selected.ID.IsZero() && selected.ID != material.RecipientID {
			span, err := modelSpan(model, selected.IDSpan)
			if err != nil {
				return nil, err
			}
			value, err := editableStringBytes(hex.EncodeToString(material.RecipientID[:]), pair.Format, span, false)
			if err != nil {
				return nil, err
			}
			edit.edits.editable = []Edit{{Offset: span.Offset, Length: span.Length, Replacement: value}}
		} else {
			insertion, insert, err := recipientIdentityEdit(ctx, model, prepared)
			if err != nil {
				return nil, err
			}
			if insert {
				edit.edits.editable = []Edit{insertion}
			}
		}
	}
	recordCount := len(model.Recipients)
	if declaration != nil {
		recordCount++
	}
	records := make([]recipientRecord, 0, recordCount)
	for _, row := range model.Recipients {
		if row.Reference == reference {
			continue
		}
		span, err := modelSpan(model, row.GeneratedSpan)
		if err != nil || !recipientRecordSpanValid(pair.Generated, span) {
			return nil, ErrEdit
		}
		records = append(records, recipientRecord{reference: row.Reference, span: span})
	}
	records = append(records, recipientRecord{reference: reference, replacement: body})
	container, err := modelSpan(model, model.GeneratedRecipientsSpan)
	if err != nil {
		return nil, err
	}
	orderRecipientRecords(records)
	edit.edits.recipients, edit.edits.records = container, records
	return edit, nil
}

func (e *RecipientEdit) EmitEditable(ctx context.Context, out io.Writer, reference string) error {
	if e == nil {
		return ErrEdit
	}
	return e.edits.emitEditable(ctx, out, reference)
}

func (e *RecipientEdit) EmitGenerated(ctx context.Context, out io.Writer) error {
	if e == nil {
		return ErrEdit
	}
	return e.edits.emitGenerated(ctx, out)
}

func modelSpan(model *Model, index uint32) (Span, error) {
	if model == nil || int(index) >= len(model.Spans) {
		return Span{}, ErrEdit
	}
	return model.Spans[index], nil
}

type recipientRecord struct {
	reference        string
	span             Span
	key, replacement []byte
}

func orderRecipientRecords(records []recipientRecord) {
	sort.Slice(records, func(i, j int) bool { return records[i].reference < records[j].reference })
	for i := range records {
		records[i].reference = ""
	}
}

func recipientRecordSpanValid(image *Image, span Span) bool {
	return image != nil && span.SourceOffset >= 0 && span.SourceLength > 0 && span.Offset >= span.SourceOffset+span.SourceLength && span.Length > 0 && span.Offset <= image.Size() && span.Length <= image.Size()-span.Offset
}

func preparedRecipientBytes(reference string, material RecipientPreparationMaterial) ([]byte, error) {
	var out bytes.Buffer
	w := &generatedWriter{out: &out, multiline: true, baseDepth: 2}
	w.quote(reference, 256)
	w.write(`:{"id":`)
	w.id(material.RecipientID)
	w.write(`,"encryption":`)
	w.key(kmsKey(material.Encryption), material.Encryption.KeySelector, false)
	if material.Creation != nil {
		w.write(`,"creation":{"snapshot":`)
		w.id(material.Creation.Snapshot)
		w.write(`,"nonce":`)
		w.id(material.Creation.Nonce)
		w.write(`}`)
	}
	w.write(`}`)
	return out.Bytes(), w.err
}

func recipientContainerEdit(ctx context.Context, image *Image, span Span, records []recipientRecord) Edit {
	return Edit{Offset: span.Offset, Length: span.Length, Emit: func(out io.Writer) error {
		w := &generatedWriter{out: out}
		w.write("{")
		buffer := make([]byte, WindowBytes)
		for i, record := range records {
			if i > 0 {
				w.write(",")
			}
			w.write("\n    ")
			if record.replacement != nil {
				w.write(string(record.replacement))
				continue
			}
			offset := record.span.SourceOffset
			if record.key != nil {
				w.write(string(record.key))
				offset += record.span.SourceLength
			}
			if w.err == nil {
				w.err = copyEditRange(ctx, writerAdapter{w}, image, offset, record.span.Offset+record.span.Length-offset, buffer)
			}
		}
		if len(records) > 0 {
			w.write("\n  ")
		}
		w.write("}")
		return w.err
	}}
}

func recipientDeclarationInsertion(ctx context.Context, pair *Pair, root, span Span, count int, reference string, value []byte) (Edit, error) {
	if span.Kind != SpanRecipients || span.Length < 2 {
		return Edit{}, ErrEdit
	}
	var first [1]byte
	if _, err := pair.Editable.ReadAt(first[:], span.Offset); err != nil {
		return Edit{}, err
	}
	if pair.Format == YAML {
		enclosing := span
		var rootFirst [1]byte
		if _, err := pair.Editable.ReadAt(rootFirst[:], root.Offset); err != nil {
			return Edit{}, err
		}
		if rootFirst[0] == '{' {
			enclosing = root
		}
		if first[0] == '{' || rootFirst[0] == '{' {
			indent := uint64(0)
			if enclosing.Offset != root.Offset {
				n, err := imageLineIndent(pair.Editable, enclosing.Offset)
				if err != nil {
					return Edit{}, err
				}
				indent = n + 2
			}
			return Edit{Offset: enclosing.Offset, Length: enclosing.Length, Emit: func(out io.Writer) error {
				appendRecipient := func(offset int64, depth uint64, existing int, w *generatedWriter) bool {
					if offset != span.Offset {
						return false
					}
					if existing > 0 || enclosing.Column != 1 {
						w.raw("\n")
					}
					if w.err == nil {
						w.err = emitRecipientDeclarationYAML(writerAdapter{w}, reference, value, depth)
					}
					return true
				}
				return emitFlowSection(ctx, out, pair.Editable, enclosing, indent, nil, appendRecipient)
			}}, nil
		}
	}
	if first[0] == '{' {
		return Edit{Offset: span.Offset + span.Length - 1, Emit: func(out io.Writer) error {
			w := &generatedWriter{out: out, multiline: true, baseDepth: 2}
			if count > 0 {
				w.raw(",")
			}
			w.raw("\n    ")
			w.quote(reference, 256)
			w.write(":")
			w.write(string(value))
			w.raw("\n  ")
			return w.err
		}}, nil
	}
	if pair.Format != YAML {
		return Edit{}, ErrEdit
	}
	offset, err := afterEditLine(pair.Editable, span.Offset+span.Length)
	if err != nil {
		return Edit{}, err
	}
	prefix, err := editLinePrefix(pair.Editable, offset)
	if err != nil {
		return Edit{}, err
	}
	return Edit{Offset: offset, Emit: func(out io.Writer) error {
		w := &generatedWriter{out: out}
		w.write(prefix)
		if w.err != nil {
			return w.err
		}
		if err := emitRecipientDeclarationYAML(writerAdapter{w}, reference, value, span.Column-1); err != nil {
			return err
		}
		w.raw("\n")
		return w.err
	}}, nil
}

func emitRecipientDeclarationYAML(out io.Writer, reference string, value []byte, indent uint64) error {
	var declaration struct {
		ID            string `json:"id"`
		DisplayName   string `json:"display_name"`
		EncryptionKey string `json:"encryption_key"`
	}
	if err := json.Unmarshal(value, &declaration); err != nil {
		return ErrEdit
	}
	w := &generatedWriter{out: out}
	w.raw(strings.Repeat(" ", int(indent)))
	w.yamlString(reference, 256, true, false)
	w.raw(":\n" + strings.Repeat(" ", int(indent+2)) + "id: ")
	w.yamlString(declaration.ID, 64, false, false)
	w.raw("\n" + strings.Repeat(" ", int(indent+2)) + "display_name: ")
	w.yamlString(declaration.DisplayName, 256, false, false)
	w.raw("\n" + strings.Repeat(" ", int(indent+2)) + "encryption_key: ")
	w.yamlString(declaration.EncryptionKey, 1024, false, false)
	return w.err
}
