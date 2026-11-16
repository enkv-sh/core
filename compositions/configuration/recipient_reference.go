package configuration

import (
	"context"
	"encoding/json"
	"io"
	"sort"
)

type RecipientReferenceEdit struct{ edits capturedEdits }

func PrepareRecipientReferenceEdit(ctx context.Context, pair *Pair, oldReference, newReference string) (*RecipientReferenceEdit, error) {
	if !referenceValid(oldReference) || !referenceValid(newReference) || oldReference == newReference {
		return nil, ErrEdit
	}
	model, err := parseEditModel(ctx, pair, &Model{selectedReference: &oldReference})
	if err != nil {
		return nil, err
	}
	if !model.Resolved {
		return nil, ErrEdit
	}
	var selected *Recipient
	for i := range model.Recipients {
		row := &model.Recipients[i]
		if row.Reference == newReference {
			return nil, ErrEdit
		}
		if row.Reference == oldReference {
			selected = row
		}
	}
	if selected == nil {
		return nil, ErrEdit
	}
	key, err := json.Marshal(newReference)
	if err != nil {
		return nil, err
	}
	edit := &RecipientReferenceEdit{edits: capturedEdits{pair: pair, reference: model.Generated}}
	editCount := 2
	for _, span := range model.Spans {
		if span.Kind == SpanRecipientReference {
			editCount++
		}
	}
	edit.edits.editable = make([]Edit, 0, editCount)
	span, err := modelSpan(model, selected.EditableSpan)
	if err != nil || !recipientRecordSpanValid(pair.Editable, span) {
		return nil, ErrEdit
	}
	editableKey, err := editableStringBytes(newReference, pair.Format, span, true)
	if err != nil {
		return nil, err
	}
	edit.edits.editable = append(edit.edits.editable, Edit{Offset: span.SourceOffset, Length: span.SourceLength, Replacement: editableKey})
	for _, span := range model.Spans {
		switch span.Kind {
		case SpanRecipientReference:
			value, err := editableStringBytes(newReference, pair.Format, span, false)
			if err != nil {
				return nil, err
			}
			edit.edits.editable = append(edit.edits.editable, Edit{Offset: span.Offset, Length: span.Length, Replacement: value})
		}
	}
	edit.edits.records = make([]recipientRecord, 0, len(model.GeneratedRecipients))
	for _, row := range model.GeneratedRecipients {
		if row.Reference == newReference {
			return nil, ErrEdit
		}
		span, err := modelSpan(model, row.GeneratedSpan)
		if err != nil || !recipientRecordSpanValid(pair.Generated, span) {
			return nil, ErrEdit
		}
		record := recipientRecord{reference: row.Reference, span: span}
		if row.Reference == oldReference {
			record.reference, record.key = newReference, key
		}
		edit.edits.records = append(edit.edits.records, record)
	}
	container, err := modelSpan(model, model.GeneratedRecipientsSpan)
	if err != nil {
		return nil, err
	}
	edit.edits.recipients = container
	orderRecipientRecords(edit.edits.records)
	sort.Slice(edit.edits.editable, func(i, j int) bool { return edit.edits.editable[i].Offset < edit.edits.editable[j].Offset })
	return edit, nil
}

func (e *RecipientReferenceEdit) EmitEditable(ctx context.Context, out io.Writer, reference string) error {
	if e == nil {
		return ErrEdit
	}
	return e.edits.emitEditable(ctx, out, reference)
}

func (e *RecipientReferenceEdit) EmitGenerated(ctx context.Context, out io.Writer) error {
	if e == nil {
		return ErrEdit
	}
	return e.edits.emitGenerated(ctx, out)
}
