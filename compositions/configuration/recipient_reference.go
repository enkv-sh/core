package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"sort"
)

type RecipientReferenceEdit struct {
	edits capturedEdits
	joins [sha256.Size]byte
}

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
			end := span.Offset + span.Length
			if pair.Format == YAML && value[0] != '"' && end < pair.Editable.Size() {
				var suffix [1]byte
				if _, err := pair.Editable.ReadAt(suffix[:], end); err != nil {
					return nil, err
				}
				if suffix[0] == '#' {
					// Only a quoted scalar can end immediately before a comment.
					value = key
				}
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
	edit.joins = recipientJoinDigest(model, oldReference, newReference)
	return edit, nil
}

// ValidateCandidate checks the declarations and entry memberships after both
// emitted files have been parsed and joined, before either can be installed.
func (e *RecipientReferenceEdit) ValidateCandidate(m *Model) error {
	if e == nil || m == nil || !m.Resolved || m.parsedPair == nil || recipientJoinDigest(m, "", "") != e.joins {
		return ErrEdit
	}
	return nil
}

// Hash the expected rename in source order for memberships and reference
// order for declarations. Only the fixed digest survives candidate staging.
func recipientJoinDigest(m *Model, oldReference, newReference string) [sha256.Size]byte {
	ref := func(s string) string {
		if s == oldReference {
			return newReference
		}
		return s
	}
	h := sha256.New()
	number := func(n int) {
		var field [4]byte
		binary.BigEndian.PutUint32(field[:], uint32(n))
		h.Write(field[:])
	}
	name := func(s string) {
		number(len(s))
		h.Write([]byte(s))
	}
	h.Write(m.Authority.ID[:])
	for _, rows := range [][]Recipient{m.Recipients, m.GeneratedRecipients} {
		number(len(rows))
		order := make([]int, len(rows))
		for i := range order {
			order[i] = i
		}
		sort.Slice(order, func(i, j int) bool { return ref(rows[order[i]].Reference) < ref(rows[order[j]].Reference) })
		for _, i := range order {
			name(ref(rows[i].Reference))
			h.Write(rows[i].ID[:])
		}
	}
	number(len(m.Entries))
	for _, entry := range m.Entries {
		name(entry.Name)
		number(len(entry.Recipients))
		for _, member := range entry.Recipients {
			name(ref(member))
		}
	}
	return [sha256.Size]byte(h.Sum(nil))
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
