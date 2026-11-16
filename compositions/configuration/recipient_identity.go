package configuration

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
)

// RecipientIdentityEdits inserts allocated IDs into the model's captured source.
// Existing IDs must agree. The caller copies these edits with its other source
// edits; this function neither changes files nor grants recipient authority.
func RecipientIdentityEdits(ctx context.Context, model *Model) ([]Edit, error) {
	if ctx == nil || model == nil {
		return nil, ErrEdit
	}
	if err := model.parsedPair.validateCaptured(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	edits := make([]Edit, 0, len(model.Recipients))
	for _, recipient := range model.Recipients {
		edit, insert, err := recipientIdentityEdit(ctx, model, recipient)
		if err != nil {
			return nil, err
		}
		if insert {
			edits = append(edits, edit)
		}
	}
	return edits, nil
}

func recipientIdentityEdit(ctx context.Context, model *Model, recipient Recipient) (Edit, bool, error) {
	if recipient.ID.IsZero() {
		return Edit{}, false, ErrEdit
	}
	pair := model.parsedPair
	if recipient.IDSpan != MaxSpans {
		span, err := modelSpan(model, recipient.IDSpan)
		if err != nil || span.Offset < 0 || span.Length <= 0 || span.Offset > pair.Editable.Size() || span.Length > pair.Editable.Size()-span.Offset {
			return Edit{}, false, ErrEdit
		}
		p := newParser(ctx, io.NewSectionReader(pair.Editable, span.Offset, span.Length), pair.Format)
		current := id(p)
		if err := p.done(); err != nil || current != recipient.ID {
			return Edit{}, false, errors.Join(ErrEdit, err)
		}
		return Edit{}, false, nil
	}
	span, err := modelSpan(model, recipient.EditableSpan)
	if err != nil || !recipientRecordSpanValid(pair.Editable, span) {
		return Edit{}, false, ErrEdit
	}
	var opener [1]byte
	if _, err := pair.Editable.ReadAt(opener[:], span.Offset); err != nil {
		return Edit{}, false, errors.Join(ErrEdit, err)
	}
	field := `"id":"` + hex.EncodeToString(recipient.ID[:]) + `"`
	if opener[0] == '{' {
		if pair.Format == YAML {
			body, err := editableStringBytes(hex.EncodeToString(recipient.ID[:]), YAML, Span{Flow: true}, false)
			if err != nil {
				return Edit{}, false, err
			}
			field = "id: " + string(body)
		}
		return Edit{Offset: span.Offset + 1, Replacement: []byte(field + ",")}, true, nil
	}
	if pair.Format != YAML || span.Column == 0 || span.Column-1 > uint64(span.Offset) {
		return Edit{}, false, ErrEdit
	}
	body, err := editableStringBytes(hex.EncodeToString(recipient.ID[:]), YAML, Span{}, false)
	if err != nil {
		return Edit{}, false, err
	}
	field = "id: " + string(body)
	image, indent := pair.Editable, int64(span.Column-1)
	return Edit{Offset: span.Offset, Emit: func(out io.Writer) error {
		if n, err := io.WriteString(out, field+"\n"); err != nil || n != len(field)+1 {
			return errors.Join(ErrEdit, err, io.ErrShortWrite)
		}
		return copyEditRange(ctx, out, image, span.Offset-indent, indent, make([]byte, WindowBytes))
	}}, true, nil
}
