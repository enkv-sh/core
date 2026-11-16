package configuration

import (
	"context"

	"enkv.sh/core/contract"
)

// RecipientReferenceByID finds one managed identity in the captured editable
// image. It does not admit generated records; the selected operation must parse
// the same pair, including its preparation-only repairs, before using the row.
func RecipientReferenceByID(ctx context.Context, pair *Pair, id contract.ID) (string, error) {
	if ctx == nil || pair == nil || pair.Editable == nil || id.IsZero() {
		return "", ErrEdit
	}
	if err := pair.validateCaptured(); err != nil {
		return "", err
	}
	model, err := parseEditableMode(ctx, pair.Editable, pair.Format, true, nil)
	if err != nil {
		return "", err
	}
	reference := ""
	for _, row := range model.Recipients {
		if row.ID != id {
			continue
		}
		if reference != "" {
			return "", ErrEdit
		}
		reference = row.Reference
	}
	if reference == "" {
		return "", ErrEdit
	}
	return reference, nil
}
