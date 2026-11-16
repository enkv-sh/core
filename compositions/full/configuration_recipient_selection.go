package compositionfull

import (
	"context"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// RecipientSelector selects a local reference or one exact domain identity.
// Its zero value means current Authority only for consuming operations.
type RecipientSelector struct {
	Reference string
	ID        contract.ID
}

func (s RecipientSelector) valid() bool {
	return s.Reference == "" || s.ID.IsZero() && len(s.Reference) <= 256 && utf8.ValidString(s.Reference)
}

func (s RecipientSelector) resolve(model *configuration.Model) (contract.ID, error) {
	if !s.valid() || model == nil {
		return contract.ID{}, configuration.ErrEdit
	}
	if s.Reference == "" {
		return s.ID, nil
	}
	for _, row := range model.Recipients {
		if row.Reference == s.Reference && !row.ID.IsZero() {
			return row.ID, nil
		}
	}
	return contract.ID{}, configuration.ErrEdit
}

func (s RecipientSelector) localReference(ctx context.Context, pair *configuration.Pair) (string, error) {
	if !s.valid() {
		return "", configuration.ErrEdit
	}
	if s.Reference != "" {
		return s.Reference, nil
	}
	if s.ID.IsZero() {
		return "", configuration.ErrEdit
	}
	return configuration.RecipientReferenceByID(ctx, pair, s.ID)
}
