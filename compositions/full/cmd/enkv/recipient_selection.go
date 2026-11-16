package main

import (
	"unicode/utf8"

	compositionfull "enkv.sh/compositions/full"
)

func commandRecipientSelection(reference, id replacementFlag) (compositionfull.RecipientSelector, bool) {
	if reference.set && id.set {
		return compositionfull.RecipientSelector{}, false
	}
	if reference.set {
		if reference.value == "" || len(reference.value) > 256 || !utf8.ValidString(reference.value) {
			return compositionfull.RecipientSelector{}, false
		}
		return compositionfull.RecipientSelector{Reference: reference.value}, true
	}
	if id.set {
		value, ok := parseID(id.value)
		return compositionfull.RecipientSelector{ID: value}, ok
	}
	return compositionfull.RecipientSelector{}, true
}
