package custody

import (
	"bytes"
	"testing"
)

// full_only: false
func TestPublicDictionaryCoversSelectedSyntheticValue(t *testing.T) {
	value, ok := syntheticValue(StandardValue)
	guesses := NewDictionaryObserver().guesses
	if !ok || len(value) == 0 || len(guesses) < 2 || !bytes.Equal(value, guesses[0]) {
		t.Fatal("public dictionary does not cover the selected synthetic value")
	}
}
