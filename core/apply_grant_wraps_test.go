package core

import (
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestExistingSecretGrantAdmissionPrecedesPreparation(t *testing.T) {
	s := &StateSession{valueReaders: make(map[contract.ID][]contract.ID)}
	s.head.K1, s.head.K3 = make([]byte, 72), make([]byte, 72)
	s.token = contract.Token{Family: contract.AWS, Value: `"` + strings.Repeat("x", 35) + `"`}
	s.pages[0] = &format.ValueEntryPage{}
	c := &Comparison{session: s, operation: &cryptoOperation{}}
	plan := transitionPlan{values: map[uint16]contract.ID{}}
	for i, count := range []int{63, 63, 4} {
		value := contract.ID{byte(200 + i)}
		name := string(rune('a' + i))
		members := []contract.ID{{1}}
		for j := 0; j < count; j++ {
			members = append(members, contract.ID{byte(j + 2)})
		}
		s.pages[0].Slots[i] = &format.ValueEntry{Name: name, ConfidentialityClass: format.Secret, ValueState: value, Recipients: []contract.ID{{1}}}
		c.slots = append(c.slots, uint16(i))
		c.intent = append(c.intent, contract.CryptoIntentRow{Name: name, ConfidentialityClass: format.Secret, Recipients: members})
	}
	// The third value changes content and source in the same grant. Count all
	// new holders against the new material even if a retained reader existed.
	plan.values[2] = contract.ID{210}
	s.valueReaders[contract.ID{202}] = []contract.ID{{2}}
	byMaterial, count, err := c.existingSecretGrants(plan)
	if err != nil || count != 130 || !slices.Equal(byMaterial[contract.ID{210}], c.intent[2].Recipients[1:]) {
		t.Fatal("fitting mixed request", count, err)
	}
	s.token.Value = `"` + strings.Repeat("x", 36) + `"`
	// This fixture has no Store or Crypto exchange. A one-byte overflow must
	// return at admission, before plan I/O or the preparation exchange.
	if result := s.prepareCompared(t.Context(), c, plan); result.Outcome != AdmissionRefused || result.Reason != CapacityExceeded ||
		c.operation.terminal || len(c.preparedRows) != 0 || !c.preparedPlan.Digest.IsZero() {
		t.Fatal("oversized grant reached preparation", result)
	}
	s.valueReaders[contract.ID{200}] = []contract.ID{{2}}
	_, count, err = c.existingSecretGrants(plan)
	if err != nil || count != 129 {
		t.Fatal("retained wrap was counted twice", count, err)
	}
	c.added = []uint16{1}
	_, count, err = c.existingSecretGrants(plan)
	if err != nil || count != 66 {
		t.Fatal("new entry consumed existing-grant capacity", count, err)
	}
}
