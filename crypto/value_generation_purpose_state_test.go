package crypto

import (
	"bytes"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedPurposeValidationPreservesCheckpointSupportUntilClear(t *testing.T) {
	for _, test := range []struct {
		name     string
		purpose  contract.CryptoGeneratedPurpose
		conflict bool
		want     bool
	}{
		{"matching", contract.CryptoGeneratedFinalPreparationPurpose, false, true},
		{"different", contract.CryptoGeneratedProducerPreparationPurpose, false, false},
		{"ambiguous", contract.CryptoGeneratedFinalPreparationPurpose, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			owned := bytes.Repeat([]byte{0xa7}, 32)
			state := generatedPurposeState{final: &generatedFinalPreparationState{checkpointSupport: []contract.SupportRecord{{Body: owned[:7]}}}}
			if test.conflict {
				state.producer = &generatedProducerPreparationState{}
			}
			if state.valid(test.purpose) != test.want {
				t.Fatal("purpose result differs")
			}
			if !bytes.Equal(owned, bytes.Repeat([]byte{0xa7}, 32)) {
				t.Fatal("purpose validation changed owned selected-support bytes")
			}
		})
	}
	t.Run("complete-owned-capacity-disposal", func(t *testing.T) {
		owned := bytes.Repeat([]byte{0xa7}, 32)
		state := generatedPurposeState{final: &generatedFinalPreparationState{checkpointSupport: []contract.SupportRecord{{Body: owned[:7]}}}}
		state.clear()
		if !bytes.Equal(owned, make([]byte, 32)) || len(state.final.checkpointSupport) != 0 {
			t.Fatal("purpose disposal retained owned support capacity")
		}
	})
}

// full_only: false
func TestGeneratedSessionDoesNotOwnPurposeState(t *testing.T) {
	typeOfSession := reflect.TypeOf(generatedAdmission{})
	for _, field := range []string{
		"streams",
		"sources",
		"recipients",
		"phase",
		"target",
		"results",
		"validated",
		"nonselectingFinal",
		"protections",
		"protection",
		"producer",
		"intents",
		"declaration",
		"entryPreparations",
		"supplied",
		"entryNext",
		"entryBatch",
		"canonicals",
		"liveSources",
		"controlledPredecessor",
	} {
		if _, present := typeOfSession.FieldByName(field); present {
			t.Errorf("common generated session still owns purpose field %q", field)
		}
	}
}

// full_only: false
func TestGeneratedPurposeStateRequiresExactlyOneMatchingPurpose(t *testing.T) {
	tests := []struct {
		name    string
		purpose contract.CryptoGeneratedPurpose
		state   generatedPurposeState
	}{
		{"reservation", contract.CryptoGeneratedReservationPurpose, generatedPurposeState{reservation: &generatedReservationState{}}},
		{"adoption", contract.CryptoGeneratedAdoptionPurpose, generatedPurposeState{adoption: &generatedAdoptionState{}}},
		{"final", contract.CryptoGeneratedFinalPreparationPurpose, generatedPurposeState{final: &generatedFinalPreparationState{}}},
		{"producer", contract.CryptoGeneratedProducerPreparationPurpose, generatedPurposeState{producer: &generatedProducerPreparationState{}}},
		{"verification", contract.CryptoGeneratedOriginalVerificationPurpose, generatedPurposeState{verification: &generatedOriginalVerificationState{}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.state.valid(test.purpose) {
				t.Fatal("matching concrete purpose refused")
			}
			for purpose := contract.CryptoGeneratedReservationPurpose; purpose <= contract.CryptoGeneratedOriginalVerificationPurpose; purpose++ {
				if purpose != test.purpose && test.state.valid(purpose) {
					t.Fatalf("purpose %d accepted concrete purpose %d", purpose, test.purpose)
				}
			}
		})
	}
	if (generatedPurposeState{}).valid(contract.CryptoGeneratedReservationPurpose) {
		t.Fatal("missing purpose state accepted")
	}
	conflict := generatedPurposeState{reservation: &generatedReservationState{}, adoption: &generatedAdoptionState{}}
	if conflict.valid(contract.CryptoGeneratedReservationPurpose) || conflict.valid(contract.CryptoGeneratedAdoptionPurpose) {
		t.Fatal("conflicting purpose states accepted")
	}
}
