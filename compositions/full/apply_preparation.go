package compositionfull

import "enkv.sh/core"

// The maximum counter has six decimal digits; false is the longer boolean.
// This charges the complete JSON field, including its separating comma.
const applyPreparationFieldBytes = 116

type applyPreparationRecord struct {
	AcknowledgedCreates          uint64 `json:"acknowledged_creates"`
	VerifiedPreparations         uint64 `json:"verified_preparations"`
	PossibleUnacknowledgedCreate bool   `json:"possible_unacknowledged_create"`
}

func validApplyPreparation(facts *core.ApplyPreparationFacts) bool {
	return facts == nil || facts.AcknowledgedCreates <= core.ApplyPreparationCountLimit && facts.VerifiedPreparations <= core.ApplyPreparationCountLimit
}

func applyPreparationProjection(facts *core.ApplyPreparationFacts) (*applyPreparationRecord, error) {
	if !validApplyPreparation(facts) {
		return nil, errApplyResult
	}
	if facts == nil {
		return nil, nil
	}
	return &applyPreparationRecord{AcknowledgedCreates: facts.AcknowledgedCreates, VerifiedPreparations: facts.VerifiedPreparations, PossibleUnacknowledgedCreate: facts.PossibleUnacknowledgedCreate}, nil
}
