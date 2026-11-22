package contract

import "encoding/binary"

// A selected Attempt can retain the host's rejection of a well-formed reply.
// Its distinct body tag prevents even a claimed acknowledgement from being
// used as a provider result. The requested identity stays in the create proof.
const rejectedRetirementSchema uint16 = 0x8001

type GeneratorAttemptFacts struct {
	GeneratorSafeFacts
	RetirementRejected bool
}

func EncodeRejectedRetirement(claim GeneratorSafeFacts) ([]byte, error) {
	if !retirementResourceClaim(claim) {
		return nil, ErrRecord
	}
	if _, err := GeneratorSafeFactsLength(claim); err != nil {
		return nil, err
	}
	claim.ProviderFacts = nil
	body, err := EncodeGeneratorSafeFacts(claim)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(body, rejectedRetirementSchema)
	return body, nil
}

func retirementResourceClaim(f GeneratorSafeFacts) bool {
	return f.Action == GeneratorActionDelete && f.LifecycleMode == GeneratorLifecycleManaged &&
		(f.Disposition == GeneratorDispositionUnknown || f.Disposition == GeneratorDispositionRetirementAcknowledged)
}

func InspectGeneratorAttemptFacts(body []byte) (GeneratorAttemptFacts, error) {
	rejected := len(body) >= 2 && binary.BigEndian.Uint16(body) == rejectedRetirementSchema
	schema := GeneratorSafeFactsSchema
	if rejected {
		schema = rejectedRetirementSchema
	}
	v, err := inspectGeneratorFacts(body, schema)
	if err != nil {
		return GeneratorAttemptFacts{}, err
	}
	if rejected && (!retirementResourceClaim(v.GeneratorSafeFacts) || len(v.ProviderFacts) != 0) {
		return GeneratorAttemptFacts{}, ErrRecord
	}
	return GeneratorAttemptFacts{v.GeneratorSafeFacts, rejected}, nil
}
