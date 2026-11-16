package contract

// GeneratorRecoveryPolicyID binds the fixed public recovery stages and finite
// allowances. Recovery key protection is independent of this effect policy.
func GeneratorRecoveryPolicyID() ID {
	return generatorDigest("recovery-policy", []byte{
		0, 1,
		GeneratedStageRetainedResult, GeneratedStageObservation, GeneratedStageExactRetry, GeneratedStageResidue,
		1, 1, 1, GeneratorMaxEnteredCreateAttempts,
	})
}
