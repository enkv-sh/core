package installedarchive

type RecoveryReplacementStep struct{ Operation, Mask, Approval uint8 }
type RecoveryReplacement struct {
	Steps     []RecoveryReplacementStep
	LaterHEAD bool
}

// ReplacementFor gives the setup writer and the independent parent the same
// explicit test history. It carries no selected-state or private-key facts.
func ReplacementFor(condition string) (RecoveryReplacement, bool) {
	var step RecoveryReplacementStep
	step.Operation, step.Approval = 1, 1
	switch condition {
	case "normal-signer-replaced", "normal-signer-by-recovery":
		step.Mask = 1
	case "authority-kek-replaced", "authority-kek-by-recovery":
		step.Mask = 2
	case "normal-combined-replaced", "normal-combined-later", "normal-combined-repeated", "generated-repeated-later":
		step.Mask = 3
	case "normal-restored-by-recovery", "adequate-anchor-fallback":
		step.Mask, step.Approval = 3, 2
	case "recovery-signer-replaced", "recovery-signer-by-recovery":
		step.Operation, step.Mask = 3, 4
	case "recovery-kek-replaced", "recovery-kek-by-recovery", "recovery-proof-recovery-only", "recovery-proof-both", "recovery-proof-normal-only", "recovery-proof-two-normal":
		step.Operation, step.Mask = 3, 8
	case "recovery-combined-replaced", "recovery-combined-by-recovery":
		step.Operation, step.Mask = 3, 12

	default:
		return RecoveryReplacement{}, false
	}
	if condition == "normal-signer-by-recovery" || condition == "authority-kek-by-recovery" || condition == "recovery-signer-by-recovery" || condition == "recovery-kek-by-recovery" || condition == "recovery-combined-by-recovery" || len(condition) >= len("recovery-proof-") && condition[:len("recovery-proof-")] == "recovery-proof-" {
		step.Approval = 2
	}
	result := RecoveryReplacement{Steps: []RecoveryReplacementStep{step}, LaterHEAD: condition == "normal-combined-later"}
	if condition == "normal-combined-repeated" || condition == "generated-repeated-later" {
		result.Steps = append(result.Steps, step)
		result.LaterHEAD = true
	}
	return result, true
}

func RecoverySecretCount(condition string) int {
	switch condition {
	case "zero-secret-genesis":
		return 0
	case "generated-active":
		return 3
	case "generated-retiring", "generated-uncertain":
		return 1
	default:
		return 5
	}
}
