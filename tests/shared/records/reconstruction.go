package records

import (
	"crypto/sha256"
	"errors"
)

// ProcessCompletion records only joined executable and terminal identities.
// Paths, provider resources, input contents and private oracle facts stay private.
type ProcessCompletion struct {
	Phase           string `json:"phase"`
	Helper          string `json:"helper"`
	BinarySHA256    string `json:"binary_sha256"`
	TerminalsSHA256 string `json:"terminals_sha256"`
	Started         bool   `json:"started"`
	Joined          bool   `json:"joined"`
	Outcome         string `json:"outcome"`
}

func (p ProcessCompletion) Validate(phase, helper, binary string) error {
	if p.Phase != phase || p.Helper != helper || p.BinarySHA256 != binary || !validHex(binary, sha256.Size) || !validHex(p.TerminalsSHA256, sha256.Size) || !p.Started || !p.Joined || p.Outcome != "passed" {
		return errors.New("reconstruction process completion refused")
	}
	return nil
}
