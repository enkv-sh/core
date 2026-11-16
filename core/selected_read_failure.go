package core

import (
	"errors"

	"enkv.sh/core/contract"
)

// selectedReadError keeps a failed exact selected-object read distinct from a
// malformed record. The caller that owns a public Result returns the
// original Store uncertainty, missing-object, or integrity outcome.
type selectedReadError struct{ result Result }

func (e *selectedReadError) Error() string { return "selected object read failed" }

func selectedReadFailure(result Result) error {
	if result.Outcome == 0 {
		return contract.ErrRecord
	}
	return &selectedReadError{result: result}
}

func selectedReadResult(err error) (Result, bool) {
	var read *selectedReadError
	if !errors.As(err, &read) {
		return Result{}, false
	}
	return read.result, true
}
