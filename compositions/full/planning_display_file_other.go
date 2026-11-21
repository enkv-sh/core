//go:build !unix

package compositionfull

import (
	"context"
	privatecrypto "enkv.sh/crypto"
	"os"
)

func NewPlanningDisplayFile(*os.File, bool) (privatecrypto.PlanningDisplayFactory, error) {
	return nil, errPlanningDisplay
}

func WritePlanningResult(context.Context, *os.File, []byte) error { return errPlanningDisplay }

func writePlanningResult(context.Context, *os.File, []byte, os.FileInfo) error {
	return errPlanningDisplay
}
