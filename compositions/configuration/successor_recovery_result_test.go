package configuration

import (
	"errors"
	"path/filepath"
	"testing"
)

// full_only: false
func TestSuccessorPendingRecoverySurvivesDisposal(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[encoding], func(t *testing.T) {
			source, _, request, material := successorFileFixture(t, encoding)
			path := filepath.Join(t.TempDir(), "successor")
			output, err := PrepareSuccessorOutput(t.Context(), source, path, request)
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("controlled successor publication interruption")
			output.io.phase = func(phase string) error {
				if phase == "generated-installed" {
					return fault
				}
				return nil
			}
			if _, err := output.Publish(t.Context(), material); !errors.Is(err, fault) || !errors.Is(err, ErrPendingEdit) {
				t.Fatal("pending successor was not established", err)
			}
			closeSourceOwner(t, output)
			recovery, exposed := any(output).(interface{ RecoverySource() (string, bool) })
			if !exposed {
				t.Error("successor result discarded its saved recovery source")
			} else if got, valid := recovery.RecoverySource(); !valid || got != path {
				t.Error("closed successor result lost exact recovery identity")
			}
			if _, err := RecoverEdit(t.Context(), path, encoding); err != nil {
				t.Fatal(err)
			}
			observed, err := PrepareSuccessorOutput(t.Context(), source, path, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, observed)
			if observed.Existing() == nil {
				t.Fatal("recovered output did not select exact observation")
			}
		})
	}
}
