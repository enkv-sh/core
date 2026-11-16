//go:build darwin || linux

package configuration

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// full_only: false
func TestRecoverySurvivesLocalOwnerDisposal(t *testing.T) {
	for _, condition := range []string{"closed-observation", "unavailable-temporary-directory"} {
		t.Run(condition, func(t *testing.T) {
			session, path := beginSourceEdit(t, JSON, true)
			generated := session.Pair().Generated.OriginalPath()
			candidate, want := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			fault := errors.New("controlled pending transaction")
			session.io.phase = func(phase string) error {
				if phase == "generated-installed" {
					return fault
				}
				return nil
			}
			_, err := session.Commit(t.Context(), candidate)
			var unknown *UnknownEdit
			if !errors.Is(err, fault) || !errors.As(err, &unknown) {
				t.Fatal("pending transaction was not established", err)
			}
			if source, ok := unknown.RecoverySource(); !ok || source != path {
				t.Fatal("pending result did not identify its recovery source")
			}
			if err := unknown.Observation.Close(); err != nil {
				t.Fatal(err)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			if condition == "closed-observation" {
				if source, ok := unknown.RecoverySource(); !ok || source != path {
					t.Error("closing local handles discarded durable recovery identity")
				}
			} else {
				t.Setenv("TMPDIR", "unavailable-relative-directory")
			}
			delivery, err := RecoverEdit(t.Context(), path, JSON)
			if err != nil || delivery == nil {
				t.Fatal("saved transaction could not complete without new temporary capture", err)
			}
			if readSource(t, path) != want || readSource(t, generated) != sourceGeneratedJSON+"\n" {
				t.Fatal("recovery changed the saved candidate")
			}
			if _, err := os.Lstat(coordinationPath(path, ".enkv-pending")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("completed recovery retained the pending marker", err)
			}
		})
	}
}

// full_only: false
func TestDeliveryRecoveryRequiresPendingMarker(t *testing.T) {
	for _, interruption := range []struct {
		phase string
		at    int
	}{
		{"marker-cleaned", 1}, {"marker-cleaned", 2}, {"markers-cleared", 1}, {"record-cleaned", 1},
	} {
		t.Run(fmt.Sprintf("%s-%d", interruption.phase, interruption.at), func(t *testing.T) {
			session, path := beginSourceEdit(t, JSON, true)
			candidate, _ := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			fault := errors.New("controlled final cleanup failure")
			hits := 0
			session.io.phase = func(phase string) error {
				if phase == interruption.phase {
					hits++
					if hits == interruption.at {
						return fault
					}
				}
				return nil
			}
			delivery, err := session.Commit(t.Context(), candidate)
			if !errors.Is(err, fault) || delivery == nil || !delivery.CleanupFailed() {
				t.Fatal("confirmed readback with incomplete cleanup was not established", err)
			}
			var unknown *UnknownEdit
			if !errors.As(err, &unknown) {
				t.Fatal("cleanup did not retain its local outcome")
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, session)
			_, markerErr := os.Lstat(coordinationPath(path, ".enkv-pending"))
			pending := markerErr == nil
			if !pending && !errors.Is(markerErr, os.ErrNotExist) {
				t.Fatal(markerErr)
			}
			if source, eligible := delivery.RecoverySource(); eligible != pending || eligible && source != path {
				t.Error("delivery offered recovery without its exact pending marker")
			}
			if source, eligible := unknown.RecoverySource(); eligible != pending || eligible && source != path {
				t.Error("unknown result recovery differs from its pending marker")
			}
			if pending {
				if _, err := RecoverEdit(t.Context(), path, JSON); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
