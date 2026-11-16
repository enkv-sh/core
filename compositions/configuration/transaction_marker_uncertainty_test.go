//go:build darwin || linux

package configuration

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// full_only: false
func TestTransactionSourceMarkerUncertaintyRetainsCandidate(t *testing.T) {
	for _, condition := range []string{"caller-canceled-after-install", "malformed-marker-after-install"} {
		t.Run(condition, func(t *testing.T) {
			session, path := beginSourceEdit(t, JSON, true)
			predecessor := session.Pair()
			original := readSource(t, path)
			generated := predecessor.Generated.OriginalPath()
			originalGenerated := readSource(t, generated)
			candidate, want := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			markerPath := coordinationPath(path, ".enkv-pending")
			const foreign = "malformed foreign marker bytes"
			fault := errors.New("controlled source marker response failure")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			native := session.io
			installed, injected := false, false
			session.io.installAbsent = func(from, to string) error {
				if err := native.installAbsent(from, to); err != nil {
					return err
				}
				if to != markerPath {
					return nil
				}
				installed = true
				if condition == "caller-canceled-after-install" {
					cancel()
				} else if err := os.WriteFile(markerPath, []byte(foreign), 0600); err != nil {
					return errors.Join(fault, err)
				}
				injected = true
				return fault
			}
			delivery, commitErr := session.Commit(ctx, candidate)
			session.io = native
			var unknown *UnknownEdit
			if delivery != nil || !installed || !injected || !errors.Is(commitErr, fault) || !errors.Is(commitErr, ErrPendingEdit) || !errors.As(commitErr, &unknown) {
				t.Fatal("uncertain marker publication did not retain its original failure and ownership", commitErr)
			}
			t.Cleanup(func() { closeSourceOwner(t, unknown.Observation) })
			confirmed := condition == "caller-canceled-after-install"
			if confirmed && !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("caller cancellation was not established after native install")
			}
			if source, eligible := unknown.RecoverySource(); eligible != confirmed || eligible && source != path {
				t.Error("uncertain marker offered the wrong recovery source")
			}
			record := session.transaction
			if record == nil {
				t.Fatal("uncertain publication lost its saved record")
			}
			ownedFiles := []*os.File{predecessor.Editable.file, predecessor.Generated.file, candidate.pair.Editable.file, candidate.pair.Generated.file}
			for _, lock := range session.locks.locks {
				ownedFiles = append(ownedFiles, lock.file)
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, session)
			if !errors.Is(commitErr, fault) || !errors.Is(commitErr, ErrPendingEdit) {
				t.Error("disposal changed the original uncertain result", commitErr)
			}
			if source, eligible := unknown.RecoverySource(); eligible != confirmed || eligible && source != path {
				t.Error("disposal changed source recovery eligibility")
			}
			if readSource(t, path) != original || readSource(t, generated) != originalGenerated {
				t.Error("uncertain publication or disposal changed the visible predecessor")
			}
			if readSource(t, candidate.editableTemp) != want || readSource(t, candidate.generatedTemp) != sourceGeneratedJSON+"\n" {
				t.Error("disposal changed the exact saved candidate")
			}
			for _, owned := range []string{record.path(), record.Description.Scratch, candidate.editableTemp + ".install", candidate.generatedTemp + ".install"} {
				if _, err := os.Lstat(owned); err != nil {
					t.Errorf("disposal lost pending ownership at %q: %v", owned, err)
				}
			}
			for _, file := range ownedFiles {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Error("disposal retained an owned descriptor", err)
				}
			}
			fresh, stop := context.WithTimeout(context.Background(), time.Minute)
			defer stop()
			captured, captureErr := Capture(fresh, path, JSON)
			if captured != nil {
				closeSourceOwner(t, captured)
			}
			if captured != nil || !errors.Is(captureErr, ErrPendingEdit) {
				t.Fatal("consumer admitted uncertain marker publication", captureErr)
			}
			if confirmed {
				if delivered, err := RecoverEdit(fresh, path, JSON); err != nil || delivered == nil {
					t.Fatal("fresh context could not recover the exact published candidate", err)
				}
				if readSource(t, path) != want || readSource(t, generated) != sourceGeneratedJSON+"\n" {
					t.Error("fresh-context recovery changed the saved candidate")
				}
			} else {
				if delivered, err := RecoverEdit(fresh, path, JSON); err == nil || delivered != nil {
					t.Error("malformed marker authorized candidate recovery")
				}
				if body, err := os.ReadFile(markerPath); err != nil || string(body) != foreign {
					t.Error("disposal or refused recovery changed the foreign marker", err)
				}
				if readSource(t, path) != original || readSource(t, generated) != originalGenerated || readSource(t, candidate.editableTemp) != want || readSource(t, candidate.generatedTemp) != sourceGeneratedJSON+"\n" {
					t.Error("refused recovery changed the predecessor or saved candidate")
				}
			}
		})
	}
}
