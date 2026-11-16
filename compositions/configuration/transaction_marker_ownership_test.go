//go:build darwin || linux

package configuration

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestTransactionMarkerOwnershipOnReturnedFailure(t *testing.T) {
	for _, failure := range []string{"record-directory-sync", "source-marker-install", "source-marker-directory-sync", "source-marker-install-response-lost"} {
		t.Run(failure, func(t *testing.T) {
			session, path := beginSourceEdit(t, JSON, true)
			original := readSource(t, path)
			generated := session.Pair().Generated.OriginalPath()
			originalGenerated := readSource(t, generated)
			candidate, want := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			markerPath := coordinationPath(path, ".enkv-pending")
			fault := errors.New("controlled transaction metadata failure")
			native := session.io
			var record *pendingRecord
			recordInstalled, markerInstalled, failed := false, false, false
			session.io.installAbsent = func(from, to string) error {
				if to == markerPath && failure == "source-marker-install" {
					failed = true
					return fault
				}
				if err := native.installAbsent(from, to); err != nil {
					return err
				}
				if session.transaction != nil && to == session.transaction.path() {
					record = session.transaction
					recordInstalled = true
				}
				if to == markerPath {
					markerInstalled = true
					if failure == "source-marker-install-response-lost" {
						failed = true
						return fault
					}
				}
				return nil
			}
			session.io.syncDir = func(directory string) error {
				if !failed && (failure == "record-directory-sync" && recordInstalled && directory == filepath.Dir(record.path()) ||
					failure == "source-marker-directory-sync" && markerInstalled && directory == filepath.Dir(markerPath)) {
					failed = true
					return fault
				}
				return native.syncDir(directory)
			}
			delivery, commitErr := session.Commit(t.Context(), candidate)
			session.io = native
			if delivery != nil || !failed || !recordInstalled || !errors.Is(commitErr, fault) {
				t.Fatal("selected metadata failure was not established", commitErr)
			}
			if record == nil {
				t.Fatal("installed record was not observed")
			}
			ownedPaths := []string{record.path(), record.Description.Scratch}
			for _, row := range record.Description.Paths {
				ownedPaths = append(ownedPaths, record.markerScratchDirectory(row), coordinationPath(row.Path, ".enkv-pending"))
			}
			for _, image := range record.Description.Images {
				ownedPaths = append(ownedPaths, image.Path, image.installPath())
			}
			if readSource(t, path) != original || readSource(t, generated) != originalGenerated {
				t.Error("metadata failure changed the visible predecessor")
			}
			pending := failure == "source-marker-directory-sync" || failure == "source-marker-install-response-lost"
			if markerInstalled != pending {
				t.Fatal("metadata failure crossed the wrong marker boundary")
			}
			var unknown *UnknownEdit
			isUnknown := errors.As(commitErr, &unknown)
			if isUnknown != pending || errors.Is(commitErr, ErrPendingEdit) != pending {
				t.Error("result claimed the wrong pending ownership", commitErr)
			}
			if unknown != nil {
				if source, eligible := unknown.RecoverySource(); eligible != pending || eligible && source != path {
					t.Error("result recovery source differs from the installed source marker")
				}
				if err := unknown.Observation.Close(); err != nil {
					t.Error("observation disposal failed", err)
				}
			}
			if err := session.Close(); err != nil {
				t.Fatal("session disposal failed", err)
			}
			captured, captureErr := Capture(t.Context(), path, JSON)
			if captured != nil {
				closeSourceOwner(t, captured)
			}
			if pending {
				if captured != nil || !errors.Is(captureErr, ErrPendingEdit) {
					t.Fatal("consumer admitted a reachable pending transaction", captureErr)
				}
				for _, image := range record.Description.Images {
					if _, err := os.Lstat(image.Path); err != nil {
						t.Fatal("disposal lost a reachable saved candidate", err)
					}
				}
				if delivered, err := RecoverEdit(t.Context(), path, JSON); err != nil || delivered == nil {
					t.Fatal("installed source marker did not permit exact recovery", err)
				}
				if readSource(t, path) != want || readSource(t, generated) != sourceGeneratedJSON+"\n" {
					t.Error("recovery did not install the exact saved candidate")
				}
			} else {
				if captured == nil || captureErr != nil {
					t.Error("pre-visible refusal did not preserve an admissible predecessor", captureErr)
				}
				if delivered, err := RecoverEdit(t.Context(), path, JSON); err == nil || delivered != nil {
					t.Error("absent source marker permitted recovery")
				}
				if readSource(t, path) != original || readSource(t, generated) != originalGenerated {
					t.Error("disposal changed the visible predecessor")
				}
			}
			for _, owned := range ownedPaths {
				if _, err := os.Lstat(owned); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("completed disposal or recovery left transaction-owned path %q: %v", owned, err)
				}
			}
		})
	}
}

// full_only: false
func TestTransactionUnpublishedRecordCleanupPreservesForeignFiles(t *testing.T) {
	for _, failure := range []string{"record-directory-sync", "source-marker-install"} {
		t.Run(failure, func(t *testing.T) {
			session, path := beginSourceEdit(t, JSON, true)
			predecessor := session.Pair()
			original := readSource(t, path)
			generated := predecessor.Generated.OriginalPath()
			originalGenerated := readSource(t, generated)
			candidate, _ := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			fault := errors.New("controlled unpublished record failure")
			native := session.io
			var record *pendingRecord
			failed := false
			session.io.installAbsent = func(from, to string) error {
				if failure == "source-marker-install" && to == coordinationPath(path, ".enkv-pending") {
					failed = true
					return fault
				}
				if err := native.installAbsent(from, to); err != nil {
					return err
				}
				if session.transaction != nil && to == session.transaction.path() {
					record = session.transaction
				}
				return nil
			}
			session.io.syncDir = func(directory string) error {
				if !failed && failure == "record-directory-sync" && record != nil && directory == filepath.Dir(record.path()) {
					failed = true
					return fault
				}
				return native.syncDir(directory)
			}
			delivery, commitErr := session.Commit(t.Context(), candidate)
			session.io = native
			var unknown *UnknownEdit
			if delivery != nil || !failed || record == nil || !errors.Is(commitErr, fault) || errors.Is(commitErr, ErrPendingEdit) || errors.As(commitErr, &unknown) {
				t.Fatal("pre-marker failure did not retain ordinary cleanup ownership", commitErr)
			}
			before, err := os.Lstat(record.path())
			if err != nil {
				t.Fatal("unpublished record was not installed", err)
			}
			const foreign = "different owner record and marker bytes"
			replacement, err := os.CreateTemp(filepath.Dir(record.path()), ".foreign-record-*")
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := replacement.WriteString(foreign)
			if err := errors.Join(writeErr, replacement.Close()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement.Name(), record.path()); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(record.path())
			if err != nil || os.SameFile(before, after) {
				t.Fatal("foreign record replacement did not change the inode", err)
			}
			foreignPaths := []string{record.path()}
			ownedPaths := []string{record.Description.Scratch}
			for _, row := range record.Description.Paths {
				marker := coordinationPath(row.Path, ".enkv-pending")
				if err := os.WriteFile(marker, []byte(foreign), 0600); err != nil {
					t.Fatal(err)
				}
				foreignPaths = append(foreignPaths, marker)
				ownedPaths = append(ownedPaths, record.markerScratchDirectory(row))
			}
			for _, image := range record.Description.Images {
				ownedPaths = append(ownedPaths, image.Path, image.installPath())
			}
			ownedFiles := []*os.File{predecessor.Editable.file, predecessor.Generated.file, candidate.pair.Editable.file, candidate.pair.Generated.file}
			for _, lock := range session.locks.locks {
				ownedFiles = append(ownedFiles, lock.file)
			}
			if err := session.Close(); !errors.Is(err, ErrEdit) {
				t.Error("foreign record cleanup refusal was not surfaced", err)
			}
			if !errors.Is(commitErr, fault) || errors.Is(commitErr, ErrPendingEdit) || errors.As(commitErr, &unknown) {
				t.Error("cleanup failure changed the original commit cause or result", commitErr)
			}
			if readSource(t, path) != original || readSource(t, generated) != originalGenerated {
				t.Error("cleanup refusal changed the visible predecessor")
			}
			for _, foreignPath := range foreignPaths {
				if body, err := os.ReadFile(foreignPath); err != nil || string(body) != foreign {
					t.Errorf("cleanup changed foreign path %q: %v", foreignPath, err)
				}
			}
			for _, owned := range ownedPaths {
				if _, err := os.Lstat(owned); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("cleanup retained our private path %q: %v", owned, err)
				}
			}
			for _, file := range ownedFiles {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Error("cleanup retained an owned descriptor", err)
				}
			}
		})
	}
}
