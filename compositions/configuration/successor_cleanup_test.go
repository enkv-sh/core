package configuration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// full_only: false
func TestSuccessorPublicationRetainsFinalCleanupFailures(t *testing.T) {
	for _, cleanup := range []string{"close", "unlink"} {
		for _, primary := range []bool{false, true} {
			name := cleanup + "-only"
			if primary {
				name = cleanup + "-with-primary-failure"
			}
			t.Run(name, func(t *testing.T) {
				pair, model, request, material := successorFileFixture(t, JSON)
				path := filepath.Join(t.TempDir(), "successor")
				output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := output.Close(); err != nil {
						t.Error(err)
					}
				})
				primaryCause := errors.New("controlled final observation failure")
				operations := output.io
				blockedTemp := ""
				if cleanup == "close" {
					output.io.phase = func(phase string) error {
						if phase != "pair-verified" {
							return nil
						}
						if err := output.editor.candidate.pair.Generated.file.Close(); err != nil {
							t.Fatal(err)
						}
						if primary {
							return primaryCause
						}
						return nil
					}
				} else {
					output.io.remove = func(path string) error {
						if strings.HasPrefix(filepath.Base(path), ".enkv-generated-") {
							blockedTemp = path
							failure := error(&os.PathError{Op: "remove", Path: path, Err: syscall.ENOTEMPTY})
							if primary {
								failure = errors.Join(primaryCause, failure)
							}
							return failure
						}
						return operations.remove(path)
					}
				}
				readback, err := output.Publish(t.Context(), material)
				cleanupCause := error(os.ErrClosed)
				if cleanup == "unlink" {
					cleanupCause = syscall.ENOTEMPTY
				}
				if readback != nil || output.Delivered() || !errors.Is(err, cleanupCause) || errors.Is(err, primaryCause) != primary {
					t.Fatal("final cleanup lost cause or became delivery", err)
				}
				if cleanup == "unlink" {
					var cause *os.PathError
					if !errors.As(err, &cause) || cause.Op != "remove" || cause.Path != blockedTemp || !errors.Is(cause, syscall.ENOTEMPTY) {
						t.Fatal("cleanup did not retain exact staging unlink", err)
					}
					if _, err := os.Stat(blockedTemp); err != nil {
						t.Fatal("failed cleanup discarded saved candidate", err)
					}
				}
				if _, err := output.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
					t.Fatal("cleanup allowed repeat publication", err)
				}
				if _, err := output.OutputIdentity(); !errors.Is(err, ErrEdit) {
					t.Fatal("cleanup exposed delivered identity", err)
				}
				if err := output.Close(); err != nil {
					t.Fatal(err)
				}
				pending := cleanup == "unlink" || primary
				installed, captureErr := Capture(t.Context(), path, JSON)
				if pending {
					if installed != nil || !errors.Is(captureErr, ErrPendingEdit) {
						t.Fatal("pending cleanup was admitted", captureErr)
					}
					if _, err := RecoverEdit(t.Context(), path, JSON); err != nil {
						t.Fatal("exact cleanup recovery failed", err)
					}
					installed, captureErr = Capture(t.Context(), path, JSON)
				}
				if captureErr != nil {
					t.Fatal("installed pair lost", captureErr)
				}
				defer closeSourceOwner(t, installed)
				parsed, err := Parse(t.Context(), installed)
				if err != nil || parsed.FileID != model.FileID || parsed.Replacement == nil || parsed.Replacement.RequestIdentity != material.RequestIdentity || !bytes.Equal(parsed.Replacement.SignedCandidate, material.SignedCandidate) {
					t.Fatal("cleanup changed installed pair correlation", err)
				}
				if err := installed.CheckUnchanged(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := pair.CheckUnchanged(t.Context()); err != nil {
					t.Fatal("cleanup changed source", err)
				}
				observed, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
				if err != nil {
					t.Fatal(err)
				}
				defer closeSourceOwner(t, observed)
				if observed.Existing() == nil || observed.CheckUnchanged(t.Context()) != nil {
					t.Fatal("exact output lost observation")
				}
				if _, err := observed.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
					t.Fatal("observation became publication", err)
				}
			})
		}
	}
}
