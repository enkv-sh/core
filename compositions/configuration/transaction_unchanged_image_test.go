//go:build darwin || linux

package configuration

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type transactionInterleaveContext struct {
	context.Context
	check func()
}

func (ctx transactionInterleaveContext) Err() error {
	ctx.check()
	return ctx.Context.Err()
}

func stageUnchangedImage(t *testing.T, format Format, unchanged string) (*EditSession, *EditCandidate, string) {
	t.Helper()
	setup := sourceSetupJSON
	if format == YAML {
		setup = sourceSetupYAML
	}
	pair := writePair(t, setup, sourceGeneratedJSON, format)
	path := pair.Editable.OriginalPath()
	if err := pair.Close(); err != nil {
		t.Fatal(err)
	}
	session, err := BeginEdit(t.Context(), path, format)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSourceOwner(t, session) })
	var candidate *EditCandidate
	if unchanged == "generated" {
		candidate, _ = stageSourceEdit(t, session, sourceGeneratedJSON)
		path = candidate.pair.Generated.path
	} else {
		candidate, _, err = session.Stage(t.Context(), func(w io.Writer) error {
			_, err := io.WriteString(w, sourceGeneratedJSON+"\n")
			return err
		}, func(w io.Writer, _ string) error {
			_, err := session.Pair().Editable.CopyTo(w)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Locks are already acquired in native identity order. Order the saved
	// record's checks so the other image supplies the controlled interleaving;
	// filenames do not determine native lock identity order.
	for index, lock := range session.locks.locks {
		if lock.path == path {
			session.locks.locks[0], session.locks.locks[index] = session.locks.locks[index], session.locks.locks[0]
			break
		}
	}
	return session, candidate, path
}

func replaceUnchangedImage(t *testing.T, path, damage string) (string, os.FileInfo) {
	t.Helper()
	body := readSource(t, path)
	if damage == "content" {
		body = "!" + body[1:]
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		temporary := filepath.Join(filepath.Dir(path), ".foreign-image")
		if err := os.WriteFile(temporary, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temporary, path); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return body, info
}

// full_only: false
func TestTransactionUnchangedImagesRefuseReplacement(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		for _, unchanged := range []string{"editable", "generated"} {
			for _, damage := range []string{"content", "identity"} {
				t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format]+"/"+unchanged+"/"+damage, func(t *testing.T) {
					session, candidate, path := stageUnchangedImage(t, format, unchanged)
					if candidate.pair.Editable.Size() >= WindowBytes || candidate.pair.Generated.Size() >= WindowBytes {
						t.Fatal("controlled interleaving requires one read per image")
					}
					installs, replacements := 0, 0
					install, replace := session.io.installAbsent, session.io.replace
					session.io.installAbsent = func(from, to string) error {
						if to == path {
							installs++
						}
						return install(from, to)
					}
					session.io.replace = func(from, to string) error {
						if to == path {
							replacements++
						}
						return replace(from, to)
					}
					armed, checks := false, 0
					var foreign string
					var foreignInfo os.FileInfo
					session.io.phase = func(phase string) error {
						if phase == "before-"+unchanged+"-install" {
							if session.transaction.Description.Paths[0].Path != path {
								t.Fatal("unchanged image must be checked before the other image")
							}
							armed = true
						}
						return nil
					}
					ctx := transactionInterleaveContext{Context: t.Context(), check: func() {
						if armed {
							checks++
							if checks == 2 {
								// The unchanged image passed checkVisible. Change it
								// while checkVisible reads the other image, before
								// completePending checks the unchanged image again.
								foreign, foreignInfo = replaceUnchangedImage(t, path, damage)
								armed = false
							}
						}
					}}
					delivery, err := session.Commit(ctx, candidate)
					var unknown *UnknownEdit
					if errors.As(err, &unknown) {
						closeSourceOwner(t, unknown.Observation)
					}
					if foreignInfo == nil {
						t.Fatal("controlled source change did not occur")
					}
					if installs != 0 || replacements != 0 {
						t.Fatalf("unchanged image reached native installation: installs %d, replacements %d", installs, replacements)
					}
					if delivery != nil || !errors.Is(err, ErrEdit) || !errors.Is(err, ErrPendingEdit) || unknown == nil {
						t.Fatal("changed unchanged-image guard lost pending ownership", err)
					}
					current, statErr := os.Lstat(path)
					if statErr != nil || !os.SameFile(foreignInfo, current) || readSource(t, path) != foreign {
						t.Fatal("completion changed the foreign file", statErr)
					}
					marker, markerErr := readMarker(t.Context(), coordinationPath(session.path, ".enkv-pending"))
					if markerErr != nil || marker.Record != candidate.pending.path() || marker.Digest != candidate.pending.Digest || !candidate.durable {
						t.Fatal("refusal lost the exact saved candidate", markerErr)
					}
				})
			}
		}
	}
}

// full_only: false
func TestTransactionUnchangedSourceAroundCompanionInstallation(t *testing.T) {
	for _, at := range []string{"before-companion", "after-companion", "unchanged"} {
		for _, damage := range []string{"content", "identity"} {
			if at == "unchanged" && damage == "identity" {
				continue
			}
			t.Run(at+"/"+damage, func(t *testing.T) {
				session, candidate, path := stageUnchangedImage(t, YAML, "editable")
				original := readSource(t, path)
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				generated := candidate.pair.Generated.path
				installs, replacements := 0, 0
				install, replace := session.io.installAbsent, session.io.replace
				session.io.installAbsent = func(from, to string) error {
					if to == path {
						installs++
					}
					return install(from, to)
				}
				session.io.replace = func(from, to string) error {
					if to == path {
						replacements++
					}
					return replace(from, to)
				}
				changed := false
				change := func() {
					original, info = replaceUnchangedImage(t, path, damage)
					changed = true
				}
				session.io.phase = func(phase string) error {
					if at == "before-companion" && phase == "before-generated-install" {
						change()
					}
					return nil
				}
				readback := session.io.readback
				session.io.readback = func(ctx context.Context, target string, image *Image, absent bool) error {
					if err := readback(ctx, target, image, absent); err != nil {
						return err
					}
					if at == "after-companion" && target == generated {
						change()
					}
					return nil
				}
				delivery, err := session.Commit(t.Context(), candidate)
				var unknown *UnknownEdit
				if errors.As(err, &unknown) {
					closeSourceOwner(t, unknown.Observation)
				}
				if at == "unchanged" {
					if err != nil || delivery == nil {
						t.Fatal("unchanged source prevented companion delivery", err)
					}
				} else if !changed || delivery != nil || unknown == nil || !errors.Is(err, ErrPendingEdit) {
					t.Fatal("source conflict lost pending ownership", err)
				}
				if installs != 0 || replacements != 0 {
					t.Fatalf("unchanged source reached native installation: installs %d, replacements %d", installs, replacements)
				}
				current, statErr := os.Lstat(path)
				if statErr != nil || !os.SameFile(info, current) || readSource(t, path) != original {
					t.Fatal("completion changed the source", statErr)
				}
				wantGenerated := sourceGeneratedJSON + "\n"
				if at == "before-companion" {
					wantGenerated = sourceGeneratedJSON
				}
				if readSource(t, generated) != wantGenerated {
					t.Fatal("companion installation or retained delivery changed")
				}
				if changed {
					if _, err := readMarker(t.Context(), coordinationPath(path, ".enkv-pending")); err != nil || !candidate.durable {
						t.Fatal("source conflict lost the saved candidate", err)
					}
				}
			})
		}
	}
}

// full_only: false
func TestTransactionRecoveryPreservesUnchangedSource(t *testing.T) {
	for _, damage := range []string{"none", "content", "identity"} {
		t.Run(damage, func(t *testing.T) {
			session, candidate, path := stageUnchangedImage(t, YAML, "editable")
			generated := candidate.pair.Generated.path
			fault := errors.New("controlled saved-candidate interruption")
			session.io.phase = func(phase string) error {
				if phase == "generated-installed" {
					return fault
				}
				return nil
			}
			_, err := session.Commit(t.Context(), candidate)
			var unknown *UnknownEdit
			if !errors.Is(err, fault) || !errors.As(err, &unknown) || !candidate.durable {
				t.Fatal("saved-candidate interruption was not established", err)
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, session)
			body := readSource(t, path)
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if damage != "none" {
				body, info = replaceUnchangedImage(t, path, damage)
			}
			delivery, err := RecoverEdit(t.Context(), path, YAML)
			if damage == "none" {
				if err != nil || delivery == nil {
					t.Fatal("recovery did not complete the exact saved companion", err)
				}
			} else {
				if delivery != nil || !errors.Is(err, ErrEdit) {
					t.Fatal("saved-candidate recovery admitted a changed source", err)
				}
				marker, markerErr := readMarker(t.Context(), coordinationPath(path, ".enkv-pending"))
				if markerErr != nil || marker.Record != candidate.pending.path() || marker.Digest != candidate.pending.Digest {
					t.Fatal("recovery refusal lost pending ownership", markerErr)
				}
			}
			current, statErr := os.Lstat(path)
			if statErr != nil || !os.SameFile(info, current) || readSource(t, path) != body {
				t.Fatal("saved-candidate recovery replaced the surviving source", statErr)
			}
			if readSource(t, generated) != sourceGeneratedJSON+"\n" {
				t.Fatal("saved-candidate recovery removed or changed the installed companion")
			}
		})
	}
}
