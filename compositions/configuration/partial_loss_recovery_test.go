//go:build darwin || linux

package configuration

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func companionReconstructionSource(t *testing.T, format Format, parent bool) (string, string, string, os.FileInfo) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "surviving")
	body := reconstructionEditableJSON + "\n"
	if format == YAML {
		body = "# keep surviving source comment\n" + reconstructionEditableYAML()
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(filepath.Dir(path), ".enkv/recovered.generated.json")
	if parent {
		if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, generated, body, info
}

// full_only: false
func TestCompanionMissingInputsSurviveSavedRecovery(t *testing.T) {
	for _, stop := range []string{"before-generated-install", "generated-installed"} {
		t.Run(stop, func(t *testing.T) {
			path, generated, original, info := companionReconstructionSource(t, YAML, false)
			entries := `{"":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}},"sibling":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}}`
			original = strings.Replace(original, `entries: {}`, `entries: `+entries, 1)
			if !strings.Contains(original, entries) {
				t.Fatal("missing-input fixture did not change its entry declaration")
			}
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeSourceOwner(t, output) })
			// This shape-only current model exercises saved native bytes. It is
			// not authenticated domain evidence and authorizes no remote effect.
			merged, err := MergeReconstructedCompanion(t.Context(), source, reconstructionModel(t, "recovered"))
			if err != nil {
				t.Fatal("missing declarations prevented reconstruction staging", err)
			}
			if _, err := output.Stage(t.Context(), merged); err != nil {
				t.Fatal("precise incomplete candidate did not stage", err)
			}
			candidate := output.editor.candidate
			wantGenerated := readSource(t, candidate.generatedTemp)
			if wantGenerated != reconstructionGeneratedLiteral() {
				t.Fatal("missing inputs acquired fabricated companion records")
			}
			fault := errors.New("controlled incomplete companion interruption")
			output.editor.io.phase = func(phase string) error {
				if phase == stop {
					return fault
				}
				return nil
			}
			_, err = output.Commit(t.Context())
			var unknown *UnknownEdit
			if !errors.Is(err, fault) || !errors.As(err, &unknown) || !candidate.durable {
				t.Fatal("incomplete candidate did not preserve durable pending ownership", err)
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, output)
			delivery, err := RecoverEdit(t.Context(), path, YAML)
			if err != nil || delivery == nil {
				t.Fatal("local recovery refused the exact saved incomplete candidate", err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(info, after) || readSource(t, path) != original || readSource(t, generated) != wantGenerated {
				t.Fatal("local recovery changed surviving source or regenerated companion bytes", err)
			}
			pair, err := Capture(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeSourceOwner(t, pair) })
			if _, err := Parse(t.Context(), pair); err == nil {
				t.Fatal("saved recovery made incomplete input ordinary operation ready")
			}
			model, err := ParseForSet(t.Context(), pair, "")
			if err != nil || len(model.Entries) != 2 || model.SelectedSecretPresent {
				t.Fatal("saved recovery lost precise missing declarations", err)
			}
			defer releaseReconstructionModel(model)
			for _, entry := range model.Entries {
				if !entry.Secret || entry.Generated != nil || entry.Retained != nil || len(entry.Sealed) != 0 {
					t.Fatal("saved recovery invented missing input content")
				}
			}
		})
	}
}

// full_only: false
func TestCompanionReconstructionInstallsOnlyAbsentCompanion(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		for _, parent := range []bool{false, true} {
			name := map[Format]string{JSON: "json", YAML: "yaml"}[format]
			if parent {
				name += "/existing-parent"
			} else {
				name += "/absent-parent"
			}
			t.Run(name, func(t *testing.T) {
				path, generated, original, info := companionReconstructionSource(t, format, parent)
				output, source, err := BeginCompanionReconstruction(t.Context(), path, format)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
				if source.Resolved || !source.FileID.IsZero() || !source.DomainID.IsZero() || source.Generated != ".enkv/recovered.generated.json" || source.Authority.SigningSelector != sourceSigningSelector {
					t.Fatal("source capture invented recovered identity or changed layout")
				}
				installs, sourceWrites, replacements := 0, 0, 0
				install, replace := output.editor.io.installAbsent, output.editor.io.replace
				output.editor.io.installAbsent = func(from, to string) error {
					if to == generated {
						installs++
					}
					if to == path {
						sourceWrites++
					}
					return install(from, to)
				}
				output.editor.io.replace = func(from, to string) error {
					if to == generated {
						replacements++
					}
					if to == path {
						sourceWrites++
					}
					return replace(from, to)
				}
				if _, err := output.Stage(t.Context(), reconstructionModel(t, "recovered")); err != nil {
					t.Fatal(err)
				}
				if readSource(t, output.editor.candidate.editableTemp) != original {
					t.Fatal("source candidate was emitted instead of copied exactly")
				}
				delivery, err := output.Commit(t.Context())
				if err != nil || delivery == nil || installs != 1 || replacements != 0 || sourceWrites != 0 {
					t.Fatal("companion reconstruction changed native installation scope", installs, replacements, sourceWrites, err)
				}
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(info, after) || readSource(t, path) != original || readSource(t, generated) != reconstructionGeneratedLiteral() {
					t.Fatal("companion delivery changed exact source or saved generated bytes", err)
				}
				if _, _, err := output.Capture(t.Context()); err != nil {
					t.Fatal("recorded companion delivery could not be captured", err)
				}
			})
		}
	}
}

// full_only: false
func TestCompanionReconstructionPreservesConcurrentCompanion(t *testing.T) {
	for _, at := range []string{"before-install", "native-install"} {
		t.Run(at, func(t *testing.T) {
			path, generated, original, info := companionReconstructionSource(t, YAML, false)
			output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
			if _, err := output.Stage(t.Context(), reconstructionModel(t, "recovered")); err != nil {
				t.Fatal(err)
			}
			candidate := output.editor.candidate
			body := readSource(t, candidate.generatedTemp)
			var foreign os.FileInfo
			create := func() {
				t.Helper()
				if err := os.WriteFile(generated, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				foreign, err = os.Lstat(generated)
				if err != nil {
					t.Fatal(err)
				}
			}
			output.editor.io.phase = func(phase string) error {
				if at == "before-install" && phase == "before-generated-install" {
					create()
				}
				return nil
			}
			install := output.editor.io.installAbsent
			output.editor.io.installAbsent = func(from, to string) error {
				if at == "native-install" && to == generated {
					create()
				}
				return install(from, to)
			}
			delivery, err := output.Commit(t.Context())
			if delivery != nil || err == nil || !errors.Is(err, ErrPendingEdit) || foreign == nil || !candidate.durable {
				t.Fatal("concurrent equal-byte companion lost exact pending ownership", err)
			}
			after, statErr := os.Lstat(path)
			current, generatedErr := os.Lstat(generated)
			if statErr != nil || generatedErr != nil || !os.SameFile(info, after) || !os.SameFile(foreign, current) || readSource(t, path) != original || readSource(t, generated) != body {
				t.Fatal("refusal changed surviving source or foreign companion", statErr, generatedErr)
			}
			if marker, err := readMarker(t.Context(), coordinationPath(path, ".enkv-pending")); err != nil || marker.Record != candidate.pending.path() || marker.Digest != candidate.pending.Digest {
				t.Fatal("refusal lost its exact saved candidate", err)
			}
			if body != reconstructionGeneratedLiteral() {
				t.Fatal("race did not use independent expected candidate bytes")
			}
		})
	}
}

// full_only: false
func TestCompanionReconstructionRefusesUnsafeAndPendingPaths(t *testing.T) {
	for _, condition := range []string{"companion-file", "companion-directory", "companion-link", "parent-link", "parent-file", "source-marker", "companion-marker", "pending-directory-link"} {
		t.Run(condition, func(t *testing.T) {
			path, generated, original, info := companionReconstructionSource(t, YAML, false)
			foreign := filepath.Join(t.TempDir(), "foreign")
			const foreignBody = "foreign file must remain exact"
			if err := os.WriteFile(foreign, []byte(foreignBody), 0600); err != nil {
				t.Fatal(err)
			}
			occupied := ""
			switch condition {
			case "parent-link":
				if err := os.Symlink(t.TempDir(), filepath.Dir(generated)); err != nil {
					t.Fatal(err)
				}
			case "parent-file":
				occupied = filepath.Dir(generated)
			case "companion-file":
				occupied = generated
			case "companion-directory", "companion-link":
				if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
					t.Fatal(err)
				}
				if condition == "companion-link" {
					if err := os.Symlink(foreign, generated); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(generated, 0700); err != nil {
					t.Fatal(err)
				}
			case "source-marker":
				occupied = coordinationPath(path, ".enkv-pending")
			case "companion-marker":
				occupied = coordinationPath(generated, ".enkv-pending")
			case "pending-directory-link":
				if err := os.Symlink(t.TempDir(), filepath.Join(filepath.Dir(path), ".enkv-pending")); err != nil {
					t.Fatal(err)
				}
			}
			if occupied != "" {
				if err := os.MkdirAll(filepath.Dir(occupied), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(occupied, []byte(foreignBody), 0600); err != nil {
					t.Fatal(err)
				}
			}
			output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if output != nil {
				closeSourceOwner(t, output)
			}
			if output != nil || source != nil || err == nil {
				t.Fatal("unsafe, pending or occupied companion path selected recovery", err)
			}
			if (condition == "source-marker" || condition == "companion-marker") && !errors.Is(err, ErrPendingEdit) {
				t.Fatal("pending ownership lost its recovery meaning", err)
			}
			after, statErr := os.Lstat(path)
			if statErr != nil || !os.SameFile(info, after) || readSource(t, path) != original || readSource(t, foreign) != foreignBody || occupied != "" && readSource(t, occupied) != foreignBody {
				t.Fatal("capture refusal changed source or foreign files", statErr)
			}
		})
	}
}

// full_only: false
func TestCompanionReconstructionRefusesChangedSource(t *testing.T) {
	for _, damage := range []string{"content", "identity"} {
		t.Run(damage, func(t *testing.T) {
			path, generated, _, _ := companionReconstructionSource(t, YAML, false)
			output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
			body, info := replaceUnchangedImage(t, path, damage)
			if err := output.CheckUnchanged(t.Context()); !errors.Is(err, ErrSourceChanged) {
				t.Fatal("changed captured source remained admitted", err)
			}
			if staged, err := output.Stage(t.Context(), reconstructionModel(t, "recovered")); staged != nil || !errors.Is(err, ErrSourceChanged) {
				t.Fatal("source change admitted a companion candidate", err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(info, after) || readSource(t, path) != body {
				t.Fatal("refused staging changed foreign source", err)
			}
			if _, err := os.Lstat(generated); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("source change installed a companion", err)
			}
		})
	}
}
