package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/telemetry"
)

func beginSourceEdit(t *testing.T, format Format, resolved bool) (*EditSession, string) {
	t.Helper()
	setup := sourceSetupJSON
	if format == YAML {
		setup = sourceSetupYAML
	}
	generated := ""
	if resolved {
		generated = sourceGeneratedJSON
	}
	p := writePair(t, setup, generated, format)
	path := p.Editable.OriginalPath()
	s, err := BeginEdit(context.Background(), path, format)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, path
}

func stageSourceEdit(t *testing.T, s *EditSession, generated string) (*EditCandidate, string) {
	t.Helper()
	original, err := io.ReadAll(io.NewSectionReader(s.Pair().Editable, 0, s.Pair().Editable.Size()))
	if err != nil {
		t.Fatal(err)
	}
	var emit func(io.Writer) error
	if generated != "" {
		emit = func(w io.Writer) error { _, err := io.WriteString(w, generated); return err }
	}
	want := ""
	c, m, err := s.Stage(context.Background(), emit, func(w io.Writer, reference string) error {
		var edits []Edit
		if s.Pair().Format == JSON {
			offset := bytes.Index(original, []byte(`"display_name":""`)) + int(len(`"display_name":`))
			edits = append(edits, Edit{Offset: int64(offset), Length: 2, Replacement: []byte(`"changed"`)})
			if s.Pair().Generated == nil && reference != "" {
				edits = append(edits, Edit{Offset: int64(len(original) - 1), Replacement: []byte(`,"generated":"` + reference + `"`)})
			} else if s.Pair().Generated != nil {
				previous := filepath.ToSlash(filepath.Join(".enkv", filepath.Base(s.Pair().Generated.path)))
				offset := bytes.Index(original, []byte(previous))
				edits = append(edits, Edit{Offset: int64(offset), Length: int64(len(previous)), Replacement: []byte(reference)})
			}
			want = strings.Replace(string(original), `"display_name":""`, `"display_name":"changed"`, 1)
			if s.Pair().Generated == nil && reference != "" {
				want = strings.TrimSuffix(want, "}") + `,"generated":"` + reference + `"}`
			} else if s.Pair().Generated != nil {
				previous := filepath.ToSlash(filepath.Join(".enkv", filepath.Base(s.Pair().Generated.path)))
				want = strings.Replace(want, previous, reference, 1)
			}
		} else {
			offset := bytes.Index(original, []byte("display_name: ''")) + int(len("display_name: "))
			edits = append(edits, Edit{Offset: int64(offset), Length: 2, Replacement: []byte("'changed'")})
			if s.Pair().Generated == nil && reference != "" {
				edits = append(edits, Edit{Offset: int64(len(original)), Replacement: []byte("generated: '" + reference + "'\n")})
			} else if s.Pair().Generated != nil {
				previous := filepath.ToSlash(filepath.Join(".enkv", filepath.Base(s.Pair().Generated.path)))
				offset := bytes.Index(original, []byte(previous))
				edits = append(edits, Edit{Offset: int64(offset), Length: int64(len(previous)), Replacement: []byte(reference)})
			}
			want = strings.Replace(string(original), "display_name: ''", "display_name: 'changed'", 1)
			if s.Pair().Generated == nil && reference != "" {
				want += "generated: '" + reference + "'\n"
			} else if s.Pair().Generated != nil {
				previous := filepath.ToSlash(filepath.Join(".enkv", filepath.Base(s.Pair().Generated.path)))
				want = strings.Replace(want, previous, reference, 1)
			}
		}
		return CopyEdits(context.Background(), w, s.Pair().Editable, edits)
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Authority.DisplayName != "changed" {
		t.Fatal("candidate semantic change missing")
	}
	return c, want
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// full_only: false
func TestEditTransaction(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format], func(t *testing.T) {
			setup := sourceSetupJSON
			if format == YAML {
				setup = sourceSetupYAML
			}
			fixture := writePair(t, setup, "", format)
			path := fixture.Editable.OriginalPath()
			const padding = 1 << 20
			backing := strings.Repeat("x", padding) + path + strings.Repeat("x", padding)
			input := backing[padding : padding+len(path)]
			s, err := BeginEdit(t.Context(), input, format)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			if s.Pair().aliasParent != filepath.Dir(path) {
				t.Error("captured edit parent differs from selected parent")
			}
			if unsafe.StringData(s.Pair().aliasParent) == unsafe.StringData(input) {
				t.Error("captured edit parent retains oversized caller backing")
			}
			for parent := range s.locks.aliases {
				if unsafe.StringData(parent) == unsafe.StringData(input) {
					t.Error("captured edit alias pin retains oversized caller backing")
				}
			}
			c, want := stageSourceEdit(t, s, sourceGeneratedJSON)
			var trace []string
			operations := s.io
			s.io.installAbsent = func(from, to string) error {
				trace = append(trace, "install:"+filepath.Ext(to))
				return operations.installAbsent(from, to)
			}
			s.io.syncDir = func(path string) error {
				trace = append(trace, "sync:"+filepath.Base(path))
				return operations.syncDir(path)
			}
			s.io.replace = func(from, to string) error { trace = append(trace, "replace"); return operations.replace(from, to) }
			d, err := s.Commit(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			editable, generated := d.Paths()
			if editable != path || readSource(t, path) != want || readSource(t, generated) != sourceGeneratedJSON {
				t.Fatal("committed pair differs")
			}
			if filepath.Base(generated) != "prod.generated.json" {
				t.Fatal("generated name is not stable")
			}
			joined := strings.Join(trace, "|")
			if !strings.Contains(joined, "install:.json|sync:.enkv") || strings.Index(joined, "sync:.enkv") > strings.Index(joined, "replace") {
				t.Fatalf("publication order differs: %v", trace)
			}
			if _, err := s.Commit(context.Background(), c); !errors.Is(err, ErrEdit) {
				t.Fatal("replacement can repeat")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(generated); err != nil {
				t.Fatal("cleanup removed installed dependency")
			}
		})
	}
	t.Run("exact-existing-reuse", func(t *testing.T) {
		s, path := beginSourceEdit(t, JSON, true)
		generated := s.Pair().Generated.OriginalPath()
		before, err := os.Stat(generated)
		if err != nil {
			t.Fatal(err)
		}
		c, want := stageSourceEdit(t, s, sourceGeneratedJSON)
		if _, err := s.Commit(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(generated)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || readSource(t, path) != want {
			t.Fatal("identical generated bytes were replaced")
		}
	})
	t.Run("changed-existing-refused", func(t *testing.T) {
		s, path := beginSourceEdit(t, JSON, false)
		original := readSource(t, path)
		c, _ := stageSourceEdit(t, s, sourceGeneratedJSON)
		if err := os.WriteFile(c.pair.Generated.path, []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(context.Background(), c); err == nil {
			t.Fatal("occupied generated destination accepted")
		}
		if readSource(t, path) != original || readSource(t, c.pair.Generated.path) != "changed" {
			t.Fatal("refusal replaced existing bytes")
		}
	})
	t.Run("stable-generated-path-replaced", func(t *testing.T) {
		s, path := beginSourceEdit(t, JSON, true)
		old := s.Pair().Generated.OriginalPath()
		c, want := stageSourceEdit(t, s, sourceGeneratedJSON+"\n")
		d, err := s.Commit(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		_, next := d.Paths()
		if old != next || readSource(t, next) != sourceGeneratedJSON+"\n" || readSource(t, path) != want {
			t.Fatal("stable generated replacement differs")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(old); err != nil {
			t.Fatal("old generated version removed")
		}
	})
	for _, mutation := range []string{"contents", "identity"} {
		t.Run("predecessor-"+mutation, func(t *testing.T) {
			s, path := beginSourceEdit(t, JSON, false)
			original := readSource(t, path)
			c, _ := stageSourceEdit(t, s, sourceGeneratedJSON)
			if mutation == "contents" {
				if err := os.WriteFile(path, []byte(original+" "), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				newPath := path + ".manual"
				if err := os.WriteFile(newPath, []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(newPath, path); err != nil {
					t.Fatal(err)
				}
			}
			want := readSource(t, path)
			if _, err := s.Commit(context.Background(), c); err == nil {
				t.Fatal("changed predecessor accepted")
			}
			if readSource(t, path) != want {
				t.Fatal("predecessor refusal changed source")
			}
			if _, err := os.Stat(c.pair.Generated.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("predecessor refusal published a generated image", err)
			}
		})
	}
}

// full_only: false
func TestEditFailures(t *testing.T) {
	fault := errors.New("injected native failure")
	for _, name := range []string{"generated-sync", "generated-close", "install", "generated-directory", "editable-sync", "editable-close", "replace-refused", "replace-response-lost", "editable-directory", "readback"} {
		t.Run(name, func(t *testing.T) {
			s, path := beginSourceEdit(t, JSON, false)
			original := readSource(t, path)
			c, want := stageSourceEdit(t, s, sourceGeneratedJSON)
			operations := s.io
			syncs, closes, dirs := 0, 0, 0
			editableInstalled := false
			s.io.syncFile = func(f *os.File) error {
				syncs++
				if name == "generated-sync" && syncs == 1 || name == "editable-sync" && syncs == 2 {
					return fault
				}
				return operations.syncFile(f)
			}
			s.io.close = func(f *os.File) error {
				closes++
				err := operations.close(f)
				if name == "generated-close" && closes == 1 || name == "editable-close" && closes == 2 {
					return errors.Join(err, fault)
				}
				return err
			}
			s.io.installAbsent = func(from, to string) error {
				if name == "install" {
					return fault
				}
				return operations.installAbsent(from, to)
			}
			s.io.syncDir = func(path string) error {
				dirs++
				if name == "generated-directory" && dirs == 1 || name == "editable-directory" && editableInstalled && path == filepath.Dir(s.path) {
					return fault
				}
				return operations.syncDir(path)
			}
			s.io.replace = func(from, to string) error {
				if name == "replace-refused" && to == s.path {
					return fault
				}
				err := operations.replace(from, to)
				if to == s.path && err == nil {
					editableInstalled = true
				}
				if name == "replace-response-lost" && to == s.path {
					return errors.Join(err, fault)
				}
				return err
			}
			s.io.readback = func(ctx context.Context, path string, image *Image, predecessor bool) error {
				if name == "readback" && !predecessor && path == s.path {
					return fault
				}
				return operations.readback(ctx, path, image, predecessor)
			}
			_, err := s.Commit(context.Background(), c)
			if !errors.Is(err, fault) {
				t.Fatal("injected native failure lost")
			}
			var unknown *UnknownEdit
			isUnknown := errors.As(err, &unknown)
			wantUnknown := strings.HasPrefix(name, "replace-") || name == "editable-directory" || name == "readback"
			if isUnknown != wantUnknown {
				t.Fatalf("unknown=%v want=%v", isUnknown, wantUnknown)
			}
			selected := original
			if wantUnknown && name != "replace-refused" {
				selected = want
			}
			if readSource(t, path) != selected {
				t.Fatal("failure reported wrong selected bytes")
			}
			if isUnknown {
				paths := unknown.Observation.Paths()
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				for _, path := range paths {
					if path != "" {
						if _, err := os.Stat(path); err != nil {
							t.Fatal("unknown observation removed by session cleanup")
						}
					}
				}
				if err := unknown.Observation.Close(); err != nil {
					t.Fatal(err)
				}
				if readSource(t, path) != selected {
					t.Fatal("observation cleanup restored source")
				}
				if _, err := os.Stat(c.pair.Generated.path); err != nil {
					t.Fatal("observation cleanup removed installed generated bytes")
				}
			}
		})
	}
	t.Run("write", func(t *testing.T) {
		s, path := beginSourceEdit(t, JSON, false)
		original := readSource(t, path)
		s.io.write = func(*os.File, []byte) (int, error) { return 0, fault }
		_, _, err := s.Stage(context.Background(), func(w io.Writer) error { _, err := io.WriteString(w, sourceGeneratedJSON); return err }, func(io.Writer, string) error { return nil })
		if !errors.Is(err, fault) || readSource(t, path) != original {
			t.Fatal("failed candidate write changed source")
		}
	})
	t.Run("cancel-before-commit", func(t *testing.T) {
		s, path := beginSourceEdit(t, JSON, false)
		original := readSource(t, path)
		c, _ := stageSourceEdit(t, s, sourceGeneratedJSON)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.Commit(ctx, c); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled commit admitted")
		}
		if readSource(t, path) != original {
			t.Fatal("cancelled commit changed source")
		}
	})
}

// full_only: false
func TestEditTelemetryExcludesSourceAndRawFailure(t *testing.T) {
	s, _ := beginSourceEdit(t, JSON, false)
	c, _ := stageSourceEdit(t, s, sourceGeneratedJSON)
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	if _, err := s.Commit(ctx, c); err != nil {
		t.Fatal(err)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8))
	if len(records) != 4 {
		t.Fatalf("wrong writer record count %d", len(records))
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Operation != telemetry.OpConfigurationWrite {
			t.Fatal("wrong telemetry owner")
		}
	}
	if records[1].Stage != telemetry.DiagnosticCandidatePersistence || records[2].Stage != telemetry.DiagnosticCommitObservation || records[3].Result != telemetry.ResultSuccess {
		t.Fatal("native stage/result order differs")
	}
	s2, _ := beginSourceEdit(t, JSON, false)
	c2, _ := stageSourceEdit(t, s2, sourceGeneratedJSON)
	const unsafeError = "untrusted-private-input-must-never-be-recorded"
	operations := s2.io
	s2.io.readback = func(ctx context.Context, path string, image *Image, predecessor bool) error {
		if !predecessor {
			return errors.New(unsafeError)
		}
		return operations.readback(ctx, path, image, predecessor)
	}
	_, err := s2.Commit(ctx, c2)
	var unknown *UnknownEdit
	if !errors.As(err, &unknown) {
		t.Fatal("unknown replacement missing")
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unknown.Observation.Close(); err != nil {
		t.Fatal(err)
	}
	records = append(records, recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8))...)
	body, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{sourceSigningSelector, sourceEncryptionSPKI, unsafeError, "fixture-bucket"} {
		if bytes.Contains(body, []byte(excluded)) {
			t.Fatal("source or raw failure entered telemetry")
		}
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

// full_only: false
func TestEditCandidateBounds(t *testing.T) {
	s := &EditSession{io: nativeEditIO()}
	image, err := s.emit(context.Background(), t.TempDir(), "candidate-*", 2, func(w io.Writer) error { _, err := io.WriteString(w, "ab"); return err })
	if err != nil || image.Size() != 2 {
		t.Fatal("exact candidate bound refused", err)
	}
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	image, err = s.emit(context.Background(), dir, "candidate-*", 2, func(w io.Writer) error { _, _ = io.WriteString(w, "abc"); _, _ = io.WriteString(w, "ab"); return nil })
	if image != nil || !errors.Is(err, ErrEditBounds) {
		t.Fatal("ignored writer error accepted")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("failed bounded emission left private files")
	}
}

// full_only: false
func TestEditReusedDependencyPersistence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "sync-before-reference"
		if fail {
			name = "sync-failure-preserves-predecessor"
		}
		t.Run(name, func(t *testing.T) {
			s, path := beginSourceEdit(t, JSON, true)
			original := readSource(t, path)
			c, want := stageSourceEdit(t, s, "")
			generated := s.Pair().Generated.OriginalPath()
			operations := s.io
			var trace []string
			fault := errors.New("existing dependency sync failed")
			s.io.syncFile = func(f *os.File) error {
				if f.Name() == c.generatedTemp {
					trace = append(trace, "dependency-sync")
					if fail {
						return fault
					}
				}
				return operations.syncFile(f)
			}
			s.io.syncDir = func(dir string) error {
				if dir == filepath.Dir(generated) {
					trace = append(trace, "dependency-directory-sync")
				}
				return operations.syncDir(dir)
			}
			s.io.replace = func(from, to string) error { trace = append(trace, "replace"); return operations.replace(from, to) }
			_, err := s.Commit(context.Background(), c)
			if fail {
				if !errors.Is(err, fault) || readSource(t, path) != original {
					t.Fatal("existing generated sync failure did not preserve predecessor")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if len(trace) < 3 || trace[0] != "dependency-sync" || trace[1] != "dependency-directory-sync" || readSource(t, path) != want {
					t.Fatalf("reused dependency persistence order differs: %v", trace)
				}
			}
		})
	}
}

func closeSourceOwner(t testing.TB, owner io.Closer) {
	t.Helper()
	if err := owner.Close(); err != nil {
		t.Error("source owner cleanup failed", err)
	}
}

// full_only: false
func TestEditTemporaryRootSeparatorsPreserveDeliveryAndSource(t *testing.T) {
	for _, output := range []bool{false, true} {
		for _, suffix := range []string{"", "/", "///"} {
			t.Run(fmt.Sprintf("separate-%t/suffix-%d", output, len(suffix)), func(t *testing.T) {
				fixture := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
				source := fixture.Editable.OriginalPath()
				before := readSource(t, source)
				generatedBefore := readSource(t, fixture.Generated.OriginalPath())
				root, outputDirectory := t.TempDir(), t.TempDir()
				t.Setenv("TMPDIR", root+suffix)
				target := source
				var session *EditSession
				var err error
				if output {
					target = filepath.Join(outputDirectory, "configuration")
					session, err = beginPairOutput(t.Context(), fixture, target, JSON, "prod")
				} else {
					session, err = BeginEdit(t.Context(), source, JSON)
				}
				if err != nil {
					t.Fatal("permitted temporary root refused edit admission", err)
				}
				t.Cleanup(func() { closeSourceOwner(t, session) })
				candidate, want := stageSourceEdit(t, session, sourceGeneratedJSON)
				delivery, err := session.Commit(t.Context(), candidate)
				if err != nil || delivery == nil || delivery.CleanupFailed() {
					t.Fatal("edit did not deliver and clean up", err)
				}
				editable, generated := delivery.Paths()
				if editable != target || readSource(t, editable) != want || readSource(t, generated) != sourceGeneratedJSON {
					t.Fatal("edit changed exact delivered images")
				}
				if _, ok := delivery.RecoverySource(); ok {
					t.Fatal("completed edit retained pending recovery")
				}
				if err := session.Close(); err != nil {
					t.Fatal(err)
				}
				if output && (readSource(t, source) != before || readSource(t, fixture.Generated.OriginalPath()) != generatedBefore) {
					t.Fatal("separate output changed borrowed source")
				}
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 0 {
					t.Fatal("edit left temporary files", err)
				}
				pair, err := Capture(t.Context(), target, JSON)
				if err != nil {
					t.Fatal("ordinary next source capture refused", err)
				}
				closeSourceOwner(t, pair)
			})
		}
	}
}

// full_only: false
func TestEditRefusesInvalidTemporaryRootsAndDestinationSpellings(t *testing.T) {
	fixture := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	source := fixture.Editable.OriginalPath()
	root := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "configuration")
	for _, directory := range []string{"relative", root + "/.", root + "/..", "/" + strings.Repeat("x", 4032), "/" + strings.Repeat("x", 4096)} {
		t.Run("temporary-"+strconv.Itoa(len(directory)), func(t *testing.T) {
			t.Setenv("TMPDIR", directory)
			session, err := BeginEdit(t.Context(), source, JSON)
			if session != nil {
				closeSourceOwner(t, session)
			}
			if session != nil || !errors.Is(err, ErrEditBounds) {
				t.Fatal("invalid temporary root accepted", err)
			}
			session, err = beginPairOutput(t.Context(), fixture, outputPath, JSON, "prod")
			if session != nil {
				closeSourceOwner(t, session)
			}
			if session != nil || !errors.Is(err, ErrEditBounds) {
				t.Fatal("invalid temporary root accepted for separate output", err)
			}
		})
	}
	for _, path := range []string{source + "/", filepath.Dir(source) + "/./config", filepath.Dir(source) + "/../" + filepath.Base(filepath.Dir(source)) + "/config"} {
		if session, err := BeginEdit(t.Context(), path, JSON); err == nil || session != nil {
			closeSourceOwner(t, session)
			t.Fatal("unclean source path accepted")
		}
		if session, err := beginPairOutput(t.Context(), fixture, path, JSON, "prod"); err == nil || session != nil {
			closeSourceOwner(t, session)
			t.Fatal("unclean output path accepted")
		}
	}
}
