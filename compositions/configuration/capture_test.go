package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// full_only: false
func TestSourceCaptureBoundsAndRefusals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	for _, n := range []int{65536, 65537} {
		body := bytes.Repeat([]byte{'x'}, n)
		if e := os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
		image, e := capture(context.Background(), path, 65536)
		if n == 65537 {
			if e == nil {
				closeSourceOwner(t, image)
				t.Fatal("accepted first excess")
			}
			if !errors.Is(e, ErrSourceInvalid) {
				t.Fatal("known source-size excess lost its positive refusal fact", e)
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		want := sha256.Sum256(body)
		var got bytes.Buffer
		if _, e = image.CopyTo(&got); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(got.Bytes(), body) || image.Size() != 65536 || image.Digest() != want {
			t.Fatal("captured bytes/length/digest differs")
		}
		if e = image.Close(); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if image, e := capture(ctx, path, 65537); e == nil {
		closeSourceOwner(t, image)
		t.Fatal("cancelled capture accepted")
	} else if !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation cause lost")
	}
	if p, e := Capture(context.Background(), "relative", JSON); e == nil {
		closeSourceOwner(t, p)
		t.Fatal("relative input accepted")
	}
}

// full_only: false
func TestSourceCaptureRefusesInvalidTemporaryDirectory(t *testing.T) {
	pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	path := pair.Editable.OriginalPath()
	for _, tc := range []struct{ name, directory string }{
		{"relative", "relative"}, {"dot", t.TempDir() + "/."}, {"parent", t.TempDir() + "/.."}, {"path-limit", "/" + strings.Repeat("x", 4096)}, {"temporary-name-limit", "/" + strings.Repeat("x", 4032)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", tc.directory)
			captured, err := Capture(t.Context(), path, JSON)
			if captured != nil {
				if closeErr := captured.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if captured != nil || !errors.Is(err, ErrCapture) {
				t.Fatal("invalid temporary directory reached source acquisition", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedCaptureRestorationDiagnostics(t *testing.T) {
	for _, damage := range []string{"missing", "symlink", "hardlink", "directory", "directory-symlink"} {
		t.Run(damage, func(t *testing.T) {
			dir := t.TempDir()
			ref := ".enkv/prod.generated.json"
			editable := strings.TrimSuffix(sourceSetupJSON, "}") + `,"generated":"` + ref + `"}`
			path := filepath.Join(dir, "config")
			if e := os.WriteFile(path, []byte(editable), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); e != nil {
				t.Fatal(e)
			}
			generatedPath := filepath.Join(dir, ref)
			switch damage {
			case "hardlink":
				target := filepath.Join(dir, "target")
				if e := os.WriteFile(target, []byte(sourceGeneratedJSON), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Link(target, generatedPath); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(generatedPath, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				target := filepath.Join(dir, "target")
				if e := os.WriteFile(target, []byte(sourceGeneratedJSON), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(target, generatedPath); e != nil {
					t.Fatal(e)
				}
			case "directory-symlink":
				if e := os.Remove(filepath.Join(dir, ".enkv")); e != nil {
					t.Fatal(e)
				}
				target := t.TempDir()
				if e := os.WriteFile(filepath.Join(target, filepath.Base(ref)), []byte(sourceGeneratedJSON), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(target, filepath.Join(dir, ".enkv")); e != nil {
					t.Fatal(e)
				}
			}
			p, e := Capture(context.Background(), path, JSON)
			if e == nil {
				closeSourceOwner(t, p)
				t.Fatal("damaged generated input accepted")
			}
			var d *Diagnostic
			if !errors.As(e, &d) || d.Field != "generated" {
				t.Fatalf("missing safe generated-field diagnosis: %v", e)
			}
			if damage == "missing" && !errors.Is(e, os.ErrNotExist) {
				t.Fatal("missing dependency cause lost")
			}
			if damage != "missing" && !errors.Is(e, ErrSourceInvalid) {
				t.Fatal("known native generated shape lost its positive refusal fact", e)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, []byte(editable)) {
				t.Fatal("capture changed editable source")
			}
		})
	}
}

// full_only: false
func TestSourceCaptureMissingImageFactExcludesTemporaryFailures(t *testing.T) {
	for _, condition := range []string{"editable-missing", "editable-parent-missing", "generated-missing", "generated-parent-missing", "temporary-directory-missing", "temporary-path-is-file"} {
		t.Run(condition, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "configuration.json")
			generated := filepath.Join(dir, ".enkv", "prod.generated.json")
			editable := strings.TrimSuffix(sourceSetupJSON, "}") + `,"generated":".enkv/prod.generated.json"}`
			if condition != "editable-missing" {
				if err := os.WriteFile(path, []byte(editable), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if condition != "generated-parent-missing" {
				if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
					t.Fatal(err)
				}
				if condition != "generated-missing" {
					if err := os.WriteFile(generated, []byte(sourceGeneratedJSON), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if condition == "temporary-directory-missing" {
				t.Setenv("TMPDIR", filepath.Join(dir, "absent-temporary-directory"))
			}
			if condition == "temporary-path-is-file" {
				t.Setenv("TMPDIR", path)
			}
			if condition == "editable-parent-missing" {
				path = filepath.Join(dir, "absent-parent", "configuration.json")
			}
			pair, err := Capture(t.Context(), path, JSON)
			if pair != nil {
				closeSourceOwner(t, pair)
			}
			wantMissing := condition == "editable-missing" || condition == "generated-missing" || condition == "generated-parent-missing"
			if pair != nil || err == nil || errors.Is(err, ErrSourceImageMissing) != wantMissing {
				t.Fatal("capture confused a selected missing image with unavailable temporary storage", condition, err)
			}
			if wantMissing && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("exact missing-image cause was discarded")
			}
			if condition == "temporary-directory-missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("temporary-storage ENOENT control did not reach its intended failure")
			}
			if condition == "editable-parent-missing" || condition == "temporary-directory-missing" || condition == "temporary-path-is-file" {
				if errors.Is(err, ErrSourceInvalid) {
					t.Fatal("unknown source or temporary-storage premise became a positive invalid-source fact", condition, err)
				}
			}
			if condition == "editable-parent-missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("selected-parent stat failure lost its original cause", err)
			}
			if condition == "generated-missing" || condition == "generated-parent-missing" {
				var diagnostic *Diagnostic
				if !errors.As(err, &diagnostic) || diagnostic.Field != "generated" || diagnostic.Reason != "restore-exact-generated-file" {
					t.Fatal("typed fact changed the existing generated diagnostic", err)
				}
			}
		})
	}
}

// full_only: true
func TestPairAggregateCapacity(t *testing.T) {
	dir := t.TempDir()
	ref := ".enkv/prod.generated.json"
	editable := strings.TrimSuffix(sourceSetupJSON, "}") + `,"generated":"` + ref + `"}`
	if e := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, ref), []byte(sourceGeneratedJSON), 0400); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "config")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = io.WriteString(f, editable); e != nil {
		t.Fatal(e)
	}
	target := MaxPairBytes - int64(len(sourceGeneratedJSON))
	padding := bytes.Repeat([]byte{' '}, WindowBytes)
	for remaining := target - int64(len(editable)); remaining > 0; {
		n := min(remaining, int64(len(padding)))
		written, e := f.Write(padding[:n])
		if e != nil || int64(written) != n {
			t.Fatal("padding write failed")
		}
		remaining -= n
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	pair, e := Capture(context.Background(), path, JSON)
	if e != nil {
		t.Fatal(e)
	}
	if pair.Editable.Size()+pair.Generated.Size() != 268435456 {
		t.Fatal("aggregate exact capacity not exercised")
	}
	if _, e = Parse(context.Background(), pair); e != nil {
		closeSourceOwner(t, pair)
		t.Fatal(e)
	}
	if e = pair.Close(); e != nil {
		t.Fatal(e)
	}
	f, e = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, writeErr := f.Write([]byte{' '})
	closeErr := f.Close()
	if e = errors.Join(writeErr, closeErr); e != nil {
		t.Fatal(e)
	}
	if pair, e = Capture(context.Background(), path, JSON); e == nil {
		closeSourceOwner(t, pair)
		t.Fatal("aggregate first excess admitted")
	}
}

// full_only: false
func TestSourceCaptureAcceptsTemporaryRootSeparators(t *testing.T) {
	for _, suffix := range []string{"", "/", "///"} {
		t.Run("suffix-"+strconv.Itoa(len(suffix)), func(t *testing.T) {
			fixture := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
			path := fixture.Editable.OriginalPath()
			root := t.TempDir()
			t.Setenv("TMPDIR", root+suffix)
			pair, err := Capture(t.Context(), path, JSON)
			if err != nil {
				t.Fatal("permitted temporary root refused capture", err)
			}
			for _, row := range []struct {
				image *Image
				body  string
			}{
				{pair.Editable, strings.TrimSuffix(sourceSetupJSON, "}") + `,"generated":".enkv/prod.generated.json"}`},
				{pair.Generated, sourceGeneratedJSON},
			} {
				var got bytes.Buffer
				if _, err := row.image.CopyTo(&got); err != nil || got.String() != row.body || row.image.Digest() != sha256.Sum256([]byte(row.body)) {
					t.Error("temporary-root spelling changed captured bytes or digest", err)
				}
			}
			if err := pair.Close(); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("capture left temporary files", err)
			}
			next, err := Capture(t.Context(), path, JSON)
			if err != nil {
				t.Fatal("ordinary next capture refused", err)
			}
			closeSourceOwner(t, next)
		})
	}
}
