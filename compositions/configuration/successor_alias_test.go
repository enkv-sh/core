package configuration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

// full_only: false
func TestSuccessorOutputParentAlias(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, changed := range []bool{false, true} {
			name := "absent"
			if existing {
				name = "existing"
			}
			if changed {
				name += "-changed-alias"
			}
			t.Run(name, func(t *testing.T) {
				source, _, request, material := successorFileFixture(t, JSON)
				directory := t.TempDir()
				canonical := filepath.Join(directory, "successor.json")
				var original []byte
				if existing {
					output, err := PrepareSuccessorOutput(t.Context(), source, canonical, request)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := output.Publish(t.Context(), material); err != nil {
						t.Fatal(err)
					}
					if err := output.Close(); err != nil {
						t.Fatal(err)
					}
					original, err = os.ReadFile(canonical)
					if err != nil {
						t.Fatal(err)
					}
				}
				alias := filepath.Join(t.TempDir(), "delivery")
				if err := os.Symlink(directory, alias); err != nil {
					t.Fatal(err)
				}
				selected := filepath.Join(alias, filepath.Base(canonical))
				const padding = 1 << 20
				backing := strings.Repeat("x", padding) + selected + strings.Repeat("x", padding)
				input := backing[padding : padding+len(selected)]
				output, err := PrepareSuccessorOutput(t.Context(), source, input, request)
				if err != nil {
					t.Fatal("permitted initial parent alias refused", err)
				}
				defer func() {
					if err := output.Close(); err != nil {
						t.Error(err)
					}
				}()
				capture := output.capture.(*SuccessorOutputCapture)
				if capture.aliasParent != filepath.Dir(selected) {
					t.Error("captured output parent differs from selected parent")
				}
				if unsafe.StringData(capture.aliasParent) == unsafe.StringData(input) {
					t.Error("captured output parent retains oversized caller backing")
				}
				for parent := range capture.parent.aliases {
					if unsafe.StringData(parent) == unsafe.StringData(input) {
						t.Error("captured output alias pin retains oversized caller backing")
					}
				}
				if (output.Existing() != nil) != existing {
					t.Fatal("alias changed output branch")
				}
				if err := output.CheckUnchanged(t.Context()); err != nil {
					t.Fatal("unchanged parent alias refused", err)
				}
				if changed {
					other := t.TempDir()
					if err := os.Remove(alias); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(other, alias); err != nil {
						t.Fatal(err)
					}
					if err := output.CheckUnchanged(t.Context()); err == nil {
						t.Fatal("retargeted parent alias accepted")
					}
					if _, err := output.Publish(t.Context(), material); err == nil {
						t.Fatal("retargeted alias allowed publication")
					}
					if _, err := os.Lstat(filepath.Join(other, filepath.Base(canonical))); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("retargeted directory received output", err)
					}
				} else if existing {
					if _, err := output.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
						t.Fatal("existing output acquired publication authority", err)
					}
				} else {
					if _, err := output.Publish(t.Context(), material); err != nil {
						t.Fatal("permitted alias publication failed", err)
					}
					if err := output.CheckUnchanged(t.Context()); err != nil {
						t.Fatal("alias readback pins failed", err)
					}
				}
				if err := output.Close(); err != nil {
					t.Fatal(err)
				}
				if existing {
					actual, err := os.ReadFile(canonical)
					if err != nil || !bytes.Equal(actual, original) {
						t.Fatal("alias observation changed output", err)
					}
				} else if changed {
					if _, err := os.Lstat(canonical); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("changed alias changed canonical output", err)
					}
				}
				if err := source.CheckUnchanged(t.Context()); err != nil {
					t.Fatal("alias changed source", err)
				}
			})
		}
	}
}
