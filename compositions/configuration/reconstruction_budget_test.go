//go:build darwin || linux

package configuration

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// full_only: false
func TestReconstructionCandidateWriterUsesRequestedBytes(t *testing.T) {
	if len(reconstructionEditableJSON) == len(reconstructionEditableYAML()) {
		t.Fatal("format control needs distinct independently specified lengths")
	}
	for _, selected := range []struct {
		name         string
		format       Format
		copyOriginal bool
	}{
		{"json", JSON, false},
		{"yaml", YAML, false},
		{"original-yaml", YAML, true},
	} {
		t.Run(selected.name, func(t *testing.T) {
			model := reconstructionModel(t, "recovered")
			t.Cleanup(func() { releaseReconstructionModel(model) })
			expected := reconstructionEditableJSON
			if selected.format == YAML {
				expected = reconstructionEditableYAML()
			}
			emit := func(w io.Writer) error { return EmitEditable(w, model, selected.format) }
			if selected.copyOriginal {
				path, _, original, _ := companionReconstructionSource(t, YAML, false)
				output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
				expected = original
				emit = func(w io.Writer) error { _, err := output.editor.predecessor.Editable.CopyTo(w); return err }
			}
			var companion bytes.Buffer
			if err := EmitGenerated(&companion, model); err != nil {
				t.Fatal(err)
			}
			if companion.String() != reconstructionGeneratedLiteral() {
				t.Fatal("small companion changed independently specified bytes")
			}
			for _, excess := range []int64{0, 1} {
				t.Run(map[int64]string{0: "exact-fit", 1: "one-byte-over"}[excess], func(t *testing.T) {
					// Account for a prior charge by reducing the remaining
					// allowance. No prior large image is allocated here.
					priorCharge := MaxPairBytes - int64(len(expected)) + excess
					remaining := MaxPairBytes - priorCharge
					var body bytes.Buffer
					image := &Image{}
					digest := sha256.New()
					writer := &candidateWriter{ctx: t.Context(), remaining: remaining, image: image, hash: digest, writer: &body}
					err := emit(writer)
					if excess != 0 {
						if !errors.Is(err, ErrEditBounds) || !errors.Is(writer.err, ErrEditBounds) || int64(body.Len()) > remaining || writer.remaining < 0 || image.size != int64(body.Len()) {
							t.Fatal("requested writer exceeded its remaining byte allowance", err, body.Len(), remaining)
						}
						return
					}
					wantDigest := sha256.Sum256([]byte(expected))
					if err != nil || body.String() != expected || image.size != remaining || writer.remaining != 0 || !bytes.Equal(digest.Sum(nil), wantDigest[:]) {
						t.Fatal("exact requested bytes did not fit remaining allowance", err)
					}
					directory := t.TempDir()
					path := filepath.Join(directory, "recovered")
					generated := filepath.Join(directory, ".enkv", "recovered.generated.json")
					if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, body.Bytes(), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(generated, companion.Bytes(), 0600); err != nil {
						t.Fatal(err)
					}
					pair, err := Capture(t.Context(), path, selected.format)
					if err != nil {
						t.Fatal("fresh requested pair capture refused", err)
					}
					t.Cleanup(func() {
						if err := pair.Close(); err != nil {
							t.Error(err)
						}
					})
					parsed, err := Parse(t.Context(), pair)
					if err != nil || parsed.DomainName != "recovered" || parsed.Generated != ".enkv/recovered.generated.json" || !reflect.DeepEqual(parsed.Basis, observationBasisFixture()) {
						t.Fatal("fresh requested pair lost its exact local basis", err)
					}
					if err := pair.CheckUnchanged(t.Context()); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestReconstructionFormatsShareOneRemainingAllowance(t *testing.T) {
	model := reconstructionModel(t, "recovered")
	t.Cleanup(func() { releaseReconstructionModel(model) })
	yamlBytes, jsonBytes := int64(len(reconstructionEditableYAML())), int64(len(reconstructionEditableJSON))
	allowance := (yamlBytes + jsonBytes) / 2
	if yamlBytes >= allowance || allowance >= jsonBytes {
		t.Fatal("independent fixture lengths need YAML below and JSON above one allowance")
	}
	path, _, original, _ := companionReconstructionSource(t, YAML, false)
	output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
	if int64(len(original)) > allowance || original == reconstructionEditableYAML() {
		t.Fatal("commented source copy must fit the same allowance")
	}
	priorCharge := MaxPairBytes - allowance
	for _, selected := range []struct {
		name     string
		format   Format
		expected string
		copy     bool
	}{
		{"yaml", YAML, reconstructionEditableYAML(), false},
		{"json", JSON, reconstructionEditableJSON, false},
		{"original-yaml", YAML, original, true},
	} {
		t.Run(selected.name, func(t *testing.T) {
			var body bytes.Buffer
			image := &Image{}
			digest := sha256.New()
			writer := &candidateWriter{ctx: t.Context(), remaining: MaxPairBytes - priorCharge, image: image, hash: digest, writer: &body}
			var err error
			if selected.copy {
				_, err = output.editor.predecessor.Editable.CopyTo(writer)
			} else {
				err = EmitEditable(writer, model, selected.format)
			}
			if selected.format == JSON {
				if !errors.Is(err, ErrEditBounds) || !errors.Is(writer.err, ErrEditBounds) || int64(body.Len()) > allowance || writer.remaining < 0 {
					t.Fatal("larger representation exceeded the shared allowance", err)
				}
				return
			}
			wantDigest := sha256.Sum256([]byte(selected.expected))
			if err != nil || body.String() != selected.expected || image.size != int64(len(selected.expected)) || writer.remaining != allowance-image.size || !bytes.Equal(digest.Sum(nil), wantDigest[:]) {
				t.Fatal("fitting requested bytes were refused under the shared allowance", err)
			}
		})
	}
	if readSource(t, path) != original {
		t.Fatal("copying changed the intact original source")
	}
}
