//go:build darwin || linux

package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/telemetry"
)

func reconstructionModel(t *testing.T, name string) *Model {
	t.Helper()
	generated := strings.Replace(sourceGeneratedJSON, `{"kind":"genesis","descriptor":"AQ=="}`, observationBasisJSON, 1)
	model, err := Parse(t.Context(), writePair(t, sourceSetupJSON, generated, JSON))
	if err != nil {
		t.Fatal(err)
	}
	model.DomainName = name
	model.Generated = ".enkv/" + name + ".generated.json"
	return model
}

// full_only: false
func TestReconstructionTelemetryExcludesSourceAndRawFailure(t *testing.T) {
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	path := filepath.Join(t.TempDir(), "configuration")
	output, err := BeginReconstruction(ctx, path, JSON, "recovered")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSourceOwner(t, output) })
	if _, err := output.Stage(ctx, reconstructionModel(t, "recovered")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := output.Capture(ctx); err != nil {
		t.Fatal(err)
	}
	failed, _, _ := stagedReconstruction(t, JSON)
	const privateError = "untrusted-private-native-failure"
	failed.editor.io.phase = func(phase string) error {
		if phase == "generated-installed" {
			return errors.New(privateError)
		}
		return nil
	}
	if _, err := failed.Commit(ctx); err == nil {
		t.Fatal("controlled native failure was not returned")
	}
	closeSourceOwner(t, failed)
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
	successes, unknown := 0, 0
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Operation == telemetry.OpConfigurationWrite && record.Event == telemetry.DiagnosticReturn {
			switch record.Result {
			case telemetry.ResultSuccess:
				successes++
			case telemetry.ResultWriteUnknown:
				unknown++
			}
		}
	}
	if successes != 4 || unknown != 1 {
		t.Fatal("native reconstruction telemetry lost operation completion facts", successes, unknown)
	}
	body, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{path, sourceSigningSelector, sourceEncryptionSPKI, "fixture-bucket", privateError} {
		if bytes.Contains(body, []byte(excluded)) {
			t.Fatal("native telemetry included source content or a raw failure")
		}
	}
}

// full_only: false
func TestReconstructionCaptureRejectsForeignImage(t *testing.T) {
	for _, selected := range []string{"editable", "generated"} {
		for _, content := range []string{"same-bytes", "changed-bytes", "changed-in-place"} {
			t.Run(selected+"/"+content, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "configuration")
				output, err := BeginReconstruction(t.Context(), path, JSON, "recovered")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { closeSourceOwner(t, output) })
				if _, err := output.Stage(t.Context(), reconstructionModel(t, "recovered")); err != nil {
					t.Fatal(err)
				}
				delivery, err := output.Commit(t.Context())
				if err != nil || delivery == nil {
					t.Fatal(err)
				}
				editable, generated := delivery.Paths()
				destination := editable
				if selected == "generated" {
					destination = generated
				}
				originalEditable, originalGenerated := readSource(t, editable), readSource(t, generated)
				original, err := os.Stat(destination)
				if err != nil {
					t.Fatal(err)
				}
				foreign := []byte(readSource(t, destination))
				if content != "same-bytes" {
					foreign = append(foreign, '\n')
				}
				if content == "changed-in-place" {
					if err := os.WriteFile(destination, foreign, 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					temporary := filepath.Join(filepath.Dir(destination), "foreign-image")
					if err := os.WriteFile(temporary, foreign, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(temporary, destination); err != nil {
						t.Fatal(err)
					}
				}
				replacement, err := os.Stat(destination)
				if err != nil || os.SameFile(original, replacement) != (content == "changed-in-place") {
					t.Fatal("foreign change used the wrong native inode", err)
				}
				pair, model, captureErr := output.Capture(t.Context())
				if captureErr == nil || pair != nil || model != nil {
					t.Error("post-delivery capture accepted a foreign image")
				}
				closeSourceOwner(t, output)
				current, err := os.Stat(destination)
				if err != nil || !os.SameFile(replacement, current) || !bytes.Equal([]byte(readSource(t, destination)), foreign) {
					t.Error("refused capture or disposal changed the foreign image", err)
				}
				ed, gd, err := delivery.Digests()
				if err != nil || ed != sha256.Sum256([]byte(originalEditable)) || gd != sha256.Sum256([]byte(originalGenerated)) || delivery.CleanupFailed() {
					t.Error("capture failure erased or changed the original confirmed delivery", err)
				}
				if _, eligible := delivery.RecoverySource(); eligible {
					t.Error("foreign replacement manufactured pending ownership")
				}
			})
		}
	}
}

// The fixed observation bytes establish source grammar and native ownership.
// Authentication is checked by the composition before it commits a staged pair.
// full_only: false
func TestReconstructionPairDelivery(t *testing.T) {
	t.Run("canceled-source-check", func(t *testing.T) {
		output, err := BeginReconstruction(t.Context(), filepath.Join(t.TempDir(), "configuration"), JSON, "recovered")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeSourceOwner(t, output) })
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := output.CheckUnchanged(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("absent source check ignored caller cancellation", err)
		}
	})
	for _, encoding := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[encoding], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "chosen-configuration")
			generated := filepath.Join(filepath.Dir(path), ".enkv/recovered.generated.json")
			output, err := BeginReconstruction(t.Context(), path, encoding, "recovered")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeSourceOwner(t, output) })
			for _, destination := range []string{path, generated} {
				if _, err := os.Lstat(destination); !os.IsNotExist(err) {
					t.Fatal("admission created a visible pair image", err)
				}
			}
			model := reconstructionModel(t, "recovered")
			inputAnchor := model.Basis.SigningAnchor
			inputPage := model.Basis.RecipientPages[0]
			staged, err := output.Stage(t.Context(), model)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*model, Model{}) || !reflect.DeepEqual(inputAnchor, []byte{0, 0, 0}) || !reflect.DeepEqual(inputPage, []byte{0, 0}) {
				t.Fatal("staging retained its consumed model or decoded witness backing")
			}
			if staged.DomainName != "recovered" || staged.Generated != ".enkv/recovered.generated.json" || !reflect.DeepEqual(staged.Basis, observationBasisFixture()) {
				t.Fatal("actual staged pair changed explicit local layout or observation bytes")
			}
			delivery, err := output.Commit(t.Context())
			if err != nil || delivery == nil || delivery.CleanupFailed() {
				t.Fatal("absent pair was not completely delivered", err)
			}
			if !reflect.DeepEqual(*staged, Model{}) {
				t.Fatal("commit retained the borrowed staged model")
			}
			if editablePath, generatedPath := delivery.Paths(); editablePath != path || generatedPath != generated {
				t.Fatal("delivery used the editable filename as the local name")
			}
			if _, eligible := delivery.RecoverySource(); eligible {
				t.Fatal("complete cleanup retained a recovery source")
			}
			editableBody, generatedBody := readSource(t, path), readSource(t, generated)
			wantEditable := reconstructionEditableJSON
			if encoding == YAML {
				wantEditable = reconstructionEditableYAML()
			}
			if editableBody != wantEditable || generatedBody != reconstructionGeneratedLiteral() {
				t.Fatal("complete emitted images differ from independently transcribed literals")
			}
			editableDigest, generatedDigest, err := delivery.Digests()
			if err != nil || editableDigest != sha256.Sum256([]byte(editableBody)) || generatedDigest != sha256.Sum256([]byte(generatedBody)) {
				t.Fatal("delivery readback differs from independently hashed complete images", err)
			}
			for _, destination := range []string{path, generated} {
				info, err := os.Stat(destination)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("delivered pair image is not mode protected", err)
				}
			}
			pair, captured, err := output.Capture(t.Context())
			if err != nil || pair == nil || captured == nil {
				t.Fatal("exact delivered pair was not available under its native owner", err)
			}
			if pair.Format != encoding || pair.Editable.Digest() != editableDigest || pair.Generated.Digest() != generatedDigest || captured.DomainName != "recovered" || captured.Generated != ".enkv/recovered.generated.json" || hex.EncodeToString(captured.FileID[:]) != sourceID1 || hex.EncodeToString(captured.DomainID[:]) != sourceID2 || captured.Authority.SigningSelector != sourceSigningSelector || captured.Authority.EncryptionSelector != sourceEncryptionSelector || !reflect.DeepEqual(captured.Basis, observationBasisFixture()) {
				t.Fatal("captured pair changed delivered identity, layout, keys or witness")
			}
			if err := pair.CheckUnchanged(t.Context()); err != nil {
				t.Fatal("delivered pair lost its exact native source check", err)
			}
			closeSourceOwner(t, output)
			if !reflect.DeepEqual(*captured, Model{}) || pair.validateCaptured() == nil {
				t.Fatal("output disposal retained its captured model or live pair")
			}
		})
	}
}

// full_only: false
func TestReconstructionTemporaryRootSeparators(t *testing.T) {
	for _, suffix := range []string{"", "/", "///"} {
		t.Run("suffix-"+strconv.Itoa(len(suffix)), func(t *testing.T) {
			model := reconstructionModel(t, "recovered")
			root, destination := t.TempDir(), filepath.Join(t.TempDir(), "configuration")
			t.Setenv("TMPDIR", root+suffix)
			output, err := BeginReconstruction(t.Context(), destination, JSON, "recovered")
			if err != nil {
				t.Fatal("permitted temporary root refused reconstruction", err)
			}
			t.Cleanup(func() { closeSourceOwner(t, output) })
			if _, err := output.Stage(t.Context(), model); err != nil {
				t.Fatal(err)
			}
			delivery, err := output.Commit(t.Context())
			if err != nil || delivery == nil || delivery.CleanupFailed() {
				t.Fatal("reconstruction delivery incomplete", err)
			}
			editable, generated := delivery.Paths()
			if editable != destination || readSource(t, editable) != reconstructionEditableJSON || readSource(t, generated) != reconstructionGeneratedLiteral() {
				t.Fatal("reconstruction changed independently transcribed images")
			}
			if _, _, err := output.Capture(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("reconstruction left temporary files", err)
			}
			pair, err := Capture(t.Context(), destination, JSON)
			if err != nil {
				t.Fatal("ordinary next use of reconstructed source refused", err)
			}
			closeSourceOwner(t, pair)
		})
	}
}

// full_only: false
func TestReconstructionRefusesInvalidTemporaryRootsAndDestinationSpellings(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(t.TempDir(), "configuration")
	for _, directory := range []string{"relative", root + "/.", root + "/..", "/" + strings.Repeat("x", 4032), "/" + strings.Repeat("x", 4096)} {
		t.Run("temporary-"+strconv.Itoa(len(directory)), func(t *testing.T) {
			t.Setenv("TMPDIR", directory)
			output, err := BeginReconstruction(t.Context(), destination, JSON, "recovered")
			if output != nil {
				closeSourceOwner(t, output)
			}
			if output != nil || !errors.Is(err, ErrEditBounds) {
				t.Fatal("invalid reconstruction temporary root accepted", err)
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused reconstruction created its destination", err)
			}
		})
	}
	for _, path := range []string{destination + "/", filepath.Dir(destination) + "/./configuration", filepath.Dir(destination) + "/../" + filepath.Base(filepath.Dir(destination)) + "/configuration"} {
		output, err := BeginReconstruction(t.Context(), path, JSON, "recovered")
		if output != nil {
			closeSourceOwner(t, output)
		}
		if output != nil || !errors.Is(err, ErrEdit) {
			t.Fatal("unclean reconstruction destination accepted", err)
		}
	}
}
