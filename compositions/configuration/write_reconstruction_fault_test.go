//go:build darwin || linux

package configuration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func stagedReconstruction(t *testing.T, format Format) (*ReconstructionOutput, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "configuration")
	output, err := BeginReconstruction(t.Context(), path, format, "recovered")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSourceOwner(t, output) })
	if _, err := output.Stage(t.Context(), reconstructionModel(t, "recovered")); err != nil {
		t.Fatal(err)
	}
	candidate := output.editor.candidate
	return output, readSource(t, candidate.editableTemp), readSource(t, candidate.generatedTemp)
}

// full_only: false
func TestReconstructionPairAdmission(t *testing.T) {
	for _, condition := range []string{"editable", "satellite", "source-marker", "satellite-marker", "editable-link", "satellite-directory-link", "lock-link", "pending-directory-link", "transaction-directory-link", "satellite-parent-file", "missing-parent", "permission"} {
		t.Run(condition, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "configuration")
			foreign := filepath.Join(t.TempDir(), "foreign")
			const body = "foreign bytes must remain"
			if err := os.WriteFile(foreign, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			occupied := ""
			switch condition {
			case "editable":
				occupied = path
			case "satellite":
				occupied = filepath.Join(directory, ".enkv/recovered.generated.json")
			case "source-marker":
				occupied = coordinationPath(path, ".enkv-pending")
			case "satellite-marker":
				occupied = coordinationPath(filepath.Join(directory, ".enkv/recovered.generated.json"), ".enkv-pending")
			case "editable-link":
				if err := os.Symlink(foreign, path); err != nil {
					t.Fatal(err)
				}
			case "satellite-directory-link", "pending-directory-link", "transaction-directory-link":
				name := map[string]string{"satellite-directory-link": ".enkv", "pending-directory-link": ".enkv-pending", "transaction-directory-link": ".enkv-transactions"}[condition]
				if err := os.Symlink(t.TempDir(), filepath.Join(directory, name)); err != nil {
					t.Fatal(err)
				}
			case "lock-link":
				if err := os.Mkdir(filepath.Join(directory, ".enkv-locks"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(foreign, coordinationPath(path, ".enkv-locks")); err != nil {
					t.Fatal(err)
				}
			case "satellite-parent-file":
				occupied = filepath.Join(directory, ".enkv")
			case "missing-parent":
				path = filepath.Join(directory, "missing", "configuration")
			case "permission":
				if err := os.Chmod(directory, 0500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(directory, 0700); err != nil {
						t.Error(err)
					}
				})
			}
			if occupied != "" {
				if err := os.MkdirAll(filepath.Dir(occupied), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(occupied, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			output, err := BeginReconstruction(t.Context(), path, JSON, "recovered")
			if output != nil {
				closeSourceOwner(t, output)
			}
			if output != nil || err == nil {
				t.Fatal("unsafe or occupied destination admitted", err)
			}
			if readSource(t, foreign) != body || occupied != "" && readSource(t, occupied) != body {
				t.Fatal("admission refusal changed foreign bytes")
			}
			if condition == "source-marker" || condition == "satellite-marker" {
				if !errors.Is(err, ErrPendingEdit) {
					t.Fatal("pending state lost its explicit recovery meaning", err)
				}
			}
		})
	}
}

// full_only: false
func TestReconstructionLocksAndDirectoryIdentity(t *testing.T) {
	for _, condition := range []string{"live-owner", "source-parent", "satellite-parent", "pending-directory", "parent-alias"} {
		t.Run(condition, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "configuration")
			alias := filepath.Join(root, "alias")
			if condition == "parent-alias" {
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, "configuration")
			}
			output, err := BeginReconstruction(t.Context(), path, JSON, "recovered")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeSourceOwner(t, output) })
			if condition == "live-owner" {
				other, err := BeginReconstruction(t.Context(), path, YAML, "recovered")
				if other != nil {
					closeSourceOwner(t, other)
				}
				if other != nil || !errors.Is(err, ErrEditLocked) {
					t.Fatal("competing reconstruction did not respect both native locks", err)
				}
				return
			}
			if condition == "parent-alias" {
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), alias); err != nil {
					t.Fatal(err)
				}
			} else {
				directory := parent
				switch condition {
				case "satellite-parent":
					directory = filepath.Join(parent, ".enkv")
				case "pending-directory":
					directory = filepath.Join(parent, ".enkv-pending")
				}
				if err := os.Rename(directory, directory+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := output.CheckUnchanged(t.Context()); err == nil {
				t.Fatal("changed admitted directory or alias remained current")
			}
			if staged, err := output.Stage(t.Context(), reconstructionModel(t, "recovered")); staged != nil || err == nil {
				t.Fatal("changed directory identity allowed staging", err)
			}
		})
	}
}

// full_only: false
func TestReconstructionStageRefusesInvalidModelAndReleasesInput(t *testing.T) {
	for _, condition := range []string{"unresolved", "name", "reference", "genesis", "mixed", "missing-head", "empty-page", "canceled", "write-failure"} {
		t.Run(condition, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configuration")
			output, err := BeginReconstruction(t.Context(), path, JSON, "recovered")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeSourceOwner(t, output) })
			model := reconstructionModel(t, "recovered")
			ctx := t.Context()
			fault := errors.New("controlled staging failure")
			switch condition {
			case "unresolved":
				model.Resolved = false
			case "name":
				model.DomainName = "other"
			case "reference":
				model.Generated = ".enkv/other.generated.json"
			case "genesis":
				model.Basis = Basis{Descriptor: []byte{1}}
			case "mixed":
				model.Basis.Descriptor = []byte{1}
			case "missing-head":
				model.Basis.HEAD = nil
			case "empty-page":
				model.Basis.RecipientPages[0] = nil
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "write-failure":
				output.editor.io.write = func(*os.File, []byte) (int, error) { return 0, fault }
			}
			staged, err := output.Stage(ctx, model)
			if err == nil || staged != nil || !reflect.DeepEqual(*model, Model{}) {
				t.Fatal("invalid staging returned a model or retained consumed input", err)
			}
			if condition == "write-failure" && !errors.Is(err, fault) {
				t.Fatal("staging discarded its write failure", err)
			}
			if delivery, err := output.Commit(t.Context()); delivery != nil || err == nil {
				t.Fatal("failed staging allowed delivery", err)
			}
			closeSourceOwner(t, output)
			for _, destination := range []string{path, filepath.Join(filepath.Dir(path), ".enkv/recovered.generated.json"), coordinationPath(path, ".enkv-pending")} {
				if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed staging published an image or recovery marker", err)
				}
			}
			for _, directory := range []string{filepath.Dir(path), filepath.Join(filepath.Dir(path), ".enkv")} {
				for _, pattern := range []string{".enkv-editable-*", ".enkv-generated-*"} {
					paths, err := filepath.Glob(filepath.Join(directory, pattern))
					if err != nil || len(paths) != 0 {
						t.Fatal("failed staging retained private candidate images", paths, err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestReconstructionPairCreationRace(t *testing.T) {
	for _, selected := range []string{"editable", "satellite"} {
		for _, at := range []string{"before-commit", "before-generated-install", "before-editable-install", "install"} {
			if selected == "satellite" && at == "before-editable-install" {
				continue
			}
			for _, content := range []string{"foreign", "same-bytes"} {
				t.Run(selected+"/"+at+"/"+content, func(t *testing.T) {
					output, editable, satellite := stagedReconstruction(t, JSON)
					candidate := output.editor.candidate
					path := output.editor.path
					destination, body := path, editable
					if selected == "satellite" {
						destination, body = candidate.pair.Generated.path, satellite
					}
					if content == "foreign" {
						body = "foreign race winner"
					}
					var winner os.FileInfo
					create := func() error {
						if err := os.WriteFile(destination, []byte(body), 0600); err != nil {
							return err
						}
						var err error
						winner, err = os.Stat(destination)
						return err
					}
					switch at {
					case "before-commit":
						if err := create(); err != nil {
							t.Fatal(err)
						}
					case "install":
						native := output.editor.io.installAbsent
						output.editor.io.installAbsent = func(from, to string) error {
							if to == destination {
								if err := create(); err != nil {
									return err
								}
							}
							return native(from, to)
						}
					default:
						output.editor.io.phase = func(phase string) error {
							if phase == at && winner == nil {
								return create()
							}
							return nil
						}
					}
					delivery, err := output.Commit(t.Context())
					if delivery != nil || err == nil || winner == nil {
						t.Fatal("concurrent destination creation did not refuse delivery", err)
					}
					closeSourceOwner(t, output)
					current, err := os.Stat(destination)
					if err != nil || !os.SameFile(winner, current) || readSource(t, destination) != body {
						t.Fatal("delivery or disposal changed the foreign race winner", err)
					}
					if recovered, err := RecoverEdit(t.Context(), path, JSON); recovered != nil || err == nil {
						t.Fatal("recovery accepted a foreign race winner", err)
					}
					if readSource(t, destination) != body {
						t.Fatal("refused recovery changed the race winner")
					}
				})
			}
		}
	}
}

// full_only: false
func TestReconstructionPairFaultRecovery(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		for _, phase := range []string{"before-candidate-flush", "candidate-flushed", "before-record", "record-durable", "marker-durable", "markers-durable", "before-generated-install", "generated-installed", "before-editable-install", "editable-installed", "pair-verified", "staging-cleaned", "markers-cleared", "record-cleaned"} {
			t.Run(fmt.Sprintf("format-%d/%s", encoding, phase), func(t *testing.T) {
				output, wantEditable, wantGenerated := stagedReconstruction(t, encoding)
				path := output.editor.path
				generated := output.editor.candidate.pair.Generated.path
				fault := errors.New("controlled reconstruction interruption")
				injected := false
				output.editor.io.phase = func(at string) error {
					if at == phase {
						injected = true
						return fault
					}
					return nil
				}
				delivery, err := output.Commit(t.Context())
				if !injected || !errors.Is(err, fault) {
					t.Fatal("selected interruption was not established", err)
				}
				verified := phase == "pair-verified" || phase == "staging-cleaned" || phase == "markers-cleared" || phase == "record-cleaned"
				private := phase == "before-candidate-flush" || phase == "candidate-flushed" || phase == "before-record"
				pending := !private && phase != "markers-cleared" && phase != "record-cleaned"
				if (delivery != nil) != verified {
					t.Fatal("interruption reported incorrect confirmed delivery", err)
				}
				var unknown *UnknownEdit
				if errors.As(err, &unknown) != !private {
					t.Fatal("interruption transferred incorrect pending ownership", err)
				}
				if unknown != nil {
					if source, eligible := unknown.RecoverySource(); eligible != pending || eligible && source != path {
						t.Error("interruption has incorrect exact recovery identity")
					}
				}
				if verified {
					assertNativeDelivery(t, delivery, path, generated, pending)
				}
				closeSourceOwner(t, output)
				if pending {
					if pair, err := Capture(t.Context(), path, encoding); pair != nil || !errors.Is(err, ErrPendingEdit) {
						t.Fatal("ordinary capture admitted a pending reconstruction", err)
					}
					if delivery, err := RecoverEdit(t.Context(), path, encoding); delivery == nil || err != nil {
						t.Fatal("explicit recovery could not finish the saved candidate", err)
					}
				}
				if !private {
					if readSource(t, path) != wantEditable || readSource(t, generated) != wantGenerated {
						t.Fatal("disposal or recovery changed the saved candidate")
					}
				} else {
					for _, destination := range []string{path, generated} {
						if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
							t.Fatal("private failure installed a visible candidate", err)
						}
					}
				}
				if delivery, err := RecoverEdit(t.Context(), path, encoding); delivery != nil || err == nil {
					t.Fatal("recovery replayed without a source marker", err)
				}
			})
		}
	}
}

// full_only: false
func TestReconstructionNativeFaultOwnership(t *testing.T) {
	for _, failure := range []string{"candidate-sync", "candidate-close", "source-marker-refused", "source-marker-response-lost", "source-marker-sync", "satellite-marker-refused", "generated-install", "generated-install-response-lost", "editable-install", "generated-directory-sync", "editable-readback", "candidate-remove", "source-marker-remove", "record-remove"} {
		t.Run(failure, func(t *testing.T) {
			output, wantEditable, wantGenerated := stagedReconstruction(t, JSON)
			editor, candidate := output.editor, output.editor.candidate
			path, generated := editor.path, candidate.pair.Generated.path
			sourceMarker := coordinationPath(path, ".enkv-pending")
			satelliteMarker := coordinationPath(generated, ".enkv-pending")
			fault := errors.New("controlled native reconstruction failure")
			native := editor.io
			injected, sourceInstalled, generatedInstalled := false, false, false
			editor.io.syncFile = func(file *os.File) error {
				if failure == "candidate-sync" && file.Name() == candidate.generatedTemp {
					injected = true
					return fault
				}
				return native.syncFile(file)
			}
			editor.io.close = func(file *os.File) error {
				if failure == "candidate-close" && file.Name() == candidate.generatedTemp {
					injected = true
					return errors.Join(native.close(file), fault)
				}
				return native.close(file)
			}
			editor.io.installAbsent = func(from, to string) error {
				if failure == "source-marker-refused" && to == sourceMarker || failure == "satellite-marker-refused" && to == satelliteMarker || failure == "generated-install" && to == generated || failure == "editable-install" && to == path {
					injected = true
					return fault
				}
				if err := native.installAbsent(from, to); err != nil {
					return err
				}
				sourceInstalled = sourceInstalled || to == sourceMarker
				generatedInstalled = generatedInstalled || to == generated
				if failure == "source-marker-response-lost" && to == sourceMarker || failure == "generated-install-response-lost" && to == generated {
					injected = true
					return fault
				}
				return nil
			}
			editor.io.syncDir = func(directory string) error {
				if failure == "source-marker-sync" && sourceInstalled && directory == filepath.Dir(sourceMarker) || failure == "generated-directory-sync" && generatedInstalled && directory == filepath.Dir(generated) {
					injected = true
					return fault
				}
				return native.syncDir(directory)
			}
			editor.io.readback = func(ctx context.Context, destination string, image *Image, old bool) error {
				if failure == "editable-readback" && destination == path {
					injected = true
					return fault
				}
				return native.readback(ctx, destination, image, old)
			}
			editor.io.remove = func(destination string) error {
				if failure == "candidate-remove" && destination == candidate.generatedTemp || failure == "source-marker-remove" && destination == sourceMarker || failure == "record-remove" && editor.transaction != nil && destination == editor.transaction.path() {
					injected = true
					return fault
				}
				return native.remove(destination)
			}
			delivery, err := output.Commit(t.Context())
			editor.io = native
			if !injected || !errors.Is(err, fault) {
				t.Fatal("native fault did not reach its intended boundary", err)
			}
			private := failure == "candidate-sync" || failure == "candidate-close" || failure == "source-marker-refused"
			verified := failure == "candidate-remove" || failure == "source-marker-remove" || failure == "record-remove"
			pending := !private && failure != "record-remove"
			var unknown *UnknownEdit
			if errors.As(err, &unknown) != !private || (delivery != nil) != verified {
				t.Fatal("native failure reported incorrect delivery or pending ownership", err)
			}
			if unknown != nil {
				if source, eligible := unknown.RecoverySource(); eligible != pending || eligible && source != path {
					t.Error("native fault changed confirmed source marker eligibility")
				}
			}
			if verified {
				assertNativeDelivery(t, delivery, path, generated, pending)
			}
			closeSourceOwner(t, output)
			if pending {
				if delivered, err := RecoverEdit(t.Context(), path, JSON); delivered == nil || err != nil {
					t.Fatal("native failure lost its exact saved candidate", err)
				}
			}
			if !private {
				if readSource(t, path) != wantEditable || readSource(t, generated) != wantGenerated {
					t.Fatal("native failure recovery changed the staged candidate")
				}
			} else {
				for _, destination := range []string{path, generated, sourceMarker} {
					if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("private failure published visible or pending state", err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestReconstructionRecoveryRefusesChangedSavedCandidate(t *testing.T) {
	for _, condition := range []string{"editable-altered", "generated-missing", "visible-conflict", "foreign-marker"} {
		t.Run(condition, func(t *testing.T) {
			output, wantEditable, wantGenerated := stagedReconstruction(t, JSON)
			editor, candidate := output.editor, output.editor.candidate
			path, generated := editor.path, candidate.pair.Generated.path
			fault := errors.New("controlled published reconstruction")
			editor.io.phase = func(phase string) error {
				if phase == "record-durable" {
					return fault
				}
				return nil
			}
			_, err := output.Commit(t.Context())
			var unknown *UnknownEdit
			if !errors.As(err, &unknown) || !errors.Is(err, fault) {
				t.Fatal("published reconstruction was not established", err)
			}
			closeSourceOwner(t, output)
			if readSource(t, candidate.editableTemp) != wantEditable || readSource(t, candidate.generatedTemp) != wantGenerated {
				t.Fatal("output disposal changed the pending saved images")
			}
			const foreign = "foreign bytes remain"
			foreignPath := ""
			switch condition {
			case "editable-altered":
				foreignPath = candidate.editableTemp
			case "generated-missing":
				if err := os.Remove(candidate.generatedTemp); err != nil {
					t.Fatal(err)
				}
			case "visible-conflict":
				foreignPath = generated
			case "foreign-marker":
				foreignPath = coordinationPath(generated, ".enkv-pending")
			}
			if foreignPath != "" {
				if err := os.WriteFile(foreignPath, []byte(foreign), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if delivery, err := RecoverEdit(t.Context(), path, JSON); delivery != nil || err == nil {
				t.Fatal("changed required recovery state was accepted", err)
			}
			if foreignPath != "" && readSource(t, foreignPath) != foreign {
				t.Fatal("refused recovery changed foreign state")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused recovery installed an editable image", err)
			}
			if source, eligible := unknown.RecoverySource(); !eligible || source != path {
				t.Fatal("disposal or refused recovery erased established pending facts")
			}
		})
	}
}

// full_only: false
func TestReconstructionUncertainMarkerSurvivesDisposal(t *testing.T) {
	for _, condition := range []string{"canceled-after-install", "unreadable-marker"} {
		t.Run(condition, func(t *testing.T) {
			output, wantEditable, wantGenerated := stagedReconstruction(t, JSON)
			editor, candidate := output.editor, output.editor.candidate
			path := editor.path
			markerPath := coordinationPath(path, ".enkv-pending")
			fault := errors.New("controlled uncertain marker response")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			native := editor.io.installAbsent
			injected := false
			editor.io.installAbsent = func(from, to string) error {
				if err := native(from, to); err != nil {
					return err
				}
				if to != markerPath {
					return nil
				}
				injected = true
				if condition == "canceled-after-install" {
					cancel()
				} else if err := os.WriteFile(markerPath, []byte("foreign malformed marker"), 0600); err != nil {
					return errors.Join(fault, err)
				}
				return fault
			}
			delivery, err := output.Commit(ctx)
			var unknown *UnknownEdit
			if delivery != nil || !injected || !errors.Is(err, fault) || !errors.Is(err, ErrPendingEdit) || !errors.As(err, &unknown) {
				t.Fatal("uncertain publication did not retain pending ownership", err)
			}
			confirmed := condition == "canceled-after-install"
			if source, eligible := unknown.RecoverySource(); eligible != confirmed || eligible && source != path {
				t.Fatal("uncertain publication has incorrect marker confirmation")
			}
			closeSourceOwner(t, output)
			closeSourceOwner(t, unknown.Observation)
			if readSource(t, candidate.editableTemp) != wantEditable || readSource(t, candidate.generatedTemp) != wantGenerated {
				t.Fatal("result disposal lost uncertain saved-candidate ownership")
			}
			for _, image := range []*Image{candidate.pair.Editable, candidate.pair.Generated} {
				if image.file != nil {
					t.Fatal("result disposal retained a candidate descriptor")
				}
			}
			recovered, err := RecoverEdit(t.Context(), path, JSON)
			if confirmed {
				if recovered == nil || err != nil || readSource(t, path) != wantEditable || readSource(t, candidate.pair.Generated.path) != wantGenerated {
					t.Fatal("confirmed marker could not recover its exact candidate", err)
				}
			} else if recovered != nil || err == nil || readSource(t, markerPath) != "foreign malformed marker" {
				t.Fatal("unconfirmed marker granted recovery or lost foreign bytes", err)
			}
		})
	}
}
