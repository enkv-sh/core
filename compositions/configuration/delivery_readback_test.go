//go:build darwin || linux

package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func interruptedReadback(t *testing.T, unknown *UnknownEdit) *PairDelivery {
	t.Helper()
	reader, ok := any(unknown).(interface{ Readback() (*PairDelivery, bool) })
	if !ok {
		t.Error("interrupted edit does not retain native readback")
		return nil
	}
	delivery, valid := reader.Readback()
	if !valid || delivery == nil {
		t.Error("confirmed pair readback was discarded")
		return nil
	}
	return delivery
}

// full_only: false
func TestCompletedPairRetainsSnapshotCleanupFailure(t *testing.T) {
	for _, kind := range []string{"reconstruction", "successor", "maintenance"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configuration")
			var editor *EditSession
			var operations *editIO
			var owner io.Closer
			var commit func() (*PairDelivery, error)
			switch kind {
			case "reconstruction":
				output, err := BeginReconstruction(t.Context(), path, JSON, "recovered")
				if err != nil {
					t.Fatal(err)
				}
				owner, editor, operations = output, output.editor, &output.editor.io
				if _, err := output.Stage(t.Context(), reconstructionModel(t, "recovered")); err != nil {
					t.Fatal(err)
				}
				commit = func() (*PairDelivery, error) { return output.Commit(t.Context()) }
			case "successor":
				pair, _, request, material := successorFileFixture(t, JSON)
				output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
				if err != nil {
					t.Fatal(err)
				}
				owner, editor, operations = output, output.editor, &output.io
				commit = func() (*PairDelivery, error) {
					_, err := output.Publish(t.Context(), material)
					return output.LocalDelivery(), err
				}
			case "maintenance":
				pair, request, material := maintenanceFileFixture(t, JSON, contract.OperationRetireRecipientIdentity)
				output, err := PrepareMaintenanceOutput(t.Context(), pair, path, request)
				if err != nil {
					t.Fatal(err)
				}
				owner, editor, operations = output, output.editor, &output.io
				commit = func() (*PairDelivery, error) {
					_, err := output.Publish(t.Context(), material)
					return output.LocalDelivery(), err
				}
			}
			t.Cleanup(func() { closeSourceOwner(t, owner) })
			injected := false
			operations.phase = func(phase string) error {
				if phase == "record-cleaned" {
					if err := editor.candidate.pair.Editable.file.Close(); err != nil {
						return err
					}
					injected = true
				}
				return nil
			}
			delivery, err := commit()
			if !injected || !errors.Is(err, os.ErrClosed) || delivery == nil {
				t.Fatal("post-delivery snapshot close failure was not established", err)
			}
			_, generated := delivery.Paths()
			assertNativeDelivery(t, delivery, path, generated, false)
			if source, eligible := delivery.RecoverySource(); eligible || source != "" {
				t.Fatal("completed transaction cleanup manufactured a recovery source")
			}
		})
	}
}

func assertNativeDelivery(t *testing.T, delivery *PairDelivery, path, generated string, pending bool) {
	t.Helper()
	if delivery == nil {
		return
	}
	editablePath, generatedPath := delivery.Paths()
	if editablePath != path || generatedPath != generated || !delivery.CleanupFailed() {
		t.Error("native delivery lost its exact paths or cleanup failure")
	}
	editable, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dependency, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	ed, gd, err := delivery.Digests()
	if err != nil || ed != sha256.Sum256(editable) || gd != sha256.Sum256(dependency) {
		t.Error("native readback differs from independently hashed visible pair", err)
	}
	if source, eligible := delivery.RecoverySource(); eligible != pending || eligible && source != path {
		t.Error("native readback has incorrect recovery eligibility")
	}
}

// full_only: false
func TestInterruptedEditRetainsNativeReadback(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		for _, phase := range []string{"verified-record-write", "pair-verified", "staging-cleaned", "markers-cleared", "record-cleaned"} {
			t.Run(fmt.Sprintf("format-%d/%s", encoding, phase), func(t *testing.T) {
				session, path := beginSourceEdit(t, encoding, true)
				generated := session.Pair().Generated.OriginalPath()
				candidate, want := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
				fault := errors.New("controlled native cleanup failure")
				native := session.io
				injected := false
				session.io.phase = func(at string) error {
					if at == phase {
						injected = true
						return fault
					}
					return nil
				}
				session.io.replace = func(from, to string) error {
					if phase == "verified-record-write" && session.transaction != nil && session.transaction.Phase == "verified" && to == session.transaction.path() {
						injected = true
						return fault
					}
					return native.replace(from, to)
				}
				delivery, err := session.Commit(t.Context(), candidate)
				session.io = native
				var unknown *UnknownEdit
				isUnknown := errors.As(err, &unknown)
				if isUnknown {
					t.Cleanup(func() { closeSourceOwner(t, unknown.Observation) })
				}
				if delivery == nil || !injected || !errors.Is(err, fault) || !isUnknown {
					t.Fatal("native readback cleanup interruption was not established", err)
				}
				closeSourceOwner(t, unknown.Observation)
				closeSourceOwner(t, session)
				retained := interruptedReadback(t, unknown)
				pending := phase == "verified-record-write" || phase == "pair-verified" || phase == "staging-cleaned"
				assertNativeDelivery(t, retained, path, generated, pending)
				if readSource(t, path) != want || readSource(t, generated) != sourceGeneratedJSON+"\n" {
					t.Fatal("interruption changed the exact delivered candidate")
				}
				if pending {
					if source, eligible := unknown.RecoverySource(); !eligible || source != path {
						t.Error("interrupted result lost the remaining exact source marker")
					}
					if _, err := RecoverEdit(t.Context(), path, encoding); err != nil {
						t.Fatal(err)
					}
					if readSource(t, path) != want || readSource(t, generated) != sourceGeneratedJSON+"\n" {
						t.Error("recovery changed the exact saved candidate")
					}
				}
			})
		}
	}
	for _, unknown := range []*UnknownEdit{nil, {}, {Observation: &EditObservation{editable: "fabricated"}}} {
		if reader, ok := any(unknown).(interface{ Readback() (*PairDelivery, bool) }); ok {
			if delivery, valid := reader.Readback(); valid || delivery != nil {
				t.Error("unissued edit manufactured native readback")
			}
		}
	}
	for _, failure := range []string{"generated-installed", "editable-readback", "directory-sync"} {
		t.Run("before-complete-readback/"+failure, func(t *testing.T) {
			session, path := beginSourceEdit(t, JSON, true)
			candidate, _ := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			fault := errors.New("controlled interruption before readback")
			native := session.io
			injected, editableInstalled := false, false
			session.io.phase = func(at string) error {
				if at == "editable-installed" {
					editableInstalled = true
				}
				if failure == "generated-installed" && at == failure {
					injected = true
					return fault
				}
				return nil
			}
			session.io.readback = func(ctx context.Context, destination string, image *Image, predecessor bool) error {
				if failure == "editable-readback" && destination == path {
					injected = true
					return fault
				}
				return native.readback(ctx, destination, image, predecessor)
			}
			session.io.syncDir = func(directory string) error {
				if failure == "directory-sync" && editableInstalled {
					injected = true
					return fault
				}
				return native.syncDir(directory)
			}
			delivery, err := session.Commit(t.Context(), candidate)
			session.io = native
			var unknown *UnknownEdit
			if delivery != nil || !injected || !errors.Is(err, fault) || !errors.As(err, &unknown) {
				t.Fatal("pre-readback interruption was not established", err)
			}
			if reader, ok := any(unknown).(interface{ Readback() (*PairDelivery, bool) }); ok {
				if delivery, valid := reader.Readback(); valid || delivery != nil {
					t.Error("unconfirmed pair manufactured native readback")
				}
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, session)
		})
	}
}

// full_only: false
func TestSuccessorRetainsNativeReadbackWithoutQualifiedDelivery(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		for _, phase := range []string{"staging-cleaned", "markers-cleared"} {
			t.Run(fmt.Sprintf("format-%d/%s", encoding, phase), func(t *testing.T) {
				source, model, request, material := successorFileFixture(t, encoding)
				path := filepath.Join(t.TempDir(), "successor")
				output, err := PrepareSuccessorOutput(t.Context(), source, path, request)
				if err != nil {
					t.Fatal(err)
				}
				fault := errors.New("controlled successor cleanup failure")
				output.io.phase = func(at string) error {
					if at == phase {
						return fault
					}
					return nil
				}
				readback, err := output.Publish(t.Context(), material)
				if readback != nil || !errors.Is(err, fault) || output.Delivered() {
					t.Fatal("cleanup interruption became qualified successor delivery", err)
				}
				if _, err := output.OutputIdentity(); !errors.Is(err, ErrEdit) {
					t.Error("native readback granted qualified output identity", err)
				}
				closeSourceOwner(t, output)
				reader, ok := any(output).(interface{ LocalDelivery() *PairDelivery })
				if !ok {
					t.Error("successor discarded its native delivery receipt")
				} else {
					delivery := reader.LocalDelivery()
					if delivery == nil {
						t.Error("successor lost confirmed native readback after disposal")
					}
					assertNativeDelivery(t, delivery, path, filepath.Join(filepath.Dir(path), generatedPath(model.DomainName)), phase == "staging-cleaned")
				}
				if phase == "staging-cleaned" {
					if _, err := RecoverEdit(t.Context(), path, encoding); err != nil {
						t.Fatal(err)
					}
				}
				observed, err := PrepareSuccessorOutput(t.Context(), source, path, request)
				if err != nil {
					t.Fatal(err)
				}
				closeSourceOwner(t, observed)
			})
		}
	}
}

// full_only: false
func TestInitializationCleanupRetainsReadbackWithoutArtifactReceipt(t *testing.T) {
	for _, phase := range []string{"staging-cleaned", "markers-cleared"} {
		t.Run(phase, func(t *testing.T) {
			descriptor, body := nativeDescriptor(t)
			generated := strings.Replace(sourceGeneratedJSON, `"descriptor":"AQ=="`, `"descriptor":"`+base64.StdEncoding.EncodeToString(body)+`"`, 1)
			session, path := beginSourceEdit(t, JSON, false)
			candidate, _ := stageSourceEdit(t, session, generated)
			generatedPath := candidate.pair.Generated.OriginalPath()
			fault := errors.New("controlled initialization cleanup failure")
			session.io.phase = func(at string) error {
				if at == phase {
					return fault
				}
				return nil
			}
			receipt, err := session.CommitInitialization(t.Context(), candidate, descriptor.DescriptorArtifactID, uint64(len(body)), nativeArtifactID(string(body)))
			var unknown *UnknownEdit
			if receipt != nil || !errors.Is(err, fault) || !errors.As(err, &unknown) {
				t.Fatal("native cleanup granted an initialization artifact receipt", err)
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, session)
			assertNativeDelivery(t, interruptedReadback(t, unknown), path, generatedPath, phase == "staging-cleaned")
			if phase == "staging-cleaned" {
				if _, err := RecoverEdit(t.Context(), path, JSON); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
