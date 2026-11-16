package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestUnknownEditObservationCloseFailureSurvivesSetAndInitializationRendering(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		for _, failClose := range []bool{false, true} {
			t.Run(fmt.Sprintf("confidential-%t/close-failure-%t", confidential, failClose), func(t *testing.T) {
				source := configurationSetPair(t, "aws", configuration.JSON, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				interrupted := &cancelPendingConfiguration{Context: ctx, cancel: cancel, marker: filepath.Join(filepath.Dir(source.path), ".enkv-pending", filepath.Base(source.path))}
				result, err := newSetResult(confidential, configuration.JSON)
				if err != nil {
					t.Fatal(err)
				}
				_, deliveryErr := setConfiguration(interrupted, source.path, configuration.JSON, "prepared", io.NopCloser(strings.NewReader("local value")), SetOptions{Confidential: confidential}, result)
				var unknown *configuration.UnknownEdit
				if !errors.As(deliveryErr, &unknown) || unknown.Observation == nil {
					t.Fatal("pending edit not established", deliveryErr)
				}
				finishSetFailure(interrupted, result, deliveryErr)
				recovery, eligible := unknown.RecoverySource()
				if !eligible || recovery != source.path {
					t.Fatal("exact recovery source not established")
				}
				if failClose {
					// Close only the private snapshot handle. Image still owns it, so
					// Observation.Close must report its real second-Close error.
					predecessor := reflect.ValueOf(unknown.Observation).Elem().FieldByName("predecessor")
					image := predecessor.Elem().FieldByName("Editable")
					fileField := image.Elem().FieldByName("file")
					if fileField.IsNil() {
						t.Fatal("private snapshot handle absent")
					}
					file := (*os.File)(fileField.UnsafePointer())
					if err := file.Close(); err != nil {
						t.Fatal("controlled snapshot close", err)
					}
				}
				deliveryErr = closeConfigurationDelivery(deliveryErr)
				if failClose && !errors.Is(deliveryErr, os.ErrClosed) {
					t.Fatal("observation Close failure not established", deliveryErr)
				}
				if after, valid := unknown.RecoverySource(); !valid || after != recovery {
					t.Error("observation disposal changed durable recovery")
				}
				check := func(body []byte, renderErr error, human bool) {
					t.Helper()
					if human {
						if renderErr != nil || !bytes.Contains(body, []byte("Local files: pending\n")) || !bytes.Contains(body, []byte(fmt.Sprintf("Recovery source: %q", recovery))) || bytes.Contains(body, []byte("Warning: local cleanup failed")) != failClose {
							t.Error("human cleanup or exact recovery fact was lost", string(body), renderErr)
						}
						return
					}
					var record struct {
						Delivery struct {
							Outcome       string `json:"outcome"`
							Recovery      string `json:"recovery_source"`
							CleanupFailed bool   `json:"cleanup_failed"`
						} `json:"local_delivery"`
					}
					if renderErr != nil || json.Unmarshal(body, &record) != nil || record.Delivery.CleanupFailed != failClose || record.Delivery.Recovery != recovery || record.Delivery.Outcome != "pending" {
						t.Error("local cleanup fact or exact recovery was lost", string(body), renderErr)
					}
				}
				body, renderErr := RenderSetJSON(result, deliveryErr)
				check(body, renderErr, false)
				body, renderErr = RenderSetHuman(result, deliveryErr)
				check(body, renderErr, true)
				initialization, err := NewInitializationRefusal(configuration.JSON)
				if err != nil {
					t.Fatal(err)
				}
				body, renderErr = RenderInitializationJSON(initialization, deliveryErr)
				check(body, renderErr, false)
				body, renderErr = RenderInitializationHuman(initialization, deliveryErr)
				check(body, renderErr, true)
				if _, err := configuration.RecoverEdit(t.Context(), source.path, configuration.JSON); err != nil {
					t.Fatal("exact recovery after observation failure", err)
				}
			})
		}
	}
}

type cancelPendingConfiguration struct {
	context.Context
	cancel context.CancelFunc
	marker string
}

type blockVerifiedCleanup struct {
	context.Context
	marker  string
	mu      sync.Mutex
	blocked bool
	failure error
}

func (c *blockVerifiedCleanup) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.blocked && c.failure == nil {
		body, err := os.ReadFile(c.marker)
		if err == nil {
			var marker struct {
				Record string `json:"record"`
			}
			if err = json.Unmarshal(body, &marker); err == nil {
				body, err = os.ReadFile(marker.Record)
			}
			var record struct {
				Phase string `json:"phase"`
			}
			if err == nil {
				err = json.Unmarshal(body, &record)
			}
			if err == nil && record.Phase == "verified" {
				err = os.Chmod(filepath.Dir(c.marker), 0555)
				c.blocked = err == nil
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			c.failure = err
		}
	}
	return c.Context.Err()
}

// full_only: false
func TestSetReadbackSurvivesPendingCleanup(t *testing.T) {
	for _, encoding := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, confidential := range []bool{false, true} {
			t.Run(fmt.Sprintf("format-%d/confidential-%t", encoding, confidential), func(t *testing.T) {
				source := configurationSetPair(t, "aws", encoding, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				interrupted := &blockVerifiedCleanup{Context: ctx,
					marker: filepath.Join(filepath.Dir(source.path), ".enkv-pending", filepath.Base(source.path))}
				t.Cleanup(func() {
					if err := os.Chmod(filepath.Dir(interrupted.marker), 0700); err != nil {
						t.Error(err)
					}
				})
				result, deliveryErr := SetConfiguration(interrupted, source.path, encoding, "prepared", io.NopCloser(strings.NewReader("local value")), SetOptions{Confidential: confidential})
				if !interrupted.blocked || interrupted.failure != nil || !errors.Is(deliveryErr, configuration.ErrPendingEdit) {
					t.Fatal("verified cleanup interruption was not established", interrupted.failure, deliveryErr)
				}
				if err := os.Chmod(filepath.Dir(interrupted.marker), 0700); err != nil {
					t.Fatal(err)
				}
				if result == nil || result.StateResult != SetSuccess {
					t.Error("cleanup failure discarded confirmed local readback")
				} else if confidential {
					editable, err := os.ReadFile(result.EditablePath)
					if err != nil {
						t.Fatal(err)
					}
					generated, err := os.ReadFile(result.GeneratedPath)
					if err != nil {
						t.Fatal(err)
					}
					if result.Payload == nil || result.Payload.Readback.EditableDigest != contract.ID(sha256.Sum256(editable)) || result.Payload.Readback.GeneratedDigest != contract.ID(sha256.Sum256(generated)) {
						t.Error("cleanup failure lost exact pair readback digests")
					}
				}
				body, err := RenderSetJSON(result, deliveryErr)
				var wire struct {
					Delivery struct {
						Outcome  string `json:"outcome"`
						Recovery string `json:"recovery_source"`
					} `json:"local_delivery"`
				}
				if err != nil || json.Unmarshal(body, &wire) != nil || wire.Delivery.Outcome != "pending" || wire.Delivery.Recovery != source.path || SetExitCode(result, deliveryErr) != 3 {
					t.Error("confirmed readback and pending cleanup were not reported separately", err)
				}
				if _, err := configuration.RecoverEdit(t.Context(), source.path, encoding); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func (c *cancelPendingConfiguration) Err() error {
	if _, err := os.Lstat(c.marker); err == nil {
		c.cancel()
	}
	return c.Context.Err()
}

type cancelBeforePendingMarker struct {
	context.Context
	cancel          context.CancelFunc
	recordDirectory string
	triggered       bool
}

func (c *cancelBeforePendingMarker) Err() error {
	rows, err := os.ReadDir(c.recordDirectory)
	if err == nil {
		for _, row := range rows {
			if !row.IsDir() && strings.HasSuffix(row.Name(), ".json") {
				c.triggered = true
				c.cancel()
				break
			}
		}
	}
	return c.Context.Err()
}

type losePendingSourceMarker struct {
	context.Context
	cancel            context.CancelFunc
	marker            string
	mu                sync.Mutex
	observed, removed bool
	failure           error
	retained          map[string]configurationApplyFileImage
}

func (c *losePendingSourceMarker) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observed || c.failure != nil {
		return c.Context.Err()
	}
	body, err := os.ReadFile(c.marker)
	if errors.Is(err, os.ErrNotExist) {
		return c.Context.Err()
	}
	if err == nil {
		var marker struct{ Record, Digest string }
		err = json.Unmarshal(body, &marker)
		sourceDirectory := filepath.Dir(filepath.Dir(c.marker))
		if err == nil && (len(marker.Digest) != 64 || marker.Record != filepath.Join(sourceDirectory, ".enkv-transactions", marker.Digest+".json")) {
			err = errors.New("source marker does not identify the fixture transaction")
		}
		var recordBody []byte
		if err == nil {
			recordBody, err = os.ReadFile(marker.Record)
		}
		var record struct {
			Digest      string
			Description struct{ Images []struct{ Path string } }
		}
		if err == nil {
			err = json.Unmarshal(recordBody, &record)
		}
		if err == nil && (record.Digest != marker.Digest || len(record.Description.Images) == 0) {
			err = errors.New("source marker lacks its exact saved candidate")
		}
		if err == nil {
			c.retained = make(map[string]configurationApplyFileImage, len(record.Description.Images)+1)
			paths := []string{marker.Record}
			for _, image := range record.Description.Images {
				paths = append(paths, image.Path)
			}
			for _, path := range paths {
				body, readErr := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if readErr != nil || statErr != nil {
					err = errors.Join(readErr, statErr)
					break
				}
				c.retained[path] = configurationApplyFileImage{Mode: info.Mode(), Body: body}
			}
		}
		if err == nil {
			c.observed = true
			err = os.Remove(c.marker)
			c.removed = err == nil
		}
	}
	c.failure = err
	c.cancel()
	return c.Context.Err()
}

// full_only: false
func TestSetUnknownWithoutRecoveryMarker(t *testing.T) {
	for _, encoding := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, confidential := range []bool{false, true} {
			t.Run(fmt.Sprintf("format-%d/confidential-%t", encoding, confidential), func(t *testing.T) {
				source := configurationSetPair(t, "aws", encoding, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				marker := filepath.Join(filepath.Dir(source.path), ".enkv-pending", filepath.Base(source.path))
				before := configurationApplySourceImage(t, filepath.Dir(source.path))
				interrupted := &losePendingSourceMarker{Context: ctx, cancel: cancel, marker: marker}
				result, deliveryErr := SetConfiguration(interrupted, source.path, encoding, "prepared", io.NopCloser(strings.NewReader("private input sentinel")), SetOptions{Confidential: confidential})
				var unknown *configuration.UnknownEdit
				if !interrupted.observed || !interrupted.removed || interrupted.failure != nil || !errors.Is(ctx.Err(), context.Canceled) || !errors.As(deliveryErr, &unknown) {
					t.Fatal("source marker publication and loss were not established", interrupted.observed, interrupted.removed, interrupted.failure, deliveryErr)
				}
				after := configurationApplySourceImage(t, filepath.Dir(source.path))
				for _, path := range []string{source.path, source.generated} {
					relative, err := filepath.Rel(filepath.Dir(source.path), path)
					if err != nil {
						t.Fatal(err)
					}
					old, current := before[relative], after[relative]
					if old.Mode != current.Mode || !bytes.Equal(old.Body, current.Body) {
						t.Fatal("uncertain delivery changed an original source image")
					}
				}
				for path, old := range interrupted.retained {
					body, readErr := os.ReadFile(path)
					info, statErr := os.Stat(path)
					if readErr != nil || statErr != nil || info.Mode() != old.Mode || !bytes.Equal(body, old.Body) {
						t.Fatal("source marker loss discarded or changed its saved candidate", readErr, statErr)
					}
				}
				if _, eligible := unknown.RecoverySource(); eligible {
					t.Fatal("missing marker granted recovery")
				}
				if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("source marker unexpectedly exists", err)
				}
				for _, view := range []struct {
					human  bool
					render func(*SetResult, error) ([]byte, error)
				}{{false, RenderSetJSON}, {true, RenderSetHuman}} {
					body, err := view.render(result, deliveryErr)
					unknown := bytes.Contains(body, []byte("Local files: unknown\n"))
					if !view.human {
						var wire struct {
							Delivery struct {
								Outcome string `json:"outcome"`
							} `json:"local_delivery"`
						}
						unknown = json.Unmarshal(body, &wire) == nil && wire.Delivery.Outcome == "unknown"
					}
					if err != nil || !unknown {
						t.Error("unconfirmed local delivery was not renderable", err)
					}
					for _, forbidden := range []string{"recovery_source", "Recovery source:", "observation_paths", "private input sentinel", "Run recover"} {
						if strings.Contains(string(body), forbidden) {
							t.Error("unconfirmed local result claimed recovery or exposed private input")
						}
					}
				}
				if SetExitCode(result, deliveryErr) != 3 {
					t.Error("unknown local delivery lost exit code 3")
				}
			})
		}
	}
}

// full_only: false
func TestLocalDeliveryKeepsDurableRecoveryAfterDisposal(t *testing.T) {
	for _, encoding := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, confidential := range []bool{false, true} {
			t.Run(fmt.Sprintf("format-%d/confidential-%t", encoding, confidential), func(t *testing.T) {
				source := configurationSetPair(t, "aws", encoding, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				interrupted := &cancelPendingConfiguration{Context: ctx, cancel: cancel,
					marker: filepath.Join(filepath.Dir(source.path), ".enkv-pending", filepath.Base(source.path))}
				result, deliveryErr := SetConfiguration(interrupted, source.path, encoding, "prepared", io.NopCloser(strings.NewReader("local value")), SetOptions{Confidential: confidential})
				var unknown *configuration.UnknownEdit
				if !errors.As(deliveryErr, &unknown) || !errors.Is(deliveryErr, configuration.ErrPendingEdit) {
					t.Fatal("controlled pending transaction was not established", deliveryErr)
				}
				if err := unknown.Observation.Close(); err != nil {
					t.Fatal(err)
				}
				check := func(body []byte, err error) {
					t.Helper()
					if err != nil {
						t.Error("durable recovery could not be rendered after disposal", err)
						return
					}
					var record struct {
						Delivery struct {
							Outcome string `json:"outcome"`
							Source  string `json:"recovery_source"`
						} `json:"local_delivery"`
					}
					if err := json.Unmarshal(body, &record); err != nil || record.Delivery.Outcome != "pending" || record.Delivery.Source != source.path {
						t.Error("local result lost the exact saved recovery source", err)
					}
					for _, forbidden := range []string{"observation_paths", ".enkv-editable-", ".enkv-generated-", "local value"} {
						if strings.Contains(string(body), forbidden) {
							t.Error("local result exposed a private temporary path or input")
						}
					}
				}
				check(RenderSetJSON(result, deliveryErr))
				if SetExitCode(result, deliveryErr) != 3 {
					t.Error("pending set did not retain the pending exit code")
				}
				initialization, err := NewInitializationRefusal(encoding)
				if err != nil {
					t.Fatal(err)
				}
				check(RenderInitializationJSON(initialization, deliveryErr))
				if InitializationExitCode(initialization, deliveryErr) != 3 {
					t.Error("pending initialization delivery did not retain the pending exit code")
				}
				if _, err := configuration.RecoverEdit(t.Context(), source.path, encoding); err != nil {
					t.Fatal("disposing the local result removed durable recovery", err)
				}
			})
		}
	}
}
