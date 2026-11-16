package compositionfull

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

type blockInitializationCleanup struct {
	context.Context
	marker       string
	otherMarker  string
	afterMarkers bool
	mu           sync.Mutex
	blocked      string
	failure      error
}

func (c *blockInitializationCleanup) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blocked == "" && c.failure == nil {
		body, err := os.ReadFile(c.marker)
		var marker struct {
			Record string `json:"record"`
		}
		if err == nil {
			err = json.Unmarshal(body, &marker)
		}
		if err == nil {
			body, err = os.ReadFile(marker.Record)
		}
		var record struct {
			Phase string `json:"phase"`
		}
		if err == nil {
			err = json.Unmarshal(body, &record)
		}
		ready := err == nil && record.Phase == "verified"
		if ready && c.afterMarkers {
			_, markerErr := os.Lstat(c.otherMarker)
			ready = errors.Is(markerErr, os.ErrNotExist)
			if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
				err = markerErr
			}
		}
		if ready {
			directory := filepath.Dir(c.marker)
			if c.afterMarkers {
				directory = filepath.Dir(marker.Record)
			}
			err = os.Chmod(directory, 0555)
			if err == nil {
				c.blocked = directory
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			c.failure = err
		}
	}
	return c.Context.Err()
}

// full_only: false
func TestInitializationReportsNativeReadbackWithoutGrantingInitialization(t *testing.T) {
	for _, encoding := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, afterMarkers := range []bool{false, true} {
			t.Run(fmt.Sprintf("format-%d/markers-cleared-%t", encoding, afterMarkers), func(t *testing.T) {
				source := configurationSetPair(t, "aws", encoding, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				interrupted := &blockInitializationCleanup{Context: ctx, afterMarkers: afterMarkers,
					marker:      filepath.Join(filepath.Dir(source.path), ".enkv-pending", filepath.Base(source.path)),
					otherMarker: filepath.Join(filepath.Dir(source.generated), ".enkv-pending", filepath.Base(source.generated))}
				t.Cleanup(func() {
					if interrupted.blocked != "" {
						if err := os.Chmod(interrupted.blocked, 0700); err != nil {
							t.Error(err)
						}
					}
				})
				_, deliveryErr := SetConfiguration(interrupted, source.path, encoding, "prepared", io.NopCloser(strings.NewReader("local value")), SetOptions{})
				var unknown *configuration.UnknownEdit
				if interrupted.failure != nil || interrupted.blocked == "" || !errors.As(deliveryErr, &unknown) {
					t.Fatal("native cleanup interruption was not established", interrupted.failure, deliveryErr)
				}
				if err := os.Chmod(interrupted.blocked, 0700); err != nil {
					t.Fatal(err)
				}
				if err := unknown.Observation.Close(); err != nil {
					t.Fatal(err)
				}
				initialization, err := NewInitializationRefusal(encoding)
				if err != nil {
					t.Fatal(err)
				}
				body, err := RenderInitializationJSON(initialization, deliveryErr)
				if err != nil {
					t.Fatal(err)
				}
				var record struct {
					State            contract.InitializationStateResult `json:"state_result"`
					OperationPayload string                             `json:"operation_payload"`
					Delivery         struct {
						Outcome       string `json:"outcome"`
						Editable      string `json:"editable_path"`
						Generated     string `json:"generated_path"`
						Recovery      string `json:"recovery_source"`
						CleanupFailed bool   `json:"cleanup_failed"`
						Readback      struct {
							Editable  string `json:"editable_digest"`
							Generated string `json:"generated_digest"`
						} `json:"readback"`
					} `json:"local_delivery"`
				}
				if err := json.Unmarshal(body, &record); err != nil {
					t.Fatal(err)
				}
				if record.State != contract.InitializationRefused || record.OperationPayload != "none" || initialization.Payload != nil || len(initialization.Receipt) != 0 || initialization.ManifestPath != "" {
					t.Error("native pair readback granted initialization authority")
				}
				editable, err := os.ReadFile(source.path)
				if err != nil {
					t.Fatal(err)
				}
				generated, err := os.ReadFile(source.generated)
				if err != nil {
					t.Fatal(err)
				}
				ed, gd := sha256.Sum256(editable), sha256.Sum256(generated)
				if record.Delivery.Editable != source.path || record.Delivery.Generated != source.generated || !record.Delivery.CleanupFailed || record.Delivery.Readback.Editable != hex.EncodeToString(ed[:]) || record.Delivery.Readback.Generated != hex.EncodeToString(gd[:]) {
					t.Error("initialization lost confirmed native pair readback")
				}
				wantOutcome, wantRecovery, wantExit := "pending", source.path, 3
				if afterMarkers {
					wantOutcome, wantRecovery, wantExit = "recorded", "", 2
				}
				if record.Delivery.Outcome != wantOutcome || record.Delivery.Recovery != wantRecovery || InitializationExitCode(initialization, deliveryErr) != wantExit {
					t.Error("initialization confused readback, cleanup failure and recovery eligibility")
				}
				if _, err := RenderInitializationHuman(initialization, deliveryErr); err != nil {
					t.Error("native readback could not be rendered for a human", err)
				}
				for _, forbidden := range []string{"local value", ".enkv-editable-", ".enkv-generated-", "observation_paths"} {
					if strings.Contains(string(body), forbidden) {
						t.Error("native readback exposed private observation or input")
					}
				}
				if !afterMarkers {
					if _, err := configuration.RecoverEdit(t.Context(), source.path, encoding); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
