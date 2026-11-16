package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
)

// full_only: false
func TestLocalConfigurationInterruptedDeliveryAxes(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, phase := range []string{"before-marker", "verified-cleanup"} {
			t.Run(fmt.Sprintf("%d/%s", format, phase), func(t *testing.T) {
				source := configurationSetPair(t, "aws", format, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				marker := filepath.Join(filepath.Dir(source.path), ".enkv-pending", filepath.Base(source.path))
				var result *LocalEditResult
				var resultErr error
				if phase == "before-marker" {
					before := configurationApplySourceImage(t, filepath.Dir(source.path))
					interrupted := &cancelBeforePendingMarker{Context: ctx, cancel: cancel, recordDirectory: filepath.Join(filepath.Dir(source.path), ".enkv-transactions")}
					result, resultErr = RenameConfigurationDomain(interrupted, source.path, format, "next")
					var unknown *configuration.UnknownEdit
					if !interrupted.triggered || !errors.Is(ctx.Err(), context.Canceled) || resultErr == nil || errors.As(resultErr, &unknown) || errors.Is(resultErr, configuration.ErrPendingEdit) {
						t.Fatal("record-only interruption did not preserve known refusal", resultErr)
					}
					after := configurationApplySourceImage(t, filepath.Dir(source.path))
					for _, path := range []string{source.path, source.generated} {
						relative, err := filepath.Rel(filepath.Dir(source.path), path)
						if err != nil {
							t.Fatal(err)
						}
						old, current := before[relative], after[relative]
						if old.Mode != current.Mode || !bytes.Equal(old.Body, current.Body) {
							t.Fatal("record-only interruption changed an original source image")
						}
					}
					record := localEditWire(t, result, resultErr)
					delivery := record["local_delivery"].(map[string]any)
					if record["outcome"] != "refused" || delivery["outcome"] != "not-recorded" || delivery["readback"] != nil || delivery["recovery_source"] != nil || LocalEditExitCode(result, resultErr) != 2 {
						t.Fatal("unconfirmed delivery claimed readback or recovery")
					}
					if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("pre-marker interruption left a source marker", err)
					}
					return
				}
				interrupted := &blockVerifiedCleanup{Context: ctx, marker: marker}
				result, resultErr = RenameConfigurationDomain(interrupted, source.path, format, "next")
				if !interrupted.blocked || interrupted.failure != nil || resultErr == nil {
					t.Fatal("verified cleanup interruption not established", interrupted.failure, resultErr)
				}
				if err := os.Chmod(filepath.Dir(marker), 0700); err != nil {
					t.Fatal(err)
				}
				generated := filepath.Join(filepath.Dir(source.path), ".enkv", "next.generated.json")
				record := localEditReadbackMatches(t, result, resultErr, source.path, generated)
				delivery := record["local_delivery"].(map[string]any)
				if record["outcome"] != "pending" || delivery["recovery_source"] != source.path || delivery["cleanup_failed"] != true || LocalEditExitCode(result, resultErr) != 3 {
					t.Fatal("confirmed readback lost independent pending cleanup")
				}
				if _, err := RecoverConfigurationEdit(ctx, source.path, format); err != nil {
					t.Fatal("exact cleanup recovery failed", err)
				}
				// Rendering is a historical receipt, not a new marker lookup.
				if again := localEditWire(t, result, resultErr); again["outcome"] != "pending" {
					t.Fatal("later recovery rewrote the original result")
				}
			})
		}
	}
}

// full_only: false
func TestLocalConfigurationRequiresFiniteContextBeforeCapture(t *testing.T) {
	for _, action := range []string{"domain-rename", "recipient-preparation", "recipient-reference-rename", "recovery"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "missing-source")
			for _, ctx := range []context.Context{nil, context.Background()} {
				var result *LocalEditResult
				var err error
				switch action {
				case "domain-rename":
					result, err = RenameConfigurationDomain(ctx, path, configuration.JSON, "next")
				case "recipient-preparation":
					result, err = PrepareConfigurationRecipient(ctx, path, configuration.JSON, "reader", RecipientPreparationOptions{Mode: RecipientPreparationCreate})
				case "recipient-reference-rename":
					result, err = RenameConfigurationRecipientReference(ctx, path, configuration.JSON, "old", "new")
				case "recovery":
					result, err = RecoverConfigurationEdit(ctx, path, configuration.JSON)
				}
				record := localEditWire(t, result, err)
				if err == nil || record["outcome"] != "refused" || record["target"] != nil || LocalEditExitCode(result, err) != 2 {
					t.Fatal("unbounded operation admitted source facts")
				}
				rows, readErr := os.ReadDir(dir)
				if readErr != nil || len(rows) != 0 {
					t.Fatal("unbounded invocation reached filesystem capture", readErr)
				}
			}
		})
	}
}
