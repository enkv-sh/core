package compositionfull

import (
	"bytes"
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
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestReplacementPendingDeliveryResult(t *testing.T) {
	for _, target := range []configuration.ReplacementTarget{configuration.ReplaceAuthority, configuration.ReplaceRecovery, configuration.ReplaceRecipient} {
		t.Run(string(target), func(t *testing.T) {
			result, err := NewReplacementCommandRefusal(target, contract.ID{19}, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(`{"path":"/alias/successor.json","status":"pending","failed":true,"cleanup_failed":false,"recovery_source":"/saved/successor.json"}`), &result.Delivery); err != nil {
				t.Fatal(err)
			}
			result.recoverySource = "/saved/successor.json"
			replacementFailureRender(t, result, "keys-replace-"+string(target), "refused", 3)
			var out bytes.Buffer
			var wire struct {
				Delivery struct {
					Recovery string `json:"recovery_source"`
				} `json:"delivery"`
			}
			if err := WriteReplacementJSON(context.Background(), &out, result); err != nil || json.Unmarshal(out.Bytes(), &wire) != nil || wire.Delivery.Recovery != "/saved/successor.json" {
				t.Error("saved recovery identity was not rendered", err)
			}
			for _, saved := range []string{"", "/other/successor.json"} {
				changed := result
				changed.recoverySource = saved
				out.Reset()
				if err := WriteReplacementJSON(context.Background(), &out, changed); err == nil || out.Len() != 0 {
					t.Error("unbound public recovery path was accepted")
				}
			}
			changed := result
			changed.Delivery.Status = "unproved"
			out.Reset()
			if err := WriteReplacementJSON(context.Background(), &out, changed); err == nil || out.Len() != 0 {
				t.Error("recovery instruction escaped the pending delivery form")
			}
		})
	}
}

// full_only: false
func TestReplacementReadbackDoesNotGrantDomainSuccess(t *testing.T) {
	for _, afterMarkers := range []bool{false, true} {
		t.Run(fmt.Sprintf("markers-cleared-%t", afterMarkers), func(t *testing.T) {
			source := configurationSetPair(t, "aws", configuration.JSON, nil)
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
			_, deliveryErr := SetConfiguration(interrupted, source.path, configuration.JSON, "prepared", io.NopCloser(strings.NewReader("local value")), SetOptions{})
			var unknown *configuration.UnknownEdit
			if interrupted.failure != nil || interrupted.blocked == "" || !errors.As(deliveryErr, &unknown) {
				t.Fatal("native cleanup interruption was not established", interrupted.failure, deliveryErr)
			}
			if err := os.Chmod(interrupted.blocked, 0700); err != nil {
				t.Fatal(err)
			}
			delivery, ok := unknown.Readback()
			if !ok {
				t.Fatal("confirmed native readback was lost")
			}
			result, err := NewReplacementCommandRefusal(configuration.ReplaceRecipient, contract.ID{19}, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			result.localDelivery = delivery
			result.Delivery = ReplacementCommandDelivery{Path: source.path, Status: "read-back", Failed: true, CleanupFailed: true}
			wantExit := 2
			if recovery, eligible := unknown.RecoverySource(); eligible {
				result.recoverySource, result.Delivery.RecoverySource = recovery, recovery
				result.Delivery.Status, wantExit = "pending", 3
			}
			replacementFailureRender(t, result, "keys-replace-recipient", "refused", wantExit)
			var out bytes.Buffer
			if err := WriteReplacementJSON(t.Context(), &out, result); err != nil {
				t.Fatal(err)
			}
			var record struct {
				Delivery struct {
					Editable  string `json:"editable_path"`
					Generated string `json:"generated_path"`
					Readback  struct {
						Editable  string `json:"editable_digest"`
						Generated string `json:"generated_digest"`
					} `json:"readback"`
				} `json:"delivery"`
			}
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
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
			if record.Delivery.Editable != source.path || record.Delivery.Generated != source.generated || record.Delivery.Readback.Editable != hex.EncodeToString(ed[:]) || record.Delivery.Readback.Generated != hex.EncodeToString(gd[:]) {
				t.Error("replacement lost confirmed local paths or readback")
			}
			for _, forbidden := range []string{"local value", ".enkv-editable-", ".enkv-generated-", "observation_paths"} {
				if strings.Contains(out.String(), forbidden) {
					t.Error("replacement exposed private input or observation")
				}
			}
			changed := result
			changed.Delivery.CleanupFailed = false
			out.Reset()
			if err := WriteReplacementJSON(t.Context(), &out, changed); err == nil || out.Len() != 0 {
				t.Error("public delivery erased known cleanup failure")
			}
			if !afterMarkers {
				if _, err := configuration.RecoverEdit(t.Context(), source.path, configuration.JSON); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
