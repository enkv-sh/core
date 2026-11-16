package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestSuccessorPublicationTelemetryFinishesOnlyNormalReturns(t *testing.T) {
	for _, condition := range []string{"success", "refusal", "write panic", "readback panic"} {
		t.Run(condition, func(t *testing.T) {
			pair, _, request, material := successorFileFixture(t, JSON)
			path := filepath.Join(t.TempDir(), "successor")
			output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := output.Close(); err != nil {
					t.Error(err)
				}
			})
			const excluded = "synthetic-private-successor-failure-sentinel"
			failure := errors.New(excluded)
			operations := output.io
			switch condition {
			case "refusal":
				output.io.syncFile = func(*os.File) error { return failure }
			case "write panic":
				output.io.write = func(*os.File, []byte) (int, error) { panic(failure) }
			case "readback panic":
				output.io.readback = func(ctx context.Context, actual string, image *Image, predecessor bool) error {
					if actual == path {
						panic(failure)
					}
					return operations.readback(ctx, actual, image, predecessor)
				}
			}
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			var recovered any
			var readback *SuccessorReadback
			var resultErr error
			func() {
				defer func() { recovered = recover() }()
				readback, resultErr = output.Publish(ctx, material)
			}()
			panicked := condition == "write panic" || condition == "readback panic"
			if panicked {
				if recovered != failure || readback != nil || resultErr != nil || output.Delivered() {
					t.Fatal("publication did not preserve callback panic and incomplete delivery")
				}
			} else if recovered != nil {
				t.Fatal("normal publication panicked")
			} else if condition == "success" {
				if resultErr != nil || readback == nil || !output.Delivered() {
					t.Fatal("successful publication lost readback")
				}
			} else if !errors.Is(resultErr, failure) || readback != nil || output.Delivered() {
				t.Fatal("normal refusal lost its cause or reported delivery")
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
			var starts, returns int
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation != telemetry.OpConfigurationWrite {
					continue
				}
				switch record.Event {
				case telemetry.DiagnosticStart:
					starts++
				case telemetry.DiagnosticReturn:
					returns++
					want := telemetry.ResultSuccess
					if condition == "refusal" {
						want = telemetry.ResultWriteRefused
					}
					if record.Result != want {
						t.Fatal("normal return reported the wrong publication result")
					}
				}
			}
			wantReturns := 1
			if panicked {
				wantReturns = 0
			}
			if starts != 1 || returns != wantReturns {
				t.Fatalf("publication normal-return telemetry: starts=%d returns=%d want_returns=%d", starts, returns, wantReturns)
			}
			encoded, err := json.Marshal(records)
			if err != nil || bytes.Contains(encoded, []byte(excluded)) || bytes.Contains(encoded, []byte(path)) {
				t.Fatal("publication recorded raw callback failure or local path")
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			if condition == "readback panic" {
				if captured, err := Capture(t.Context(), path, JSON); captured != nil || !errors.Is(err, ErrPendingEdit) {
					t.Fatal("panic lost pending ownership", err)
				}
				if _, err := RecoverEdit(t.Context(), path, JSON); err != nil {
					t.Fatal(err)
				}
			}
			if err := pair.CheckUnchanged(t.Context()); err != nil {
				t.Fatal("publication changed its borrowed source", err)
			}
			_, statErr := os.Lstat(path)
			published := condition == "success" || condition == "readback panic"
			if published && statErr != nil || !published && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("callback failure changed installed-name disposition")
			}
			for _, dir := range []string{filepath.Dir(path), filepath.Dir(pair.Generated.OriginalPath())} {
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".enkv-editable-") || strings.HasPrefix(entry.Name(), ".enkv-generated-") {
						t.Fatal("callback failure left an owned publication temporary")
					}
				}
			}
		})
	}
}
