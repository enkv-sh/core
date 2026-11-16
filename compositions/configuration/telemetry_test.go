package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/telemetry"
)

type panickingRecoveryContext struct {
	context.Context
	cause error
}

func (ctx panickingRecoveryContext) Err() error { panic(ctx.cause) }

// full_only: false
func TestConfigurationRecoveryPanicHasNoNormalReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.json")
	marker := coordinationPath(path, ".enkv-pending")
	if err := os.Mkdir(filepath.Dir(marker), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	recorder := telemetry.NewRecorder()
	base := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	sentinel := errors.New("private-recovery-panic-sentinel")
	ctx := panickingRecoveryContext{Context: base, cause: sentinel}
	func() {
		defer func() {
			if recovered := recover(); recovered != sentinel {
				t.Errorf("recovery changed its panic: %v", recovered)
			}
		}()
		_, _ = RecoverEdit(ctx, path, JSON)
		t.Error("recovery swallowed its panic")
	}()
	starts, returns := 0, 0
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 4)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Event == telemetry.DiagnosticStart {
			starts++
		}
		if record.Event == telemetry.DiagnosticReturn {
			returns++
		}
	}
	if starts != 1 || returns != 0 {
		t.Errorf("panic emitted a normal terminal: starts=%d returns=%d", starts, returns)
	}
	if _, err := RecoverEdit(base, path, JSON); err == nil {
		t.Fatal("ordinary invalid-marker refusal changed")
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 4))
	if len(records) != 2 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticReturn || records[1].Result != telemetry.ResultWriteRefused {
		t.Fatal("ordinary recovery refusal lacks one truthful return", records)
	}
}

// full_only: false
func TestSourceTelemetryExcludesContent(t *testing.T) {
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	dir := t.TempDir()
	path := filepath.Join(dir, "private-path-sentinel")
	if err := os.WriteFile(path, []byte(sourceSetupJSON), 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := Capture(ctx, path, JSON)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, pair)
	if _, err = Parse(ctx, pair); err != nil {
		t.Fatal(err)
	}
	bad := strings.TrimSuffix(sourceSetupJSON, "}") + `,"secret-sentinel":"secret-payload-sentinel"}`
	if err = os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if p, e := Capture(ctx, path, JSON); e == nil {
		closeSourceOwner(t, p)
		t.Fatal("bad source accepted")
	} else if strings.Contains(e.Error(), "sentinel") {
		t.Fatal("diagnostic echoed source or path")
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 9))
	if len(records) != 9 {
		t.Fatalf("records %d status %+v", len(records), recorder.Status())
	}
	for i, r := range records {
		if e := r.Validate(); e != nil {
			t.Fatal(e)
		}
		if i%3 == 2 {
			want := telemetry.ResultSuccess
			if i == 8 {
				want = telemetry.ResultAdmissionRefused
			}
			if r.Result != want {
				t.Fatalf("return %+v", r)
			}
		}
	}
	encoded, e := json.Marshal(records)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(encoded), "sentinel") || strings.Contains(string(encoded), sourceSigningSelector) {
		t.Fatal("telemetry exposed source content")
	}
	if p, e := Capture(context.Background(), path, JSON); e == nil {
		closeSourceOwner(t, p)
		t.Fatal("disabled telemetry changed refusal")
	}
}
