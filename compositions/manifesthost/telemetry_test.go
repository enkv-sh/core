package manifesthost

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/telemetry"
)

type panickingAdmissionContext struct {
	context.Context
	cause error
}

func (ctx panickingAdmissionContext) Err() error { panic(ctx.cause) }

// full_only: false
func TestManifestAdmissionPanicHasNoNormalReturn(t *testing.T) {
	for _, construct := range []bool{false, true} {
		t.Run(map[bool]string{false: "check", true: "construct"}[construct], func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			base := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			sentinel := errors.New("private-admission-panic-sentinel")
			ctx := panickingAdmissionContext{Context: base, cause: sentinel}
			m := metadataFixture()
			func() {
				defer func() {
					if recovered := recover(); recovered != sentinel {
						t.Errorf("admission changed the panic: %v", recovered)
					}
				}()
				if construct {
					_, _ = NewNative(ctx, filepath.Join(t.TempDir(), "plugin"), m, fixtureDependency(m))
				} else {
					_ = Check(ctx, m, fixtureDependency(m))
				}
				t.Error("admission swallowed its panic")
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
		})
	}
}

// full_only: false
func TestManifestHostAdmissionTelemetryKeepsClosedFacts(t *testing.T) {
	recorder := telemetry.NewRecorder()
	base := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	ctx, cancel := context.WithTimeout(base, time.Minute)
	defer cancel()
	m := metadataFixture()
	if err := Check(ctx, m, fixtureDependency(m)); err != nil {
		t.Fatal(err)
	}
	m.Family.Facts = []byte(`{"private-metadata-sentinel":true}`)
	if err := Check(ctx, m, fixtureDependency(m)); err == nil {
		t.Fatal("unsupported metadata accepted")
	}
	m = metadataFixture()
	path := filepath.Join(t.TempDir(), "private-path-sentinel")
	if _, err := NewNative(ctx, path, m, fixtureDependency(m)); err == nil {
		t.Fatal("missing executable accepted")
	}
	cancel()
	if err := Check(ctx, m, fixtureDependency(m)); err == nil {
		t.Fatal("cancelled admission accepted")
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16))
	starts, returns := 0, 0
	outcomes := []telemetry.Result{}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Provider != telemetry.ProviderManifestHost || record.Operation != telemetry.OpManifestHostCheck {
			t.Fatal("unexpected diagnostic owner", record)
		}
		switch record.Event {
		case telemetry.DiagnosticStart:
			starts++
		case telemetry.DiagnosticReturn:
			returns++
			outcomes = append(outcomes, record.Result)
		}
	}
	if starts != 4 || returns != 4 || outcomes[0] != telemetry.ResultSuccess || outcomes[1] != telemetry.ResultAdmissionRefused || outcomes[2] != telemetry.ResultAdmissionRefused || outcomes[3] != telemetry.ResultCancelled {
		t.Fatal("closed admission outcomes differ", starts, returns, outcomes)
	}
	b, err := json.Marshal(records)
	if err != nil || strings.Contains(string(b), "private-metadata-sentinel") || strings.Contains(string(b), "private-path-sentinel") {
		t.Fatal("metadata or path entered diagnostics", err)
	}
	if telemetry.Start(context.Background(), telemetry.ProviderManifestHost, telemetry.OpManifestHostCheck) != nil {
		t.Fatal("disabled telemetry started admission call")
	}
}

// full_only: false
func TestManifestHostClosedFailureTelemetryDoesNotReportSuccess(t *testing.T) {
	for _, test := range []struct {
		failure manifest.Failure
		want    telemetry.Result
	}{{manifest.InvalidInput, telemetry.ResultInvalid}, {manifest.InvalidUTF8, telemetry.ResultInvalid}, {manifest.InvalidResult, telemetry.ResultInvalid}, {manifest.LimitExceeded, telemetry.ResultCapacityExceeded}, {manifest.Cancelled, telemetry.ResultCancelled}, {manifest.Expired, telemetry.ResultExpired}} {
		t.Run(string(test.failure), func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			call := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostRender)
			finishRender(call, nil, test.failure)
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 4))
			returns := 0
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Event == telemetry.DiagnosticReturn {
					returns++
					if record.Result != test.want {
						t.Fatal("closed failure reported another outcome", record.Result, test.want)
					}
				}
			}
			if returns != 1 {
				t.Fatal("missing closed refusal diagnostic")
			}
		})
	}
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	n := &Native{}
	result := n.Render(ctx, manifest.Borrow(nil))
	if result.Failure != manifest.InvalidInput || result.Artifact != nil {
		t.Fatal("validation refusal changed", result.Failure)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 4))
	if len(records) == 0 || records[len(records)-1].Result != telemetry.ResultInvalid {
		t.Fatal("validation refusal reported success")
	}
}
