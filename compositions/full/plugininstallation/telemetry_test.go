package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestInstallationTelemetryKeepsSafeOutcomesAndDisabledParity(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	r := request(scope, "private-renderer", "", Ordinary)
	_, disabledRows, disabledErr := c.Resolve(t.Context(), r)
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	_, enabledRows, enabledErr := c.Resolve(ctx, r)
	if !errors.Is(disabledErr, ErrMissing) || !errors.Is(enabledErr, ErrMissing) {
		t.Fatal("missing outcome differs")
	}
	left, _ := json.Marshal(disabledRows)
	right, _ := json.Marshal(enabledRows)
	if !bytes.Equal(left, right) {
		t.Fatal("telemetry changed safe rows")
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
	if len(records) != 3 || records[0].Operation != telemetry.OpPluginResolve || records[2].Result != telemetry.ResultReadMissing {
		t.Fatalf("closed missing telemetry %#v", records)
	}
	const sentinel = "PRIVATE/PATH/URL/RAW-ERROR-SENTINEL"
	r.CheckSource = func(context.Context) error { return errors.New(sentinel) }
	_, _, _ = c.Resolve(ctx, r)
	records = recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
	body, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(sentinel)) || bytes.Contains(body, []byte(scope)) || bytes.Contains(body, []byte(c.origin)) {
		t.Fatal("private diagnostic bytes escaped")
	}
	if recorder.Status().Rejected != 0 {
		t.Fatal("installation telemetry rejected")
	}
	defer func() {
		if recover() == nil {
			t.Error("panic did not propagate")
		}
		after := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
		for _, record := range after {
			if record.Event == telemetry.DiagnosticReturn {
				t.Error("panic emitted normal return")
			}
		}
	}()
	r.CheckSource = func(context.Context) error { panic("controlled") }
	_, _, _ = c.Resolve(ctx, r)
}
