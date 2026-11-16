package compositionfull

import (
	"context"
	"errors"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/telemetry"
)

// full_only: false
func TestLocalTelemetryUsesOwnedCancellationCause(t *testing.T) {
	prepare, err := NewPrepareRefusal()
	if err != nil {
		t.Fatal(err)
	}
	set, err := newSetResult(false, configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalEditRefusal("domain-rename")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("late cancellation was not established")
	}
	for _, row := range []struct {
		name     string
		classify func(error) telemetry.Result
	}{
		{"prepare", prepare.TelemetryResult},
		{"set", set.TelemetryResult},
		{"local", local.TelemetryResult},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := row.classify(errors.New("owned refusal")); got != telemetry.ResultWriteRefused {
				t.Fatal("later context cancellation replaced an owned refusal", got)
			}
			for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
				if got := row.classify(cause); got != telemetry.ResultCancelled {
					t.Fatal("owned cancellation cause was lost", cause, got)
				}
			}
		})
	}
}
