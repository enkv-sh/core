package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestGCPlanArtifactUsesExactBoundAndProtectedCompleteDelivery(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	open, h := configurationCapacityOpener(t, source)
	dir := protectedConfigurationTestDirectory(t)
	planned := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{41}, OperationID: contract.ID{42}, ArtifactPath: filepath.Join(dir, "original.bin")}, source.pair, open, nativeAbandonPlanIO())
	if planned.Operation.Payload == nil || !planned.Delivery.PlanReadback {
		t.Fatal("authentic preview fixture", planned.Operation.PublicQueryResult, planned.Delivery)
	}
	body := planned.Operation.Payload.EncodedPlan
	for _, fault := range []string{"none", "short-write", "sync", "close", "directory-sync", "readback", "panic"} {
		t.Run(fault, func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			metrics := make(chan telemetry.MetricPoint, 16)
			callCtx := telemetry.WithCapability(ctx, telemetry.NewCapability(metrics, recorder))
			checkTelemetry := func(panicked bool) {
				records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 4))
				want := 3
				if panicked {
					want = 2
				}
				if len(records) != want {
					t.Fatal("panic reported a normal return or lost its start", fault, len(records))
				}
				for _, record := range records {
					if record.Validate() != nil || record.Provider != telemetry.ProviderApplication || record.Operation != telemetry.OpGCPlanWrite {
						t.Fatal("GC artifact telemetry lost its closed owner")
					}
				}
				for len(metrics) != 0 {
					point := <-metrics
					if point.Provider != telemetry.ProviderApplication || point.Operation != telemetry.OpGCPlanWrite || bytes.Contains([]byte(point.Status), []byte("sentinel")) {
						t.Fatal("private text escaped GC artifact metrics")
					}
					if panicked && point.Name != telemetry.OperationCalls {
						t.Fatal("panic emitted completed-operation metrics")
					}
				}
			}
			ops := nativeAbandonPlanIO()
			path := filepath.Join(dir, fault+".bin")
			failure := errors.New("private-failure-sentinel")
			ops.readback = func(ctx context.Context, path string, limit int64) ([]byte, error) {
				if limit != contract.GCPlanMaxLength {
					t.Fatal("GC readback used another format's larger limit", limit)
				}
				if fault == "panic" {
					panic(failure)
				}
				if fault == "readback" {
					return []byte("altered"), nil
				}
				return os.ReadFile(path)
			}
			switch fault {
			case "short-write":
				ops.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:1]) }
			case "sync":
				ops.sync = func(*os.File) error { return failure }
			case "close":
				ops.close = func(f *os.File) error { return errors.Join(f.Close(), failure) }
			case "directory-sync":
				ops.syncDirectory = func(int) error { return failure }
			}
			if fault == "panic" {
				var recovered any
				func() { defer func() { recovered = recover() }(); _, _ = writeGCPlan(callCtx, path, body, ops) }()
				if recovered != failure {
					t.Fatal("plan worker swallowed or changed panic")
				}
				checkTelemetry(true)
				return
			}
			delivery, err := writeGCPlan(callCtx, path, body, ops)
			checkTelemetry(false)
			if fault == "none" {
				if err != nil || !delivery.PlanCreated || !delivery.PlanSynced || !delivery.PlanReadback {
					t.Fatal("complete plan delivery", err, delivery)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writeGCPlan(ctx, path, body, ops); err == nil {
					t.Fatal("existing plan overwritten")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("overwrite refusal changed existing bytes", err)
				}
			} else if err == nil || !delivery.PlanCreated || delivery.PlanReadback {
				t.Fatal("partial delivery reported complete", fault, err, delivery)
			}
		})
	}
	c, pins, err := configurationPublicQueryInput(ctx, contract.ID{43}, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	domain, store := capacityReaderScope(c)
	for _, damage := range []string{"truncated", "trailing", "oversized"} {
		b := bytes.Clone(body)
		switch damage {
		case "truncated":
			b = b[:len(b)-1]
		case "trailing":
			b = append(b, 0)
		case "oversized":
			b = make([]byte, contract.GCPlanMaxLength+1)
		}
		path := filepath.Join(dir, damage+".bin")
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("malformed artifact fixture")
		}
		if _, err := readGCPlan(ctx, path, domain, store, c.AWS.PublicBasis, pins); err == nil {
			t.Fatal("unbounded/noncanonical artifact admitted", damage)
		}
	}
	h.base.assertNoEffects(t)
	source.assertUnchanged(t)
}
