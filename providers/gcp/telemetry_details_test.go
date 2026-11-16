package gcp

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestStoreDiagnosticsKeepValidatedRelativePathAndFailureClass(t *testing.T) {
	store := &Store{config: StoreConfig{Prefix: "operator-prefix"}, descriptor: contract.Descriptor{HeadKey: "operator-prefix/HEAD"}}
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	_, call := startTelemetryDetails(ctx, telemetry.OpStoreRead, storeDetails(store, store.descriptor.HeadKey))
	finishReadTelemetry(call, contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport})
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
	if len(records) != 3 || records[0].Path != "HEAD" || records[2].Path != "HEAD" ||
		records[2].PathKind != "state_head" || records[2].ErrorClass != telemetry.DiagnosticReasonEvidenceUnavailable ||
		records[2].ErrorDetailStatus != "unavailable" || records[2].Validate() != nil {
		t.Fatalf("Store diagnostics = %+v", records)
	}
	if details := storeDetails(store, "operator-prefix/private-value"); details != (telemetry.DiagnosticDetails{}) {
		t.Fatal("invalid Store key entered diagnostic details")
	}
}
