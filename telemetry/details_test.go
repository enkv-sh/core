package telemetry

import (
	"context"
	"strings"
	"testing"
)

// full_only: false
func TestDiagnosticDetailsOwnReviewedFieldsAndOmitRawErrors(t *testing.T) {
	const secret = "SYNTHETIC_SECRET_VALUE"
	rawError := "provider rejected credential=" + secret
	recorder := NewRecorder()
	ctx := WithCapability(context.Background(), NewCapability(nil, recorder))
	details := (DiagnosticDetails{}).WithEntryName("member-alpha").WithKeyID(strings.Repeat("ab", 32)).WithCommandID(strings.Repeat("cd", 32)).WithAttemptID(strings.Repeat("ef", 32)).WithInvocationID(strings.Repeat("01", 16)).WithWorkerID("0000-writer").WithPathKind("state_head").WithReviewedPath("state/head/"+strings.Repeat("ab", 32)).WithConfigField("recovery_mode").WithErrorFacts(DiagnosticReasonEvidenceUnavailable, 503).WithReviewedErrorText("state read returned HTTP 503")
	call := StartWithDetails(ctx, ProviderCore, OpCoreOpen, details)
	call.Finish(ResultEvidenceUnavailable)
	got := recorder.Drain(make([]DiagnosticRecord, 0, 4))
	if len(got) != 2 {
		t.Fatalf("records=%d", len(got))
	}
	for _, record := range got {
		if record.Validate() != nil || record.EntryName != "member-alpha" || record.KeyID != strings.Repeat("ab", 32) || record.CommandID != strings.Repeat("cd", 32) || record.AttemptID != strings.Repeat("ef", 32) || record.InvocationID != strings.Repeat("01", 16) || record.WorkerID != "0000-writer" || record.PathKind != "state_head" || record.Path != "state/head/"+strings.Repeat("ab", 32) || record.ConfigField != "recovery_mode" || record.ErrorClass != DiagnosticReasonEvidenceUnavailable || record.HTTPStatus != 503 || record.ErrorDetail != "state read returned HTTP 503" || record.ErrorDetailStatus != "reviewed" || strings.Contains(record.ErrorDetail, secret) || strings.Contains(record.ErrorDetail, rawError) || len(record.ErrorDetail) > MaximumErrorBytes {
			t.Fatalf("reviewed detail was changed or raw input admitted: %+v", record)
		}
	}
	StartWithDetails(ctx, ProviderCore, OpCoreOpen, (DiagnosticDetails{}).WithErrorFacts(DiagnosticReasonDenied, 403)).Finish(ResultDenied)
	for _, record := range recorder.Drain(make([]DiagnosticRecord, 0, 4)) {
		if record.ErrorDetail != "" || record.ErrorDetailStatus != "unavailable" || record.Validate() != nil {
			t.Fatal("unreviewed error text looked reviewed")
		}
	}
	invalid := (DiagnosticDetails{}).WithPathKind(secret)
	StartWithDetails(ctx, ProviderCore, OpCoreOpen, invalid).Finish(ResultFailure)
	StartWithDetails(ctx, ProviderCore, OpCoreOpen, (DiagnosticDetails{}).WithCommandID(secret)).Finish(ResultFailure)
	StartWithDetails(ctx, ProviderCore, OpCoreOpen, (DiagnosticDetails{}).WithAttemptID(secret)).Finish(ResultFailure)
	StartWithDetails(ctx, ProviderCore, OpCoreOpen, (DiagnosticDetails{}).WithInvocationID(secret+"/")).Finish(ResultFailure)
	StartWithDetails(ctx, ProviderCore, OpCoreOpen, (DiagnosticDetails{}).WithWorkerID(secret+"/")).Finish(ResultFailure)
	if recorder.Status().Rejected != 10 || len(recorder.Drain(make([]DiagnosticRecord, 0, 10))) != 0 {
		t.Fatal("unreviewed path entered capture")
	}
}
