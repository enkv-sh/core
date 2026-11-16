package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledAdministrativePlanLocalAdmissionKeepsRemoteBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target contract.ID
		path   string
		valid  bool
	}{
		{"zero-target", contract.ID{}, "/plan.json", false},
		{"root", generatedVectorID(230), "/", false},
		{"relative", generatedVectorID(230), "plan.json", false},
		{"nonclean", generatedVectorID(230), "/a/../plan.json", false},
		{"nul", generatedVectorID(230), "/plan\x00.json", false},
		{"invalid-utf8", generatedVectorID(230), "/plan\xff.json", false},
		{"overlength", generatedVectorID(230), "/" + strings.Repeat("a", 4096), false},
		{"maximum-path-shape", generatedVectorID(230), "/" + strings.Repeat("a", 4095), true},
		{"multibyte-path-shape", generatedVectorID(230), "/" + strings.Repeat("é", 2047) + "a", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, store := observationSelectedPredecessor(t)
			reader := &installedAdministrativeTestReader{store: store, beforeRead: func(context.Context, string) (contract.ReadResult, bool) {
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
			}}
			session, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativePlan)
			if err != nil {
				t.Fatal("valid installed reader constructor failed")
			}
			t.Cleanup(func() {
				if err := session.Close(); err != nil {
					t.Error("reader cleanup failed")
				}
			})
			nonce := generatedVectorID(231)
			out := session.Plan(installedAdministrativeTestContext(t), nonce, AdministrativePlanRequest{TargetGroupID: tc.target, ArtifactPath: tc.path})
			if out.Operation != AdministrativePlan || out.RequestID != nonce || out.PreAdmission != nil || out.List != nil || out.Plan != nil || out.End != nil || out.Receipt != nil || out.Result.Evidence != NoEvidence || out.Result.CommitMayHaveOccurred {
				t.Fatal("local boundary fabricated payload, identity or evidence")
			}
			if tc.valid {
				if out.Query == nil || out.Query.Observation != nil || out.Query.RequestNonce != nonce || out.Query.TargetGroupID != tc.target || out.Query.ArtifactPath != tc.path || out.Query.Artifact != nil || !out.Query.PlanIdentity.IsZero() || out.RequestIdentity.IsZero() || out.RequestIdentity != out.Query.Digest || out.OperationID.IsZero() || out.Result.Outcome != EvidenceUnavailable || out.Result.Reason != ReadUnavailable || out.Result.StoreReason != contract.ReasonAccess || out.StateResult != AdministrativeUnavailable || reader.reads.Load() != 1 || reader.heads.Load() != 1 {
					t.Fatal("valid path shape lost unavailable query or one HEAD boundary")
				}
			} else if out.Query != nil || !out.RequestIdentity.IsZero() || !out.OperationID.IsZero() || out.Result != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) || out.StateResult != AdministrativeRefused || reader.reads.Load() != 0 {
				t.Fatal("unformable plan queried remote state or acquired identity")
			}
			if err := session.Close(); err != nil {
				t.Fatal("reader close failed")
			}
			if err := session.Close(); err != nil || reader.closes.Load() != 1 {
				t.Fatal("reader was not closed exactly once")
			}
		})
	}
	for _, scenario := range []string{"method-mismatch", "zero-nonce", "nil-context", "expired-context", "unbounded-context", "closed-parent", "reused-parent"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, store := observationSelectedPredecessor(t)
			reader := &installedAdministrativeTestReader{store: store, beforeRead: func(context.Context, string) (contract.ReadResult, bool) {
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
			}}
			operation := AdministrativePlan
			if scenario == "method-mismatch" {
				operation = AdministrativeList
			}
			session, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), operation)
			if err != nil {
				t.Fatal("valid reader constructor failed")
			}
			t.Cleanup(func() {
				if err := session.Close(); err != nil {
					t.Error("reader cleanup failed")
				}
			})
			request := AdministrativePlanRequest{TargetGroupID: generatedVectorID(230), ArtifactPath: "/plan.json"}
			nonce := generatedVectorID(231)
			ctx := installedAdministrativeTestContext(t)
			switch scenario {
			case "zero-nonce":
				nonce = contract.ID{}
			case "nil-context":
				ctx = nil
			case "expired-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				defer cancel()
			case "unbounded-context":
				ctx = context.Background()
			case "closed-parent":
				if err := session.Close(); err != nil {
					t.Fatal("early close failed")
				}
			case "reused-parent":
				first := session.Plan(ctx, generatedVectorID(232), request)
				if first.Result.Outcome != EvidenceUnavailable || first.Query == nil || reader.reads.Load() != 1 {
					t.Fatal("first invocation did not establish used parent")
				}
			}
			before := reader.reads.Load()
			out := session.Plan(ctx, nonce, request)
			if out.Operation != AdministrativePlan || out.RequestID != nonce || out.Result != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) || out.StateResult != AdministrativeRefused || out.PreAdmission != nil || out.Plan != nil || out.List != nil || out.Receipt != nil || out.End != nil || reader.reads.Load() != before {
				t.Fatal("early parent refusal changed operation or read again")
			}
			if scenario == "zero-nonce" {
				if out.Query != nil || !out.RequestIdentity.IsZero() || !out.OperationID.IsZero() {
					t.Fatal("zero nonce acquired a query")
				}
			} else if out.Query == nil || out.Query.Observation != nil || out.Query.RequestNonce != nonce || out.Query.TargetGroupID != request.TargetGroupID || out.Query.ArtifactPath != request.ArtifactPath || out.RequestIdentity != out.Query.Digest || out.RequestIdentity.IsZero() || out.OperationID.IsZero() {
				t.Fatal("early refusal discarded an otherwise valid query")
			}
			if err := session.Close(); err != nil {
				t.Fatal("reader close failed")
			}
			if reader.closes.Load() != 1 {
				t.Fatal("early refusal lost reader ownership")
			}
		})
	}
}
