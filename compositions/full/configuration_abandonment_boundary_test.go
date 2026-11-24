package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestAdministrativeApplyPreAdmissionKeepsActualCoreBoundary(t *testing.T) {
	fixture := installedarchive.LoadAdministrative(t, "aws")
	var basis struct {
		Descriptor []byte `json:"descriptor"`
	}
	if json.Unmarshal(fixture.Basis, &basis) != nil {
		t.Fatal("fixture basis")
	}
	descriptor, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name    string
		outcome core.Outcome
		code    contract.DiagnosticReason
	}{
		{"denied", core.EvidenceUnavailable, contract.ReasonEvidenceUnavailable},
		{"object", core.IntegrityFailure, contract.ReasonSelectedObjectInvalid},
		{"proof", core.IntegrityFailure, contract.ReasonProofInvalid},
		{"stale", core.AdmissionRefused, contract.ReasonReadContention},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := protectedConfigurationTestDirectory(t)
			source := WriteAdministrativeFixtureSource(t, fixture, dir)
			testtrust.AdministrativeNativeCredentials(t, dir, "aws", "boundary")
			h, transport := testtrust.NewAdministrativeMutationHTTP(t, fixture.Before.Archive.Location, administrativeHTTPObjects(fixture.Before.Archive), descriptor.NormalSigning)
			planPath := filepath.Join(dir, "plan.json")
			plan := administrativeSourceCall(t, source, AbandonmentRequest{Operation: core.AdministrativePlan, TargetGroupID: fixture.GroupID, ArtifactPath: planPath}, transport)
			if plan.Operation.Plan == nil || !plan.Delivery.PlanReadback {
				t.Fatal("actual valid plan fixture", plan.Operation.Result)
			}
			headKey := fixture.Before.Archive.Location.PrefixBeforeHEAD + "/HEAD"
			head, err := format.DecodeHead(fixture.Before.Archive.MustObject(t, headKey).Body)
			if err != nil {
				t.Fatal(err)
			}
			rootKey, err := format.Key(fixture.Before.Archive.Location.PrefixBeforeHEAD, head.Core.Root)
			if err != nil {
				t.Fatal(err)
			}
			switch row.name {
			case "denied":
				h.Fail("denied", rootKey)
			case "object":
				h.Fail("corrupt", rootKey)
			case "proof":
				h.Fail("corrupt", headKey)
			case "stale":
				h.SetObjects(administrativeHTTPObjects(fixture.After.Archive))
			}
			out := administrativeSourceCall(t, source, AbandonmentRequest{Operation: core.AdministrativeApply, PlanPath: planPath}, transport)
			p := out.Operation
			if p.Result.Outcome != row.outcome || p.PreAdmission == nil || p.PreAdmission.Stage != "observation" || p.PreAdmission.Code != string(row.code) || p.PreAdmission.RequestNonce != p.RequestID || p.OperationID.IsZero() || !p.RequestIdentity.IsZero() || p.Query != nil || p.End != nil || p.Result.CommitMayHaveOccurred || out.Delivery.CleanupFailed {
				t.Fatal("Core refusal was relabelled as local construction input", p.Result, p.PreAdmission)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			for _, human := range []bool{false, true} {
				var body bytes.Buffer
				if human {
					err = WriteAdministrativeHuman(ctx, &body, out)
				} else {
					err = WriteAdministrativeJSON(ctx, &body, out)
				}
				if err != nil || !bytes.Contains(body.Bytes(), []byte(string(row.code))) || !bytes.Contains(body.Bytes(), []byte("observation")) || bytes.Contains(body.Bytes(), []byte("private-sentinel")) {
					t.Fatal("safe refusal rendering lost actual boundary", human, err)
				}
			}
			if creates, cas, signs := h.MutationCounts(); creates != 0 || cas != 0 || signs != 0 {
				t.Fatal("pre-admission refusal started mutation", creates, cas, signs)
			}
		})
	}
}

type abandonmentBoundaryReader struct {
	descriptor    contract.Descriptor
	reads, closes int
}

func (r *abandonmentBoundaryReader) Descriptor() contract.Descriptor { return r.descriptor }
func (*abandonmentBoundaryReader) StoreConfiguration() contract.StoreConfiguration {
	return contract.StoreConfiguration{}
}
func (r *abandonmentBoundaryReader) Read(context.Context, string, uint32) contract.ReadResult {
	r.reads++
	return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
}
func (r *abandonmentBoundaryReader) Close() { r.closes++ }

func abandonmentBoundaryRendered(t *testing.T, ctx context.Context, out AbandonmentResult, state, identity string) {
	t.Helper()
	for _, human := range []bool{false, true} {
		var body bytes.Buffer
		var err error
		if human {
			err = WriteAdministrativeHuman(ctx, &body, out)
		} else {
			err = WriteAdministrativeJSON(ctx, &body, out)
		}
		if err != nil {
			t.Errorf("recognized result did not render: human=%t bytes=%d", human, body.Len())
			continue
		}
		text := body.String()
		if strings.Contains(text, "private-sentinel") {
			t.Error("local invalid input escaped into public result")
		}
		if human {
			p := out.Operation
			if !strings.Contains(text, "abandon-plan: "+state+"\n") ||
				!strings.Contains(text, "Operation: "+readerID(p.OperationID)+".\n") ||
				(p.PreAdmission != nil && !strings.Contains(text, "Admission: "+p.PreAdmission.Stage+" / "+p.PreAdmission.Code+".\n")) {
				t.Error("human abandonment refusal lost operation, state or admission reason")
			}
			continue
		}
		var result struct {
			Schema      string          `json:"schema"`
			Operation   string          `json:"operation_kind"`
			State       string          `json:"state_result"`
			Effect      string          `json:"effect_summary"`
			Output      string          `json:"output_summary"`
			Evidence    string          `json:"evidence_ceiling"`
			Replay      string          `json:"replay_identity"`
			PayloadKind string          `json:"operation_payload"`
			Payload     json.RawMessage `json:"payload"`
			Identity    struct {
				Schema string `json:"schema"`
			} `json:"request_identity"`
			Commit bool `json:"commit_may_have_occurred"`
		}
		if json.Unmarshal([]byte(text), &result) != nil || result.Schema != "ProductResult/v1" || result.Operation != "abandon-plan" || result.State != state || result.Identity.Schema != identity || result.Effect != "not-applicable" || result.Output != "not-applicable" || result.Evidence != "unavailable" || result.Replay != "none" || result.PayloadKind != "none" || string(result.Payload) != "null" || result.Commit {
			t.Errorf("recognized result changed closed tuple: human=%t", human)
		}
	}
}

// full_only: false
func TestAbandonmentPlanLocalRefusalsKeepRecognizedResult(t *testing.T) {
	fixture := installedarchive.LoadAdministrative(t, "gcp")
	dir := protectedConfigurationTestDirectory(t)
	source := WriteAdministrativeFixtureSource(t, fixture, dir)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pair, err := configuration.Capture(ctx, source, configuration.JSON)
	if err != nil {
		t.Fatal("valid source capture failed")
	}
	t.Cleanup(func() {
		if err := pair.Close(); err != nil {
			t.Error("source close failed")
		}
	})
	model, err := configuration.Parse(ctx, pair)
	if err != nil || !model.Resolved {
		t.Fatal("local refusal fixture is not a resolved valid source")
	}
	if _, err := abandonmentSourceFacts(pair, model); err != nil {
		t.Fatal("local refusal fixture lacks independent source facts")
	}
	for _, tc := range []struct {
		name   string
		target contract.ID
		path   string
	}{
		{"zero-target", contract.ID{}, filepath.Join(dir, "plan.json")},
		{"root", fixture.GroupID, "/"},
		{"relative", fixture.GroupID, "private-sentinel.json"},
		{"nonclean", fixture.GroupID, dir + "/../private-sentinel.json"},
		{"nul", fixture.GroupID, dir + "/private-sentinel\x00.json"},
		{"invalid-utf8", fixture.GroupID, dir + "/private-sentinel\xff.json"},
		{"overlength", fixture.GroupID, "/" + strings.Repeat("a", 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nonce := contract.Hash([]byte("local plan refusal " + tc.name))
			reader := &abandonmentBoundaryReader{}
			opens, closes := 0, 0
			out := abandonConfigurationFile(ctx, nonce, source, configuration.JSON, AbandonmentRequest{Operation: core.AdministrativePlan, TargetGroupID: tc.target, ArtifactPath: tc.path}, func(_ context.Context, _ *configuration.Model, s abandonmentSource, mutation bool) (abandonmentResources, error) {
				opens++
				if mutation {
					t.Error("local plan asked for mutation resources")
				}
				reader.descriptor = s.store
				return abandonmentResources{reader: reader, close: func() error { closes++; return nil }}, nil
			}, nativeAbandonPlanIO())
			abandonmentBoundaryRendered(t, ctx, out, "refused", "PreAdmissionRequestIdentity/v1")
			p := out.Operation
			if p.Operation != core.AdministrativePlan || p.RequestID != nonce || p.OperationID.IsZero() || p.PreAdmission == nil || p.Query != nil || !p.RequestIdentity.IsZero() || p.Result != (core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}) || p.StateResult != core.AdministrativeRefused || p.Plan != nil || p.List != nil || p.End != nil || p.Receipt != nil || out.Delivery != (AbandonmentDelivery{}) || AbandonmentExitCode(out) != 2 {
				t.Errorf("local plan refusal tuple: recognized=%t nonce=%t operation-id=%t pre-admission=%t query=%t mutation-id=%t outcome=%d reason=%d exit=%d", p.Operation == core.AdministrativePlan, p.RequestID == nonce, !p.OperationID.IsZero(), p.PreAdmission != nil, p.Query != nil, !p.RequestIdentity.IsZero(), p.Result.Outcome, p.Result.Reason, AbandonmentExitCode(out))
			} else if p.PreAdmission.Stage != "declaration" || p.PreAdmission.Code != string(contract.ReasonInvalidInput) || p.PreAdmission.RequestNonce != nonce {
				t.Error("local plan refusal changed closed declaration identity")
			}
			if opens != 0 || reader.reads != 0 || reader.closes != 0 || closes != 0 {
				t.Errorf("local invalid request acquired resources: opens=%d reads=%d reader-closes=%d resource-closes=%d", opens, reader.reads, reader.closes, closes)
			}
			if err := pair.CheckUnchanged(ctx); err != nil {
				t.Error("local refusal changed the valid source pair")
			}
		})
	}
}

// full_only: false
func TestAbandonmentPlanUnavailableKeepsExactQueryAndCleanup(t *testing.T) {
	fixture := installedarchive.LoadAdministrative(t, "gcp")
	for _, scenario := range []string{"remote-unavailable", "cleanup-failure", "construction-refusal"} {
		t.Run(scenario, func(t *testing.T) {
			dir := protectedConfigurationTestDirectory(t)
			source := WriteAdministrativeFixtureSource(t, fixture, dir)
			path := filepath.Join(dir, "plan.json")
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			nonce := contract.Hash([]byte("valid plan control " + scenario))
			reader := &abandonmentBoundaryReader{}
			opens, closes := 0, 0
			failure := errors.New("private-sentinel")
			out := abandonConfigurationFile(ctx, nonce, source, configuration.JSON, AbandonmentRequest{Operation: core.AdministrativePlan, TargetGroupID: fixture.GroupID, ArtifactPath: path}, func(_ context.Context, _ *configuration.Model, s abandonmentSource, mutation bool) (abandonmentResources, error) {
				opens++
				if mutation {
					t.Error("read control asked for mutation resources")
				}
				reader.descriptor = s.store
				resources := abandonmentResources{reader: reader, close: func() error {
					closes++
					if scenario == "cleanup-failure" {
						return failure
					}
					return nil
				}}
				if scenario == "construction-refusal" {
					return resources, failure
				}
				return resources, nil
			}, nativeAbandonPlanIO())
			p := out.Operation
			if opens != 1 || reader.closes != 1 || closes != 1 || p.Operation != core.AdministrativePlan || p.RequestID != nonce || p.OperationID.IsZero() || p.Plan != nil || p.List != nil || p.End != nil || p.Receipt != nil || out.Delivery.PlanCreated || out.Delivery.PlanSynced || out.Delivery.PlanReadback || out.Delivery.PlanFailed {
				t.Fatal("valid plan control lost ownership or gained delivery", opens, reader.reads, reader.closes, closes)
			}
			if scenario == "construction-refusal" {
				abandonmentBoundaryRendered(t, ctx, out, "refused", "PreAdmissionRequestIdentity/v1")
				if reader.reads != 0 || p.Query != nil || p.PreAdmission == nil || p.PreAdmission.Stage != "construction" || p.PreAdmission.RequestNonce != nonce || !p.RequestIdentity.IsZero() || p.Result != (core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}) || out.Delivery.CleanupFailed || AbandonmentExitCode(out) != 2 {
					t.Fatal("constructor failure lost pre-admission or cleanup")
				}
				return
			}
			abandonmentBoundaryRendered(t, ctx, out, "unavailable", "QueryRequestIdentity/v1")
			if reader.reads != 1 || p.Query == nil || p.PreAdmission != nil || p.Query.Observation != nil || p.Query.RequestNonce != nonce || p.Query.TargetGroupID != fixture.GroupID || p.Query.ArtifactPath != path || p.Query.Artifact != nil || !p.Query.PlanIdentity.IsZero() || p.RequestIdentity != p.Query.Digest || p.RequestIdentity.IsZero() || p.Result.Outcome != core.EvidenceUnavailable || p.Result.Reason != core.ReadUnavailable || p.Result.StoreReason != contract.ReasonAccess || p.Result.Evidence != core.NoEvidence || p.Result.CommitMayHaveOccurred || p.StateResult != core.AdministrativeUnavailable {
				t.Fatal("unavailable plan lost exact absent-observation query")
			}
			wantExit := 3
			if scenario == "cleanup-failure" {
				wantExit = 2
			}
			if out.Delivery.CleanupFailed != (scenario == "cleanup-failure") || AbandonmentExitCode(out) != wantExit {
				t.Fatal("cleanup failure changed operation or exit join")
			}
		})
	}
}
