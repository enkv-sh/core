package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func completePlanningResult() compositionfull.ConfigurationPlanningResult {
	id := contract.Hash([]byte("planning observation"))
	return compositionfull.ConfigurationPlanningResult{PlanningResult: core.PlanningResult{Context: core.ReaderOperationContext{Operation: contract.PlanningOperation}, StateResult: contract.ReaderSuccess, PlanningPayload: contract.PlanningPayload{ComparisonPayload: contract.ComparisonPayload{Observation: &contract.ComparisonObservation{DomainID: id, HeadRevisionID: id, SnapshotID: id}, Verdict: contract.ComparisonMatch, DiagnosticsComplete: true, EvidenceLimit: contract.PlanningEvidenceLimit}, PrivateComplete: true, DisplayDelivery: contract.PlanningNotRequested}}, InstallationRequirements: compositionfull.InstallationRequirementComparison{Differences: []compositionfull.InstallationRequirementDifference{}}}
}

// full_only: false
func TestPlanPrivateFlagGrammar(t *testing.T) {
	for _, extra := range [][]string{{"--show-secret", "a"}, {"--check-secrets", "--show-secret", "a", "--show-secret", "a"}, {"--check-secrets", "--show-secret"}} {
		var out, diagnostic bytes.Buffer
		args := append([]string{"--trusted", "/absent", "--trusted-format", "json"}, extra...)
		if code := runPlan(args, &out, &diagnostic); code != 2 || !strings.Contains(diagnostic.String(), "--trusted") {
			t.Fatal("invalid private grammar reached execution", code)
		}
	}
	names := planSecretNames{}
	if err := names.Set(""); err != nil {
		t.Fatal(err)
	}
	if err := names.Set("é/\n"); err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "" || names[1] != "é/\n" {
		t.Fatal("exact selector presence lost")
	}
}

// full_only: false
func TestPlanDisplayTerminalFollowsFinalization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var diagnostic bytes.Buffer
	out, err := os.Create(filepath.Join(t.TempDir(), "stream"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	}()
	factory, _ := compositionfull.NewPlanningDisplayFile(out, true)
	sink, err := factory.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sinkClosed := false
	defer func() {
		if !sinkClosed {
			if err := sink.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	if err := sink.Accept(ctx, "", contract.PlanningRetained, []byte{0, 255}); err != nil {
		t.Fatal(err)
	}
	sinkClosed = true
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	result := completePlanningResult()
	result.DisplayDelivery = contract.PlanningDeliveryComplete
	result.SelectedRecords = 1
	result.CompletedRecords = 1
	result.PrivateEntries = []contract.PlanningRelation{{Name: "", Form: contract.PlanningRetained, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}}
	if code := writePlanningOutcome(ctx, result, true, true, out, &diagnostic); code != 0 {
		t.Fatal("complete stream failed", code)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(body, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal("stream record count differs")
	}
	var terminal struct {
		Kind   string
		Result json.RawMessage
	}
	if json.Unmarshal(lines[1], &terminal) != nil || terminal.Kind != "plan-result" || !json.Valid(terminal.Result) || bytes.Contains(terminal.Result, []byte("AP8=")) {
		t.Fatal("safe terminal differs")
	}
	var ordinary bytes.Buffer
	if code := writePlanningOutcomeWithOutput(ctx, completePlanningResult(), true, false, func(_ context.Context, body []byte) error { _, err := ordinary.Write(body); return err }, &diagnostic); code != 0 || !json.Valid(bytes.TrimSpace(ordinary.Bytes())) || bytes.Contains(ordinary.Bytes(), []byte(`"kind":"plan-result"`)) {
		t.Fatal("equality JSON became a display stream")
	}
}

// full_only: false
func TestPlanDisplayAndTerminalFailuresNeverReportSuccess(t *testing.T) {
	result := completePlanningResult()
	result.DisplayDelivery = contract.PlanningDeliveryComplete
	result.SelectedRecords = 1
	result.CompletedRecords = 1
	result.PrivateEntries = []contract.PlanningRelation{{Name: "", Form: contract.PlanningRetained, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}}
	var diagnostic bytes.Buffer
	if code := writePlanningOutcomeWithOutput(context.Background(), result, true, true, func(context.Context, []byte) error { return io.ErrShortWrite }, &diagnostic); code != 2 || !strings.Contains(diagnostic.String(), "output failed") {
		t.Fatal("short terminal write reported success")
	}
	for _, state := range []contract.ReaderStateResult{contract.ReaderRefused, contract.ReaderUnavailable} {
		var out bytes.Buffer
		diagnostic.Reset()
		result.StateResult = state
		result.Verdict = contract.ComparisonUnable
		result.DisplayDelivery = contract.PlanningDeliveryIncomplete
		want := 2
		if state == contract.ReaderUnavailable {
			want = 3
		}
		if code := writePlanningOutcome(context.Background(), result, true, true, &out, &diagnostic); code != want || out.Len() != 0 || !strings.Contains(diagnostic.String(), "incomplete") {
			t.Fatal("failed sink received terminal or lost safe exit", code)
		}
	}
}
