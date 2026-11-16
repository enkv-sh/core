package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func initRefusalResult() compositionfull.InitializationResult {
	return compositionfull.InitializationResult{PublicInitializationResult: core.PublicInitializationResult{
		Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.InitializationRefused, EffectSummary: "effect-no-change"}}
}

// full_only: false
func TestInitRejectsInvalidSourceSelectionBeforeOpening(t *testing.T) {
	for _, args := range [][]string{{"--source", ""}, {"--source", "/source"}, {"--source", "/source", "--source-format", "automatic"},
		{"--source", "/source", "--source-format", "json", "unexpected"},
		{"--source", "/source", "--source-format", "json", "--credentials", "private"}, {"--source", "/source", "--source-format", "json", "--recovery=false"}} {
		var out, diagnostic bytes.Buffer
		code := runInitWithInitializer(t.Context(), args, &out, &diagnostic, func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error) {
			t.Fatal("invalid command opened initialization")
			return compositionfull.InitializationResult{}, nil
		})
		if code != 2 || !strings.Contains(out.String(), "Initialization: refused") || !strings.Contains(diagnostic.String(), "--source") {
			t.Fatal("ambiguous initialization input accepted", code, out.String(), diagnostic.String())
		}
	}
}

// full_only: false
func TestInitMalformedSourceReturnsSafeRefusalWithoutChangingIt(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.json")
	body := []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	code := runInit([]string{"--source", source, "--source-format", "json", "--json"}, &out, &diagnostic)
	var result struct {
		Schema      string         `json:"schema"`
		State       string         `json:"state_result"`
		Payload     string         `json:"operation_payload"`
		OperationID string         `json:"operation_id"`
		Identity    map[string]any `json:"request_identity"`
		Replay      string         `json:"replay_identity"`
		Delivery    struct {
			Outcome string `json:"outcome"`
		} `json:"local_delivery"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || code != 2 || result.Schema != "ProductResult/v1" || result.State != "refused" || result.Payload != "none" {
		t.Fatal("wrong malformed-source result", code, out.String())
	}
	if len(result.OperationID) != 64 || result.Identity["schema"] != "PreAdmissionRequestIdentity/v1" || result.Identity["operation_id"] != result.OperationID || result.Replay != "none" {
		t.Error("malformed init source lost pre-admission identity")
	}
	if result.Delivery.Outcome != "not-attempted" || strings.Contains(diagnostic.String(), "local delivery is incomplete") || strings.Contains(diagnostic.String(), "recovery instructions") {
		t.Error("parse refusal invented an attempted local delivery", result.Delivery.Outcome, diagnostic.String())
	}
	for _, output := range [][]byte{out.Bytes(), diagnostic.Bytes()} {
		if bytes.Contains(output, []byte("secret-sentinel")) || bytes.Contains(output, []byte("raw-parser-error-sentinel")) {
			t.Fatal("source values escaped refusal")
		}
	}
	actual, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("invalid initialization changed source", err)
	}
}

// full_only: false
func TestInitPreservesRemoteAndLocalUnknownFactsWithoutRetry(t *testing.T) {
	for _, mode := range []string{"remote-unknown", "local-unknown", "local-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			var out, diagnostic bytes.Buffer
			calls := 0
			code := runInitWithInitializer(ctx, []string{"--source", "/source/config.yaml", "--source-format", "yaml", "--json"}, &out, &diagnostic,
				func(ctx context.Context, path string, format configuration.Format) (compositionfull.InitializationResult, error) {
					calls++
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Minute || path != "/source/config.yaml" || format != configuration.YAML {
						t.Fatal("command lost finite context or exact source")
					}
					result := initRefusalResult()
					result.EditablePath, result.GeneratedPath, result.ManifestPath = path, "/source/.enkv/generated.json", "/source/.enkv/manifest.init"
					result.DeliveryAttempted = true
					if mode == "remote-unknown" {
						result.StateResult = contract.InitializationCommitUnknown
						result.Result = core.Result{Outcome: core.UnresolvedCommit, Reason: core.WriteUncertain, RequestedRevision: contract.ID{2}, CommitMayHaveOccurred: true}
						result.OperationID = contract.ID{1}
						return result, nil
					}
					if mode == "local-unknown" {
						return result, errors.Join(errors.New("raw-error-sentinel secret-sentinel"), &configuration.UnknownEdit{})
					}
					return result, errors.New("raw-error-sentinel secret-sentinel")
				})
			want := 3
			if mode == "local-failure" {
				want = 2
			}
			var record struct {
				State         string `json:"state_result"`
				Payload       string `json:"operation_payload"`
				CommitUnknown bool   `json:"commit_may_have_occurred"`
				Delivery      struct {
					Outcome   string `json:"outcome"`
					Editable  string `json:"editable_path"`
					Generated string `json:"generated_path"`
					Manifest  string `json:"manifest_path"`
				} `json:"local_delivery"`
			}
			if json.Unmarshal(out.Bytes(), &record) != nil || code != want || calls != 1 || record.Payload != "none" || record.Delivery.Editable != "/source/config.yaml" || record.Delivery.Generated != "/source/.enkv/generated.json" || record.Delivery.Manifest != "/source/.enkv/manifest.init" {
				t.Fatal("unknown result lost exact delivery or retried", code, calls, out.String())
			}
			if mode == "remote-unknown" && (record.State != "commit-outcome-unknown" || !record.CommitUnknown) || mode == "local-unknown" && (record.State != "refused" || record.Delivery.Outcome != "unknown") {
				t.Fatal("local and canonical uncertainty were conflated")
			}
			for _, output := range [][]byte{out.Bytes(), diagnostic.Bytes()} {
				if bytes.Contains(output, []byte("raw-error-sentinel")) || bytes.Contains(output, []byte("secret-sentinel")) {
					t.Fatal("raw error escaped command")
				}
			}
		})
	}
}

// full_only: false
func TestInitOutputFailureAndTelemetryRefusalAreClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, out := range []io.Writer{commandShortWriter{}, &commandNewlineShortWriter{}} {
		calls := 0
		var diagnostic bytes.Buffer
		code := runInitWithInitializer(ctx, []string{"--source", "/source", "--source-format", "json", "--json"}, out, &diagnostic,
			func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error) {
				calls++
				return initRefusalResult(), nil
			})
		if code != 2 || calls != 1 || !strings.Contains(diagnostic.String(), "init output failed") {
			t.Fatal("short output returned success or retried", code, calls)
		}
	}
	var out, diagnostic bytes.Buffer
	code := runInitWithInitializer(ctx, []string{"--source", "/source", "--source-format", "json", "--telemetry-config", "/absent/telemetry.json"}, &out, &diagnostic,
		func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error) {
			t.Fatal("invalid telemetry entered initialization")
			return compositionfull.InitializationResult{}, nil
		})
	if code != 2 || !strings.Contains(out.String(), "Initialization: refused") || !strings.Contains(diagnostic.String(), "telemetry configuration refused") {
		t.Fatal("invalid telemetry entered command", code)
	}
	if runInitWithInitializer(ctx, []string{"--source", "/source", "--source-format", "json"}, nil, &diagnostic, func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error) {
		t.Fatal("missing output entered initialization")
		return compositionfull.InitializationResult{}, nil
	}) != 2 {
		t.Fatal("missing output accepted")
	}
}
