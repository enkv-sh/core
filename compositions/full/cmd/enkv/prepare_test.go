package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

const prepareAWSNormal = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
const prepareGCPNormal = "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/signing/cryptoKeyVersions/1"

func prepareCommandRecord(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal("prepare did not return one structured result", err)
	}
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	want := []string{"branch", "dependencies", "diagnostics", "local_delivery", "missing_inputs", "operation", "outcome", "recovery", "request_id", "schema"}
	if !reflect.DeepEqual(keys, want) || record["schema"] != "enkv/prepare-result/v2" || record["operation"] != "prepare" {
		t.Fatal("prepare emitted another result family", record)
	}
	if _, ok := record["missing_inputs"].([]any); !ok {
		t.Fatal("prepare lost its complete missing-input vector")
	}
	id, ok := record["request_id"].(string)
	if !ok {
		t.Fatal("prepare lost request correlation")
	}
	if _, ok := parseID(id); !ok {
		t.Fatal("prepare lost nonzero request correlation")
	}
	return record
}

// full_only: false
func TestPrepareCLIUpgradeAcceptsOneFlagAndRejectsRepeats(t *testing.T) {
	for _, condition := range []struct {
		name    string
		flags   []string
		calls   int
		upgrade bool
	}{
		{"upgrade", []string{"--upgrade"}, 1, true},
		{"upgrade-false", []string{"--upgrade=false"}, 1, false},
		{"repeated-upgrade", []string{"--upgrade", "--upgrade=false"}, 0, false},
	} {
		t.Run(condition.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			path := filepath.Join(t.TempDir(), "configuration.json")
			args := append([]string{"--source", path, "--source-format", "json", "--json", "--log-level", "off"}, condition.flags...)
			var out, diagnostic bytes.Buffer
			calls := 0
			code := runPrepareWithCoordinator(ctx, args, &out, &diagnostic, func(_ context.Context, request compositionfull.PrepareRequest) (*compositionfull.PrepareResult, error) {
				calls++
				if request.Source != path || request.Format != configuration.JSON || request.Recovery != nil || request.Upgrade != condition.upgrade {
					t.Fatal("upgrade changed source or recovery inputs", request)
				}
				return compositionfull.NewPrepareRefusal()
			})
			if calls != condition.calls || code != 2 {
				t.Fatal("upgrade flag dispatch differs", calls, code)
			}
			prepareCommandRecord(t, out.Bytes())
		})
	}
}

// full_only: false
func TestPrepareCLIRejectsInvalidSingletonsBeforeCoordinator(t *testing.T) {
	base := []string{"--source", filepath.Join(t.TempDir(), "configuration.json"), "--source-format", "json", "--json", "--log-level", "off"}
	for _, condition := range []struct {
		name  string
		extra []string
	}{
		{"unknown", []string{"--selection", "private-selection-sentinel"}},
		{"repeated-source", []string{"--source", "/private-repeated-source-sentinel"}},
		{"repeated-json-false", []string{"--json=false"}},
		{"incomplete-recovery", []string{"--name", "restored"}},
		{"missing-prefix", []string{"--name", "restored", "--provider", "aws", "--bucket", "fixture-bucket", "--region", "us-east-1", "--normal-signing-key", prepareAWSNormal}},
		{"empty-signing", []string{"--name", "restored", "--provider", "aws", "--bucket", "fixture-bucket", "--region", "us-east-1", "--prefix", "fixture", "--normal-signing-key", ""}},
		{"zero-pin", []string{"--name", "restored", "--provider", "aws", "--bucket", "fixture-bucket", "--region", "us-east-1", "--prefix", "fixture", "--normal-signing-key", prepareAWSNormal, "--expected-domain", strings.Repeat("0", 64)}},
		{"gcp-owner", []string{"--name", "restored", "--provider", "gcp", "--bucket", "fixture-bucket", "--region", "us-central1", "--prefix", "fixture", "--normal-signing-key", prepareGCPNormal, "--expected-owner", "123456789012"}},
	} {
		t.Run(condition.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			calls := 0
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			code := runPrepareWithCoordinator(ctx, append(append([]string(nil), base...), condition.extra...), &out, &diagnostic,
				func(context.Context, compositionfull.PrepareRequest) (*compositionfull.PrepareResult, error) {
					calls++
					return nil, errors.New("private-coordinator-sentinel")
				})
			record := prepareCommandRecord(t, out.Bytes())
			if code != 2 || calls != 0 || record["branch"] != "unclassified" || record["outcome"] != "refused" || !reflect.DeepEqual(record["diagnostics"], []any{map[string]any{"reason": "invalid-request", "subject": "request"}}) {
				t.Fatal("invalid CLI input reached preparation", code, calls, record)
			}
			for _, sentinel := range []string{"private-selection-sentinel", "private-repeated-source-sentinel", "private-coordinator-sentinel"} {
				if bytes.Contains(out.Bytes(), []byte(sentinel)) || bytes.Contains(diagnostic.Bytes(), []byte(sentinel)) {
					t.Fatal("untrusted CLI text entered public output")
				}
			}
		})
	}
}

// full_only: false
func TestPrepareCLIPreservesTypedRecoveryInputs(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configuration.json")
			region, normal, family := "us-east-1", prepareAWSNormal, contract.AWS
			if provider == "gcp" {
				region, normal, family = "us-central1", prepareGCPNormal, contract.GCP
			}
			args := []string{"--source", path, "--source-format", "yaml", "--json", "--log-level", "off", "--name", "restored", "--provider", provider, "--bucket", "fixture-bucket", "--region", region, "--prefix", "fixture", "--normal-signing-key", normal, "--expected-domain", strings.Repeat("a", 64)}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var out, diagnostic bytes.Buffer
			calls := 0
			code := runPrepareWithCoordinator(ctx, args, &out, &diagnostic, func(ctx context.Context, request compositionfull.PrepareRequest) (*compositionfull.PrepareResult, error) {
				calls++
				if _, finite := ctx.Deadline(); !finite {
					t.Fatal("CLI lost finite invocation")
				}
				r := request.Recovery
				if request.Source != path || request.Format != configuration.YAML || r == nil || r.Provider != family || r.Name != "restored" || r.Bucket != "fixture-bucket" || r.Region != region || r.Prefix == nil || *r.Prefix != "fixture" || r.NormalSigningKey == nil || *r.NormalSigningKey != normal || r.ExpectedDomain == nil || idText(*r.ExpectedDomain) != strings.Repeat("a", 64) || r.RecoverySigningKey != nil || r.ExpectedOwner != nil || r.ExpectedAuthorityEncryptionKey != nil {
					t.Fatal("CLI changed independent recovery inputs", request)
				}
				return compositionfull.NewPrepareRefusal()
			})
			if code != 2 || calls != 1 {
				t.Fatal("valid CLI inputs failed dispatch", code, calls, diagnostic.String())
			}
			prepareCommandRecord(t, out.Bytes())
		})
	}
}

type prepareShortWriter struct{}

func (prepareShortWriter) Write(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	return len(body) - 1, nil
}

// full_only: false
func TestPrepareCLIPresentationFailurePreservesUnavailableFacts(t *testing.T) {
	for _, structured := range []bool{false, true} {
		t.Run(map[bool]string{false: "human", true: "json"}[structured], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "configuration.json")
			if err := os.WriteFile(path, []byte("private-source-sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, ".enkv-pending"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ".enkv-pending", filepath.Base(path)), []byte("private-marker-sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--source", path, "--source-format", "json", "--log-level", "off"}
			if structured {
				args = append(args, "--json")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var retained *compositionfull.PrepareResult
			var before []byte
			var diagnostic bytes.Buffer
			code := runPrepareWithCoordinator(ctx, args, prepareShortWriter{}, &diagnostic, func(ctx context.Context, r compositionfull.PrepareRequest) (*compositionfull.PrepareResult, error) {
				var err error
				retained, err = compositionfull.PrepareConfiguration(ctx, r)
				before, _ = compositionfull.RenderPrepareJSON(retained)
				return retained, err
			})
			after, err := compositionfull.RenderPrepareJSON(retained)
			if code != 3 || err != nil || !bytes.Equal(before, after) || compositionfull.PrepareExitCode(retained, io.ErrShortWrite) != 3 {
				t.Fatal("short write erased unavailable operation facts", code, err)
			}
			record := prepareCommandRecord(t, after)
			if record["branch"] != "unclassified" || record["local_delivery"].(map[string]any)["recovery_source"] != nil {
				t.Fatal("foreign pending marker supplied a recovery source", record)
			}
			if strings.Contains(diagnostic.String(), "private-") {
				t.Fatal("private source or marker entered CLI diagnostic")
			}
		})
	}
}

// full_only: false
func TestPrepareCLITelemetrySetupRefusesBeforeCoordinator(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var out, diagnostic bytes.Buffer
	code := runPrepareWithCoordinator(ctx, []string{"--source", filepath.Join(t.TempDir(), "configuration.json"), "--source-format", "json", "--json", "--log-level", "private-invalid-level-sentinel"}, &out, &diagnostic,
		func(context.Context, compositionfull.PrepareRequest) (*compositionfull.PrepareResult, error) {
			t.Fatal("telemetry setup failure entered preparation")
			return nil, nil
		})
	if code != 2 || !strings.Contains(diagnostic.String(), "telemetry configuration refused") || strings.Contains(diagnostic.String(), "private-invalid-level-sentinel") {
		t.Fatal("telemetry refusal changed safe CLI facts", code, diagnostic.String())
	}
	prepareCommandRecord(t, out.Bytes())
}
