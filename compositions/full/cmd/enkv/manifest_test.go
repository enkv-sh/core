package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

func manifestCLIUnavailable() compositionfull.ManifestFileResult {
	r := compositionfull.NewManifestFileResult(core.PublicManifestResult{Context: core.ReaderOperationContext{Operation: contract.ReaderManifestOperation}, StateResult: contract.ReaderUnavailable, FailureReason: contract.ReasonSelectedObjectUnavailable})
	r.SourceCleanup = compositionfull.ManifestSourceComplete
	return r
}

// full_only: false
func TestManifestCLIConstructsDefaultExplicitAndEmptySelection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		request compositionfull.ManifestOptions
	}{
		{"default", nil, compositionfull.ManifestOptions{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}},
		{"empty-name", []string{"--name="}, compositionfull.ManifestOptions{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.ExactNames, EntryNames: []string{""}}},
		{"empty-set", []string{"--empty-selection"}, compositionfull.ManifestOptions{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.ExactNames, EntryNames: []string{}}},
		{"exact", []string{"--recipient-id=" + strings.Repeat("07", 32), "--name=z", "--name=a"}, compositionfull.ManifestOptions{TargetMode: manifest.ExactRecipient, TargetRecipientID: repeatedManifestID(7), EntryMode: manifest.ExactNames, EntryNames: []string{"a", "z"}}},
	} {
		for _, service := range []string{"", "PRIVATE/SERVICE/v1"} {
			t.Run(tc.name+"/"+service, func(t *testing.T) {
				args := append([]string{"--source=source.json", "--source-format=json", "--out=manifest.json", "--plugin=private-renderer", "--json", "--log-level=off"}, tc.args...)
				want := tc.request
				want.Plugin = "private-renderer"
				want.Settings = []byte("{}")
				if service != "" {
					args = append(args, "--service="+service)
					want.ServiceFilter = &service
				}
				calls := 0
				var out, diagnostic bytes.Buffer
				code := runManifestWithExecutor(t.Context(), args, &out, &diagnostic, func(ctx context.Context, id contract.ID, path string, format configuration.Format, request compositionfull.ManifestOptions, destination string) compositionfull.ManifestFileResult {
					calls++
					wantPath, _ := filepath.Abs("source.json")
					wantOut, _ := filepath.Abs("manifest.json")
					if id.IsZero() || path != wantPath || destination != wantOut || format != configuration.JSON || !reflect.DeepEqual(request, want) {
						t.Fatal("captured request differs", request, want)
					}
					return manifestCLIUnavailable()
				})
				if code != 3 || calls != 1 || !json.Valid(out.Bytes()) || bytes.Contains(out.Bytes(), []byte("value_base64")) {
					t.Fatal("CLI request or result differs", code, calls, diagnostic.String(), out.String())
				}
			})
		}
	}
}
func repeatedManifestID(b byte) (id contract.ID) {
	for i := range id {
		id[i] = b
	}
	return id
}

// full_only: false
func TestManifestCLIRefusesBeforeSourceOrOutputActivity(t *testing.T) {
	base := []string{"--source=missing.json", "--source-format=json", "--out=manifest.json", "--plugin=private-renderer", "--json"}
	cases := [][]string{nil, {"--source=missing.json", "--source-format=json", "--plugin=private-renderer", "--json"}, {"--source=missing.json", "--source-format=json", "--out=manifest.json", "--json"}}
	for _, extra := range [][]string{{"--settings="}, {"--settings={"}, {"--settings=" + string([]byte{0xff})}, {"--settings=" + `"` + strings.Repeat("x", 16383) + `"`}, {"--settings={}", "--settings={}"}, {"--plugin="}, {"--plugin=private-renderer", "--plugin=other-renderer"}, {"--plugin=../renderer"}, {"--plugin=" + strings.Repeat("p", 256)}, {"--service="}, {"--service=" + strings.Repeat("s", 257)}, {"--service=" + string([]byte{0xff})}, {"--service=PRIVATE/SERVICE/v1", "--service=PRIVATE/SERVICE/v1"}, {"--manifest-format="}, {"--manifest-format=unknown-private-sentinel"}, {"--manifest-format=generic-json", "--manifest-format=opentofu-tfvars-json"}, {"--out=another"}, {"--recipient-id=bad"}, {"--provider="}, {"--provider=unknown-private-sentinel"}, {"--empty-selection", "--name="}, {"--empty-selection=false"}, {"--name=x", "--name=x"}, {"--name=" + strings.Repeat("x", 257)}, {"--json"}, {"leftover"}, {"--"}, {"--unknown=private-error-sentinel"}} {
		prefix := append([]string{}, base...)
		if len(extra) > 0 && strings.HasPrefix(extra[0], "--plugin=") {
			prefix = append(prefix[:3], prefix[4:]...)
		}
		cases = append(cases, append(prefix, extra...))
	}
	cases = append(cases, []string{"--source=missing.json", "--source-format=json", "--out=-", "--plugin=private-renderer", "--json"})
	for index, args := range cases {
		calls := 0
		var out, diagnostic bytes.Buffer
		code := runManifestWithExecutor(t.Context(), args, &out, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.ManifestOptions, string) compositionfull.ManifestFileResult {
			calls++
			return manifestCLIUnavailable()
		})
		if code != 2 || calls != 0 || bytes.Contains(out.Bytes(), []byte("private-")) || bytes.Contains(diagnostic.Bytes(), []byte("private-")) {
			t.Fatal("invalid request reached activity or leaked input", args, code, calls, out.String(), diagnostic.String())
		}
		if json.Valid(out.Bytes()) != (index != 0) {
			t.Fatal("recognized refusal did not use the accepted JSON flag", args, out.String())
		}
	}
}

type manifestCLIOutputFailure struct{}

func (manifestCLIOutputFailure) Write([]byte) (int, error) {
	return 0, errors.New("private-output-sentinel")
}

// full_only: false
func TestManifestCLIOutputAndSourceFailureOverrideUnavailableWithoutRetry(t *testing.T) {
	args := []string{"--source=source.json", "--source-format=json", "--out=manifest.json", "--plugin=private-renderer", "--json", "--log-level=off"}
	for _, source := range []compositionfull.ManifestSourceCleanup{compositionfull.ManifestSourceComplete, compositionfull.ManifestSourceFailed, compositionfull.ManifestSourceUnknown} {
		for _, failOutput := range []bool{false, true} {
			var out, diagnostic bytes.Buffer
			var writer io.Writer = &out
			if failOutput {
				writer = manifestCLIOutputFailure{}
			}
			calls := 0
			code := runManifestWithExecutor(t.Context(), args, writer, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.ManifestOptions, string) compositionfull.ManifestFileResult {
				calls++
				r := manifestCLIUnavailable()
				r.SourceCleanup = source
				return r
			})
			want := 2
			if !failOutput && source == compositionfull.ManifestSourceComplete {
				want = 3
			}
			if code != want || calls != 1 || bytes.Contains(diagnostic.Bytes(), []byte("private-output-sentinel")) {
				t.Fatal("terminal failure precedence or invocation count differs", code, want, calls, diagnostic.String())
			}
		}
	}
}

func manifestCLIComplete() compositionfull.ManifestFileResult {
	selection := manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
	observation := manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}
	payload := &contract.ManifestPayload{Renderer: contract.ManifestRendererSelection{Name: "private-renderer", Version: "1.0.0", ProtocolID: contract.ID{8}, DescriptorID: contract.ID{9}, ExecutorID: contract.ID{10}, ArtifactContractID: contract.ID{11}, DependencyManifestID: contract.ID{12}, ArtifactID: contract.ID{13}, ArtifactSHA256: contract.ID{14}, ArtifactLength: 1}, FormatContractID: "PRIVATE/FORMAT/v1", ConfigContractID: "PRIVATE/SETTINGS/v1", Settings: []byte(`{}`), ArtifactLength: 12, ArtifactDigest: contract.ID{5}, EvidenceLimit: manifest.EvidenceLimit, Observation: observation, TargetRecipientID: contract.ID{4}, Selection: selection, IncludedEntries: []manifest.EntryIdentity{{Name: "a\n雪", EntryIncarnationID: manifest.ID{6}}}, ExcludedEntries: []manifest.ExcludedEntry{}}
	r := compositionfull.NewManifestFileResult(core.PublicManifestResult{Context: core.ReaderOperationContext{Operation: contract.ReaderManifestOperation}, StateResult: contract.ReaderSuccess, RequestScope: &contract.ManifestRequestScope{Renderer: payload.Renderer, FormatContractID: payload.FormatContractID, ConfigContractID: payload.ConfigContractID, Settings: payload.Settings, Selection: selection}, Observation: &observation, TargetRecipientID: payload.TargetRecipientID, Payload: payload})
	r.SourceCleanup = compositionfull.ManifestSourceComplete
	r.Delivery = compositionfull.ManifestDelivery{TargetPath: "/tmp/consumption.json", Artifact: &compositionfull.ManifestArtifact{RendererArtifactID: payload.Renderer.ArtifactID, FormatContractID: payload.FormatContractID, Length: payload.ArtifactLength, Digest: payload.ArtifactDigest}, Replacement: compositionfull.ManifestReplaced, CandidateVerification: compositionfull.ManifestVerified, InstalledVerification: compositionfull.ManifestVerified, NativeCompletion: compositionfull.ManifestNativeComplete, CandidateCleanup: compositionfull.ManifestCandidateRenamed}
	return r
}

// full_only: false
func TestManifestCLIKeepsNativeSuccessAfterSourceOrOutputFailure(t *testing.T) {
	for _, human := range []bool{false, true} {
		for _, source := range []compositionfull.ManifestSourceCleanup{compositionfull.ManifestSourceComplete, compositionfull.ManifestSourceFailed} {
			for _, failOutput := range []bool{false, true} {
				args := []string{"--source=source.json", "--source-format=json", "--out=manifest.json", "--plugin=private-renderer", "--log-level=off"}
				if !human {
					args = append(args, "--json")
				}
				var out, diagnostic bytes.Buffer
				var writer io.Writer = &out
				if failOutput {
					writer = manifestCLIOutputFailure{}
				}
				calls := 0
				r := manifestCLIComplete()
				r.SourceCleanup = source
				code := runManifestWithExecutor(t.Context(), args, writer, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.ManifestOptions, string) compositionfull.ManifestFileResult {
					calls++
					return r
				})
				want := 2
				if source == compositionfull.ManifestSourceComplete && !failOutput {
					want = 0
				}
				if code != want || calls != 1 || r.Delivery.NativeCompletion != compositionfull.ManifestNativeComplete || r.Issuance.StateResult != contract.ReaderSuccess {
					t.Fatal("late failure rewrote successful facts or repeated work", code, want, calls)
				}
				if !failOutput && (!bytes.Contains(out.Bytes(), []byte(`"native_completion":"complete"`)) || !bytes.Contains(out.Bytes(), []byte(`a\n雪`)) || bytes.Contains(out.Bytes(), []byte("value_base64")) || bytes.Contains(out.Bytes(), []byte("consumer_locator"))) {
					t.Fatal("safe native result lost facts or exposed artifact fields", out.String())
				}
			}
		}
	}
}

// full_only: false
func TestManifestCLITelemetrySetupFailureEmitsOneCorrelatedRefusal(t *testing.T) {
	for _, key := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(key, "")
	}
	args := []string{"--source=private-source-sentinel.json", "--source-format=json", "--out=private-target-sentinel.json", "--plugin=private-renderer", "--json", "--log-level=private-log-level-sentinel"}
	calls := 0
	var out, diagnostic bytes.Buffer
	code := runManifestWithExecutor(t.Context(), args, &out, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.ManifestOptions, string) compositionfull.ManifestFileResult {
		calls++
		return manifestCLIComplete()
	})
	var result struct {
		Schema   string
		Issuance struct {
			State       string `json:"state_result"`
			Operation   string `json:"operation_kind"`
			OperationID string `json:"operation_id"`
		}
		Delivery struct {
			Target      *string `json:"target_path"`
			Artifact    any
			Replacement string
		}
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || code != 2 || calls != 0 || result.Schema != "ManifestFileResult/v2" || result.Issuance.Operation != contract.ReaderManifestOperation || result.Issuance.State != "refused" || result.Issuance.OperationID == "" || result.Delivery.Target != nil || result.Delivery.Artifact != nil || result.Delivery.Replacement != "not-attempted" {
		t.Fatal("setup failure lost safe correlated refusal", err, code, calls, out.String())
	}
	if !strings.Contains(diagnostic.String(), "telemetry configuration refused") || strings.Contains(diagnostic.String(), "private-") || strings.Contains(out.String(), "private-") {
		t.Fatal("setup failure leaked input", diagnostic.String(), out.String())
	}
}

// full_only: false
func TestManifestCLISelectsInstalledRendererIndependentlyFromSourceFormat(t *testing.T) {
	for _, source := range []struct {
		name   string
		format configuration.Format
	}{{"json", configuration.JSON}, {"yaml", configuration.YAML}} {
		for _, plugin := range []string{"private-renderer", "another-renderer"} {
			t.Run(source.name+"/"+plugin, func(t *testing.T) {
				settings := `{"private_format":"custom", "size":42}`
				args := []string{"--source=source." + source.name, "--source-format=" + source.name, "--out=manifest.bytes", "--plugin=" + plugin, "--settings=" + settings, "--json", "--log-level=off"}
				calls := 0
				var out, diagnostic bytes.Buffer
				code := runManifestWithExecutor(t.Context(), args, &out, &diagnostic, func(_ context.Context, _ contract.ID, _ string, format configuration.Format, request compositionfull.ManifestOptions, _ string) compositionfull.ManifestFileResult {
					calls++
					if format != source.format || request.Plugin != plugin || string(request.Settings) != settings {
						t.Fatal("source, renderer or settings changed", request)
					}
					return manifestCLIUnavailable()
				})
				if code != 3 || calls != 1 || !json.Valid(out.Bytes()) {
					t.Fatal("renderer selection failed", code, calls, diagnostic.String())
				}
			})
		}
	}
}
