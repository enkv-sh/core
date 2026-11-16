package compositionfull

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type configurationSetInput struct {
	io.Reader
	reads, closes int
	closeErr      error
}

func (s *configurationSetInput) Read(p []byte) (int, error) { s.reads++; return s.Reader.Read(p) }
func (s *configurationSetInput) Close() error               { s.closes++; return s.closeErr }

// These local proposals use newly encoded proof-free descriptors with current
// assembly facts and the archive's canonical public keys. The signed archive
// and its selected-state evidence are never changed or claimed by these tests.
func configurationSetPair(t *testing.T, family string, format configuration.Format, edit func(map[string]any, map[string]any)) configurationReaderSource {
	t.Helper()
	source := configurationReaderPair(t, family, format, func(editable, generated map[string]any) {
		basis := generated["public_basis"].(map[string]any)
		d, err := contract.DecodeGenesisDescriptorCore(basis["descriptor"].([]byte))
		if err != nil {
			t.Fatal(err)
		}
		d = configurationCurrentDescriptor(t, d)
		body, err := contract.EncodeGenesisDescriptorCore(d)
		if err != nil {
			t.Fatal("current local proposal descriptor", err)
		}
		basis["descriptor"] = body
		if edit != nil {
			edit(editable, generated)
		}
	})
	return source
}

func configurationSetWritable(t *testing.T, s configurationReaderSource) {
	t.Helper()
	for _, p := range []string{filepath.Dir(s.path), filepath.Dir(s.generated)} {
		if err := os.Chmod(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
}
func configurationSetModel(t *testing.T, path string, format configuration.Format) *configuration.Model {
	t.Helper()
	p, err := configuration.Capture(context.Background(), path, format)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	}()
	m, err := configuration.Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func configurationSetEntry(t *testing.T, m *configuration.Model, name string) configuration.Entry {
	t.Helper()
	for _, e := range m.Entries {
		if e.Name == name {
			return e
		}
	}
	t.Fatal("selected entry absent")
	return configuration.Entry{}
}

func assertConfigurationSetTelemetry(t *testing.T, recorder *telemetry.Recorder, capability *telemetry.Capability, points chan telemetry.MetricPoint, setResult, sealResult telemetry.Result, excluded []byte) {
	t.Helper()
	status := recorder.Status()
	if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 || capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
		t.Fatal("local proposal telemetry evidence was lost")
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 256))
	var parent uint64
	starts, returns := map[telemetry.Operation]int64{}, map[telemetry.Operation]int64{}
	outerReturns, sealReturns := 0, 0
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Event == telemetry.DiagnosticStart {
			starts[record.Operation]++
			if record.Operation == telemetry.OpConfigurationWrite && record.ParentCall == 0 {
				if parent != 0 {
					t.Fatal("more than one local proposal return owner")
				}
				parent = record.Call
			}
		}
		if record.Event != telemetry.DiagnosticReturn {
			continue
		}
		returns[record.Operation]++
		if record.Call == parent {
			outerReturns++
			wantReason, wantSeverity := telemetry.DiagnosticReasonNone, "INFO"
			if setResult == telemetry.ResultWriteRefused {
				wantReason, wantSeverity = telemetry.DiagnosticReasonDenied, "WARN"
			}
			if record.Result != setResult || record.Reason != wantReason || record.SeverityText != wantSeverity {
				t.Fatal("local proposal telemetry changed result", record.Result)
			}
		}
		if record.Operation == telemetry.OpCryptoSealSource {
			sealReturns++
			wantReason, wantSeverity := telemetry.DiagnosticReasonNone, "INFO"
			if sealResult == telemetry.ResultInvalid {
				wantReason, wantSeverity = telemetry.DiagnosticReasonInvalid, "ERROR"
			}
			if record.ParentCall != parent || record.Result != sealResult || record.Reason != wantReason || record.SeverityText != wantSeverity {
				t.Fatal("public seal telemetry lost parent or result")
			}
		}
	}
	if parent == 0 || outerReturns != 1 || starts[telemetry.OpCryptoSealSource] != 1 || sealReturns != 1 {
		t.Fatal("public local proposal/seal did not each return once")
	}
	encoded, err := json.Marshal(records)
	if err != nil || bytes.Contains(encoded, excluded) || bytes.Contains(encoded, []byte("opaque-input-close")) {
		t.Fatal("confidential input or raw error entered proposal telemetry")
	}
	calls, results, durations := map[telemetry.Operation]int64{}, map[telemetry.Operation]int64{}, map[telemetry.Operation]int64{}
	for len(points) != 0 {
		point := <-points
		if point.Operation == telemetry.OpCryptoSealSource && (point.Name == telemetry.OperationInputBytes || point.Name == telemetry.OperationOutputBytes) {
			t.Fatal("public sealing telemetry recorded private lengths")
		}
		switch point.Name {
		case telemetry.OperationCalls:
			calls[point.Operation] += point.IntValue
		case telemetry.OperationResults:
			results[point.Operation] += point.IntValue
			if point.Operation == telemetry.OpCryptoSealSource && point.Result != sealResult {
				t.Fatal("public seal metric changed result")
			}
		case telemetry.OperationDuration:
			durations[point.Operation]++
		}
	}
	for _, operation := range []telemetry.Operation{telemetry.OpConfigurationWrite, telemetry.OpCryptoSealSource} {
		if starts[operation] != returns[operation] || calls[operation] != starts[operation] || results[operation] != returns[operation] || durations[operation] != returns[operation] {
			t.Fatal("public proposal telemetry call/result/duration counts differ", operation)
		}
	}
}

// full_only: false
func TestConfigurationSetLocalProposal(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, format), func(t *testing.T) {
				// A trusted complete public pair is sufficient even with no ready observation
				// and with unusable ambient cloud configuration. This is a local proposal.
				t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent"))
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent"))
				s := configurationSetPair(t, family, format, nil)
				configurationSetWritable(t, s)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				marker := []byte("local-sealed-proposal-unique-input\x00\n")
				var previous []byte
				for attempt := 0; attempt < 2; attempt++ {
					input := &configurationSetInput{Reader: bytes.NewReader(marker)}
					points := make(chan telemetry.MetricPoint, 2048)
					recorder := telemetry.NewRecorder()
					capability := telemetry.NewCapability(points, recorder)
					result, err := SetConfiguration(telemetry.WithCapability(ctx, capability), s.path, format, "new", input, SetOptions{Confidential: true})
					if err != nil {
						t.Fatal(err)
					}
					assertConfigurationSetTelemetry(t, recorder, capability, points, telemetry.ResultSuccess, telemetry.ResultSuccess, marker)
					if input.reads == 0 || input.closes != 1 || result.EditablePath != s.path || result.GeneratedPath != s.generated {
						t.Fatal("input ownership or local path result differs")
					}
					m := configurationSetModel(t, s.path, format)
					entry := configurationSetEntry(t, m, "new")
					if !entry.Secret || entry.Generated != nil || entry.Retained != nil || len(entry.Recipients) != 0 {
						t.Fatal("new supplied declaration differs")
					}
					envelope, err := contract.DecodeSealedInputEnvelope(entry.Sealed)
					if err != nil {
						t.Fatal(err)
					}
					if envelope.Core.ContentLength != uint32(len(marker)) || envelope.Core.Name != "new" || envelope.Core.DomainID != m.DomainID || envelope.Core.FileIdentity != m.FileID {
						t.Fatal("sealed exact public target differs")
					}
					if attempt > 0 && bytes.Equal(previous, entry.Sealed) {
						t.Fatal("new call reused old sealed proposal")
					}
					previous = bytes.Clone(entry.Sealed)
					for _, p := range []string{result.EditablePath, result.GeneratedPath} {
						body, err := os.ReadFile(p)
						if err != nil {
							t.Fatal(err)
						}
						if bytes.Contains(body, marker) {
							t.Fatal("confidential input escaped Crypto custody")
						}
					}
					if len(m.Entries) != 5 || configurationSetEntry(t, m, "secret").Retained == nil {
						t.Fatal("unselected rows changed")
					}
				}
				current, err := os.ReadFile(s.generated)
				if err != nil {
					t.Fatal(err)
				}
				var before, after map[string]json.RawMessage
				if json.Unmarshal(s.generatedBytes, &before) != nil || json.Unmarshal(current, &after) != nil || len(before) != len(after) {
					t.Fatal("generated public field set changed")
				}
				for key, body := range before {
					if key != "secrets" && !bytes.Equal(body, after[key]) {
						t.Fatal("unrelated generated public bytes changed", key)
					}
				}
				var beforeSecrets, afterSecrets map[string]json.RawMessage
				if json.Unmarshal(before["secrets"], &beforeSecrets) != nil || json.Unmarshal(after["secrets"], &afterSecrets) != nil || len(afterSecrets) != len(beforeSecrets)+1 {
					t.Fatal("generated secret record set differs")
				}
				for name, body := range beforeSecrets {
					if !bytes.Equal(body, afterSecrets[name]) {
						t.Fatal("unselected encrypted record bytes changed", name)
					}
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationSetPlainAndSelectedMissingSecret(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, encoded := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", format, encoded), func(t *testing.T) {
				s := configurationSetPair(t, "aws", format, func(_, generated map[string]any) { delete(generated["secrets"].(map[string]any), "secret") })
				configurationSetWritable(t, s)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				want := []byte{0, 255, 10, 65}
				body := want
				retained := want
				encoding := contract.InputEncodingRaw
				if encoded {
					body = []byte(base64.StdEncoding.EncodeToString(want))
					retained = []byte("AP8KQQ==")
					encoding = contract.InputEncodingBase64
				}
				input := &configurationSetInput{Reader: bytes.NewReader(body)}
				result, err := SetConfiguration(ctx, s.path, format, "secret", input, SetOptions{Base64: encoded})
				if err != nil {
					t.Fatal(err)
				}
				if input.closes != 1 || result.GeneratedPath != s.generated {
					t.Fatal("plain reuse or input ownership differs")
				}
				body, renderErr := RenderSetJSON(result, nil)
				var local struct {
					LocalEdit string          `json:"local_edit"`
					Outcome   string          `json:"outcome"`
					Operation string          `json:"operation_kind"`
					Payload   json.RawMessage `json:"payload"`
				}
				if renderErr != nil || json.Unmarshal(body, &local) != nil || local.LocalEdit != "plain" || local.Outcome != "edited" || local.Operation != "" || local.Payload != nil || result.Confidential || result.Payload != nil {
					t.Fatal("plain editing acquired confidential artifact meaning")
				}

				m := configurationSetModel(t, s.path, format)
				entry := configurationSetEntry(t, m, "secret")
				if entry.Secret || entry.Generated != nil || !bytes.Equal(entry.Plain, retained) || entry.InputEncoding != encoding || entry.ContentLength != uint32(len(want)) || len(entry.Recipients) != 1 {
					t.Fatal("plain selected replacement differs")
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationSetPreflightOwnsUnreadInput(t *testing.T) {
	for _, condition := range []string{"bad-basis", "unrelated-present-invalid-secret", "entry-capacity", "bad-authority-key", "no-deadline"} {
		t.Run(condition, func(t *testing.T) {
			s := configurationSetPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
				switch condition {
				case "bad-basis":
					generated["public_basis"].(map[string]any)["descriptor"] = []byte{1}
				case "unrelated-present-invalid-secret":
					generated["secrets"].(map[string]any)["encoded"] = map[string]any{"sealed": []byte{1}}
				case "entry-capacity":
					entries := editable["entries"].(map[string]any)
					for len(entries) < 512 {
						entries[fmt.Sprintf("extra%03d", len(entries))] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": ""}}
					}
					editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}, "groups": []any{}}
					delete(generated, "canonical_records")
				case "bad-authority-key":
					generated["domain"].(map[string]any)["authority"].(map[string]any)["encryption"].(map[string]any)["selector"] = "different-selector"
				}
			})
			configurationSetWritable(t, s)
			if condition == "entry-capacity" {
				model := configurationSetModel(t, s.path, configuration.JSON)
				if len(model.Entries) != 512 || len(model.Outputs) != 0 || len(model.Routes) != 0 {
					t.Fatal("capacity fixture is not a complete valid pair with exactly 512 entries and no output routes")
				}
				*model = configuration.Model{}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			callCtx := ctx
			if condition == "no-deadline" {
				callCtx = context.Background()
			}
			input := &configurationSetInput{Reader: strings.NewReader("must-remain-unread")}
			result, err := SetConfiguration(callCtx, s.path, configuration.JSON, "new", input, SetOptions{Confidential: true})
			if err == nil || !configurationSetUndelivered(result) {
				t.Fatal("invalid source accepted")
			}
			if condition == "entry-capacity" && !errors.Is(err, configuration.ErrEditBounds) {
				t.Fatal("entry capacity did not refuse at the candidate bound", err)
			}
			if input.reads != 0 || input.closes != 1 {
				t.Fatal("preflight read input or lost accepted ownership")
			}
			s.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationSetInputFailureLeavesSource(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		for _, condition := range []string{"read", "close", "base64", "over-limit", "decoded-one-over"} {
			t.Run(fmt.Sprintf("confidential-%t/%s", confidential, condition), func(t *testing.T) {
				source := configurationSetPair(t, "aws", configuration.JSON, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				input := &configurationSetInput{Reader: strings.NewReader("plain")}
				options := SetOptions{Confidential: confidential}
				switch condition {
				case "read":
					input.Reader = configurationSetReadError{}
				case "close":
					input.closeErr = errors.New("opaque-input-close")
				case "base64":
					options.Base64 = true
					input.Reader = strings.NewReader("AB==")
				case "over-limit":
					input.Reader = bytes.NewReader(make([]byte, contract.CryptoMaxRawValue+1))
				case "decoded-one-over":
					options.Base64 = true
					input.Reader = strings.NewReader(strings.Repeat("A", 87384))
				}
				var recorder *telemetry.Recorder
				var capability *telemetry.Capability
				var points chan telemetry.MetricPoint
				if confidential && condition == "base64" {
					points = make(chan telemetry.MetricPoint, 2048)
					recorder = telemetry.NewRecorder()
					capability = telemetry.NewCapability(points, recorder)
					ctx = telemetry.WithCapability(ctx, capability)
				}
				result, err := SetConfiguration(ctx, source.path, configuration.JSON, "new", input, options)
				if err == nil || !configurationSetUndelivered(result) {
					t.Fatal("failed input accepted")
				}
				if input.closes != 1 {
					t.Fatal("input close owner lost")
				}
				if recorder != nil {
					assertConfigurationSetTelemetry(t, recorder, capability, points, telemetry.ResultWriteRefused, telemetry.ResultInvalid, []byte("AB=="))
				}
				source.assertUnchanged(t)
			})
		}
	}
}

type configurationSetReadError struct{}

func (configurationSetReadError) Read([]byte) (int, error) { return 0, errors.New("opaque-input-read") }

// full_only: false
func TestConfigurationSetRequiresOnlyLocalPreparationFacts(t *testing.T) {
	baseline := configurationSetPair(t, "aws", configuration.JSON, nil)
	configurationSetWritable(t, baseline)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	model, err := configuration.Parse(ctx, baseline.pair)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := configurationPublicBasis(model); err != nil || !validResolvedConfiguration(ctx, model) {
		t.Fatal("valid baseline did not pass installed public/basis admission", err)
	}
	*model = configuration.Model{}
	baselineInput := &configurationSetInput{Reader: configurationSetReadError{}}
	baselineResult, baselineErr := SetConfiguration(ctx, baseline.path, configuration.JSON, "new", baselineInput, SetOptions{Confidential: true})
	if baselineErr == nil || !configurationSetUndelivered(baselineResult) || baselineInput.reads == 0 || baselineInput.closes != 1 {
		t.Fatal("valid baseline did not reach the controlled input stage", baselineInput.reads, baselineInput.closes)
	}
	baseline.assertUnchanged(t)

	for _, condition := range []string{"absent-generator", "absent-output", "malformed-common", "malformed-canonical"} {
		t.Run(condition, func(t *testing.T) {
			s := configurationSetPair(t, "aws", configuration.JSON, func(editable, _ map[string]any) {
				switch condition {
				case "absent-generator":
					entries := editable["entries"].(map[string]any)
					entries["unrelated-private"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{
						"kind": "generated", "plugin": "private-set-generator-absent", "epoch": 1, "retirement": "manual", "settings": map[string]any{"opaque": "generator settings"},
					}}
				case "absent-output":
					destinations := editable["outputs"].(map[string]any)["destinations"].(map[string]any)
					destinations["unrelated-private"] = map[string]any{"plugin": "private-set-output-absent", "settings": map[string]any{"opaque": "output settings"}}
				}
			})
			configurationSetWritable(t, s)
			inputExpected := condition == "absent-generator" || condition == "absent-output"
			if !inputExpected {
				var editable map[string]any
				if err := json.Unmarshal(s.editableBytes, &editable); err != nil {
					t.Fatal(err)
				}
				destinations := editable["outputs"].(map[string]any)["destinations"].(map[string]any)
				if condition == "malformed-common" {
					destinations["unrelated-private"] = map[string]any{"plugin": "private-set-output-absent", "settings": map[string]any{}, "unexpected": true}
				} else {
					destinations["unrelated-private"] = map[string]any{"plugin": nil, "canonical": map[string]any{"settings": map[string]any{}}}
					var generated map[string]any
					if err := json.Unmarshal(s.generatedBytes, &generated); err != nil {
						t.Fatal(err)
					}
					configurationCanonicalBacking(generated, "outputs", "unrelated-private", []byte{0, 2})
					generatedBody, err := json.Marshal(generated)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(s.generated, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(s.generated, generatedBody, 0600); err != nil {
						t.Fatal(err)
					}
					s.generatedBytes = generatedBody
				}
				body, err := json.Marshal(editable)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(s.path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(s.path, body, 0600); err != nil {
					t.Fatal(err)
				}
				s.editableBytes = body
			}
			input := &configurationSetInput{Reader: configurationSetReadError{}}
			result, err := SetConfiguration(ctx, s.path, configuration.JSON, "new", input, SetOptions{Confidential: true})
			var failure *SetError
			stage := "source"
			if inputExpected {
				stage = "input"
			}
			if !errors.As(err, &failure) || failure.reason != stage || !configurationSetUndelivered(result) || result.PreAdmission == nil || result.PreAdmission.Stage != stage || (input.reads > 0) != inputExpected || input.closes != 1 {
				t.Fatal("local preparation dependency or malformed-source boundary differs", input.reads, input.closes)
			}
			s.assertUnchanged(t)
		})
	}
}

func configurationSetUndelivered(r *SetResult) bool {
	return r != nil && r.StateResult != SetSuccess && r.Payload == nil && r.EditablePath == "" && r.GeneratedPath == ""
}
