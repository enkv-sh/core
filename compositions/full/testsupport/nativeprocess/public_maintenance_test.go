package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
)

func nativeMaintenanceCanonicalGenerator(t *testing.T, endpoint string, generated map[string]any) map[string]any {
	t.Helper()
	config, err := hex.DecodeString("0280ab3c4fbe2f8279f592344001095c9509d7ebd749f01be042e138b1033d2f")
	if err != nil {
		t.Fatal(err)
	}
	resource := sha256.Sum256([]byte("example/local-token-resource/v1"))
	settings := []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"extension","subject":"token"}`, endpoint))
	intent := append([]byte{0, 1}, config...)
	intent = append(intent, 2)
	intent = append(intent, resource[:]...)
	intent = binary.BigEndian.AppendUint32(intent, uint32(len(settings)))
	intent = append(intent, settings...)
	nativeCanonicalBacking(generated, "generators", "TOKEN", intent)
	return map[string]any{"kind": "generated", "plugin": "private-local-token", "epoch": 0, "retirement": "manual", "canonical": map[string]any{"settings": json.RawMessage(settings)}}
}

func nativeMaintenanceCanonicalOutput(t *testing.T, endpoint string, generated map[string]any) map[string]any {
	t.Helper()
	capabilities := contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned
	binding := contract.NormalOutputBinding{DestinationID: "vault", Destination: contract.OutputDestination{ConfigContractID: "local-values-config/v1", ServiceContractID: "local-values-service/v1", CanonicalSettings: []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"extension"}`, endpoint)), Capabilities: capabilities}}
	for _, name := range []string{"PLAIN", "TOKEN"} {
		key := base64.RawURLEncoding.EncodeToString([]byte(name))
		locator := endpoint + "/values/extension/" + key
		binding.Targets = append(binding.Targets, contract.NormalOutputTarget{Name: name, Target: contract.OutputTarget{ServiceContractID: "local-values-service/v1", TargetContractID: "local-values-target/v1", CanonicalTarget: locator, ConsumerLocator: locator, TargetData: []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"extension","key":%q}`, endpoint, key)), PayloadEncoding: 1, Capabilities: capabilities, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}}})
	}
	body, err := contract.EncodeNormalOutputBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	nativeCanonicalBacking(generated, "outputs", "vault", body)
	return map[string]any{"plugin": "private-local-values", "canonical": map[string]any{"settings": json.RawMessage(binding.Destination.CanonicalSettings)}}
}

// full_only: false
func TestPublicNativeMaintenancePreservesPluginSettingsAndCanonicalMeaning(t *testing.T) {
	cli, _ := workflowBuildExecutables(t, false)
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	var builds []artifact.LocalPlugin
	for _, example := range []string{"local-token-generator", "local-value-output"} {
		directory := nativeExtensionCopyExample(t, example)
		build, _ := nativeExtensionBuildAuthor(t, directory)
		builds = append(builds, build)
	}
	for _, canonical := range []bool{false, true} {
		t.Run(map[bool]string{false: "settings", true: "canonical"}[canonical], func(t *testing.T) {
			f := newNativeExtensionCase(t, cli, builds)
			f.declare(t, 0, "manual", nil, true)
			nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, []string{"ENKV_EXAMPLE_TOKEN=" + nativeExtensionBearer}, "apply", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
			if canonical {
				generatedPath := filepath.Join(filepath.Dir(f.path), f.source["generated"].(string))
				var generated map[string]any
				nativeGeneratedReadJSON(t, generatedPath, &generated)
				f.source["entries"].(map[string]any)["TOKEN"].(map[string]any)["source"] = nativeMaintenanceCanonicalGenerator(t, f.server.URL, generated)
				f.source["outputs"].(map[string]any)["destinations"].(map[string]any)["vault"] = nativeMaintenanceCanonicalOutput(t, f.server.URL, generated)
				nativeGeneratedWriteJSON(t, generatedPath, generated)
				nativeGeneratedWriteJSON(t, f.path, f.source)
			}
			pair := workflowReadPair(t, f.path)
			captured, err := configuration.Capture(t.Context(), f.path, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			model, err := configuration.Parse(t.Context(), captured)
			if err != nil {
				t.Fatal(err)
			}
			if err := captured.Close(); err != nil {
				t.Fatal(err)
			}
			var generator *configuration.Generator
			for _, entry := range model.Entries {
				if entry.Name == "TOKEN" {
					generator = entry.Generated
				}
			}
			if generator == nil || len(model.Outputs) != 1 {
				t.Fatal("complete plugin source fixture missing")
			}
			beforeEffects := f.service.Counts()
			for _, operation := range []string{"rekey", "retire"} {
				output := nativeMaintenanceOutput(t)
				args := []string{"rekey", "--name", "TOKEN"}
				if operation == "retire" {
					args = []string{"recipients", "retire", "--recipient", "reader"}
				}
				args = append(args, "--source", f.path, "--source-format", "json", "--out", output, "--json")
				child := f.run(t, "apply", false, nil, args...)
				workflowResult(t, child, "success")
				nativeMaintenanceDelivered(t, child, output)
				if f.service.Counts() != beforeEffects {
					t.Fatal("maintenance started a generator or output effect")
				}
				workflowUnchanged(t, f.path, pair)
				readback, err := configuration.Capture(t.Context(), output, configuration.JSON)
				if err != nil {
					t.Fatal(err)
				}
				delivered, err := configuration.Parse(t.Context(), readback)
				if err != nil {
					t.Fatal(err)
				}
				if err := readback.Close(); err != nil {
					t.Fatal(err)
				}
				for _, entry := range delivered.Entries {
					if entry.Name == "TOKEN" && !reflect.DeepEqual(entry.Generated, generator) {
						t.Fatal("successor rewrote exact generator source meaning")
					}
				}
				if len(delivered.Outputs) != 1 || !bytes.Equal(delivered.Outputs[0].Settings, model.Outputs[0].Settings) || !reflect.DeepEqual(delivered.Outputs[0].Binding, model.Outputs[0].Binding) || delivered.Outputs[0].Plugin != model.Outputs[0].Plugin {
					t.Fatal("successor rewrote exact output source meaning")
				}
				// A fresh Reader has the exact source and successor but no local plugin installation.
				observed := workflowRun(t, f.store, cli, "reader", observer.Policy{NoKMS: true}, nil, args...)
				f.children = append(f.children, observed)
				var result struct {
					State       string `json:"state_result"`
					Usability   string `json:"source_usability"`
					Observation struct {
						Receipt string `json:"receipt_hex"`
						Current bool   `json:"candidate_current"`
						Checked bool   `json:"source_usability_checked"`
						Usable  bool   `json:"source_usable"`
					} `json:"maintenance_observation"`
				}
				if json.Unmarshal(observed.out, &result) != nil || observed.code != 0 || result.State != "success" || result.Usability != "confirmed" || result.Observation.Receipt == "" || !result.Observation.Current || !result.Observation.Checked || !result.Observation.Usable || f.service.Counts() != beforeEffects {
					t.Fatal("existing plugin-backed successor did not preserve exact observation")
				}
				workflowGETOnly(t, observed)
			}
			f.finish(t, len(f.children), "token/t1")
		})
	}
}

// full_only: false
func TestPublicNativeFreshGenerationCannotUseRetirementOnlySelection(t *testing.T) {
	cli, _ := workflowBuildExecutables(t, false)
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	build, _ := nativeExtensionBuildAuthor(t, nativeExtensionCopyExample(t, "local-token-generator"))
	f := newNativeExtensionCase(t, cli, []artifact.LocalPlugin{build})
	f.declare(t, 0, "manual", nil, false)
	credential := []string{"ENKV_EXAMPLE_TOKEN=" + nativeExtensionBearer}
	nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "apply", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
	generatedPath := filepath.Join(filepath.Dir(f.path), f.source["generated"].(string))
	var generated map[string]any
	nativeGeneratedReadJSON(t, generatedPath, &generated)
	canonical := nativeMaintenanceCanonicalGenerator(t, f.server.URL, generated)
	nativeGeneratedWriteJSON(t, generatedPath, generated)
	canonical["plugin"] = nil
	f.source["entries"].(map[string]any)["TOKEN"].(map[string]any)["source"] = canonical
	nativeGeneratedWriteJSON(t, f.path, f.source)
	args := []string{"apply", "--source", f.path, "--source-format", "json", "--retire-generator", "TOKEN=private-local-token", "--json"}
	beforeEffects := f.service.Counts()
	workflowResult(t, f.run(t, "apply", false, nil, args...), "no-op")
	if f.service.Counts() != beforeEffects {
		t.Fatal("canonical no-op entered a generator effect")
	}
	canonical["epoch"] = 1
	nativeGeneratedWriteJSON(t, f.path, f.source)
	beforeHead, _ := workflowHead(t, f.store)
	beforePair := workflowReadPair(t, f.path)
	refused := f.run(t, "apply", false, credential, args...)
	if refused.code != 2 {
		t.Fatal("retirement-only selection authorized epoch-advance generation", refused.code)
	}
	var result struct {
		State string `json:"state_result"`
	}
	if json.Unmarshal(refused.out, &result) != nil || result.State != "refused" || f.service.Counts() != beforeEffects {
		t.Fatal("missing current selection reached an effect or lost its refusal")
	}
	afterHead, _ := workflowHead(t, f.store)
	if !reflect.DeepEqual(beforeHead, afterHead) {
		t.Fatal("missing current selection changed canonical state")
	}
	workflowUnchanged(t, f.path, beforePair)
	delete(f.source["entries"].(map[string]any), "TOKEN")
	delete(generated["canonical_records"].(map[string]any)["generators"].(map[string]any), "TOKEN")
	nativeGeneratedWriteJSON(t, generatedPath, generated)
	nativeGeneratedWriteJSON(t, f.path, f.source)
	removed := nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, nil, args...), "retirement-pending", 3)
	if len(removed.Duties) != 1 || len(removed.Effects) != 0 || f.service.Counts() != beforeEffects {
		t.Fatal("removed entry lost its permitted NEW retirement selection")
	}
	nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "generated", "retire", "--source", f.path, "--source-format", "json", "--duty", removed.Duties[0].Facts.DutyID, "--json"), "success", 0)
	if f.service.Counts().TokenCreates != beforeEffects.TokenCreates || f.service.Counts().TokenRetires != beforeEffects.TokenRetires+1 || f.service.Counts().Tokens != 0 {
		t.Fatal("accepted exact retirement did not close only its original resource")
	}
	f.finish(t, len(f.children), "token/t1")
}

func nativeMaintenanceOutput(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "configuration.json")
}

func nativeMaintenanceDelivered(t *testing.T, child workflowChild, output string) {
	t.Helper()
	var result struct {
		Delivery struct {
			Status        string `json:"status"`
			Failed        bool   `json:"failed"`
			CleanupFailed bool   `json:"cleanup_failed"`
			Pins          struct {
				EditableDigest  string `json:"editable_digest"`
				GeneratedDigest string `json:"generated_digest"`
				EditableLength  uint64 `json:"editable_length"`
				GeneratedLength uint64 `json:"generated_length"`
			} `json:"pair_pins"`
		} `json:"delivery"`
		Usability string `json:"source_usability"`
	}
	if json.Unmarshal(child.out, &result) != nil || result.Delivery.Status != "delivered" || result.Delivery.Failed || result.Delivery.CleanupFailed || result.Usability != "confirmed" {
		t.Fatal("selected maintenance lacks separately confirmed delivery and source usability")
	}
	pair := workflowReadPair(t, output)
	ed, gd := sha256.Sum256(pair.editable), sha256.Sum256(pair.generated)
	if result.Delivery.Pins.EditableDigest != hex.EncodeToString(ed[:]) || result.Delivery.Pins.GeneratedDigest != hex.EncodeToString(gd[:]) || result.Delivery.Pins.EditableLength != uint64(len(pair.editable)) || result.Delivery.Pins.GeneratedLength != uint64(len(pair.generated)) {
		t.Fatal("delivery evidence does not match complete independently reopened output")
	}
}

func nativeObserveMaintenance(t *testing.T, s *workflowServer, cli string, args []string, usable bool) {
	t.Helper()
	child := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, args...)
	var result struct {
		Operation   string                  `json:"operation_kind"`
		State       string                  `json:"state_result"`
		Delivery    struct{ Status string } `json:"delivery"`
		Usability   string                  `json:"source_usability"`
		Observation struct {
			CandidateCurrent       bool   `json:"candidate_current"`
			SourceUsable           bool   `json:"source_usable"`
			SourceUsabilityChecked bool   `json:"source_usability_checked"`
			Receipt                string `json:"receipt_hex"`
		} `json:"maintenance_observation"`
	}
	if json.Unmarshal(child.out, &result) != nil || result.Operation != "mutation-receipt" || result.Delivery.Status != "existing" {
		t.Fatal("existing maintenance output did not select exact observation")
	}
	workflowGETOnly(t, child)
	if usable {
		if child.code != 0 || result.State != "success" || result.Usability != "confirmed" || result.Observation.Receipt == "" || !result.Observation.CandidateCurrent || !result.Observation.SourceUsable || !result.Observation.SourceUsabilityChecked {
			t.Fatal("existing selected output lacks exact receipt and current source usability")
		}
	} else if child.code != 3 || result.State != "unavailable" || result.Observation.Receipt != "" || result.Observation.CandidateCurrent {
		t.Fatal("unselected candidate was reported selected or its mutation was replayed")
	}
}

// full_only: false
func TestPublicNativeRetainedMaintenanceSeparatesReceiptFromLaterUsability(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, family)
			s := f.server
			source := nativeReconstructedPair(t, s, cli, helper, f.source, f.pair, f.value)
			pair := workflowReadPair(t, source)
			var editable map[string]any
			if err := json.Unmarshal(pair.editable, &editable); err != nil {
				t.Fatal(err)
			}
			pending := []byte("independent pending maintenance bytes")
			editable["entries"].(map[string]any)["pending-maintenance"] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": string(pending)}}
			body, err := json.MarshalIndent(editable, "", "  ")
			if err != nil || os.WriteFile(source, append(body, '\n'), 0600) != nil {
				t.Fatal("pending proposal write failed", err)
			}
			pair = workflowReadPair(t, source)
			originalEditable, originalGenerated := sha256.Sum256(pair.editable), sha256.Sum256(pair.generated)
			first := nativeMaintenanceOutput(t)
			firstArgs := []string{"rekey", "--source", source, "--source-format", "json", "--name", "binary", "--out", first, "--json"}
			selected := workflowRun(t, s, cli, "change", observer.Policy{}, nil, firstArgs...)
			workflowResult(t, selected, "success")
			nativeMaintenanceDelivered(t, selected, first)
			current, _ := workflowHead(t, s)
			if _, present := nativeLifecycleEntries(t, s, workflowRoot(t, s, current))["pending-maintenance"]; present {
				t.Fatal("rekey applied pending proposal")
			}
			output := workflowReadPair(t, first)
			var preserved map[string]any
			if json.Unmarshal(output.editable, &preserved) != nil || preserved["entries"].(map[string]any)["pending-maintenance"].(map[string]any)["source"].(map[string]any)["value"] != string(pending) {
				t.Fatal("successor changed independent pending bytes")
			}
			workflowResult(t, workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", first, "--source-format", "json", "--json"), "success")
			current, _ = workflowHead(t, s)
			if entry := nativeLifecycleEntries(t, s, workflowRoot(t, s, current))["pending-maintenance"]; string(entry.ValueBytes) != string(pending) {
				t.Fatal("adopted successor did not apply the exact pending bytes")
			}
			nativeSequenceColdValue(t, s, helper, first, f.value, false)
			second := nativeMaintenanceOutput(t)
			secondArgs := []string{"rekey", "--source", first, "--source-format", "json", "--name", "binary", "--out", second, "--json"}
			advanced := workflowRun(t, s, cli, "change", observer.Policy{}, nil, secondArgs...)
			workflowResult(t, advanced, "success")
			nativeMaintenanceDelivered(t, advanced, second)
			nativeObserveMaintenance(t, s, cli, secondArgs, true)
			historical := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, firstArgs...)
			var observed struct {
				Operation   string `json:"operation_kind"`
				State       string `json:"state_result"`
				Usability   string `json:"source_usability"`
				Observation struct {
					Receipt string `json:"receipt_hex"`
					Current bool   `json:"candidate_current"`
					Checked bool   `json:"source_usability_checked"`
					Usable  bool   `json:"source_usable"`
				} `json:"maintenance_observation"`
			}
			if json.Unmarshal(historical.out, &observed) != nil || historical.code != 0 || observed.Operation != "mutation-receipt" || observed.State != "success" || observed.Usability != "unusable" || observed.Observation.Receipt == "" || observed.Observation.Current || !observed.Observation.Checked || observed.Observation.Usable {
				t.Fatal("historical receipt was conflated with current candidate or retained source usability")
			}
			workflowGETOnly(t, historical)
			actual := workflowReadPair(t, source)
			if sha256.Sum256(actual.editable) != originalEditable || sha256.Sum256(actual.generated) != originalGenerated {
				t.Fatal("maintenance changed exact captured source hashes")
			}
			workflowUnchanged(t, first, output)
			s.clean(t)
		})
	}
}

func nativeCanonicalBacking(generated map[string]any, family, name string, body []byte) {
	records, ok := generated["canonical_records"].(map[string]any)
	if !ok {
		records = map[string]any{"generators": map[string]any{}, "outputs": map[string]any{}}
		generated["canonical_records"] = records
	}
	records[family].(map[string]any)[name] = body
}
