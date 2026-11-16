package compositionfull

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

func initializationSetupSource(t *testing.T, family string, recovery, withEntry bool) []byte {
	t.Helper()
	region := "us-east-1"
	key := func(n int) string {
		return fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%08d-1111-1111-1111-111111111111", n)
	}
	store := map[string]any{"region": region, "bucket": "fixture-bucket", "prefix": "fixture", "expected_owner": "123456789012"}
	if family == "gcp" {
		store = map[string]any{"region": "australia-southeast1", "bucket": "fixture-bucket", "prefix": "fixture"}
		key = func(n int) string {
			return fmt.Sprintf("projects/fixture-project/locations/australia-southeast1/keyRings/fixture/cryptoKeys/key%d/cryptoKeyVersions/1", n)
		}
	}
	recoverySource := map[string]any{"enabled": recovery}
	if recovery {
		recoverySource["signing_key"], recoverySource["encryption_key"] = key(3), key(4)
	}
	entries := map[string]any{}
	if withEntry {
		entries[""] = map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": ""}}
	}
	source := map[string]any{
		"schema": "enkv/configuration/v3",
		"domain": map[string]any{"name": "prod", "provider": family, "store": store,
			"authority": map[string]any{"display_name": "Authority", "signing_key": key(1), "encryption_key": key(2)}, "recovery": recoverySource},
		"recipients": map[string]any{"recipient": map[string]any{"display_name": "Recipient", "encryption_key": key(5)}},
		"entries":    entries, "outputs": map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}},
	}
	body, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestInitializationEqualKeySelectorsRefuseBeforePublicLookup(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			for _, relation := range []string{"independent-unresolved", "equal-signing", "equal-encryption"} {
				t.Run(fmt.Sprintf("%s/%d/%s", family, format, relation), func(t *testing.T) {
					var source map[string]any
					if err := json.Unmarshal(initializationSetupSource(t, family, true, false), &source); err != nil {
						t.Fatal(err)
					}
					domain := source["domain"].(map[string]any)
					authority := domain["authority"].(map[string]any)
					recovery := domain["recovery"].(map[string]any)
					switch relation {
					case "equal-signing":
						recovery["signing_key"] = authority["signing_key"]
					case "equal-encryption":
						recovery["encryption_key"] = authority["encryption_key"]
					}
					body, err := json.Marshal(source)
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(t.TempDir(), "configuration")
					if err := os.WriteFile(path, body, 0600); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					calls := 0
					result, err := initializeConfiguration(ctx, path, format, func(context.Context, *configuration.Model) (initializationResources, error) {
						calls++
						return initializationResources{}, ErrCell
					})
					wantCalls, wantStage := 0, "declaration"
					if relation == "independent-unresolved" {
						wantCalls, wantStage = 1, "construction"
					}
					if calls != wantCalls || err == nil || result.StateResult != contract.InitializationRefused || result.PreAdmission == nil || result.PreAdmission.Stage != wantStage || result.OperationID.IsZero() || !result.RequestIdentity.IsZero() || result.DeliveryAttempted {
						t.Fatal("setup key relation crossed the public lookup boundary", calls, wantCalls, result, err)
					}
					actual, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(actual, body) {
						t.Fatal("setup refusal changed source bytes", err)
					}
				})
			}
		}
	}
}

// full_only: false
func TestInitializationSetupValidationPrecedesProviderOpen(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
				for _, withEntry := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/recovery-%t/format-%d/entry-%t", family, recovery, format, withEntry), func(t *testing.T) {
						body := initializationSetupSource(t, family, recovery, withEntry)
						path := filepath.Join(t.TempDir(), "configuration")
						if err := os.WriteFile(path, body, 0600); err != nil {
							t.Fatal(err)
						}
						ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
						defer cancel()
						// Establish a valid complete source before testing the consumer's gate.
						pair, err := configuration.Capture(ctx, path, format)
						if err != nil {
							t.Fatal(err)
						}
						model, parseErr := configuration.Parse(ctx, pair)
						closeErr := pair.Close()
						if parseErr != nil || closeErr != nil || model.Resolved {
							t.Fatal("invalid setup fixture", parseErr, closeErr)
						}
						calls := 0
						result, err := initializeConfiguration(ctx, path, format, func(_ context.Context, m *configuration.Model) (initializationResources, error) {
							calls++
							if m.DomainID.IsZero() || m.FileID.IsZero() || m.RecoveryEnabled != recovery {
								t.Fatal("setup identity or mode missing before resolution")
							}
							return initializationResources{}, ErrCell
						})
						want := 1
						if withEntry {
							want = 0
						}
						if calls != want || err == nil || result.StateResult != contract.InitializationRefused {
							t.Fatalf("provider open count=%d want=%d; state=%s", calls, want, result.StateResult)
						}
						stage := "construction"
						if withEntry {
							stage = "declaration"
						}
						if result.OperationID.IsZero() || !result.RequestIdentity.IsZero() || result.PreAdmission == nil || result.PreAdmission.Stage != stage {
							t.Fatal("setup refusal lost correlation or exact failure stage")
						}
						actual, readErr := os.ReadFile(path)
						if readErr != nil || !bytes.Equal(actual, body) {
							t.Fatal("refused setup changed source", readErr)
						}
					})
				}
			}
		}
	}
	// This source-ready binding has destination "private", plugin-owned settings
	// {"n":1.00}, all six action bits and no targets or encoding overrides.
	// Each blob is u32-length-prefixed; schema and final counts are u16.
	const canonicalBinding = "00010000000770726976617465000000380000000e707269766174652d636f6e6669670000000f707269766174652d736572766963650000000a7b226e223a312e30307d000000003f00000000"
	binding, decodeErr := hex.DecodeString(canonicalBinding)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, condition := range []string{"ordinary", "canonical-without-backing", "old-canonical-arm", "unknown-destination", "recipient-routing-refused", "invalid-canonical"} {
			t.Run(fmt.Sprintf("declared-output/format-%d/%s", format, condition), func(t *testing.T) {
				var source map[string]any
				if err := json.Unmarshal(initializationSetupSource(t, "aws", false, false), &source); err != nil {
					t.Fatal(err)
				}
				output := map[string]any{"plugin": "uninstalled-private-output", "settings": map[string]any{"n": 1}}
				if condition == "canonical-without-backing" || condition == "old-canonical-arm" || condition == "invalid-canonical" {
					name := "private"
					if condition == "invalid-canonical" {
						name = "different"
					}
					output = map[string]any{"plugin": nil, "canonical": map[string]any{"settings": json.RawMessage(`{"n":1.00}`)}}
					if condition == "old-canonical-arm" {
						output = map[string]any{"plugin": nil, "canonical": map[string]any{"binding_base64": base64.StdEncoding.EncodeToString(binding)}}
					}
					if condition == "invalid-canonical" {
						source["outputs"] = map[string]any{"destinations": map[string]any{name: output}, "routing": map[string]any{}}
					}
				}
				if condition != "invalid-canonical" {
					destination := "private"
					if condition == "unknown-destination" {
						destination = "absent"
					}
					routing := map[string]any{"default": []string{destination}}
					if condition == "recipient-routing-refused" {
						routing = map[string]any{"recipients": map[string]any{"absent": map[string]any{"fallback": []string{destination}}}}
					}
					source["outputs"] = map[string]any{"destinations": map[string]any{"private": output}, "routing": routing}
				}
				body, err := json.Marshal(source)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "configuration")
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				calls := 0
				result, err := initializeConfiguration(ctx, path, format, func(context.Context, *configuration.Model) (initializationResources, error) {
					calls++
					return initializationResources{}, ErrCell
				})
				want := 0
				if condition == "ordinary" {
					want = 1
				}
				if calls != want || err == nil || result.StateResult != contract.InitializationRefused {
					t.Fatalf("provider open count=%d want=%d; state=%s", calls, want, result.StateResult)
				}
				actual, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(actual, body) {
					t.Fatal("refused setup changed source", readErr)
				}
			})
		}
	}

	t.Run("resolved-ordinary-output", func(t *testing.T) {
		const signingPublic = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQTzYWEkW1iOq4qApEvP1XY9AOHHdWk7mMxJdPPvdF8UC10LFN2Ca8RTA+Uy1nTwf1BBL7q+gidu39bDviUJEJw=="
		const encryptionPublic = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArQ4yfWElR37fxikvGbZTz0GfK0v2ONmOuRGQsVL3BpjA3L9bL0ehNVDl+Te5dvr/xuHnNAA/m/9JzKSgEC80BdkGvocFDWOpYzajbzOF0cq+TaAdQBW/5+6TIHzMIrfckTiHtCLaqWEHbLK9O7labv7Ly2BtNSDS+yCXVhzX2RqwkOntM2E3GDq1bLiT0ScfqBNru5w/dCdBl02xBRumsO4dEY1wjhL3Kzu1hkApV7hHdxy9wzkeuKEfNryvoaycMTQFPus0smOovV/rwviM17mbGXfNq5/foZJO8y0WnGjFBJOXA0mVC4brBo1ONNNvPg68opt2jguVl6z+T868lnt/TOPEkbgMgq3YwAGcTY3uMp052ryWk8AFCjDx3iiUghOLbHTUx30APvg4PszrtIh3/X9euECFR2GvtuKbVRbFupEt65MQoh5644hBJSfDqg/EIHHYEiDZeGcTLltjloujU672hr6bOg0w2b1HE4dMCPWYJhcy1GOKR/l2C5YhAgMBAAE="
		// The fixed public keys are source-shaped test fixtures. The one-byte
		// descriptor cannot authenticate genesis; this case checks public facts only.
		var source map[string]any
		if err := json.Unmarshal(initializationSetupSource(t, "aws", false, false), &source); err != nil {
			t.Fatal(err)
		}
		source["outputs"] = map[string]any{"destinations": map[string]any{"private": map[string]any{"plugin": "uninstalled-private-output", "settings": map[string]any{"n": 1}}}, "routing": map[string]any{"default": []string{"private"}}}
		source["generated"] = ".enkv/prod.generated.json"
		id := func(name string) string {
			return readerID(contract.Hash([]byte("initialization public source " + name)))
		}
		domain := source["domain"].(map[string]any)
		authority := domain["authority"].(map[string]any)
		encryption := func(selector string) map[string]any {
			return map[string]any{"selector": selector, "public_key": encryptionPublic, "binding": map[string]any{"id": id(selector + "binding"), "incarnation": id(selector + "incarnation"), "serial": 1, "protection": "software"}}
		}
		recipient := source["recipients"].(map[string]any)["recipient"].(map[string]any)
		recipient["id"] = id("recipient")
		generated := map[string]any{"schema": "enkv/generated/v2", "file_id": id("file"), "domain": map[string]any{"id": id("domain"), "authority": map[string]any{"id": id("authority"), "signing": map[string]any{"selector": authority["signing_key"], "public_key": signingPublic}, "encryption": encryption(authority["encryption_key"].(string))}, "recovery": map[string]any{"enabled": false}}, "recipients": map[string]any{"recipient": map[string]any{"id": id("recipient"), "encryption": encryption(recipient["encryption_key"].(string))}}, "secrets": map[string]any{}, "public_basis": map[string]any{"kind": "genesis", "descriptor": "AQ=="}}
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "configuration")
		for name, value := range map[string]any{path: source, filepath.Join(dir, ".enkv", "prod.generated.json"): generated} {
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, body, 0600); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		pair, err := configuration.Capture(ctx, path, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		model, parseErr := configuration.Parse(ctx, pair)
		closeErr := pair.Close()
		if parseErr != nil || closeErr != nil || !model.Resolved {
			t.Fatal("invalid resolved source fixture", parseErr, closeErr)
		}
		if !validResolvedInitializationConfiguration(ctx, model) || validResolvedConfiguration(ctx, model) {
			t.Fatal("init and apply did not keep their separate output dependencies")
		}
		model.Public.Authority.Signing.PublicKey.State = contract.PublicUnavailable
		if validResolvedInitializationConfiguration(ctx, model) {
			t.Fatal("resolved init accepted unavailable signing key")
		}
	})

}

// full_only: false
func TestInitializationReferenceReusesYAMLFlowTrailingComma(t *testing.T) {
	baseline := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		editable["entries"] = map[string]any{}
		editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
		delete(generated, "canonical_records")
		generated["secrets"] = map[string]any{}
	})
	before, err := configuration.Parse(t.Context(), baseline.pair)
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if err := json.Unmarshal(baseline.editableBytes, &source); err != nil {
		t.Fatal(err)
	}
	delete(source, "generated")
	setup, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, trailing := range []bool{false, true} {
		t.Run(fmt.Sprintf("trailing-%t", trailing), func(t *testing.T) {
			body := string(setup)
			if trailing {
				body = body[:len(body)-1] + ",}"
			}
			path := filepath.Join(t.TempDir(), "configuration")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := configuration.Capture(t.Context(), path, configuration.YAML)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			model, err := configuration.Parse(t.Context(), pair)
			if err != nil || model.Resolved {
				t.Fatal("flow setup fixture refused", err)
			}
			var emitted bytes.Buffer
			if err := emitInitializationReference(t.Context(), &emitted, pair.Editable, configuration.YAML, model, before.Generated); err != nil {
				t.Fatal(err)
			}
			separator := ", generated: "
			if trailing {
				separator = " generated: "
			}
			quoted, err := json.Marshal(before.Generated)
			if err != nil {
				t.Fatal(err)
			}
			want := body[:len(body)-1] + separator + string(quoted) + "}"
			if emitted.String() != want {
				t.Errorf("initialization separator differs: got %q want %q", emitted.String(), want)
			}
			root := t.TempDir()
			candidatePath := filepath.Join(root, "configuration")
			generatedPath := filepath.Join(root, before.Generated)
			if err := os.MkdirAll(filepath.Dir(generatedPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(generatedPath, baseline.generatedBytes, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(candidatePath, emitted.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			afterPair, err := configuration.Capture(t.Context(), candidatePath, configuration.YAML)
			if err != nil {
				t.Fatal("initialization reference candidate refused", err)
			}
			defer func() {
				if err := afterPair.Close(); err != nil {
					t.Error(err)
				}
			}()
			after, err := configuration.Parse(t.Context(), afterPair)
			if err != nil || !after.Resolved || !reflect.DeepEqual(before.Public, after.Public) || len(after.Entries) != 0 || len(before.Recipients) != len(after.Recipients) {
				t.Fatal("reference insertion changed whole-pair meaning", err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || string(actual) != body {
				t.Fatal("reference insertion changed original source", err)
			}
		})
	}
}

// full_only: false
func TestInitializationReferencePreservesKeepChompedEOF(t *testing.T) {
	const reference = ".enkv/prod.generated.json"
	baseline := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		editable["entries"] = map[string]any{}
		editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
		delete(generated, "canonical_records")
		generated["secrets"] = map[string]any{}
	})
	var source map[string]any
	if err := json.Unmarshal(baseline.editableBytes, &source); err != nil {
		t.Fatal(err)
	}
	var prefix strings.Builder
	for _, key := range []string{"schema", "domain", "recipients", "entries"} {
		encoded, err := json.Marshal(source[key])
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&prefix, "%s: %s\n", key, encoded)
	}
	prefix.WriteString("outputs:\n  routing: {}\n  destinations:\n    sink:\n      plugin: private-output\n      settings:\n        note: ")
	for _, tc := range []struct {
		name, scalar, wantSettings, lineBreak string
		indented                              bool
	}{
		{"literal-lf", "|+\n          X\n\n", `{"note":"X\n\n"}`, "\n", false},
		{"folded-crlf", ">+\n          X\n          Y\n\n\n", `{"note":"X Y\n\n\n"}`, "\r\n", false},
		{"no-final-break-indented-root", "|+\n          X", `{"note":"X"}`, "\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := prefix.String() + tc.scalar
			if tc.indented {
				lines := strings.Split(body, "\n")
				for i, line := range lines {
					if line != "" {
						lines[i] = "  " + line
					}
				}
				body = "# retained root comment\n" + strings.Join(lines, "\n")
			}
			body = strings.ReplaceAll(body, "\n", tc.lineBreak)
			root := t.TempDir()
			path := filepath.Join(root, "configuration")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			result, err := initializeConfiguration(ctx, path, configuration.YAML, func(_ context.Context, m *configuration.Model) (initializationResources, error) {
				calls++
				if len(m.Entries) != 0 || len(m.Outputs) != 1 || m.Outputs[0].Plugin != "private-output" || !bytes.Equal(m.Outputs[0].Settings, []byte(tc.wantSettings)) {
					t.Fatal("initialization construction changed declared settings")
				}
				return initializationResources{}, ErrCell
			})
			if calls != 1 || err == nil || result.PreAdmission == nil || result.PreAdmission.Stage != "construction" {
				t.Fatal("admitted keep-chomp setup did not reach resource construction", calls, result, err)
			}
			original, err := os.ReadFile(path)
			if err != nil || string(original) != body {
				t.Fatal("construction refusal changed setup source", err)
			}
			pair, err := configuration.Capture(t.Context(), path, configuration.YAML)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			model, err := configuration.Parse(t.Context(), pair)
			if err != nil || len(model.Outputs) != 1 || !bytes.Equal(model.Outputs[0].Settings, []byte(tc.wantSettings)) || model.Resolved {
				t.Fatal("keep-chomp setup meaning differs", err)
			}
			var emitted bytes.Buffer
			if err := emitInitializationReference(t.Context(), &emitted, pair.Editable, configuration.YAML, model, reference); err != nil {
				t.Fatal(err)
			}
			quoted, err := json.Marshal(reference)
			if err != nil {
				t.Fatal(err)
			}
			inserted := "generated: " + string(quoted) + "\n"
			if tc.indented {
				inserted += "  "
			}
			want := strings.Replace(body, "schema:", inserted+"schema:", 1)
			generatedPath := filepath.Join(root, reference)
			if err := os.MkdirAll(filepath.Dir(generatedPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(generatedPath, baseline.generatedBytes, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, emitted.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			afterPair, err := configuration.Capture(t.Context(), path, configuration.YAML)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := afterPair.Close(); err != nil {
					t.Error(err)
				}
			}()
			after, err := configuration.Parse(t.Context(), afterPair)
			if err != nil || !after.Resolved || len(after.Outputs) != 1 || !bytes.Equal(after.Outputs[0].Settings, []byte(tc.wantSettings)) || len(after.Entries) != 0 || len(after.Recipients) != len(model.Recipients) {
				t.Fatal("initialization append changed retained settings or complete sets", err)
			}
			if emitted.String() != want {
				t.Errorf("initialization append bytes %q, want %q", emitted.String(), want)
			}
		})
	}
}
