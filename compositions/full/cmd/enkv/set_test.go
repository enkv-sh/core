package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type setCommandInput struct {
	reads, closes int
	closeErr      error
}

func (i *setCommandInput) Read([]byte) (int, error) { i.reads++; return 0, io.EOF }
func (i *setCommandInput) Close() error             { i.closes++; return i.closeErr }

// full_only: false
func TestSetCommandPreflightOwnsInput(t *testing.T) {
	for _, condition := range []string{"missing-source", "relative-source", "missing-name", "bad-format", "extra-argument", "explicit-empty-name", "close-failure"} {
		t.Run(condition, func(t *testing.T) {
			args := []string{"--source", filepath.Join(t.TempDir(), "absent"), "--source-format", "json", "--name", ""}
			switch condition {
			case "missing-source":
				args = []string{"--source-format", "json", "--name", "item"}
			case "relative-source":
				args[1] = "relative"
			case "missing-name":
				args = args[:4]
			case "bad-format":
				args[3] = "toml"
			case "extra-argument":
				args = append(args, "extra")
			}
			input := &setCommandInput{}
			if condition == "close-failure" {
				input.closeErr = errors.New("opaque-close-detail")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var out, diagnostic bytes.Buffer
			if code := runSetContext(ctx, args, input, &out, &diagnostic); code != 2 {
				t.Fatal("invalid source command accepted", code)
			}
			if input.reads != 0 || input.closes != 1 || !strings.Contains(out.String(), "Supplied secret preparation: refused") {
				t.Fatal("preflight input ownership or output differs")
			}
			if condition == "explicit-empty-name" && strings.Contains(diagnostic.String(), "set requires") {
				t.Fatal("explicit empty entry name treated as absent flag")
			}
			if strings.Contains(diagnostic.String(), "opaque-close-detail") {
				t.Fatal("raw close error escaped command diagnostic")
			}
		})
	}
}

// This newly encoded proof-free source adapts only public assembly facts.
// It proves local artifact delivery, not readiness or a changed signed archive.
func setCommandPreparedSource(t *testing.T) (path string, fileID, predecessor, domain contract.ID) {
	t.Helper()
	archive, basisBytes := installedarchive.LoadReader(t, "aws")
	var basis struct{ Descriptor []byte }
	if err := json.Unmarshal(basisBytes, &basis); err != nil {
		t.Fatal(err)
	}
	d, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if d.Recovery != nil {
		t.Fatal("local source fixture expects disabled Recovery")
	}
	d.InterpretationID, d.TrustInterpretationID = contract.InterpretationID(), contract.TrustInterpretationID()
	d.CompatibilityID, d.CryptoSupportID = contract.CompatibilityID(), contract.CryptoSupportID()
	d.NormalSigning.Binding.Interpretation = d.InterpretationID
	descriptor, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal("current public descriptor fixture refused")
	}
	var authority contract.RecipientRecord
	for _, row := range d.Recipients {
		if row.RecipientID == d.AuthorityRecipientID {
			authority = row
		}
	}
	if authority.CurrentBinding == nil {
		t.Fatal("public descriptor Authority missing")
	}
	key := authority.CurrentBinding
	protection := "software"
	if key.ProtectionClass == contract.HardwareProtection {
		protection = "hardware"
	}
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	fileID = contract.ID(sha256.Sum256([]byte("CLI set local input-file fixture")))
	domain = d.DomainID
	generated := map[string]any{"schema": "enkv/generated/v2", "file_id": id(fileID), "domain": map[string]any{"id": id(domain), "authority": map[string]any{"id": id(d.AuthorityRecipientID), "signing": map[string]any{"selector": d.NormalSigning.KeySelector, "public_key": d.NormalSigning.SPKI}, "encryption": map[string]any{"selector": key.KeySelector, "public_key": key.SPKI, "binding": map[string]any{"id": id(key.BindingID), "incarnation": id(key.BindingIncarnationID), "serial": key.BindingSerial, "protection": protection}}}, "recovery": map[string]any{"enabled": false}}, "recipients": map[string]any{}, "secrets": map[string]any{}, "public_basis": map[string]any{"kind": "genesis", "descriptor": descriptor}}
	generatedBody, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	reference := ".enkv/prod.generated.json"
	store := map[string]any{"region": archive.Archive.Location.Region, "bucket": archive.Archive.Location.Bucket, "prefix": archive.Archive.Location.PrefixBeforeHEAD, "expected_owner": archive.Archive.Location.ExpectedOwner}
	editable := map[string]any{"schema": "enkv/configuration/v3", "domain": map[string]any{"name": "prod", "provider": "aws", "store": store, "authority": map[string]any{"display_name": authority.DisplayName, "signing_key": d.NormalSigning.KeySelector, "encryption_key": key.KeySelector}, "recovery": map[string]any{"enabled": false}}, "recipients": map[string]any{}, "entries": map[string]any{}, "outputs": map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}, "generated": reference}
	editableBody, err := json.Marshal(editable)
	if err != nil {
		t.Fatal(err)
	}
	predecessor = contract.ID(sha256.Sum256(editableBody))
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "source.json")
	if err := os.WriteFile(filepath.Join(dir, reference), generatedBody, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, editableBody, 0600); err != nil {
		t.Fatal(err)
	}
	return path, fileID, predecessor, domain
}

type setCommandValueInput struct {
	io.Reader
	closes int
}

func (i *setCommandValueInput) Close() error { i.closes++; return nil }

// full_only: false
func TestSetCommandPlainSavesExactDecodedBytesAndKeepsGeneratedDependency(t *testing.T) {
	for _, row := range []struct {
		name, input string
		base64      bool
		want        []byte
	}{
		{"utf8-newlines", "first line\nsecond café line\n", false, []byte("first line\nsecond café line\n")},
		{"base64-binary", "AP8KQQ==", true, []byte{0, 255, 10, 65}},
	} {
		t.Run(row.name, func(t *testing.T) {
			path, _, _, _ := setCommandPreparedSource(t)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var source struct{ Generated string }
			if err := json.Unmarshal(before, &source); err != nil {
				t.Fatal(err)
			}
			generatedPath := filepath.Join(filepath.Dir(path), source.Generated)
			generated, err := os.ReadFile(generatedPath)
			if err != nil {
				t.Fatal(err)
			}
			input := &setCommandValueInput{Reader: strings.NewReader(row.input)}
			args := []string{"--source", path, "--source-format", "json", "--name", "plain-entry", "--confidential=false", "--json"}
			if row.base64 {
				args = append(args, "--base64")
			}
			var out, diagnostic bytes.Buffer
			if code := runSet(args, input, &out, &diagnostic); code != 0 || input.closes != 1 {
				t.Fatal("installed plain set command did not complete", code, input.closes)
			}
			var result struct {
				LocalEdit, Outcome string
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if json.Unmarshal(fields["local_edit"], &result.LocalEdit) != nil || json.Unmarshal(fields["outcome"], &result.Outcome) != nil ||
				result.LocalEdit != "plain" || result.Outcome != "edited" || fields["schema"] != nil || fields["operation_kind"] != nil || fields["payload"] != nil {
				t.Fatal("plain set did not return its local edit result")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var saved struct {
				Generated string
				Entries   map[string]struct {
					Confidentiality string
					Source          struct {
						Kind, Value, Encoding string
					}
				}
			}
			if err := json.Unmarshal(after, &saved); err != nil {
				t.Fatal(err)
			}
			entry := saved.Entries["plain-entry"]
			decoded := []byte(entry.Source.Value)
			if row.base64 {
				if entry.Source.Encoding != "base64" || entry.Source.Value != row.input {
					t.Fatal("stored literal lost its Base64 representation")
				}
				decoded, err = base64.StdEncoding.Strict().DecodeString(entry.Source.Value)
			}
			current, readErr := os.ReadFile(generatedPath)
			if err != nil || readErr != nil || entry.Confidentiality != "plain" || entry.Source.Kind != "supplied" ||
				!bytes.Equal(decoded, row.want) || saved.Generated != source.Generated || !bytes.Equal(current, generated) {
				t.Fatal("plain set changed decoded bytes or the generated dependency")
			}
		})
	}
}

type setCommandPayload struct {
	Schema      string `json:"schema"`
	FileID      string `json:"input_file_id"`
	Predecessor string `json:"predecessor_digest"`
	Target      struct {
		Domain string `json:"domain_id"`
		Name   string `json:"name"`
	} `json:"target"`
	Artifact string `json:"sealed_artifact_digest"`
	Readback struct {
		Editable  string `json:"editable_digest"`
		Generated string `json:"generated_digest"`
	} `json:"readback"`
}

// full_only: false
func TestSetCommandPreservesConfirmedDeliveryAfterCleanupFailure(t *testing.T) {
	for _, structured := range []bool{false, true} {
		t.Run(map[bool]string{false: "human", true: "json"}[structured], func(t *testing.T) {
			path, fileID, predecessor, domain := setCommandPreparedSource(t)
			input := &setCommandValueInput{Reader: strings.NewReader("private-input-must-not-be-rendered")}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			args := []string{"--source", path, "--source-format", "json", "--name", "item"}
			if structured {
				args = append(args, "--json")
			}
			var out, diagnostic bytes.Buffer
			var delivered *compositionfull.SetResult
			calls := 0
			code := runSetWithSetter(ctx, args, input, &out, &diagnostic, func(ctx context.Context, got string, format configuration.Format, name string, accepted io.ReadCloser, options compositionfull.SetOptions) (*compositionfull.SetResult, error) {
				calls++
				if got != path || format != configuration.JSON || name != "item" || !options.Confidential {
					t.Fatal("target/default confidential branch changed")
				}
				result, err := compositionfull.SetConfiguration(ctx, got, format, name, accepted, options)
				if err != nil || result == nil || result.StateResult != compositionfull.SetSuccess || result.Payload == nil {
					t.Fatal("real public confidential preparation did not reach exact readback")
				}
				delivered = result
				return result, errors.New("opaque-post-commit-cleanup-detail")
			})
			if code != 2 || calls != 1 || input.closes != 1 || delivered == nil {
				t.Fatal("cleanup failure or input ownership changed", code, calls, input.closes)
			}
			var payload setCommandPayload
			var delivery struct {
				Outcome       string `json:"outcome"`
				EditablePath  string `json:"editable_path"`
				GeneratedPath string `json:"generated_path"`
				CleanupFailed bool   `json:"cleanup_failed"`
			}
			// Structured output retains complete artifact facts; the human result
			// keeps the confirmed target, paths and cleanup action.
			if structured {
				var record struct {
					Schema, Operation, State, Effect, Output, Variant string
					Payload                                           setCommandPayload
					Delivery                                          json.RawMessage
					Warnings                                          []string
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
					t.Fatal(err)
				}
				for key, target := range map[string]*string{"schema": &record.Schema, "operation_kind": &record.Operation, "state_result": &record.State, "effect_summary": &record.Effect, "output_summary": &record.Output, "operation_payload": &record.Variant} {
					if err := json.Unmarshal(fields[key], target); err != nil {
						t.Fatal(err)
					}
				}
				if record.Schema != "ProductResult/v1" || record.Operation != "set-confidential" || record.State != "success" || record.Effect != "not-applicable" || record.Output != "not-applicable" || record.Variant != "SealedArtifactPayload/v1" || fields["outcome"] != nil {
					t.Fatal("closed Product result replaced confirmed artifact success")
				}
				if err := json.Unmarshal(fields["payload"], &payload); err != nil {
					t.Fatal(err)
				}
				record.Delivery = fields["local_delivery"]
				if err := json.Unmarshal(record.Delivery, &delivery); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(fields["warning_summary"], &record.Warnings); err != nil || len(record.Warnings) == 0 {
					t.Fatal("cleanup warning absent")
				}
			} else {
				for _, fact := range []string{"Supplied secret preparation: success", "Entry: \"item\"", "Local files: recorded", "Editable file: " + strconv.Quote(path), "Generated file: " + strconv.Quote(delivered.GeneratedPath), "Warning: The local pair was read back. Later cleanup failed; retain the confirmed paths."} {
					if !strings.Contains(out.String(), fact) {
						t.Fatal("confirmed human result fact absent", fact)
					}
				}
			}
			if structured && (delivery.Outcome != "recorded" || delivery.EditablePath != path || delivery.GeneratedPath != delivered.GeneratedPath || !delivery.CleanupFailed) {
				t.Fatal("confirmed paths/cleanup facts were lost")
			}
			editableBody, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			generatedBody, err := os.ReadFile(delivered.GeneratedPath)
			if err != nil {
				t.Fatal(err)
			}
			var generated struct {
				Secrets map[string]struct{ Sealed []byte }
			}
			if err := json.Unmarshal(generatedBody, &generated); err != nil {
				t.Fatal(err)
			}
			if len(generated.Secrets["item"].Sealed) == 0 {
				t.Fatal("confirmed operation did not retain the sealed artifact")
			}
			hash := func(body []byte) string { digest := sha256.Sum256(body); return hex.EncodeToString(digest[:]) }
			id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
			if structured && (payload.Schema != "SealedArtifactPayload/v1" || payload.FileID != id(fileID) || payload.Predecessor != id(predecessor) || payload.Target.Domain != id(domain) || payload.Target.Name != "item" || payload.Artifact != hash(generated.Secrets["item"].Sealed) || payload.Readback.Editable != hash(editableBody) || payload.Readback.Generated != hash(generatedBody)) {
				t.Fatal("exact sealed artifact/readback fields changed")
			}
			if strings.Contains(out.String()+diagnostic.String(), "opaque-post-commit-cleanup-detail") || strings.Contains(out.String()+diagnostic.String(), "private-input-must-not-be-rendered") {
				t.Fatal("private input or raw cleanup error escaped")
			}
		})
	}
}

// full_only: false
func TestSetCommandSourceFailureIdentifiesFault(t *testing.T) {
	input := &setCommandInput{}
	var out, diagnostic bytes.Buffer
	args := []string{"--source", filepath.Join(t.TempDir(), "configuration"), "--source-format", "yaml", "--name", "item", "--json"}
	code := runSetWithSetter(t.Context(), args, input, &out, &diagnostic, func(ctx context.Context, path string, format configuration.Format, name string, in io.ReadCloser, options compositionfull.SetOptions) (*compositionfull.SetResult, error) {
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
		result, err := compositionfull.NewSetRefusal(true)
		if err != nil {
			t.Fatal(err)
		}
		return result, &configuration.Diagnostic{Field: "schema", Reason: "unsupported-schema", Line: 3, Column: 9}
	})
	if code != 2 || input.reads != 0 || input.closes != 1 || !strings.Contains(diagnostic.String(), "schema at 3:9: unsupported-schema") {
		t.Fatalf("set fault diagnostic lost origin: %d %s", code, diagnostic.String())
	}
	var record struct {
		SourceFailure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
	}
	if err := json.Unmarshal(out.Bytes(), &record); err != nil || record.SourceFailure == nil || record.SourceFailure.Field != "schema" || record.SourceFailure.Line != 3 || record.SourceFailure.Column != 9 {
		t.Fatalf("set structured source failure differs: %s, %v", out.Bytes(), err)
	}
}
