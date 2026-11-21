package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

func localEditWire(t *testing.T, result *LocalEditResult, resultErr error) map[string]any {
	t.Helper()
	body, err := RenderLocalEditJSON(result, resultErr)
	if err != nil {
		t.Fatal("local result unavailable", err)
	}
	human, err := RenderLocalEditHuman(result, resultErr)
	if err != nil || !bytes.Contains(human, []byte(result.outcome)) {
		t.Fatal("human result lost the local outcome", err)
	}
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 6 || record["schema"] != "LocalEditResult/v1" {
		t.Fatal("local result schema changed")
	}
	for _, warning := range record["warning_summary"].([]any) {
		if !bytes.Contains(human, []byte(warning.(string))) {
			t.Fatal("human result lost a required warning")
		}
	}
	delivery := record["local_delivery"].(map[string]any)
	for _, key := range []string{"editable_path", "generated_path", "recovery_source"} {
		path := delivery[key]
		if path == nil {
			continue
		}
		required := key == "recovery_source" || result.action == "recovery" || result.action == "domain-rename" && key == "generated_path" || resultErr != nil || delivery["cleanup_failed"] == true || result.outcome != "edited"
		if bytes.Contains(human, []byte(fmt.Sprintf("%q", path))) != required {
			t.Fatal("human path projection differs from its action or failure need", key)
		}
	}
	return record
}

func localEditReadbackMatches(t *testing.T, result *LocalEditResult, resultErr error, path, generated string) map[string]any {
	t.Helper()
	record := localEditWire(t, result, resultErr)
	delivery := record["local_delivery"].(map[string]any)
	if len(delivery) != 6 || delivery["editable_path"] != path || delivery["generated_path"] != generated {
		t.Fatal("local result lost exact delivery paths")
	}
	readback, ok := delivery["readback"].(map[string]any)
	if !ok || len(readback) != 2 {
		t.Fatal("local result lost confirmed readback")
	}
	for key, path := range map[string]string{"editable_digest": path, "generated_digest": generated} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		if readback[key] != hex.EncodeToString(digest[:]) {
			t.Fatal("readback does not identify exact installed bytes")
		}
	}
	return record
}

func localEditOpaquePlugins(t *testing.T, source configurationReaderSource, format configuration.Format, reference string) *configuration.Model {
	t.Helper()
	body, err := os.ReadFile(source.path)
	if err != nil {
		t.Fatal(err)
	}
	settings := fmt.Sprintf(`{"domain":"prod","reference":%q,"private":{"sizes":[17,29],"enabled":true}}`, reference)
	entry := `"private-token":{"confidentiality":"secret","recipients":[],"source":{"kind":"generated","plugin":"absent-private-generator","epoch":0,"retirement":"manual","settings":` + settings + `}},`
	destination := `"private-destination":{"plugin":"absent-private-output","settings":` + settings + `},`
	entries := `"entries":{`
	if format == configuration.YAML {
		entries = `entries: {`
	}
	text := string(body)
	if !strings.Contains(text, entries) || strings.Count(text, `"destinations":{`) != 1 {
		t.Fatal("local fixture lost its editable maps")
	}
	text = strings.Replace(text, entries, entries+entry, 1)
	text = strings.Replace(text, `"destinations":{`, `"destinations":{`+destination, 1)
	if err := os.Chmod(source.path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source.path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	model := configurationSetModel(t, source.path, format)
	if generator := configurationSetEntry(t, model, "private-token").Generated; generator == nil || generator.Plugin != "absent-private-generator" || string(generator.Settings) != settings || len(generator.Intent) != 0 {
		t.Fatal("opaque generator fixture lost its exact ordinary settings")
	}
	for _, output := range model.Outputs {
		if output.DestinationID == "private-destination" {
			if output.Plugin != "absent-private-output" || string(output.Settings) != settings {
				t.Fatal("opaque output fixture lost its exact ordinary settings")
			}
			return model
		}
	}
	t.Fatal("opaque output fixture is absent")
	return nil
}

func assertLocalEditPluginPreservation(t *testing.T, before, after *configuration.Model) {
	t.Helper()
	if !reflect.DeepEqual(configurationSetEntry(t, before, "private-token").Generated, configurationSetEntry(t, after, "private-token").Generated) || !reflect.DeepEqual(before.Outputs, after.Outputs) {
		t.Fatal("local edit changed opaque plugin settings or canonical output carriers")
	}
}

// full_only: false
func TestLocalConfigurationDomainRename(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			source := configurationSetPair(t, "aws", format, nil)
			configurationSetWritable(t, source)
			before := configurationSetModel(t, source.path, format)
			before = localEditOpaquePlugins(t, source, format, before.Recipients[0].Reference)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			result, err := RenameConfigurationDomain(ctx, source.path, format, "next")
			if err != nil || LocalEditExitCode(result, err) != 0 {
				t.Fatal("valid local rename refused", err)
			}
			generated := filepath.Join(filepath.Dir(source.path), ".enkv", "next.generated.json")
			record := localEditReadbackMatches(t, result, err, source.path, generated)
			if record["outcome"] != "edited" || !reflect.DeepEqual(record["target"], map[string]any{"old_name": "prod", "new_name": "next"}) {
				t.Fatal("rename result lost exact target")
			}
			if _, err := os.Lstat(source.generated); !os.IsNotExist(err) {
				t.Fatal("old generated path remains", err)
			}
			body, err := os.ReadFile(generated)
			if err != nil || !bytes.Equal(body, source.generatedBytes) {
				t.Fatal("rename changed generated records", err)
			}
			after := configurationSetModel(t, source.path, format)
			assertLocalEditPluginPreservation(t, before, after)
			if after.DomainName != "next" || after.FileID != before.FileID || !reflect.DeepEqual(after.Public, before.Public) || !reflect.DeepEqual(after.Basis, before.Basis) {
				t.Fatal("rename changed domain facts")
			}
		})
	}
}

// full_only: false
func TestLocalConfigurationRecipientReferenceRename(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			source := configurationSetPair(t, "aws", format, nil)
			configurationSetWritable(t, source)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			if _, err := SetConfiguration(ctx, source.path, format, "secret", io.NopCloser(strings.NewReader("private sealed reference fixture")), SetOptions{Confidential: true}); err != nil {
				t.Fatal("sealed source setup failed", err)
			}
			before := configurationSetModel(t, source.path, format)
			old := ""
			for _, entry := range before.Entries {
				if len(entry.Recipients) != 0 {
					old = entry.Recipients[0]
					break
				}
			}
			if old == "" {
				t.Fatal("reference fixture has no recipient membership")
			}

			before = localEditOpaquePlugins(t, source, format, old)
			selector := RecipientSelector{Reference: old}
			if format == configuration.YAML {
				for _, row := range before.Recipients {
					if row.Reference == old {
						selector = RecipientSelector{ID: row.ID}
					}
				}
			}
			result, err := RenameConfigurationSelectedRecipient(ctx, source.path, format, selector, "new-reference")
			if err != nil || LocalEditExitCode(result, err) != 0 {
				t.Fatal("valid reference rename refused", err)
			}
			record := localEditReadbackMatches(t, result, err, source.path, source.generated)
			if !reflect.DeepEqual(record["target"], map[string]any{"old_reference": old, "new_reference": "new-reference"}) {
				t.Fatal("reference result lost exact target")
			}
			after := configurationSetModel(t, source.path, format)
			assertLocalEditPluginPreservation(t, before, after)
			beforePublic, afterPublic := before.Public, after.Public
			beforePublic.Recipients.Value, afterPublic.Recipients.Value = slices.Clone(beforePublic.Recipients.Value), slices.Clone(afterPublic.Recipients.Value)
			compare := func(a, b contract.PublicRecipient) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) }
			slices.SortFunc(beforePublic.Recipients.Value, compare)
			slices.SortFunc(afterPublic.Recipients.Value, compare)
			if !reflect.DeepEqual(afterPublic, beforePublic) || !reflect.DeepEqual(after.Basis, before.Basis) {
				t.Fatal("reference rename changed public domain facts")
			}
			foundEditable, foundGenerated := false, false
			for _, row := range before.Recipients {
				if row.Reference != old {
					continue
				}
				for _, changed := range after.Recipients {
					if changed.Reference == "new-reference" && changed.ID == row.ID && reflect.DeepEqual(changed.Encryption.Binding, row.Encryption.Binding) && bytes.Equal(changed.Encryption.PublicKey, row.Encryption.PublicKey) && changed.DisplayName == row.DisplayName {
						foundEditable = true
					}
				}
				for _, changed := range after.GeneratedRecipients {
					if changed.Reference == "new-reference" && changed.ID == row.ID && reflect.DeepEqual(changed.Encryption.Binding, row.Encryption.Binding) && bytes.Equal(changed.Encryption.PublicKey, row.Encryption.PublicKey) {
						foundGenerated = true
					}
				}
			}
			if !foundEditable || !foundGenerated || !bytes.Equal(configurationSetEntry(t, before, "secret").Sealed, configurationSetEntry(t, after, "secret").Sealed) {
				t.Fatal("reference rename changed identity, binding or sealed bytes")
			}
			for _, entry := range after.Entries {
				for _, reference := range entry.Recipients {
					if reference == old {
						t.Fatal("membership kept the old reference")
					}
				}
			}
			if !reflect.DeepEqual(before.Routes, after.Routes) {
				t.Fatal("recipient reference rename changed shared routing")
			}

		})
	}
}

// full_only: false
func TestLocalConfigurationPendingRecoveryAndResult(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			source := configurationSetPair(t, "aws", format, nil)
			configurationSetWritable(t, source)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			interrupted := &cancelPendingConfiguration{Context: ctx, cancel: cancel, marker: filepath.Join(filepath.Dir(source.path), ".enkv-pending", filepath.Base(source.path))}
			result, deliveryErr := RenameConfigurationDomain(interrupted, source.path, format, "next")
			record := localEditWire(t, result, deliveryErr)
			delivery := record["local_delivery"].(map[string]any)
			if deliveryErr == nil || record["outcome"] != "pending" || delivery["outcome"] != "pending" || delivery["recovery_source"] != source.path || delivery["readback"] != nil || LocalEditExitCode(result, deliveryErr) != 3 {
				t.Fatal("interrupted edit lost saved recovery facts")
			}
			ctx, recoverCancel := context.WithTimeout(t.Context(), time.Minute)
			defer recoverCancel()
			recovered, recoverErr := RecoverConfigurationEdit(ctx, source.path, format)
			if recoverErr != nil || LocalEditExitCode(recovered, recoverErr) != 0 {
				t.Fatal("saved exact edit did not recover", recoverErr)
			}
			generated := filepath.Join(filepath.Dir(source.path), ".enkv", "next.generated.json")
			localEditReadbackMatches(t, recovered, recoverErr, source.path, generated)
			if again, err := RecoverConfigurationEdit(ctx, source.path, format); err == nil || LocalEditExitCode(again, err) != 2 {
				t.Fatal("recovery replayed without an exact pending marker")
			}
		})
	}
}

// full_only: false
func TestRecipientRenameCollisionLeavesPairUnchanged(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			var old string
			source := configurationSetPair(t, "aws", format, func(editable, generated map[string]any) {
				declarations := editable["recipients"].(map[string]any)
				for ref := range declarations {
					old = ref
					break
				}
				rows := generated["recipients"].(map[string]any)
				row := rows[old].(map[string]any)
				rows["occupied"] = map[string]any{"id": strings.Repeat("71", 32), "encryption": row["encryption"]}
			})
			configurationSetWritable(t, source)
			configurationSetModel(t, source.path, format)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			result, err := RenameConfigurationRecipientReference(ctx, source.path, format, old, "occupied")
			if err == nil || LocalEditExitCode(result, err) != 2 {
				t.Fatal("rename to an occupied companion reference was accepted")
			}
			source.assertUnchanged(t)
		})
	}
}
