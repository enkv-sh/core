package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
)

func editableOnlyLocalConfiguration(t *testing.T, format configuration.Format) (string, []byte) {
	t.Helper()
	var editable map[string]any
	source := configurationSetPair(t, "aws", format, func(e, _ map[string]any) {
		editable = e
		e["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
		var generatedSource map[string]any
		if err := json.Unmarshal([]byte(`{"kind":"generated","plugin":"cloudflare-account-token","epoch":3,"retirement":"manual","settings":{"account":"0123456789abcdef0123456789abcdef","name":"edge-token","policies":[{"effect":"allow","permission_groups":["123456789abcdef0123456789abcdef0"],"resources":[{"kind":"account","id":"0123456789abcdef0123456789abcdef"}]}]}}`), &generatedSource); err != nil {
			t.Fatal(err)
		}
		e["entries"].(map[string]any)["token"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": generatedSource}
	})
	configurationSetWritable(t, source)
	if err := source.pair.Close(); err != nil {
		t.Fatal(err)
	}
	delete(editable, "generated")
	var body []byte
	if format == configuration.JSON {
		var err error
		body, err = json.Marshal(editable)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		var out bytes.Buffer
		for _, key := range []string{"schema", "domain", "recipients", "entries", "outputs"} {
			value, err := json.Marshal(editable[key])
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&out, "%s: %s\n", key, value)
		}
		body = out.Bytes()
	}
	if err := os.Chmod(source.path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source.path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source.generated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(source.generated), "independent-notes.json"), []byte("unchanged local fixture notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return source.path, body
}

func localGeneratedOrdinaryImages(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	images := map[string][]byte{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || path == directory {
			return walkErr
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch name {
			case ".enkv-locks", ".enkv-pending", ".enkv-transactions":
				return filepath.SkipDir
			}
			images[name+"/"] = nil
			return nil
		}
		if !entry.Type().IsRegular() {
			return fs.ErrInvalid
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		images[name] = body
		return nil
	})
	if err != nil {
		t.Fatal("generated fixture image unavailable", err)
	}
	return images
}

// full_only: false
func TestLocalEditableOnlyEditsAndRecoveryProveSatelliteAbsence(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, action := range []string{"rename"} {
			for _, interrupt := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/pending-%t", format, action, interrupt), func(t *testing.T) {
					path, before := editableOnlyLocalConfiguration(t, format)
					generatedDirectory := filepath.Join(filepath.Dir(path), ".enkv")
					beforeImages := localGeneratedOrdinaryImages(t, generatedDirectory)
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					operationContext := context.Context(ctx)
					if interrupt {
						operationContext = &cancelPendingConfiguration{Context: ctx, cancel: cancel, marker: filepath.Join(filepath.Dir(path), ".enkv-pending", filepath.Base(path))}
					}
					var result *LocalEditResult
					var err error
					result, err = RenameConfigurationDomain(operationContext, path, format, "next")
					name := `"name":"next"`
					if format == configuration.YAML {
						name = `"name":next`
					}
					want := strings.Replace(string(before), `"name":"prod"`, name, 1)
					if interrupt {
						if LocalEditExitCode(result, err) != 3 {
							t.Fatal("editable-only interruption lost its saved owner", err)
						}
						recoveryContext, recoveryCancel := context.WithTimeout(t.Context(), time.Minute)
						defer recoveryCancel()
						result, err = RecoverConfigurationEdit(recoveryContext, path, format)
					}
					if err != nil || LocalEditExitCode(result, err) != 0 {
						t.Fatal("valid editable-only local edit refused", err)
					}
					body, err := os.ReadFile(path)
					if err != nil || string(body) != want {
						t.Fatal("editable-only edit changed another source byte", err)
					}
					record := localEditWire(t, result, nil)
					delivery := record["local_delivery"].(map[string]any)
					readback := delivery["readback"].(map[string]any)
					digest := sha256.Sum256(body)
					if delivery["generated_path"] != nil || readback["generated_digest"] != nil || readback["editable_digest"] != hex.EncodeToString(digest[:]) {
						t.Fatal("proved absence was reported as a file or a zero digest")
					}
					for _, satellite := range []string{"prod.generated.json", "next.generated.json"} {
						if _, err := os.Lstat(filepath.Join(generatedDirectory, satellite)); !os.IsNotExist(err) {
							t.Fatal("editable-only edit created a satellite", err)
						}
					}
					afterImages := localGeneratedOrdinaryImages(t, generatedDirectory)
					t.Logf("editable-only delivery: ordinary_before=%d ordinary_after=%d ordinary_exact=%t generated_path_absent=%t generated_digest_absent=%t", len(beforeImages), len(afterImages), reflect.DeepEqual(afterImages, beforeImages), delivery["generated_path"] == nil, readback["generated_digest"] == nil)
					if !reflect.DeepEqual(afterImages, beforeImages) {
						t.Fatal("editable-only edit changed unrelated generated-directory files")
					}
				})
			}
		}
	}
}
