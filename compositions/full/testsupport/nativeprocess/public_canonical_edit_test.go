package nativeprocess

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/examples/testservice"
)

// full_only: false
func TestPublicNativeRecoveredGeneratorEditsRespectCurrentEpoch(t *testing.T) {
	cli, _ := workflowBuildExecutables(t, false)
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	build, _ := nativeExtensionBuildAuthor(t, nativeExtensionCopyExample(t, "local-token-generator"))
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(map[configuration.Format]string{configuration.JSON: "json", configuration.YAML: "yaml"}[format], func(t *testing.T) {
			f := newNativeExtensionCase(t, cli, []artifact.LocalPlugin{build})
			subject := "token"
			f.declare(t, 0, "manual", &subject, false)
			credential := []string{"ENKV_EXAMPLE_TOKEN=" + nativeExtensionBearer}
			nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "apply", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
			generatedPath := filepath.Join(filepath.Dir(f.path), f.source["generated"].(string))
			var generated map[string]any
			nativeGeneratedReadJSON(t, generatedPath, &generated)
			canonical := nativeMaintenanceCanonicalGenerator(t, f.server.URL, generated)
			canonical["epoch"] = 0
			f.source["entries"].(map[string]any)["TOKEN"].(map[string]any)["source"] = canonical
			nativeGeneratedWriteJSON(t, generatedPath, generated)
			nativeGeneratedWriteJSON(t, f.path, f.source)
			captured, err := configuration.Capture(t.Context(), f.path, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			model, parseErr := configuration.Parse(t.Context(), captured)
			closeErr := captured.Close()
			if parseErr != nil || closeErr != nil {
				t.Fatal(parseErr, closeErr)
			}
			var readable bytes.Buffer
			if err := configuration.EmitEditable(&readable, model, format); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.path, readable.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			formatName := map[configuration.Format]string{configuration.JSON: "json", configuration.YAML: "yaml"}[format]
			args := []string{"apply", "--source", f.path, "--source-format", formatName, "--json"}
			workflowResult(t, f.run(t, "apply", false, nil, args...), "no-op")
			beforeHead, _, beforeEntries := f.selected(t)
			edited := strings.ReplaceAll(readable.String(), `"subject": "token"`, `"subject": "worker"`)
			if edited == readable.String() {
				t.Fatal("recovered settings fixture did not edit subject")
			}
			if err := os.WriteFile(f.path, []byte(edited), 0600); err != nil {
				t.Fatal(err)
			}
			beforeSource, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			beforeBacking, err := os.ReadFile(generatedPath)
			if err != nil {
				t.Fatal(err)
			}
			conflict := f.run(t, "apply", false, nil, args...)
			var refused struct {
				State  string `json:"state_result"`
				Commit bool   `json:"commit_may_have_occurred"`
			}
			if json.Unmarshal(conflict.out, &refused) != nil || conflict.code != 2 || refused.State != "generated-intent-conflict" || refused.Commit {
				t.Fatal("same-epoch recovered edit did not reach Core intent conflict")
			}
			afterConflict, _, _ := f.selected(t)
			if !reflect.DeepEqual(beforeHead, afterConflict) || f.service.Counts() != (testservice.Counts{Tokens: 1, TokenCreates: 1}) {
				t.Fatal("refused canonical edit selected state or reached an effect")
			}
			advanced := strings.ReplaceAll(edited, `"epoch": 0`, `"epoch": 1`)
			if advanced == edited {
				t.Fatal("recovered settings fixture did not advance epoch")
			}
			if err := os.WriteFile(f.path, []byte(advanced), 0600); err != nil {
				t.Fatal(err)
			}
			selectedSource, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			rotated := nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, args...), "retirement-pending", 3)
			_, root, afterEntries := f.selected(t)
			duties := nativeExtensionDutyRecords(t, f.store, root)
			beforeEntry, hadBefore := beforeEntries["TOKEN"]
			afterEntry, hadAfter := afterEntries["TOKEN"]
			before, after := beforeEntry.Generated, afterEntry.Generated
			if !hadBefore || !hadAfter || before.Epoch != 0 || after.Epoch != 1 || after.GenerationID == before.GenerationID || len(rotated.Duties) != 1 || len(duties) != 1 || duties[0].ResourceID != before.ResourceIncarnationID || f.service.Counts() != (testservice.Counts{Tokens: 2, TokenCreates: 2}) {
				t.Fatal("advanced canonical edit did not preserve exact old retirement and select new generation")
			}
			nativeExtensionReadToken(t, f, "t2", []byte("\x00\xffextension/worker/t2"))
			afterSource, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			afterBacking, err := os.ReadFile(generatedPath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(beforeSource, selectedSource) || !bytes.Equal(afterSource, selectedSource) || !bytes.Equal(beforeBacking, afterBacking) {
				t.Fatal("apply silently saved edited canonical backing or changed source")
			}
			f.finish(t, len(f.children), "token/t1", "worker/t2")
		})
	}
}
