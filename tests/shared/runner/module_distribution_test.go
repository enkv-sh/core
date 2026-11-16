package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func distributionRoots(t *testing.T) (string, string) {
	t.Helper()
	root := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	return root, filepath.Join(filepath.Dir(root), "enkv-extensions")
}

// full_only: false
func TestModuleDistributionGenerationIsExact(t *testing.T) {
	root, docs := distributionRoots(t)
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	if _, err := runGo(ctx, root, "", "run", filepath.Join(docs, "distribution/generate.go"), "-root", docs, "-check"); err != nil {
		t.Fatal("module distribution output differs from its inventory", err)
	}

	// These source owners come from the approved module map, independently of the inventory.
	expected := map[string][]string{
		"enkv-core":       {"core", "crypto", "telemetry", "providers/aws", "providers/gcp", "compositions/generatorhost", "compositions/internal/nativeprocess", "compositions/outputhost", "compositions/manifesthost", "compositions/configuration", "compositions/observability", "compositions/aws", "compositions/gcp", "compositions/full", "tests/fixtures/output-contract-test"},
		"enkv-extensions": {"sdk/protocols/generator", "sdk/protocols/output", "sdk/generator", "sdk/output", "sdk/manifest-generator", "sdk/examples/local-token-generator", "sdk/examples/local-value-output", "sdk/examples/ini-reference-manifest", "sdk/examples/testservice", "plugins/generators/cloudflare-account-token", "plugins/generators/local-random-secret", "plugins/outputs/aws-secrets-manager", "plugins/outputs/gcp-secret-manager", "plugins/outputs/github-actions", "plugins/manifest-generators/generic-json", "plugins/manifest-generators/opentofu-tfvars-json", "sdk/artifact", "sdk/protocols/manifest-generator"},
	}
	body, err := os.ReadFile(filepath.Join(docs, moduleInventoryPath))
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Modules []struct {
			Module        string `json:"module"`
			Repository    string `json:"repository"`
			RepositoryURL string `json:"repository_url"`
			Directory     string `json:"directory"`
			TagPrefix     string `json:"tag_prefix"`
		}
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Modules) != 33 {
		t.Fatal("module inventory is incomplete", len(inventory.Modules))
	}
	actual := make(map[string]bool)
	for _, row := range inventory.Modules {
		key := row.Repository + "/" + row.Directory
		if actual[key] || row.Module != "enkv.sh/"+row.Directory || row.RepositoryURL != "https://github.com/enkv-sh/"+strings.TrimPrefix(row.Repository, "enkv-") || row.TagPrefix != row.Directory+"/" {
			t.Fatal("module location differs", row)
		}
		actual[key] = true
		page, err := os.ReadFile(filepath.Join(docs, "distribution/go-import", row.Directory, "go-import.html"))
		if err != nil {
			t.Fatal(err)
		}
		tag := `<meta name="go-import" content="` + row.Module + " git " + row.RepositoryURL + " " + row.Directory + `">`
		if bytes.Count(page, []byte(tag)) != 1 || bytes.Count(page, []byte(`name="go-import"`)) != 1 {
			t.Fatal("module mapping differs", row.Module)
		}
	}
	for repository, dirs := range expected {
		for _, dir := range dirs {
			if !actual[repository+"/"+dir] {
				t.Fatal("module owner missing", repository, dir)
			}
		}
	}
	if err := verifyModuleInventory(root); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestModuleDistributionRejectsAmbiguousAndUnknownInventory(t *testing.T) {
	root, docs := distributionRoots(t)
	original, err := os.ReadFile(filepath.Join(docs, moduleInventoryPath))
	if err != nil {
		t.Fatal(err)
	}
	generator := filepath.Join(docs, "distribution/generate.go")
	baseline := filepath.Join(t.TempDir(), "enkv-extensions")
	rawSourceWrite(t, baseline, moduleInventoryPath, string(original))
	copyDistributionModuleFiles(t, root, baseline)
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	if _, err := runGo(ctx, root, "", "run", generator, "-root", baseline); err != nil {
		t.Fatal("valid module inventory baseline failed", err)
	}
	snapshot := func(t *testing.T, root string) map[string]string {
		t.Helper()
		files := make(map[string]string)
		err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, filename)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			value := info.Mode().String()
			if !entry.IsDir() {
				body, err := os.ReadFile(filename)
				if err != nil {
					return err
				}
				value += string(body)
			}
			files[relative] = value
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	for _, condition := range []struct{ name, diagnostic string }{
		{"unknown_repository", "unknown module repository"},
		{"duplicate_module", "overlapping module ownership"},
		{"overlapping_module", "overlapping module ownership"},
		{"overlapping_owner", "overlapping module ownership"},
		{"duplicate_field", "duplicate inventory field"},
	} {
		t.Run(condition.name, func(t *testing.T) {
			var input map[string]any
			if err := json.Unmarshal(original, &input); err != nil {
				t.Fatal(err)
			}
			rows := input["modules"].([]any)
			first := rows[0].(map[string]any)
			second := rows[1].(map[string]any)
			switch condition.name {
			case "unknown_repository":
				first["repository"] = "outside"
			case "duplicate_module":
				second["module"] = first["module"]
			case "overlapping_module":
				second["module"] = first["module"].(string) + "/child"
			case "overlapping_owner":
				second["directory"] = first["directory"].(string) + "/child"
				second["tag_prefix"] = second["directory"].(string) + "/"
			}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if condition.name == "duplicate_field" {
				body = bytes.Replace(body, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
			}
			copyRoot := filepath.Join(t.TempDir(), "enkv-extensions")
			if err := os.MkdirAll(filepath.Join(copyRoot, "distribution"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(copyRoot, moduleInventoryPath), body, 0600); err != nil {
				t.Fatal(err)
			}
			copyDistributionModuleFiles(t, root, copyRoot)
			before := snapshot(t, filepath.Dir(copyRoot))
			ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
			defer cancel()
			_, err = runGo(ctx, root, "", "run", generator, "-root", copyRoot)
			var failure *toolFailure
			if !errors.As(err, &failure) || !failure.process.Started || !failure.process.Joined || failure.process.Status != "process_failed" || failure.overflow || len(failure.stdout) != 0 || string(failure.stderr) != condition.diagnostic+"\nexit status 1\n" {
				t.Fatal("invalid module ownership did not reach its exact guard", condition.name, err)
			}
			if !maps.Equal(before, snapshot(t, filepath.Dir(copyRoot))) {
				t.Fatal("invalid inventory changed source or produced output", condition.name)
			}
			for _, name := range []string{"go.work", "distribution/go-import"} {
				if _, err := os.Lstat(filepath.Join(copyRoot, name)); !os.IsNotExist(err) {
					t.Fatal("invalid inventory produced output", name, err)
				}
			}
		})
	}
}

// full_only: false
func TestModuleDistributionRejectsObsoleteMappingFiles(t *testing.T) {
	root, docs := distributionRoots(t)
	copyRoot := filepath.Join(t.TempDir(), "enkv-extensions")
	body, err := os.ReadFile(filepath.Join(docs, moduleInventoryPath))
	if err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, copyRoot, moduleInventoryPath, string(body))
	copyDistributionModuleFiles(t, root, copyRoot)
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	generator := filepath.Join(docs, "distribution/generate.go")
	if _, err := runGo(ctx, root, "", "run", generator, "-root", copyRoot); err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, copyRoot, "distribution/go-import/obsolete/go-import.html", "obsolete")
	if _, err := runGo(ctx, root, "", "run", generator, "-root", copyRoot, "-check"); err == nil {
		t.Fatal("obsolete deployable mapping accepted")
	}
}

func copyDistributionModuleFiles(t *testing.T, root, copyRoot string) {
	t.Helper()
	copiedRoot := filepath.Join(filepath.Dir(copyRoot), "enkv-core")
	for _, row := range moduleSources {
		owner, err := moduleSourceDirectory(root, row)
		if err != nil {
			t.Fatal(err)
		}
		modbody, err := os.ReadFile(filepath.Join(owner, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		copyOwner := filepath.Join(copiedRoot, row.Directory)
		if row.Sibling != "" {
			copyOwner = filepath.Join(filepath.Dir(copiedRoot), row.Sibling, row.Directory)
		}
		rawSourceWrite(t, copyOwner, "go.mod", string(modbody))
	}
}

// full_only: false
func TestModuleInventoryFreshnessBindsExactInventoryBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "enkv-core")
	copyModuleInventoryFixture(t, root)
	if err := verifyModuleInventory(root); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(filepath.Dir(root), "enkv-extensions", moduleInventoryPath)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte("\n"))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	if err := verifyModuleInventory(root); err == nil {
		t.Fatal("stale generated module table accepted")
	}
}

// full_only: false
func TestModuleDistributionWorkspaceUsesExactRequiredVersions(t *testing.T) {
	root, docs := distributionRoots(t)
	copiedDocs := filepath.Join(t.TempDir(), "enkv-extensions")
	copiedImpl := filepath.Join(filepath.Dir(copiedDocs), "enkv-core")
	// Four real registered owners give two versions of one dependency and a
	// duplicate exact requirement. The external module must remain unresolved.
	type location struct {
		Selector      string `json:"selector"`
		Module        string `json:"module"`
		Repository    string `json:"repository"`
		RepositoryURL string `json:"repository_url"`
		Directory     string `json:"directory"`
		TagPrefix     string `json:"tag_prefix"`
	}
	inv := struct {
		SchemaVersion int        `json:"schema_version"`
		Go            string     `json:"go"`
		Modules       []location `json:"modules"`
	}{SchemaVersion: 1, Go: "1.27.0"}
	for _, selector := range []string{"core", "crypto", "compositions/outputhost", "telemetry"} {
		inv.Modules = append(inv.Modules, location{selector, "enkv.sh/" + selector, "enkv-core", "https://github.com/enkv-sh/core", selector, selector + "/"})
	}
	inventory, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, copiedDocs, moduleInventoryPath, string(inventory))
	sources := map[string]string{
		"core":                    "module enkv.sh/core\n\ngo 1.27.0\nrequire ( // stock module syntax\n \"enkv.sh/telemetry\" v0.0.1\n example.invalid/external v1.2.3\n)\n",
		"crypto":                  "module enkv.sh/crypto\n\ngo 1.27.0\nrequire enkv.sh/telemetry v0.0.2\n",
		"compositions/outputhost": "module enkv.sh/compositions/outputhost\n\ngo 1.27.0\nrequire enkv.sh/telemetry v0.0.1\n",
		"telemetry":               "module enkv.sh/telemetry\n\ngo 1.27.0\n",
	}
	for selector, body := range sources {
		rawSourceWrite(t, copiedImpl, selector+"/go.mod", body)
	}
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	generator := filepath.Join(docs, "distribution/generate.go")
	if _, err := runGo(ctx, root, "", "run", generator, "-root", copiedDocs); err != nil {
		t.Fatal(err)
	}
	t.Run("ambient module selection", func(t *testing.T) {
		// Every alternate has its owner's real identity but different requirements.
		// Ambient Go settings must not select these files in place of go.mod.
		for selector, body := range sources {
			body = strings.ReplaceAll(strings.ReplaceAll(body, "v0.0.1", "v0.0.9"), "v0.0.2", "v0.0.9")
			rawSourceWrite(t, copiedImpl, selector+"/ambient.mod", body)
		}
		goenv := filepath.Join(t.TempDir(), "goenv")
		if err := os.WriteFile(goenv, []byte("GOFLAGS=-modfile=ambient.mod\n"), 0600); err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(t.TempDir(), "generate")
		if _, err := runGo(ctx, root, "", "build", "-o", binary, generator); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "-root", copiedDocs)
		command.Dir = copiedDocs
		command.Env = environment(goEnvironment(), map[string]string{"GOFLAGS": "-modfile=ambient.mod", "GOENV": goenv, "GOWORK": "off"})
		output := new(limitedOutput)
		command.Stdout, command.Stderr = output, output
		result := superviseProcess(ctx, command)
		if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
			t.Fatalf("ambient settings changed generator module inputs: result=%+v output=%s", result, output.String())
		}
	})
	body := runModuleModeCommand(t, ctx, copiedDocs, map[string]string{"GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off"}, "work", "edit", "-json", filepath.Join(copiedDocs, "go.work"))
	var workspace struct {
		Use     []struct{ DiskPath string }
		Replace []struct {
			Old, New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal(body, &workspace); err != nil {
		t.Fatal(err)
	}
	if len(workspace.Use) != 4 || len(workspace.Replace) != 2 {
		t.Fatal("workspace changed use owners or replacement set", workspace)
	}
	for i, version := range []string{"v0.0.1", "v0.0.2"} {
		row := workspace.Replace[i]
		if row.Old.Path != "enkv.sh/telemetry" || row.Old.Version != version || row.New.Path != "../enkv-core/telemetry" || row.New.Version != "" {
			t.Fatal("workspace lost exact required version or local owner", row)
		}
	}
	for selector, expected := range sources {
		body, err := os.ReadFile(filepath.Join(copiedImpl, selector, "go.mod"))
		if err != nil || string(body) != expected {
			t.Fatal("generation changed source module", selector, err)
		}
	}
	rawSourceWrite(t, copiedImpl, "crypto/go.mod", strings.Replace(sources["crypto"], "v0.0.2", "v0.0.3", 1))
	if _, err := runGo(ctx, root, "", "run", generator, "-root", copiedDocs, "-check"); err == nil {
		t.Fatal("unchanged inventory hid module requirement drift")
	}
}
