package main

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func localLivePreparationFixture(t *testing.T, provider string) (context.Context, string, string) {
	t.Helper()
	if provider != "gcp" && provider != "aws" {
		t.Fatal("unknown local preparation provider")
	}
	root, bootstrap := lintFixture(t, t.TempDir())
	// Preparation binds the real output child even when the scenario selects no
	// output. Keep those small source owners and their required metadata intact.
	for _, module := range []string{"sdk/artifact", "protocols/output", "sdk/output", outputTestModule} {
		from, err := sourcePath(testRepositoryRoot(t), module)
		if err != nil {
			t.Fatal(err)
		}
		target, err := sourcePath(root, module)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(target); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(target, os.DirFS(from)); err != nil {
			t.Fatal("copy local preparation output owner", module, err)
		}
	}
	// The live worker entrypoints are compiled and classified, but no fixture
	// body may execute before the caller's controlled run-owned build refusal.
	for path, body := range map[string]string{
		"core/fixture.go":                       "package core\nimport _ \"" + modulePrefix + "telemetry\"\n",
		"telemetry/fixture.go":                  "package telemetry\n",
		"providers/" + provider + "/fixture.go": "package " + provider + "\nimport _ \"" + modulePrefix + "core/contract\"\n",
		"tests/shared/fixture_test.go":          "package core\n",
		"tests/shared/process_fixture_test.go": `package core
import "testing"
// full_only: false
func TestFreshProcessChild(t *testing.T) { t.Fatal("local fixture worker must not execute") }
`,
		"tests/live/shared/fixture_test.go": `package core
import "testing"
// full_only: false
func TestLiveInventoryFreshProcess(t *testing.T) { t.Fatal("local fixture control must not execute") }
`,
		"tests/live/runner/fixture_test.go": `package core
import "testing"
// full_only: false
func TestLiveRun(t *testing.T) { t.Fatal("local fixture worker must not execute") }
// full_only: false
func TestLiveChild(t *testing.T) { t.Fatal("local fixture worker must not execute") }
// full_only: false
func TestLiveCleanup(t *testing.T) { t.Fatal("local fixture worker must not execute") }
`,
		"tests/live/providers/" + provider + "/fixture_test.go": fmt.Sprintf(`package core
import (
 "testing"
 _ %q
)
// full_only: false
func TestPreparedLocalProvider(t *testing.T) { t.Fatal("local fixture control must not execute") }
`, modulePrefix+"providers/"+provider),
	} {
		writeLocalGoFixture(t, root, path, body)
	}
	initializeWorkflowExecutionFixture(t, root)
	ctx := withResourceLocks(withExecutionParallel(t.Context(), 1), resourceLockFixture(t))
	return ctx, root, bootstrap
}
