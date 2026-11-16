package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestExecutionPreparationKeepsAssignedParallel(t *testing.T) {
	t.Run("unassigned_command", func(t *testing.T) {
		got, err := executionGoArguments(t.Context(), []string{"build", "."})
		if err != nil || !reflect.DeepEqual(got, []string{"build", "-p=1", "."}) {
			t.Fatal("unassigned command restored root allowance", got, err)
		}
	})
	t.Run("unassigned_policy", func(t *testing.T) {
		policy, err := executionWithinContext(t.Context(), defaultExecutionPolicy())
		if err != nil || policy.Resolved.Parallel != 1 || policy.Resolved.MemoryLimitMiB != 8192 {
			t.Fatal("unassigned nested policy restored root allowance", policy, err)
		}
	})
	for _, assigned := range []bool{false, true} {
		name := "workflow_unassigned"
		if assigned {
			name = "workflow_assigned"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
				t.Fatal(err)
			}
			writeLocalGoFixture(t, root, "core/go.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			arguments := filepath.Join(root, "go-arguments")
			t.Setenv("ENKV_PREPARATION_ARGUMENTS", arguments)
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			probe := `#!/bin/sh
if [ "$#" -eq 4 ] && [ "$1" = mod ] && [ "$2" = edit ] && [ "$3" = -json ]; then
 case "$4" in -modfile=?*) exec ` + shellQuote(realGo) + ` "$@" ;; esac
fi
` + "printf '%s\\n' \"$@\" > \"$ENKV_PREPARATION_ARGUMENTS\"\nprintf '%s\\n' '{\"Match\":[\"./...\"]}'\n"
			if err := os.WriteFile(filepath.Join(root, "go"), []byte(probe), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "workflow.json")
			if err := os.WriteFile(path, []byte(`{"schema_version":1,"name":"capacity","execution":{"parallel":4},"steps":[{"id":"unit","kind":"unit","packages":["core"]}]}`), 0600); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if assigned {
				ctx = withExecutionParallel(ctx, 1)
			}
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(arguments)
			if err != nil || !strings.Contains(string(body), "\n-p=1\n") || strings.Contains(string(body), "\n-p=4\n") || plan.Execution.Resolved.Parallel != 1 {
				t.Fatalf("workflow preparation restored root allowance: arguments=%q policy=%+v error=%v", body, plan.Execution, err)
			}
		})
	}
	t.Run("explicit_root_default", func(t *testing.T) {
		root, err := resolveExecution(executionRequest{}, executionRequest{})
		if err != nil || root.Resolved.Parallel != 4 {
			t.Fatal("root default changed", root, err)
		}
		policy, err := executionWithinContext(withExecutionCapacity(t.Context(), root), root)
		if err != nil || policy.Resolved.Parallel != 4 {
			t.Fatal("explicit root lost its assigned allowance", policy, err)
		}
	})
}
