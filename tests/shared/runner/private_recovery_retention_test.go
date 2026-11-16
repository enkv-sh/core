package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func unresolvedPrivateRecoveryFixture(t *testing.T, root string) (*runState, map[string][]byte) {
	t.Helper()
	s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp"}, records.Source{}, "controlled")
	if err != nil {
		t.Fatal(err)
	}
	s.fail("cleanup_incomplete", "cleanup")
	s.finish()
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	files := privateRecoveryPacket(t, s)
	path := filepath.Join(s.directory, "run.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	files[path] = body
	return s, files
}

func privateRecoveryPacket(t *testing.T, s *runState) map[string][]byte {
	t.Helper()
	state := filepath.Join(s.private, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"input.json":     "{\"cleanup\":\"required\"}\n",
		"inventory.json": "{\"outcome\":\"unknown\"}\n",
	} {
		if err := os.WriteFile(filepath.Join(state, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ledger := filepath.Join(state, "generator-cleanup.json")
	account := strings.Repeat("a", 32)
	if err := records.NewGeneratorFixtureLedger(ledger, s.record.RunID, account); err != nil {
		t.Fatal(err)
	}
	if err := records.UpdateGeneratorFixtureLedger(ledger, s.record.RunID, account, func(current *records.GeneratorFixtureLedger) error {
		return current.BeginCreate(strings.Repeat("b", 64))
	}); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, name := range []string{"input.json", "inventory.json", "generator-cleanup.json"} {
		path := filepath.Join(state, name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[path] = body
	}
	return files
}

func assertPrivateRecoveryUnchanged(t *testing.T, files map[string][]byte) {
	t.Helper()
	for path, want := range files {
		if body, err := os.ReadFile(path); err != nil || !bytes.Equal(body, want) {
			t.Errorf("original recovery state changed: %s: %v", path, err)
		}
	}
}

// full_only: false
func TestRetiredPrivateCleanupPreservesRecoveryState(t *testing.T) {
	source := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	t.Run("body", func(t *testing.T) {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		_, files := unresolvedPrivateRecoveryFixture(t, root)
		body := filepath.Join(source, "tests/scripts/clean-private-body")
		if _, err := os.Lstat(body); err == nil {
			// Characterize the historical route only in this synthetic root.
			output, runErr := exec.Command("/bin/sh", body, root).CombinedOutput()
			if runErr != nil {
				t.Errorf("historical route could not be exercised: %v: %s", runErr, output)
			}
			t.Error("historical private cleanup body remains executable")
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		assertPrivateRecoveryUnchanged(t, files)
	})
	t.Run("entrypoints", func(t *testing.T) {
		if _, err := os.Lstat(filepath.Join(source, "tests/scripts/clean-private")); !os.IsNotExist(err) {
			t.Error("historical private cleanup wrapper remains", err)
		}
		for name, retired := range map[string]string{"Makefile": "clean-test-private", "tests/scripts/supervisor-sources.tsv": "clean-private"} {
			body, err := os.ReadFile(filepath.Join(source, name))
			if err != nil || strings.Contains(string(body), retired) {
				t.Error("retired cleanup remains in dispatch inputs", name, err)
			}
		}
		if _, err := preflightSupervisorExecution(source, []string{"clean-private"}); err == nil {
			t.Error("supervisor policy admits retired private cleanup")
		}
	})
}
