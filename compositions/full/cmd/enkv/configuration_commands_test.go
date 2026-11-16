package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestConfigurationCommandsReachTheirInstalledHandlers(t *testing.T) {
	if command := os.Getenv("ENKV_CONFIGURATION_DISPATCH_TEST"); command != "" {
		args := []string{command, "--source", filepath.Join(os.TempDir(), "absent-enkv-dispatch-source"), "--source-format", "json", "--json"}
		if command == "set" {
			args = []string{command}
		}
		os.Exit(run(args, os.Stdout, os.Stderr))
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ command, marker string }{
		{"init", `"operation_kind": "initialize-empty-domain"`},
		{"apply", `"operation_kind":"apply-declaration"`},
		{"set", "set requires --name"},
	} {
		t.Run(row.command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, executable, "-test.run=^TestConfigurationCommandsReachTheirInstalledHandlers$")
			child.Env = append(os.Environ(), "ENKV_CONFIGURATION_DISPATCH_TEST="+row.command)
			body, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 || !bytes.Contains(body, []byte(row.marker)) {
				t.Fatalf("command did not reach its installed handler: %s; error=%v; output=%s", row.command, err, body)
			}
		})
	}
}
