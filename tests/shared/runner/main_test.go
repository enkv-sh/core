package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
)

// full_only: false
func TestListAndInvalidCommandsHaveNoFixtureEffects(t *testing.T) {
	for _, args := range [][]string{{"list"}, {"list", "synthetic-secret"}, {"synthetic-secret"}} {
		root := t.TempDir()
		var output bytes.Buffer
		err := runCommand(context.Background(), root, "", args, &output)
		valid := len(args) == 1 && args[0] == "list"
		if (err == nil) != valid {
			t.Fatalf("list command status differs: %v", err)
		}
		if valid {
			lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
			listed := map[string]string{}
			for _, line := range lines {
				name, _, found := strings.Cut(line, "\t")
				if !found || listed[name] != "" {
					t.Fatal("scenario list has missing fields or duplicate identity")
				}
				listed[name] = line
			}
			if len(listed) != len(catalog.Names()) {
				t.Fatal("scenario list inventory differs")
			}
			for _, name := range catalog.Names() {
				if listed[name] == "" {
					t.Fatal("scenario list omitted a case", name)
				}
			}
			for _, members := range []string{"1", "32", "64"} {
				name := "state.single-value-update-preserves-other-values/members_" + members
				if !strings.Contains(listed[name], "\tfixed fixture\tfixture members "+members+", value bytes ") {
					t.Fatal("scenario list lost the fixed case fixture", name)
				}
			}
		}
		if !valid && (output.Len() != 0 || strings.Contains(err.Error(), "synthetic-secret")) {
			t.Fatal("invalid command exposed input")
		}
		files, readErr := os.ReadDir(root)
		if readErr != nil || len(files) != 0 {
			t.Fatal("list or invalid command created fixture files")
		}
	}
}
