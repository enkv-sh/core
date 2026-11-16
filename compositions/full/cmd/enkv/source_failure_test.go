package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

// full_only: false
func TestFileCommandsRetainTypedSourceOrigin(t *testing.T) {
	for _, row := range []struct {
		name             string
		command, options []string
	}{
		{"initialization", []string{"init"}, nil},
		{"prepare", []string{"prepare"}, nil},
		{"apply", []string{"apply"}, nil},
		{"apply-publication", []string{"apply"}, []string{"--publish"}},
		{"apply-continuation", []string{"apply"}, []string{"--operation", idText(contract.ID{1})}},
		{"generated-cleanup", []string{"generated", "cleanup"}, nil},
		{"generated-retirement", []string{"generated", "retire"}, []string{"--duty", idText(contract.ID{1})}},
		{"publication", []string{"publish"}, []string{"--name", "VALUE"}},
		{"generated-list", []string{"generated", "list"}, nil},
		{"materialization", []string{"materialize"}, []string{"--name", "VALUE", "--out", "OUTPUT"}},
		{"manifest", []string{"manifest"}, []string{"--plugin", "private-renderer", "--out", "OUTPUT"}},
		{"gc-preview", []string{"gc", "plan"}, []string{"--out", "OUTPUT"}},
		{"gc-execution", []string{"gc", "apply"}, []string{"--operation", idText(contract.ID{1})}},
		{"abandonment", []string{"abandon", "list"}, nil},
		{"key-replacement", []string{"keys", "replace"}, []string{"--target", "authority", "--authorizer", "recovery", "--signing", replacementCLIKey, "--out", "OUTPUT"}},
		{"envelope-rekey", []string{"rekey"}, []string{"--name", "VALUE", "--out", "OUTPUT"}},
		{"recipient-retirement", []string{"recipients", "retire"}, []string{"--recipient", "member", "--out", "OUTPUT"}},
		{"domain-rename", []string{"rename"}, []string{"--name", "next"}},
		{"recipient-preparation", []string{"recipients", "add"}, []string{"--recipient", "member", "--mode", "current"}},
		{"recipient-reference-rename", []string{"recipients", "rename"}, []string{"--recipient", "member", "--new-reference", "reader"}},
		{"domain-inspection", []string{"inspect"}, nil},
		{"recipient-inspection", []string{"inspect"}, []string{"--recipient-id", idText(contract.ID{1})}},
		{"capacity", []string{"inspect"}, []string{"--capacity"}},
		{"receipt-list", []string{"receipt"}, nil},
		{"receipt-detail", []string{"receipt"}, []string{"--operation", idText(contract.ID{1})}},
	} {
		t.Run(row.name, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "source.json")
			if err := os.WriteFile(source, []byte(`{"schema":"wrong"}`), 0600); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, row.command...), "--json", "--source", source, "--source-format", "json", "--log-level", "off")
			for _, arg := range row.options {
				if arg == "OUTPUT" {
					arg = filepath.Join(directory, "output.json")
				}
				args = append(args, arg)
			}
			var out, diagnostic bytes.Buffer
			wantExit := 2
			if code := run(args, &out, &diagnostic); code != wantExit {
				t.Fatalf("invalid source returned %d, want %d: %s %s", code, wantExit, out.String(), diagnostic.String())
			}
			var wire struct {
				SourceFailure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
				Apply         struct {
					SourceFailure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
				} `json:"apply"`
			}
			if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
				t.Fatal(err, out.String())
			}
			if row.name == "apply-publication" {
				wire.SourceFailure = wire.Apply.SourceFailure
			}
			want := compositionfull.ConfigurationSourceFailure{SourceID: "source", Path: source, Field: "schema", Reason: "unsupported-schema", Line: 1, Column: 11, Precision: "exact"}
			if wire.SourceFailure == nil || *wire.SourceFailure != want {
				t.Fatalf("command lost typed source origin: %s %s", out.String(), diagnostic.String())
			}
		})
	}
}
