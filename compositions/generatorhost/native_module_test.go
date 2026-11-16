package generatorhost

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func prepareNativeModule(t testing.TB, root string, command *exec.Cmd, output string) string {
	t.Helper()
	root, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	directory := command.Dir
	if directory == "" {
		directory, err = os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	input, overlay := "", ""
	args := append([]string(nil), command.Args[:2]...)
	for _, arg := range command.Args[2:] {
		if value, ok := strings.CutPrefix(arg, "-modfile="); ok {
			input = value
			continue
		}
		if value, ok := strings.CutPrefix(arg, "-overlay="); ok {
			overlay = value
		}
		args = append(args, arg)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	prepare := exec.CommandContext(ctx, "go", "run", "-mod=readonly", filepath.Join(root, "tests/scripts/bootstrap.go"), "modfile", root, directory, input, overlay, output)
	prepare.Dir = root
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOWORK" && key != "GOTOOLCHAIN" {
			prepare.Env = append(prepare.Env, entry)
		}
	}
	prepare.Env = append(prepare.Env, "GOWORK=off", "GOTOOLCHAIN=local")
	if body, err := prepare.CombinedOutput(); err != nil {
		t.Fatalf("prepare native module inputs: %v\n%s", err, body)
	}
	command.Args = append(args[:2], append([]string{"-modfile=" + output}, args[2:]...)...)
	return output
}
