package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestLimitedOutputBoundsCopyAndConsumesAllInput(t *testing.T) {
	const bound = 32 << 20
	body := bytes.Repeat([]byte("x"), bound+1)
	for _, test := range []struct {
		name string
		size int
	}{
		{name: "at_bound", size: bound},
		{name: "over_bound", size: bound + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output limitedOutput
			// Expose only Read so io.Copy can select any destination ReadFrom.
			// An embedded bytes.Buffer would bypass the bounded Write method.
			source := struct{ io.Reader }{bytes.NewReader(body[:test.size])}
			n, err := io.Copy(&output, source)
			if err != nil || n != int64(test.size) {
				t.Fatalf("capture did not consume all input: copied %d, error %v", n, err)
			}
			if output.Len() != bound || !bytes.Equal(output.Bytes(), body[:bound]) {
				t.Fatal("capture did not retain exactly the bounded prefix")
			}
			if output.overflow != (test.size > bound) {
				t.Fatalf("capture overflow = %t for %d bytes", output.overflow, test.size)
			}
		})
	}
}

func copyPublicModuleKit(t *testing.T, maintained, root string, selectors []string) {
	t.Helper()
	for _, selector := range selectors {
		source, ok := registeredModule(selector)
		if !ok || source.Sibling == "" {
			t.Fatal("kit source is not a registered public module", selector)
		}
		owner, err := moduleSourceDirectory(maintained, source)
		if err != nil {
			t.Fatal(err)
		}
		err = filepath.WalkDir(owner, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("kit input is not regular")
			}
			relative, err := filepath.Rel(owner, path)
			if err != nil {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			target, err := sourcePath(root, selector+"/"+filepath.ToSlash(relative))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return err
			}
			return os.WriteFile(target, body, info.Mode().Perm())
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
