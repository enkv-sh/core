package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestArtifactBuildFactsBindLongestOwnerAndSelectedBytes(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "helper")
	if err := os.MkdirAll(helper, 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{filepath.Join(root, "go.mod"): "module example.test/main\n", filepath.Join(root, "main.go"): "package main\n", filepath.Join(helper, "go.mod"): "module example.test/main/helper\n", filepath.Join(helper, "helper.go"): "package helper\n"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	modules := []resolvedModule{{Path: "example.test/main", Dir: root, Main: true}, {Path: "example.test/main/helper", Dir: helper, Main: true}}
	packages := []compiledPackage{{ImportPath: "example.test/main", Dir: root, GoFiles: []string{"main.go"}}, {ImportPath: "example.test/main/helper", Dir: helper, GoFiles: []string{"helper.go"}}}
	info := &debug.BuildInfo{GoVersion: "go1.27.0", Path: "example.test/main", Main: debug.Module{Path: "example.test/main", Version: "(devel)"}, Deps: []*debug.Module{{Path: "example.test/main/helper", Version: "(devel)"}}, Settings: []debug.BuildSetting{{Key: "GOOS", Value: runtime.GOOS}, {Key: "GOARCH", Value: runtime.GOARCH}, {Key: "-trimpath", Value: "true"}}}
	selected, err := artifactSourcePackages(modules, packages)
	if err != nil || selected[1].Module.Path != "example.test/main/helper" {
		t.Fatal("longest owner", err)
	}
	first, err := captureArtifactBuildFacts(t.Context(), root, "output", modules, packages, info, []artifact.Contract{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Sources) != 2 || first.Resolved[1].Version != "" || first.Compiled[1].Version != "(devel)" {
		t.Fatal("actual workspace facts lost")
	}
	before, err := artifact.EncodeDependency(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helper, "second.go"), []byte("package helper\nconst Added=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	packages[1].GoFiles = append(packages[1].GoFiles, "second.go")
	second, err := captureArtifactBuildFacts(t.Context(), root, "output", modules, packages, info, []artifact.Contract{})
	if err != nil {
		t.Fatal(err)
	}
	after, err := artifact.EncodeDependency(second)
	if err != nil || bytes.Equal(before, after) {
		t.Fatal("new selected Go file did not change identity", err)
	}
	packages[1].ImportPath = "unowned.invalid/package"
	if _, err := artifactSourcePackages(modules, packages); err == nil {
		t.Fatal("unowned input accepted")
	}
}
