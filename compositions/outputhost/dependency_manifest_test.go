package outputhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

func fixtureDependencyManifest(t *testing.T, module, command string) DependencyManifest {
	t.Helper()
	facts := fixturePublicBuildFacts(module, module+"/cmd/"+command)
	helper := "example.test/helper"
	digest := sha256.Sum256([]byte("independent helper source"))
	facts.Sources = append([]artifact.Source{{Module: helper, Digest: digest}}, facts.Sources...)
	facts.Resolved = append([]artifact.Dependency{{Path: helper, Version: "v0.0.0", Replacement: &artifact.Replacement{Path: "../helper", SourceDigest: digest}}}, facts.Resolved...)
	facts.Compiled = append([]artifact.Dependency{{Path: helper, Version: "v0.0.0", Replacement: &artifact.Replacement{Path: "../helper", Version: "(devel)", SourceDigest: digest}}}, facts.Compiled...)
	// helper precedes module for all source owners used below.
	return DependencyManifest{Facts: &facts}
}

// full_only: false
func TestDependencyManifestCanonicalFramingAndHelperIdentity(t *testing.T) {
	m := fixtureDependencyManifest(t, "example.test/output", "deliver")
	body, err := EncodeDependencyManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDependencyManifest(body)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatal("complete manifest changed", err)
	}
	if binary.BigEndian.Uint16(body) != 3 || int(binary.BigEndian.Uint32(body[2:])) != len(body)-6 {
		t.Fatal("framing changed")
	}
	preimage := binary.BigEndian.AppendUint32([]byte("ENKV/OUTPUT/v3/dependency-manifest\x00"), uint32(len(body)))
	want := sha256.Sum256(append(preimage, body...))
	id, err := DependencyManifestID(body)
	if err != nil || id != want {
		t.Fatal("independent identity differs", err)
	}
	changed := fixtureDependencyManifest(t, "example.test/output", "deliver")
	changed.Facts.Sources[0].Digest[0] ^= 1
	changed.Facts.Resolved[0].Replacement.SourceDigest = changed.Facts.Sources[0].Digest
	changed.Facts.Compiled[0].Replacement.SourceDigest = changed.Facts.Sources[0].Digest
	other, err := EncodeDependencyManifest(changed)
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := DependencyManifestID(other)
	if err != nil || otherID == id {
		t.Fatal("helper source lost identity", err)
	}
	for _, bad := range [][]byte{body[:len(body)-1], append(bytes.Clone(body), 0), bytes.Repeat([]byte{0}, artifact.MaxDependencyBytes+1)} {
		if _, err := DecodeDependencyManifest(bad); err == nil {
			t.Fatal("damaged framing admitted")
		}
	}
}

// full_only: false
func TestDependencyManifestRejectsUnboundClosureAndInvalidRepresentations(t *testing.T) {
	for name, change := range map[string]func(*artifact.BuildFacts){
		"missing-source": func(f *artifact.BuildFacts) { f.Sources = nil },
		"missing-helper": func(f *artifact.BuildFacts) { f.Resolved = f.Resolved[1:] },
		"compiled-only": func(f *artifact.BuildFacts) {
			f.Compiled = append(f.Compiled, artifact.Dependency{Path: "example.test/z", Version: "v1.0.0"})
		},
		"duplicate-resolved":          func(f *artifact.BuildFacts) { f.Resolved = append(f.Resolved, f.Resolved[0]) },
		"duplicate-compiled":          func(f *artifact.BuildFacts) { f.Compiled = append(f.Compiled, f.Compiled[0]) },
		"wrong-version":               func(f *artifact.BuildFacts) { f.Compiled[0].Version = "v1.0.0" },
		"substituted-source":          func(f *artifact.BuildFacts) { f.Compiled[0].Replacement.Path = "../other" },
		"missing-replacement-version": func(f *artifact.BuildFacts) { f.Compiled[0].Replacement.Version = "" },
		"local-replacement-version":   func(f *artifact.BuildFacts) { f.Compiled[0].Replacement.Version = "v1.0.0" },
		"invalid-utf8":                func(f *artifact.BuildFacts) { f.Command += "\xff" },
		"long-string":                 func(f *artifact.BuildFacts) { f.Command = strings.Repeat("c", 1025) },
		"too-many-rows":               func(f *artifact.BuildFacts) { f.Resolved = make([]artifact.Dependency, 257) },
	} {
		t.Run(name, func(t *testing.T) {
			m := fixtureDependencyManifest(t, "example.test/output", "deliver")
			change(m.Facts)
			if _, err := EncodeDependencyManifest(m); err == nil {
				t.Fatal("invalid closure admitted")
			}
		})
	}
}
func fixtureBuildInfo(m DependencyManifest) *debug.BuildInfo {
	f := m.Facts
	info := &debug.BuildInfo{GoVersion: f.Toolchain, Path: f.Command, Main: debug.Module{Path: f.MainModule, Version: "(devel)"}}
	for _, option := range f.BuildOptions {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: option.Name, Value: option.Value})
	}
	for _, row := range f.Compiled {
		if row.Path == f.MainModule {
			continue
		}
		dep := &debug.Module{Path: row.Path, Version: row.Version, Sum: row.Sum}
		if row.Replacement != nil {
			dep.Replace = &debug.Module{Path: row.Replacement.Path, Version: row.Replacement.Version, Sum: row.Replacement.Sum}
		}
		info.Deps = append(info.Deps, dep)
	}
	return info
}

// full_only: false
func TestArtifactBuildInfoRequiresExactCompiledSetForEveryCommand(t *testing.T) {
	for _, command := range []string{"deliver", "tools/publish"} {
		t.Run(command, func(t *testing.T) {
			m := fixtureDependencyManifest(t, "example.test/output", command)
			if err := verifyArtifactInfo(fixtureBuildInfo(m), m); err != nil {
				t.Fatal("exact closure refused", err)
			}
			for name, change := range map[string]func(*debug.BuildInfo){
				"missing": func(i *debug.BuildInfo) { i.Deps = nil }, "extra": func(i *debug.BuildInfo) {
					i.Deps = append(i.Deps, &debug.Module{Path: "example.test/extra", Version: "v1.0.0"})
				},
				"main": func(i *debug.BuildInfo) { i.Main.Path += "-other" }, "main-version": func(i *debug.BuildInfo) { i.Main.Version = "v1.0.0" }, "main-sum": func(i *debug.BuildInfo) { i.Main.Sum = "unexpected" }, "main-replacement": func(i *debug.BuildInfo) { i.Main.Replace = &debug.Module{Path: "elsewhere"} },
				"command": func(i *debug.BuildInfo) { i.Path += "/other" }, "toolchain": func(i *debug.BuildInfo) { i.GoVersion = "go1.27.4" }, "tuple": func(i *debug.BuildInfo) {
					i.Settings = append(i.Settings, debug.BuildSetting{Key: "GOOS", Value: "other"})
				},
				"tags": func(i *debug.BuildInfo) {
					i.Settings = append(i.Settings, debug.BuildSetting{Key: "-tags", Value: "netgo"})
				}, "race": func(i *debug.BuildInfo) {
					i.Settings = append(i.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
				},
				"empty-replacement-version": func(i *debug.BuildInfo) { i.Deps[0].Replace.Version = "" }, "substituted-sdk": func(i *debug.BuildInfo) { i.Deps[0].Replace.Path = "../other" }, "nested-replacement": func(i *debug.BuildInfo) { i.Deps[0].Replace.Replace = &debug.Module{Path: "../other"} }, "duplicate": func(i *debug.BuildInfo) { i.Deps = append(i.Deps, i.Deps[0]) },
			} {
				t.Run(name, func(t *testing.T) {
					info := fixtureBuildInfo(m)
					change(info)
					if verifyArtifactInfo(info, m) == nil {
						t.Fatal("different build admitted")
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicDependencyManifestUsesActualClosureAndRetainsOriginalBytes(t *testing.T) {
	m := fixtureDependencyManifest(t, "example.test/output", "deliver")
	body, err := EncodeDependencyManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDependencyManifest(body)
	if err != nil || got.Facts.Resolved[1].Version != "" || got.Facts.Compiled[1].Version != "(devel)" {
		t.Fatal("workspace facts changed", err)
	}
	clear(body)
	if !reflect.DeepEqual(got, m) {
		t.Fatal("decoded facts borrow input bytes")
	}
}
