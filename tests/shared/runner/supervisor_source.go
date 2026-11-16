package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

const supervisorSourceFormat = 1
const supervisorSourceMapPath = "tests/scripts/supervisor-sources.tsv"
const maximumSupervisorSourceBytes = 32 << 20

type supervisorNativeTarget struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	CGO    string `json:"cgo"`
}

type supervisorSourceInput struct{ Original, Compiler string }
type supervisorSourceDigest struct{ Path, Compiler, SHA256 string }
type supervisorSourceBinding struct {
	Format int
	Native supervisorNativeTarget
	Inputs []supervisorSourceDigest
	Digest string
	bytes  map[string][]byte
}

func currentSupervisorNativeTarget() (supervisorNativeTarget, error) {
	target := supervisorNativeTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return target, errors.New("supervisor build target unavailable")
	}
	for _, setting := range info.Settings {
		if setting.Key == "CGO_ENABLED" {
			target.CGO = setting.Value
		}
	}
	if (target.GOOS != "darwin" && target.GOOS != "linux") || target.GOARCH == "" || (target.CGO != "0" && target.CGO != "1") || target.GOOS == "darwin" && target.CGO != "1" {
		return target, errors.New("supervisor native target refused")
	}
	return target, nil
}

func parseSupervisorSourceMap(body []byte) ([]supervisorSourceInput, error) {
	refused := errors.New("supervisor finite source map refused")
	if len(body) == 0 || len(body) > maximumSupervisorSourceBytes || body[len(body)-1] != '\n' {
		return nil, refused
	}
	var inputs []supervisorSourceInput
	originals, compiler := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || !validSupervisorSourcePath(fields[0]) || originals[fields[0]] {
			return nil, refused
		}
		target := fields[1]
		if target != "-" {
			if !validSupervisorSourcePath(target) || compiler[target] || !(target == "core/go.mod" || target == "core/go.sum" || strings.HasPrefix(target, "core/internal/supervisor/") && strings.HasSuffix(target, ".go") || target == "core/internal/testrecords/io.go" || target == "core/internal/testrecords/layout.go" || target == "core/internal/testrecords/source.go" || target == "core/internal/testrecords/live_limits.go") {
				return nil, refused
			}
			compiler[target] = true
		}
		originals[fields[0]] = true
		inputs = append(inputs, supervisorSourceInput{fields[0], target})
	}
	if !originals[supervisorSourceMapPath] {
		return nil, refused
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Original < inputs[j].Original })
	return inputs, nil
}

func validSupervisorSourcePath(value string) bool {
	return value != "" && fs.ValidPath(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\\\t\r\n ") && !strings.HasPrefix(value, ".")
}

// The embedded source map owns the path set. No mutable sidecar is authority.
// Each digest input is length-prefixed; format and native target precede paths.
func bindSupervisorSources(inputs fs.FS, target supervisorNativeTarget) (supervisorSourceBinding, error) {
	refused := errors.New("supervisor embedded source inputs refused")
	body, err := fs.ReadFile(inputs, supervisorSourceMapPath+".source")
	if err != nil {
		return supervisorSourceBinding{}, refused
	}
	paths, err := parseSupervisorSourceMap(body)
	if err != nil {
		return supervisorSourceBinding{}, err
	}
	binding := supervisorSourceBinding{Format: supervisorSourceFormat, Native: target, bytes: map[string][]byte{}}
	expected := map[string]bool{}
	total := 0
	for _, input := range paths {
		name := input.Original + ".source"
		body, err := fs.ReadFile(inputs, name)
		total += len(body)
		if err != nil || total > maximumSupervisorSourceBytes {
			return supervisorSourceBinding{}, refused
		}
		sum := sha256.Sum256(body)
		binding.Inputs = append(binding.Inputs, supervisorSourceDigest{input.Original, input.Compiler, hex.EncodeToString(sum[:])})
		binding.bytes[input.Original] = bytes.Clone(body)
		expected[name] = true
	}
	err = fs.WalkDir(inputs, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return refused
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || !expected[name] {
			return refused
		}
		delete(expected, name)
		return nil
	})
	if err != nil || len(expected) != 0 {
		return supervisorSourceBinding{}, refused
	}
	hash := sha256.New()
	put := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		hash.Write(size[:])
		hash.Write([]byte(value))
	}
	put(fmt.Sprintf("enkv-test-supervisor-%d", binding.Format))
	put(target.GOOS)
	put(target.GOARCH)
	put(target.CGO)
	for _, input := range binding.Inputs {
		put(input.Path)
		put(input.Compiler)
		put(input.SHA256)
	}
	binding.Digest = hex.EncodeToString(hash.Sum(nil))
	return binding, nil
}

func (binding supervisorSourceBinding) validate(root string, native supervisorNativeTarget) error {
	if binding.Format != supervisorSourceFormat || binding.Native != native || binding.Digest == "" || len(binding.Inputs) == 0 || len(binding.Inputs) != len(binding.bytes) {
		return errors.New("supervisor source/native binding refused")
	}
	actual, err := filepath.EvalSymlinks(root)
	if err != nil || actual != root {
		return errors.New("supervisor repository spelling refused")
	}
	return nil
}

// Candidate and destination share one filesystem. Validation precedes rename,
// so a failed binding, native or placement check preserves the installed artifact.
func publishSupervisorArtifact(binding supervisorSourceBinding, root, candidate, destination string, native supervisorNativeTarget) error {
	if err := binding.validate(root, native); err != nil {
		return err
	}
	installation := filepath.Join(root, "tests/.supervisor")
	if destination != filepath.Join(installation, "supervisor") || filepath.Base(candidate) != "supervisor-candidate" || filepath.Dir(filepath.Dir(candidate)) != installation || !strings.HasPrefix(filepath.Base(filepath.Dir(candidate)), "setup.") {
		return errors.New("supervisor installation placement refused")
	}
	for _, name := range []string{candidate, destination} {
		if _, err := records.SafePath(root, mustSupervisorRelative(root, name)); err != nil {
			return errors.New("supervisor artifact path refused")
		}
	}
	info, err := os.Lstat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.New("supervisor candidate unavailable")
	}
	if current, err := os.Lstat(destination); err == nil && !current.Mode().IsRegular() || err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("supervisor installed artifact refused")
	}
	return os.Rename(candidate, destination)
}

func mustSupervisorRelative(root, file string) string {
	relative, err := filepath.Rel(root, file)
	if err != nil {
		return ""
	}
	return relative
}
