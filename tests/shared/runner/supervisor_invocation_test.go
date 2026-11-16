package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func checkSupervisorInvocationList(t *testing.T, output string) {
	t.Helper()
	if strings.Count(output, "\n") != len(catalog.Names()) || !strings.Contains(output, "fixed fixture") || !strings.Contains(output, "state.single-value-update-preserves-other-values/members_1\t") || !strings.Contains(output, "state.single-value-update-preserves-other-values/members_32\t") || !strings.Contains(output, "state.single-value-update-preserves-other-values/members_64\t") {
		t.Fatal("real runner list omitted scenario definitions or parameters", output)
	}
	for _, name := range catalog.Names() {
		if !strings.Contains(output, name+"\t") {
			t.Fatal("real runner list omitted a scenario", name)
		}
	}
}

func checkSupervisorInvocationStages(t *testing.T, parent string) {
	t.Helper()
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() {
		t.Fatal("invocation fixture stage parent unavailable", err)
	}
	stages, err := filepath.Glob(filepath.Join(parent, "invoke.*"))
	if err != nil || len(stages) != 0 {
		t.Fatal("joined invocation retained an owned bootstrap stage", stages, err)
	}
}

func supervisorFixtureStageParent(t *testing.T, root string, settled *bool) string {
	t.Helper()
	parent, err := os.MkdirTemp("", "enkv-invocation-stages-")
	if err != nil {
		t.Fatal(err)
	}
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() || !*settled {
			t.Log("retained invocation stage fixture:", parent)
			return
		}
		checkSupervisorInvocationStages(t, parent)
		current, err := os.Lstat(parent)
		if err != nil || !records.SameLocalFile(identity, current) || !current.IsDir() || current.Mode().Perm() != 0700 {
			t.Error("invocation stage fixture ownership changed", err)
			return
		}
		if err := os.RemoveAll(parent); err != nil {
			t.Error("remove settled invocation stage fixture", err)
		}
	})
	path := filepath.Join(root, "tests/shared/runner/supervisor_invocation.go")
	body, err := os.ReadFile(path)
	const anchor = "supervisorInvocationStageParent(root, os.TempDir(), home)"
	if err != nil || strings.Count(string(body), anchor) != 1 {
		t.Fatal("copied invocation stage parent construction changed", err)
	}
	replacement := fmt.Sprintf("supervisorInvocationStageParent(root, %q, home)", parent)
	if err := os.WriteFile(path, []byte(strings.Replace(string(body), anchor, replacement, 1)), 0700); err != nil {
		t.Fatal(err)
	}
	return parent
}

func rewriteSupervisorFixtureResources(t *testing.T, root, previous, resources string) {
	t.Helper()
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	setup := filepath.Join(root, "tests/scripts/setup-supervisor")
	body, err := os.ReadFile(setup)
	anchor := "resource_root=" + quote(previous)
	if err != nil || strings.Count(string(body), anchor) != 1 {
		t.Fatal("copied setup resource construction changed", err)
	}
	if err := os.WriteFile(setup, []byte(strings.Replace(string(body), anchor, "resource_root="+quote(resources), 1)), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tests/shared/runner/resource_locks.go")
	body, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(body), "func defaultResourceLocks() (*resourceLocks, error) {")
	end := strings.Index(string(body), "\nfunc openResourceLocks(")
	if start < 0 || end <= start {
		t.Fatal("copied native resource construction changed")
	}
	replacement := fmt.Sprintf("func defaultResourceLocks() (*resourceLocks, error) {\n return openResourceLocks(%q)\n}\n", resources)
	if err := os.WriteFile(path, []byte(string(body[:start])+replacement+string(body[end:])), 0700); err != nil {
		t.Fatal(err)
	}
}

func checkSupervisorFixtureResources(t *testing.T, resources string) {
	t.Helper()
	locks, err := openResourceLocks(resources)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"machine.lock", "live.lock"} {
		file, err := locks.openFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		closeErr := file.Close()
		if lockErr != nil || closeErr != nil {
			t.Fatal("joined fixture retained a resource descriptor", lockErr, closeErr)
		}
	}
}

// full_only: false
func TestSupervisorInvocationStageParentRequiresProtectedAncestors(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	checkout := filepath.Join(root, "checkout")
	if err := os.Mkdir(checkout, 0700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Run("protected_temporary_parent_precedes_home", func(t *testing.T) {
		temporary := filepath.Join(root, "temporary")
		if err := os.Mkdir(temporary, 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TMPDIR", temporary)
		if got, err := supervisorInvocationStageParent(checkout, os.TempDir(), home); err != nil || got != temporary {
			t.Fatalf("protected temporary parent was not selected: got=%q want=%q err=%v", got, temporary, err)
		}
	})
	t.Run("physical_parent", func(t *testing.T) {
		if got, err := supervisorInvocationStageParent(checkout, "", home); err != nil || got != home {
			t.Fatal("protected physical home was refused", err)
		}
	})
	t.Run("home_alias_uses_physical_parent", func(t *testing.T) {
		alias := filepath.Join(root, "home-alias")
		if err := os.Symlink(home, alias); err != nil {
			t.Fatal(err)
		}
		if got, err := supervisorInvocationStageParent(checkout, "", alias); err != nil || got != home {
			t.Fatal("home alias did not resolve to its protected physical parent", err)
		}
	})
	t.Run("private_leaf_below_writable_ancestor_is_refused", func(t *testing.T) {
		ancestor := filepath.Join(root, "writable")
		leaf := filepath.Join(ancestor, "private")
		if err := os.MkdirAll(leaf, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0777); err != nil {
			t.Fatal(err)
		}
		if got, err := supervisorInvocationStageParent(checkout, "", leaf); err == nil || got != "" {
			t.Fatal("private leaf bypassed its writable ancestor")
		}
		if entries, err := os.ReadDir(leaf); err != nil || len(entries) != 0 {
			t.Fatal("parent refusal created a stage", err)
		}
	})
	t.Run("candidate_selection", func(t *testing.T) {
		temporary := filepath.Join(root, "scratch")
		unsafe := filepath.Join(root, "unsafe-temporary")
		leaf := filepath.Join(unsafe, "private")
		child := filepath.Join(checkout, "temporary")
		for _, path := range []string{temporary, leaf, child} {
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(unsafe, os.ModeSticky|0777); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(root, "temporary-file")
		if err := os.WriteFile(file, []byte("not a directory"), 0600); err != nil {
			t.Fatal(err)
		}
		alias, inside, dangling := filepath.Join(root, "scratch-alias"), filepath.Join(root, "checkout-alias"), filepath.Join(root, "dangling")
		for _, link := range []struct{ target, path string }{{temporary, alias}, {child, inside}, {filepath.Join(root, "missing"), dangling}} {
			if err := os.Symlink(link.target, link.path); err != nil {
				t.Fatal(err)
			}
		}
		for _, row := range []struct{ name, temporary, home, want string }{
			{"temporary_alias", alias, home, temporary},
			{"writable_temporary_ancestor", leaf, home, home},
			{"missing_temporary", filepath.Join(root, "missing"), home, home},
			{"relative_temporary", "relative", home, home},
			{"file_temporary", file, home, home},
			{"dangling_temporary", dangling, home, home},
			{"checkout_temporary", checkout, home, home},
			{"checkout_descendant", child, home, home},
			{"checkout_alias", inside, home, home},
			{"temporary_without_home", temporary, "", temporary},
			{"temporary_with_unsafe_home", temporary, leaf, temporary},
			{"neither_suitable", leaf, filepath.Join(root, "missing"), ""},
			{"home_inside_checkout", file, child, ""},
			{"checkout_ancestor", root, home, root},
		} {
			t.Run(row.name, func(t *testing.T) {
				got, err := supervisorInvocationStageParent(checkout, row.temporary, row.home)
				if got != row.want || (err != nil) != (row.want == "") {
					t.Fatalf("stage parent=%q want=%q err=%v", got, row.want, err)
				}
				for _, path := range []string{root, home, temporary, leaf, checkout, child} {
					matches, err := filepath.Glob(filepath.Join(path, "invoke.*"))
					if err != nil || len(matches) != 0 {
						t.Fatal("selection created an invocation stage", matches, err)
					}
				}
			})
		}
	})
}

// full_only: false
func TestSupervisorInvocationStageDisposalRequiresJoinedOwnership(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error("restore test-owned directory permissions", err)
		}
	})
	newStage := func(t *testing.T) (string, os.FileInfo, string) {
		t.Helper()
		stage, err := os.MkdirTemp(root, "invoke.")
		if err != nil {
			t.Fatal(err)
		}
		identity, err := os.Lstat(stage)
		if err != nil {
			t.Fatal(err)
		}
		leaf := filepath.Join(stage, "manifest-build", "builds", "id")
		if err := os.MkdirAll(leaf, 0700); err != nil {
			t.Fatal(err)
		}
		for _, file := range []struct {
			name string
			mode os.FileMode
		}{{"plugin", 0555}, {"metadata.json", 0444}} {
			if err := os.WriteFile(filepath.Join(leaf, file.name), []byte("private fixture"), file.mode); err != nil {
				t.Fatal(err)
			}
		}
		for path := leaf; path != stage; path = filepath.Dir(path) {
			if err := os.Chmod(path, 0555); err != nil {
				t.Fatal(err)
			}
		}
		return stage, identity, leaf
	}
	t.Run("readonly_published_directories", func(t *testing.T) {
		stage, identity, _ := newStage(t)
		if err := os.RemoveAll(stage); err == nil {
			t.Fatal("raw removal unexpectedly removed read-only published directories")
		}
		if err := removeSupervisorInvocationStage(t.Context(), stage, identity, true); err != nil {
			t.Fatal("owned read-only stage cleanup", err)
		}
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatal("joined stage remains", err)
		}
	})
	t.Run("current_directory_owner", func(t *testing.T) {
		stage, identity, leaf := newStage(t)
		owner := currentDirectory{path: stage, identity: identity}
		if err := owner.remove(false); err == nil {
			t.Fatal("current owner removed an unjoined build")
		}
		if info, err := os.Stat(leaf); err != nil || info.Mode().Perm() != 0555 {
			t.Fatal("unjoined current owner changed immutable build", err)
		}
		if err := owner.remove(true); err != nil {
			t.Fatal("current owner retained joined read-only build", err)
		}
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatal("joined current directory remains", err)
		}
	})
	t.Run("current_directory_replaced", func(t *testing.T) {
		stage, identity, _ := newStage(t)
		retained := stage + "-retained"
		if os.Rename(stage, retained) != nil || os.Mkdir(stage, 0700) != nil || os.WriteFile(filepath.Join(stage, "keep"), []byte("replacement sentinel"), 0600) != nil {
			t.Fatal("replacement current-directory fixture")
		}
		if err := (currentDirectory{path: stage, identity: identity}).remove(true); err == nil {
			t.Fatal("current owner removed a replacement directory")
		}
		if body, err := os.ReadFile(filepath.Join(stage, "keep")); err != nil || string(body) != "replacement sentinel" {
			t.Fatal("replacement current-directory bytes changed", err)
		}
		if original, err := os.Lstat(retained); err != nil || !records.SameLocalFile(identity, original) || original.Mode().Perm() != 0700 {
			t.Fatal("original current-directory ownership changed", err)
		}
	})
	t.Run("external_links_and_siblings_unchanged", func(t *testing.T) {
		stage, identity, _ := newStage(t)
		external := filepath.Join(root, "external")
		if err := os.Mkdir(external, 0700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(external, "sentinel")
		if err := os.WriteFile(file, []byte("unchanged outside file"), 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(external, 0555); err != nil {
			t.Fatal(err)
		}
		for _, link := range []struct{ target, path string }{{external, "directory-link"}, {file, "file-link"}} {
			if err := os.Symlink(link.target, filepath.Join(stage, link.path)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Link(file, filepath.Join(stage, "hard-link")); err != nil {
			t.Fatal(err)
		}
		before := map[string]os.FileInfo{}
		for _, path := range []string{root, external, file} {
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			before[path] = info
		}
		if err := (currentDirectory{path: stage, identity: identity}).remove(true); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatal("joined linked stage remains", err)
		}
		for path, original := range before {
			current, err := os.Lstat(path)
			if err != nil || !records.SameLocalFile(original, current) || current.Mode() != original.Mode() {
				t.Fatal("stage cleanup changed outside identity or mode", path, err)
			}
		}
		if body, err := os.ReadFile(file); err != nil || string(body) != "unchanged outside file" {
			t.Fatal("stage cleanup changed outside bytes", err)
		}
	})
	for _, condition := range []string{"unjoined", "missing_identity", "different_identity", "changed_stage_mode", "replacement_directory", "replacement_symlink", "cancelled", "unreadable_directory"} {
		t.Run(condition, func(t *testing.T) {
			stage, identity, leaf := newStage(t)
			originalPath, joined, ctx := stage, true, t.Context()
			var replacement string
			switch condition {
			case "unjoined":
				joined = false
			case "missing_identity":
				identity = nil
			case "different_identity":
				other, err := os.Lstat(root)
				if err != nil {
					t.Fatal(err)
				}
				identity = other
			case "changed_stage_mode":
				if err := os.Chmod(stage, 0555); err != nil {
					t.Fatal(err)
				}
			case "replacement_directory", "replacement_symlink":
				originalPath = stage + ".saved"
				if err := os.Rename(stage, originalPath); err != nil {
					t.Fatal(err)
				}
				leaf = filepath.Join(originalPath, "manifest-build", "builds", "id")
				replacement = stage
				if condition == "replacement_symlink" {
					replacement = stage + ".target"
				}
				if err := os.Mkdir(replacement, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(replacement, "sentinel"), []byte("replacement"), 0444); err != nil {
					t.Fatal(err)
				}
				if condition == "replacement_symlink" {
					if err := os.Chmod(replacement, 0555); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(replacement, stage); err != nil {
						t.Fatal(err)
					}
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unreadable_directory":
				if err := os.Chmod(leaf, 0); err != nil {
					t.Fatal(err)
				}
			}
			err := removeSupervisorInvocationStage(ctx, stage, identity, joined)
			if err == nil {
				t.Fatal("unsafe stage cleanup succeeded")
			}
			if condition == "unreadable_directory" && !errors.Is(err, os.ErrPermission) {
				t.Fatal("directory open failure lost its cause", err)
			}
			if _, err := os.Lstat(originalPath); err != nil {
				t.Fatal("refused stage was removed", err)
			}
			want := os.FileMode(0555)
			if condition == "unreadable_directory" {
				want = 0
			}
			if info, err := os.Lstat(leaf); err != nil || info.Mode().Perm() != want {
				t.Fatal("refusal changed directory permissions", err)
			}
			if replacement != "" {
				mode := os.FileMode(0700)
				if condition == "replacement_symlink" {
					mode = 0555
				}
				if info, err := os.Lstat(replacement); err != nil || info.Mode().Perm() != mode {
					t.Fatal("refusal changed replacement mode", err)
				}
				if body, err := os.ReadFile(filepath.Join(replacement, "sentinel")); err != nil || string(body) != "replacement" {
					t.Fatal("refusal changed replacement bytes", err)
				}
			}
		})
	}
}

// A fixture process owns two sequential independent native roots. Their
// resource directory is distinct from the outer test invocation.
// full_only: false
func TestSupervisorSequentialInvocationOwner(t *testing.T) {
	root := os.Getenv("ENKV_INVOCATION_FIXTURE_ROOT")
	if root == "" {
		return
	}
	stageParent := os.Getenv("ENKV_INVOCATION_FIXTURE_STAGE_PARENT")
	if stageParent == "" {
		t.Fatal("nested invocation fixture stage parent absent")
	}
	binary := filepath.Join(root, "tests/.supervisor/supervisor")
	for attempt := range 2 {
		args := []string{"invoke", "--root", root, "--", "list", fmt.Sprintf("--parallel=%d", supervisorFixtureParallel(t))}
		if attempt == 1 {
			args[len(args)-1] = "--parallel=1"
			args = append(args, "--memory-limit-mib=2048")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
		command := exec.Command(binary, args...)
		command.Dir, command.Env = root, goEnvironment()
		output := new(limitedOutput)
		command.Stdout, command.Stderr = output, output
		result := superviseProcess(ctx, command)
		cancel()
		if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
			t.Fatalf("nested invocation %d did not pass and join: result=%+v output=%s", attempt+1, result, output.String())
		}
		if !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
			t.Fatal("nested invocation group remains present or uncertain", attempt+1)
		}
		checkSupervisorInvocationList(t, output.String())
		checkSupervisorInvocationStages(t, stageParent)
	}
	if err := os.WriteFile(filepath.Join(root, "nested-complete"), []byte("2\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

// One real native setup serves every invocation witness below. Only the copied
// default resource construction changes; production has no root override.
// full_only: false
func TestSupervisorInstalledInvocationBoundaries(t *testing.T) {
	parent, err := filepath.EvalSymlinks("/var/tmp")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.MkdirTemp(parent, "enkv-invoke-")
	if err != nil {
		t.Fatal(err)
	}
	resources := filepath.Join(fixture, "a")
	settled := true
	t.Cleanup(func() {
		if t.Failed() || !settled {
			t.Log("retained invocation fixture:", fixture)
			return
		}
		checkSupervisorFixtureResources(t, resources)
		if err := os.RemoveAll(fixture); err != nil {
			t.Error("remove settled invocation fixture", err)
		}
	})
	initial, setupResources, _, _ := copiedSupervisorSetupFixture(t)
	root := filepath.Join(fixture, "r")
	copyInputs := func(destination string) {
		t.Helper()
		for _, name := range supervisorFixturePaths {
			body, err := os.ReadFile(filepath.Join(initial, filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(destination, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0700); err != nil {
				t.Fatal(err)
			}
		}
		copyModuleInventoryFixture(t, destination)
	}
	copyInputs(root)
	stageParent := supervisorFixtureStageParent(t, root, &settled)
	setup := filepath.Join(root, "tests/scripts/setup-supervisor")
	rewriteSupervisorFixtureResources(t, root, setupResources, resources)
	env := goEnvironment()
	realEnv := append([]string{}, env...)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	command := exec.Command("/bin/bash", setup)
	command.Dir, command.Env = root, env
	setupOutput := new(limitedOutput)
	command.Stdout, command.Stderr = setupOutput, setupOutput
	result := superviseProcess(ctx, command)
	settled = result.Joined
	if result.Status != "passed" || !result.Started || !result.Joined || setupOutput.overflow {
		t.Fatalf("native invocation setup failed: result=%+v output=%s", result, setupOutput.String())
	}
	binary := filepath.Join(root, "tests/.supervisor/supervisor")
	checkSupervisorFixtureResources(t, resources)
	locks, err := openResourceLocks(resources)
	if err != nil {
		t.Fatal(err)
	}
	controls := filepath.Join(fixture, "c")
	if err := os.Mkdir(controls, 0700); err != nil {
		t.Fatal(err)
	}
	const shim = `#!/bin/bash
set -euo pipefail
printf '%s\n' "$$" "$@" > "$ENKV_INVOCATION_FIXTURE_CONTROL/compiler"
stage_source="${!#}"
stage_path="${stage_source%/bootstrap.go}"
if [ "$stage_path" = "$stage_source" ] || [ ! -d "$stage_path" ] || [ ! -f "$stage_source" ]; then exit 98; fi
printf '%s\n' "$stage_path" > "$ENKV_INVOCATION_FIXTURE_CONTROL/stage"
printf '%s\n' "$TMPDIR" "$GOTMPDIR" > "$ENKV_INVOCATION_FIXTURE_CONTROL/temporary"
printf 'owned invocation descendant\n' > "$stage_path/fixture-child"
mkdir -p "$stage_path/manifest-build/builds/id"
printf 'readonly plugin\n' > "$stage_path/manifest-build/builds/id/plugin"
chmod 0555 "$stage_path/manifest-build/builds/id/plugin" "$stage_path/manifest-build/builds/id" "$stage_path/manifest-build/builds" "$stage_path/manifest-build"
if [ -f "$ENKV_INVOCATION_FIXTURE_CONTROL/cancel-arm" ]; then
    printf 'ready\n' > "$ENKV_INVOCATION_FIXTURE_CONTROL/cancel-ready"
    while [ -f "$ENKV_INVOCATION_FIXTURE_CONTROL/cancel-arm" ]; do :; done
fi
printf 'fixture bootstrap compiler exit 7\n' >&2
exit 7
`
	if err := os.WriteFile(filepath.Join(controls, "go"), []byte(shim), 0700); err != nil {
		t.Fatal(err)
	}
	env = environment(env, map[string]string{
		"PATH":                            controls + string(os.PathListSeparator) + os.Getenv("PATH"),
		"ENKV_INVOCATION_FIXTURE_CONTROL": controls,
	})
	// These private siblings are outside every invocation's owned stage.
	siblings := map[string]os.FileInfo{}
	for _, path := range []string{filepath.Join(resources, "kept-private"), filepath.Join(root, "tests/.supervisor/kept-private"), filepath.Join(stageParent, "kept-private")} {
		if err := os.WriteFile(path, []byte("test-owned sibling\n"), 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		siblings[path] = info
	}
	checkSiblings := func(t *testing.T) {
		t.Helper()
		for path, original := range siblings {
			current, err := os.Lstat(path)
			body, readErr := os.ReadFile(path)
			if err != nil || !records.SameLocalFile(original, current) || readErr != nil || string(body) != "test-owned sibling\n" {
				t.Error("invocation changed unrelated private sibling", path, err, readErr)
			}
		}
	}
	invoke := func(t *testing.T, checkout string, args ...string) (processResult, string, int) {
		t.Helper()
		for _, name := range []string{"compiler", "stage", "temporary"} {
			if err := os.Remove(filepath.Join(controls, name)); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		args = append(args, fmt.Sprintf("--parallel=%d", supervisorFixtureParallel(t)))
		command := exec.Command(binary, append([]string{"invoke", "--root", checkout, "--"}, args...)...)
		command.Dir, command.Env = checkout, env
		output := new(limitedOutput)
		command.Stdout, command.Stderr = output, output
		result := superviseProcess(ctx, command)
		if !result.Started || !result.Joined || result.Status != "process_failed" || output.overflow {
			settled = settled && result.Joined
			t.Fatalf("invocation did not fail and join: result=%+v output=%s", result, output.String())
		}
		pid := command.Process.Pid
		if !errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) {
			settled = false
			t.Fatal("invocation process group remains present or uncertain", pid)
		}
		checkSiblings(t)
		checkSupervisorInvocationStages(t, stageParent)
		return result, output.String(), pid
	}
	noCompiler := func(t *testing.T) {
		t.Helper()
		if _, err := os.Lstat(filepath.Join(controls, "compiler")); !os.IsNotExist(err) {
			t.Fatal("refused invocation reached compiler", err)
		}
	}
	resourcesReleased := func(t *testing.T) { t.Helper(); checkSupervisorFixtureResources(t, resources) }
	waitMarker := func(t *testing.T, ctx context.Context, path string) {
		t.Helper()
		for {
			if _, err := os.Stat(path); err == nil {
				return
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal("fixture did not reach its physical marker", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	t.Run("machine_lock_before_compiler", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(controls, "cancel-arm"), []byte("hold"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(filepath.Join(controls, "cancel-arm"))
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		command := exec.Command(binary, "invoke", "--root", root, "--", "list", fmt.Sprintf("--parallel=%d", min(2, supervisorFixtureParallel(t))), "--memory-limit-mib=512")
		command.Dir, command.Env = root, env
		output := new(limitedOutput)
		command.Stdout, command.Stderr = output, output
		done := make(chan processResult, 1)
		go func() { done <- superviseProcess(ctx, command) }()
		collected := false
		defer func() {
			cancel()
			if !collected {
				result := <-done
				settled = settled && result.Joined
			}
		}()
		waitMarker(t, ctx, filepath.Join(controls, "cancel-ready"))
		file, err := locks.openFile("machine.lock")
		if err != nil {
			t.Fatal(err)
		}
		probeErr := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(probeErr, syscall.EWOULDBLOCK) {
			t.Fatal("compiler ran without the initial shared machine lock", probeErr)
		}
		marker, err := os.ReadFile(filepath.Join(controls, "compiler"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(marker)), "\n")
		compilerPID, err := strconv.Atoi(lines[0])
		if err != nil || compilerPID <= 0 || !strings.Contains(string(marker), "build") {
			t.Fatal("compiler process marker invalid", err)
		}
		stageBytes, err := os.ReadFile(filepath.Join(controls, "stage"))
		if err != nil {
			t.Fatal(err)
		}
		stage := strings.TrimSpace(string(stageBytes))
		if !filepath.IsAbs(stage) || filepath.Dir(stage) != stageParent {
			t.Fatal("compiler stage was not owned by its protected external parent")
		}
		temporary, err := os.ReadFile(filepath.Join(controls, "temporary"))
		if err != nil || string(temporary) != filepath.Join(stage, "tmp")+"\n"+filepath.Join(stage, "go-tmp")+"\n" {
			t.Fatal("compiler temporary descendants escaped the selected stage", err)
		}
		t.Logf("compiler stage=%s TMPDIR=%s GOTMPDIR=%s", stage, filepath.Join(stage, "tmp"), filepath.Join(stage, "go-tmp"))
		for path := stageParent; ; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
				t.Fatal("stage has an unprotected ancestor", err)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 && uint64(stat.Uid) != uint64(os.Geteuid()) {
				t.Fatal("stage has a foreign ancestor")
			}
			if path == filepath.Dir(path) {
				break
			}
		}
		if err := os.Remove(filepath.Join(controls, "cancel-arm")); err != nil {
			t.Fatal(err)
		}
		result := <-done
		collected = true
		settled = settled && result.Joined
		if result.Status != "process_failed" || !result.Started || !result.Joined || output.overflow || !strings.Contains(output.String(), "bootstrap compiler") || !strings.Contains(output.String(), "exit status 7") {
			t.Fatal("controlled compiler failure did not fail and join", result, output.String())
		}
		if _, err := nativeProcessIdentity(compilerPID); !errors.Is(err, syscall.ESRCH) || !errors.Is(syscall.Kill(-compilerPID, 0), syscall.ESRCH) {
			settled = false
			t.Fatal("compiler remains present or uncertain", err)
		}
		if !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
			settled = false
			t.Fatal("native root group remains present")
		}
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatal("joined compiler failure retained its owned stage", err)
		}
		resourcesReleased(t)
		checkSupervisorInvocationStages(t, stageParent)
		checkSiblings(t)
	})
	t.Run("waiting_across_commands_and_checkouts", func(t *testing.T) {
		second := filepath.Join(fixture, "r2")
		copyInputs(second)
		for _, name := range []string{"tests/scripts/setup-supervisor", "tests/shared/runner/resource_locks.go", "tests/shared/runner/supervisor_invocation.go"} {
			body, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(second, name), body, 0700); err != nil {
				t.Fatal(err)
			}
		}
		workflow := filepath.Join(second, "workflow.json")
		if err := os.WriteFile(workflow, []byte(`{"schema_version":1,"name":"fixture","steps":[{"id":"runner","kind":"runner-tests"}]}`), 0600); err != nil {
			t.Fatal(err)
		}
		for index, item := range []struct {
			checkout string
			args     []string
			preview  bool
		}{{root, []string{"list"}, false}, {second, []string{"run", "--workflow", workflow, "--step", "runner", "--test", "TestFixture"}, false}, {second, []string{"plan", "--workflow", workflow, "--step", "runner", "--test", "TestFixture"}, true}} {
			if err := os.Remove(filepath.Join(controls, "compiler")); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			lease, err := locks.acquireMachine(t.Context(), true)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			started := filepath.Join(controls, fmt.Sprintf("waiting-%d", index))
			item.args = append(item.args, fmt.Sprintf("--parallel=%d", supervisorFixtureParallel(t)))
			args := append([]string{"-c", `printf '%s\n' "$$" > "$ENKV_INVOCATION_FIXTURE_STARTED"; exec "$@"`, "fixture", binary, "invoke", "--root", item.checkout, "--"}, item.args...)
			command := exec.Command("/bin/sh", args...)
			command.Dir = item.checkout
			command.Env = environment(env, map[string]string{"ENKV_INVOCATION_FIXTURE_STARTED": started})
			output := new(limitedOutput)
			command.Stdout, command.Stderr = output, output
			done := make(chan processResult, 1)
			go func() { done <- superviseProcess(ctx, command) }()
			collected := false
			defer func() {
				cancel()
				_ = lease.Close()
				if !collected {
					result := <-done
					settled = settled && result.Joined
				}
			}()
			waitMarker(t, ctx, started)
			if item.preview {
				result := <-done
				collected = true
				settled = settled && result.Joined
				var preview workflowPreview
				if !result.Started || !result.Joined || result.Status != "passed" || output.overflow || json.Unmarshal(output.Bytes(), &preview) != nil || preview.Kind != "selection_preview" || len(preview.Steps) != 1 || !preview.Steps[0].Selected || len(preview.Steps[0].Tests) != 1 || preview.Steps[0].Tests[0] != "TestFixture" || len(preview.Unresolved) == 0 {
					t.Fatal("preview did not complete exact pure selection while the machine lock remained occupied", result, output.String())
				}
				noCompiler(t)
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
				cancel()
				if !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
					settled = false
					t.Fatal("preview native group remains present")
				}
				resourcesReleased(t)
				checkSupervisorInvocationStages(t, stageParent)
				checkSiblings(t)
				continue
			}
			select {
			case result := <-done:
				collected = true
				settled = settled && result.Joined
				t.Fatal("occupied machine lock did not wait", result, output.String())
			case <-time.After(100 * time.Millisecond):
			}
			noCompiler(t)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			result := <-done
			collected = true
			cancel()
			settled = settled && result.Joined
			if !result.Started || !result.Joined || result.Status != "process_failed" || output.overflow || !strings.Contains(output.String(), "exit status 7") {
				t.Fatal("released waiter did not reach its controlled compiler and join", result, output.String())
			}
			if !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
				settled = false
				t.Fatal("released native waiter group remains present")
			}
			resourcesReleased(t)
			checkSupervisorInvocationStages(t, stageParent)
		}
	})
	t.Run("source_edit_reaches_compiler", func(t *testing.T) {
		path := filepath.Join(root, "tests/shared/runner/execution.go")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(append([]byte{}, body...), '\n'), 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(path, body, 0700); err != nil {
				t.Error("restore test-owned bound source", err)
			}
		})
		_, output, _ := invoke(t, root, "list")
		if !strings.Contains(output, "fixture bootstrap compiler exit 7") || strings.Contains(output, "supervisor source changed") {
			t.Fatal("source edit stopped the installed tool before its compiler", output)
		}
		if _, err := os.Stat(filepath.Join(controls, "compiler")); err != nil {
			t.Fatal("source edit did not reach the compiler", err)
		}
		checkSupervisorInvocationStages(t, stageParent)
		resourcesReleased(t)
	})

	t.Run("native_memory_before_compiler", func(t *testing.T) {
		_, output, _ := invoke(t, root, "list", "--memory-limit-mib=1")
		if !strings.Contains(output, "resource_limit") {
			t.Fatal("native precompiler resource refusal was not reported", output)
		}
		noCompiler(t)
		resourcesReleased(t)
	})
	// Copy the maintained production Go tree, module metadata and embedded archives.
	// Existing bound inputs retain their exact fixture modifications.
	source := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	copyProductionFile := func(relative string) error {
		destination := filepath.Join(root, relative)
		if _, err := os.Lstat(destination); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		body, err := os.ReadFile(filepath.Join(source, relative))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		return os.WriteFile(destination, body, 0600)
	}
	for _, directory := range []string{"core", "crypto", "telemetry", "providers", "compositions", "tests/fixtures/output-contract-test", "tests/shared/runner", "tests/shared/records", "tests/shared/catalog"} {
		if err := filepath.WalkDir(filepath.Join(source, directory), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			name := entry.Name()
			archive := strings.HasPrefix(filepath.ToSlash(relative), "crypto/testsupport/installedarchive/testdata/")
			if !archive && name != "go.mod" && name != "go.sum" && name != "telemetry_test.mod" && name != "telemetry_test.sum" && name != "LICENSE" && (!strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go")) {
				return nil
			}
			return copyProductionFile(relative)
		}); err != nil {
			t.Fatal("copy maintained runner build inputs", err)
		}
	}
	var publicModules []string
	for _, module := range moduleSources {
		if module.Sibling != "" {
			publicModules = append(publicModules, module.Selector)
		}
	}
	copyPublicModuleKit(t, source, root, publicModules)
	for _, admission := range records.TestAdmissionOverlays() {
		if err := copyProductionFile(admission.Source); err != nil {
			t.Fatal("copy maintained test admission input", admission.Source, err)
		}
	}
	for _, relative := range []string{
		"tests/hermetic/hermetic.mod", "tests/hermetic/hermetic.sum",
		"core/testsupport/nativeprocess/runtime.go.txt",
		"core/testsupport/nativeprocess/recovery.go.txt",
		"core/testsupport/nativeprocess/sourcekind.go.txt",
	} {
		if err := copyProductionFile(relative); err != nil {
			t.Fatal("copy maintained runner build input", relative, err)
		}
	}
	for _, directory := range []string{"testmain", "testrecords", "testcatalog"} {
		if err := os.MkdirAll(filepath.Join(root, "core/internal", directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("real_bootstrap_and_runner", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
		defer cancel()
		command := exec.Command(binary, "invoke", "--root", root, "--", "list", fmt.Sprintf("--parallel=%d", min(2, supervisorFixtureParallel(t))), "--memory-limit-mib=2048")
		command.Dir, command.Env = root, realEnv
		output := new(limitedOutput)
		command.Stdout, command.Stderr = output, output
		result := superviseProcess(ctx, command)
		settled = settled && result.Joined
		if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
			t.Fatalf("real bootstrap/runner invocation did not pass and join: result=%+v output=%s", result, output.String())
		}
		if !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
			settled = false
			t.Fatal("real bootstrap/runner invocation group remains present or uncertain")
		}
		checkSupervisorInvocationList(t, output.String())
		checkSupervisorInvocationStages(t, stageParent)
		resourcesReleased(t)
		checkSiblings(t)
	})

	t.Run("sequential_independent_fixture_roots", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
		defer cancel()
		command := exec.Command(os.Args[0], "-test.run=^TestSupervisorSequentialInvocationOwner$", "-test.count=1", "-test.parallel=1")
		command.Dir = root
		command.Env = environment(realEnv, map[string]string{"ENKV_INVOCATION_FIXTURE_ROOT": root, "ENKV_INVOCATION_FIXTURE_STAGE_PARENT": stageParent})
		output := new(limitedOutput)
		command.Stdout, command.Stderr = output, output
		result := superviseProcess(ctx, command)
		settled = settled && result.Joined
		if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
			t.Fatal("sequential fixture roots did not pass and join", result, output.String())
		}
		if !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
			settled = false
			t.Fatal("fixture owner group remains present")
		}
		body, err := os.ReadFile(filepath.Join(root, "nested-complete"))
		if err != nil || string(body) != "2\n" {
			t.Fatal("fixture owner omitted its two completed native roots", err)
		}
		resourcesReleased(t)
		checkSupervisorInvocationStages(t, stageParent)
		checkSiblings(t)
	})
}
