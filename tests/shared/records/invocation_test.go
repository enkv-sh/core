package records

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testRunID = "0123456789abcdef0123456789abcdef"
const oldRunID = "abcdef0123456789abcdef0123456789"

func canonicalTemp(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func testInvocation(t *testing.T) Invocation {
	t.Helper()
	state := filepath.Join(canonicalTemp(t), "tests", "hermetic", "runs", testRunID, "private", "0000-point")
	output := filepath.Join(state, "workers", "writer")
	if err := os.MkdirAll(output, 0o700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(state, "input.json")
	if err := WriteJSON(input, struct{}{}, 0o400); err != nil {
		t.Fatal(err)
	}
	return Invocation{SchemaVersion: SchemaVersion, Scenario: "state.single-value-update-preserves-other-values/members_32", Nonce: "0123456789abcdef0123456789abcdef", RunID: testRunID, Worker: "0000-point-writer", Role: "writer", Input: input, StateDir: state, OutputDir: output}
}

// full_only: false
func TestRunIDAndSafePathRefuseEscapes(t *testing.T) {
	for _, id := range []string{testRunID, "20260907T095814Z-zu_evmf5", "legacy-baseline"} {
		if !ValidRunID(id) {
			t.Fatalf("retained ID refused: %q", id)
		}
	}
	for _, id := range []string{"", "../" + testRunID, strings.ToUpper(testRunID), testRunID + "/", "20260907T095814Z-", "20260907T095814Z-" + strings.Repeat("a", 33), "legacy-baseline/../x"} {
		if ValidRunID(id) {
			t.Fatalf("unsafe ID admitted: %q", id)
		}
	}
	root := canonicalTemp(t)
	for _, relative := range []string{"", "../x", "a/../x", "a//x", "/x", "a/./x", `a\..\x`} {
		if _, err := SafePath(root, relative); err == nil {
			t.Fatalf("unsafe path admitted: %q", relative)
		}
	}
	if _, err := SafePath(root, "not-yet-created/record.json"); err != nil {
		t.Fatal("safe missing descendants refused")
	}
	target := canonicalTemp(t)
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := SafePath(root, "link/missing.json"); err == nil {
		t.Fatal("symlink ancestor admitted")
	}
	if _, err := SafePath(filepath.Join(root, "link"), "missing.json"); err == nil {
		t.Fatal("symlink root admitted")
	}
}

// full_only: false
func TestInvocationIdentityAndFreshFacts(t *testing.T) {
	inv := testInvocation(t)
	path := filepath.Join(inv.OutputDir, "invocation.json")
	if err := WriteJSON(path, inv, 0o400); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadInvocation(path); err != nil || !reflect.DeepEqual(got, inv) {
		t.Fatalf("valid invocation refused: %+v %v", got, err)
	}
	for name, mutate := range map[string]func(*Invocation){
		"schema":       func(i *Invocation) { i.SchemaVersion++ },
		"run identity": func(i *Invocation) { i.RunID = oldRunID },
		"worker":       func(i *Invocation) { i.Worker = "../worker" },
		"role":         func(i *Invocation) { i.Role = "resume" },
		"input escape": func(i *Invocation) {
			i.Input = filepath.Join(canonicalTemp(t), "input.json")
			_ = WriteJSON(i.Input, struct{}{}, 0o400)
		},
		"state escape":        func(i *Invocation) { i.StateDir = canonicalTemp(t) },
		"missing fresh facts": func(i *Invocation) { i.Role = "fresh_before" },
		"unexpected facts":    func(i *Invocation) { i.Facts = "input.json" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := inv
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid invocation admitted")
			}
		})
	}
	facts := filepath.Join(inv.StateDir, "facts")
	if err := os.Mkdir(facts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(filepath.Join(facts, "fresh.json"), struct{}{}, 0o400); err != nil {
		t.Fatal(err)
	}
	inv.Role, inv.Facts = "fresh_before", "facts/fresh.json"
	if inv.Validate() != nil {
		t.Fatal("fresh invocation refused")
	}
	inv.Facts = "facts/../input.json"
	if inv.Validate() == nil {
		t.Fatal("non-clean facts admitted")
	}
	inv.Facts = "facts/link.json"
	if err := os.Symlink(inv.Input, filepath.Join(facts, "link.json")); err != nil {
		t.Fatal(err)
	}
	if inv.Validate() == nil {
		t.Fatal("symlink facts admitted")
	}
	inv.Role, inv.Facts = "writer", ""
	wrongDirectory := filepath.Join(inv.StateDir, "invocation.json")
	if err := WriteJSON(wrongDirectory, inv, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInvocation(wrongDirectory); err == nil {
		t.Fatal("invocation file outside output directory admitted")
	}
}

// full_only: false
func TestHistoricalInvocationReadingDoesNotAdmitNewExecution(t *testing.T) {
	for _, role := range []string{"writer", "rerun", "fresh_before", "fresh_after"} {
		t.Run(role, func(t *testing.T) {
			inv := testInvocation(t)
			inv.Role = role
			if role == "fresh_before" || role == "fresh_after" {
				inv.Facts = "facts.json"
				if err := WriteJSON(filepath.Join(inv.StateDir, inv.Facts), struct{}{}, 0400); err != nil {
					t.Fatal(err)
				}
			}
			if err := inv.Validate(); err != nil {
				t.Fatal("current control refused", err)
			}
			inv.Scenario = "state.single-value-update-preserves-other-values"
			path := filepath.Join(inv.OutputDir, "invocation.json")
			if err := WriteJSON(path, inv, 0400); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadInvocation(path); err == nil {
				t.Fatal("historical evidence admitted a current worker")
			}
			got, err := LoadRecordedInvocation(path)
			if err != nil || !reflect.DeepEqual(got, inv) {
				t.Fatal("historical reader changed invocation", err)
			}
			inv.Scenario += "/../members_32"
			if err := WriteJSON(path, inv, 0400); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRecordedInvocation(path); err == nil {
				t.Fatal("historical reader accepted unknown identity")
			}
		})
	}
}

// full_only: false
func TestCleanupInvocationKeepsOriginalStateOwner(t *testing.T) {
	inv := testInvocation(t)
	_, runs, _, err := PrivateOwner(inv.OutputDir)
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(runs, oldRunID, "private", "0000-point")
	if err := os.MkdirAll(original, 0o700); err != nil {
		t.Fatal(err)
	}
	originalInput := filepath.Join(original, "input.json")
	if err := WriteJSON(originalInput, struct{}{}, 0o400); err != nil {
		t.Fatal(err)
	}
	inv.StateDir = original
	if inv.Validate() == nil {
		t.Fatal("writer admitted another run's state")
	}
	inv.Role = "cleanup"
	if inv.Validate() != nil {
		t.Fatal("cleanup replacement input refused")
	}
	inv.Input = originalInput
	if inv.Validate() != nil {
		t.Fatal("cleanup original input refused")
	}
	other := testInvocation(t)
	inv.StateDir, inv.Input = other.StateDir, other.Input
	if inv.Validate() == nil {
		t.Fatal("cleanup admitted state from another suite owner")
	}
}

// full_only: false
func TestInvocationNestedRunLayout(t *testing.T) {
	for _, relative := range []string{
		filepath.Join("2026-09-08", "03-11-01+1000-"+testRunID),
		filepath.Join("undated", testRunID),
	} {
		t.Run(relative, func(t *testing.T) {
			state := filepath.Join(canonicalTemp(t), "tests", "hermetic", "runs", relative, "private", "0000-point")
			output := filepath.Join(state, "workers", "writer")
			if err := os.MkdirAll(output, 0o700); err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(state, "input.json")
			if err := WriteJSON(input, struct{}{}, 0o400); err != nil {
				t.Fatal(err)
			}
			inv := Invocation{SchemaVersion: SchemaVersion, Scenario: "state.single-value-update-preserves-other-values/members_32", Nonce: "0123456789abcdef0123456789abcdef", RunID: testRunID, Worker: "0000-point-writer", Role: "writer", Input: input, StateDir: state, OutputDir: output}
			if err := inv.Validate(); err != nil {
				t.Fatalf("nested run invocation refused: %v", err)
			}
			path := filepath.Join(output, "invocation.json")
			if err := WriteJSON(path, inv, 0o400); err != nil {
				t.Fatal(err)
			}
			if got, err := LoadInvocation(path); err != nil || !reflect.DeepEqual(got, inv) {
				t.Fatalf("nested run invocation did not round trip: %+v %v", got, err)
			}
		})
	}
}

// full_only: false
func TestPrivateOwnerReturnsOriginalIdentityForEveryLayout(t *testing.T) {
	for _, relative := range []string{testRunID, "undated/" + testRunID, "2026-09-08/03-11-01+1000-" + testRunID} {
		t.Run(relative, func(t *testing.T) {
			runs := filepath.Join(canonicalTemp(t), "tests/live/runs")
			private := filepath.Join(runs, filepath.FromSlash(relative), "private")
			state := filepath.Join(private, "0000-point")
			output := filepath.Join(state, "workers/writer")
			if os.MkdirAll(output, 0o700) != nil {
				t.Fatal("owned directory fixture")
			}
			input := filepath.Join(state, "input.json")
			if WriteJSON(input, struct{}{}, 0o400) != nil {
				t.Fatal("owned input fixture")
			}
			for _, path := range []string{private, state, output, input} {
				owner, ownerRuns, id, err := PrivateOwner(path)
				if err != nil || owner != private || ownerRuns != runs || id != testRunID {
					t.Fatalf("owner parser lost original identity: %q %q %q %v", owner, ownerRuns, id, err)
				}
			}
			alias := filepath.Join(runs, "alias")
			if os.Symlink(private, alias) != nil {
				t.Fatal("alias fixture")
			}
			if _, _, _, err := PrivateOwner(filepath.Join(alias, "0000-point")); err == nil {
				t.Fatal("owner parser accepted a symlink alias")
			}
		})
	}
}

// full_only: false
func TestNestedInvocationKeepsRunAndSuiteOwnership(t *testing.T) {
	root := canonicalTemp(t)
	makeInvocation := func(suite, relative, id string) Invocation {
		t.Helper()
		state := filepath.Join(root, "tests", suite, "runs", filepath.FromSlash(relative), "private", "0000-point")
		output := filepath.Join(state, "workers", "writer")
		if err := os.MkdirAll(output, 0o700); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(state, "input.json")
		if err := WriteJSON(input, struct{}{}, 0o400); err != nil {
			t.Fatal(err)
		}
		return Invocation{SchemaVersion: SchemaVersion, Scenario: "state.single-value-update-preserves-other-values/members_32", Nonce: "0123456789abcdef0123456789abcdef", RunID: id, Worker: "0000-point-writer", Role: "writer", Input: input, StateDir: state, OutputDir: output}
	}
	inv := makeInvocation("hermetic", "2026-09-08/03-11-01+1000-"+testRunID, testRunID)
	original := makeInvocation("hermetic", "2026-09-07/23-11-01+1000-"+oldRunID, oldRunID)
	_, runs, id, err := PrivateOwner(inv.OutputDir)
	if err != nil || runs != filepath.Join(root, "tests", "hermetic", "runs") || id != testRunID {
		t.Fatalf("nested owner did not preserve suite and identity: %q, %q, %v", runs, id, err)
	}
	changed := inv
	changed.StateDir = original.StateDir
	if changed.Validate() == nil {
		t.Fatal("writer admitted another nested run's state")
	}
	changed.Role = "cleanup"
	if err := changed.Validate(); err != nil {
		t.Fatalf("cleanup with replacement input refused: %v", err)
	}
	changed.Input = original.Input
	if err := changed.Validate(); err != nil {
		t.Fatalf("cleanup of another nested run refused: %v", err)
	}
	third := makeInvocation("hermetic", "undated/20260907T010203Z-third", "20260907T010203Z-third")
	changed.Input = third.Input
	if changed.Validate() == nil {
		t.Fatal("cleanup admitted input from a third run")
	}
	otherSuite := makeInvocation("live", "undated/"+oldRunID, oldRunID)
	changed.Input, changed.StateDir = otherSuite.Input, otherSuite.StateDir
	if changed.Validate() == nil {
		t.Fatal("cleanup admitted another suite's state")
	}
	changed = inv
	changed.RunID = oldRunID
	if changed.Validate() == nil {
		t.Fatal("nested output identity mismatch admitted")
	}
	changed = makeInvocation("hermetic", "2026-02-30/03-11-01+1000-"+testRunID, testRunID)
	if changed.Validate() == nil {
		t.Fatal("invalid calendar owner admitted")
	}
	changed = inv
	changed.OutputDir = filepath.Join(inv.OutputDir, "runs", "undated", testRunID, "private", "worker")
	if err := os.MkdirAll(changed.OutputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if changed.Validate() == nil {
		t.Fatal("nested private owner confusion admitted")
	}
}

// full_only: false
func TestPrivateJSONBoundedStrictAndAtomic(t *testing.T) {
	root := canonicalTemp(t)
	path := filepath.Join(root, "record.json")
	value := struct {
		Outcome string `json:"outcome"`
	}{Outcome: "passed"}
	for _, mode := range []os.FileMode{0o400, 0o600} {
		if err := WriteJSON(path, value, mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("private record permissions changed")
		}
		var got struct {
			Outcome string `json:"outcome"`
		}
		if ReadJSON(path, &got) != nil || got != value {
			t.Fatal("private record did not round trip")
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if WriteJSON(path, make(chan int), 0o600) == nil || WriteJSON(path, value, 0o644) == nil {
		t.Fatal("invalid JSON or public permissions admitted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("failed replacement damaged prior record")
	}
	for _, body := range []string{`{"outcome":"passed","secret":"SYNTHETIC_SECRET"}`, `{"outcome":"passed"} {}`, `{`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Outcome string `json:"outcome"`
		}
		if err := ReadJSON(path, &got); err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Fatal("invalid JSON accepted or raw content leaked")
		}
	}
	large, err := os.Create(filepath.Join(root, "large.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate(MaximumJSONBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := large.Close(); err != nil {
		t.Fatal(err)
	}
	if ReadJSON(large.Name(), new(any)) == nil || ReadJSON(root, new(any)) == nil {
		t.Fatal("oversized or non-regular record admitted")
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if ReadJSON(link, new(any)) == nil || WriteJSON(link, value, 0o600) == nil {
		t.Fatal("symlink record admitted")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".record-") {
			t.Fatal("atomic write left a temporary record")
		}
	}
}

// full_only: false
func TestTemporaryRecordCleanupPreservesFailure(t *testing.T) {
	root := canonicalTemp(t)
	prior := errors.New("record write failed")
	for _, name := range []string{"absent", "regular", "blocked"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			switch name {
			case "regular":
				if err := os.WriteFile(path, []byte("private record"), 0600); err != nil {
					t.Fatal(err)
				}
			case "blocked":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "owned"), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := removeTemporaryRecord(path, prior)
			if !errors.Is(err, prior) {
				t.Fatal("prior record failure lost", err)
			}
			if name != "blocked" {
				if err != prior {
					t.Fatal("successful or absent cleanup added a failure", err)
				}
				if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
					t.Fatal("temporary record remained", statErr)
				}
				return
			}
			var removeErr *os.PathError
			if !errors.As(err, &removeErr) || removeErr.Op != "remove" || removeErr.Path != path {
				t.Fatal("temporary cleanup failure lost", err)
			}
		})
	}
}
