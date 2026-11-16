package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestGoCancellationStopsDescendantsBeforeOverlayCleanup(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(root, "core")
	if err := os.Mkdir(core, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"go.mod": "module example.test/process\n\ngo 1.27.0\n",
		"main.go": `package main
import (
 "os"
 "os/exec"
 "path/filepath"
 "strconv"
 "time"
)
func main() {
 directory := os.Args[1]
 if len(os.Args) == 3 {
  if err := os.WriteFile(filepath.Join(directory, "child.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil { panic(err) }
  time.Sleep(time.Minute)
  return
 }
 if err := os.WriteFile(filepath.Join(directory, "writer.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil { panic(err) }
 executable, err := os.Executable()
 if err != nil { panic(err) }
 child := exec.Command(executable, directory, "child")
 child.Stdout, child.Stderr = os.Stdout, os.Stderr
 if err := child.Run(); err != nil { panic(err) }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(core, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	overlay, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{
		filepath.Join(core, "internal/testmain/main.go"): filepath.Join(core, "main.go"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(core, "overlay.json"), overlay, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runGo(ctx, root, "core", "run", "-mod=readonly", "-overlay="+filepath.Join(core, "overlay.json"), "./internal/testmain", root)
		done <- err
	}()
	var writer, child int
	finished := false
	t.Cleanup(func() {
		cancel()
		// The regression must clean up even when the old implementation leaves
		// children holding its output pipes open after the Go parent exits.
		for _, pid := range []int{child, writer} {
			if pid > 0 {
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					t.Errorf("fixture process cleanup: %v", err)
				}
			}
		}
		if !finished {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("Go fixture did not join after emergency cleanup")
			}
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for writer == 0 || child == 0 {
		for name, target := range map[string]*int{"writer.pid": &writer, "child.pid": &child} {
			body, readErr := os.ReadFile(filepath.Join(root, name))
			if readErr == nil {
				*target, _ = strconv.Atoi(string(body))
			}
		}
		select {
		case err := <-done:
			finished = true
			t.Fatalf("Go fixture exited before descendant readiness: %v", err)
		default:
		}
		if !time.Now().Before(deadline) {
			t.Fatal("Go fixture did not register its descendants")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(core, "internal/testmain")); err != nil {
		t.Fatalf("overlay directories missing while command runs: %v", err)
	}
	cancel()
	var commandErr error
	select {
	case commandErr = <-done:
		finished = true
		var failure *toolFailure
		if !errors.As(commandErr, &failure) || !failure.process.Started || !failure.process.Joined || failure.process.Status != "interrupted" || !errors.Is(commandErr, context.Canceled) {
			t.Error("canceled Go command lost native failure or positive settlement", commandErr)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("canceled Go command did not stop and join its descendants")
	}
	for _, pid := range []int{writer, child} {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Errorf("Go descendant %d remains after return: %v", pid, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(core, "internal")); !os.IsNotExist(err) {
		t.Errorf("canceled Go command retained its temporary overlay directories: stat=%v, command=%v", err, commandErr)
		for _, relative := range []string{"internal", "internal/testmain", "internal/testcatalog", "internal/testrecords"} {
			entries, readErr := os.ReadDir(filepath.Join(core, relative))
			names := make([]string, len(entries))
			for i, entry := range entries {
				names[i] = entry.Name()
			}
			t.Logf("retained directory %s: entries=%q, error=%v", relative, names, readErr)
		}
	}
}

// full_only: false
func TestGoPreflightDoesNotStartCommand(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "go")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf started > \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	marker := filepath.Join(root, "canceled")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := runGo(ctx, root, ".", marker)
	var failure *toolFailure
	if !errors.As(err, &failure) || failure.process.Started || !failure.process.Joined ||
		!errors.Is(err, context.Canceled) || failure.process.Status != "interrupted" {
		t.Errorf("Go preflight lost canceled physical result: %v", err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Error("canceled Go command started a process", err)
	}
}

// full_only: false
func TestPreparationCommandDeadlineKeepsParentAndTestExecution(t *testing.T) {
	parent, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	defer cancel()
	before := time.Now()
	command, stop := preparationCommandContext(parent)
	defer stop()
	deadline, bounded := command.Deadline()
	if !bounded || deadline.Before(before.Add(15*time.Minute)) || deadline.After(time.Now().Add(15*time.Minute)) {
		t.Fatal("preparation command has no independent finite deadline", deadline, bounded)
	}
	cancel()
	if !errors.Is(command.Err(), context.Canceled) {
		t.Fatal("preparation lost parent cancellation")
	}
	earlier, finish := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer finish()
	command, stopEarlier := preparationCommandContext(earlier)
	defer stopEarlier()
	want, _ := earlier.Deadline()
	if got, _ := command.Deadline(); !got.Equal(want) {
		t.Fatal("preparation extended parent deadline")
	}
	<-command.Done()
	if !errors.Is(command.Err(), context.DeadlineExceeded) {
		t.Fatal("preparation lost deadline cause")
	}
	for _, row := range []struct {
		name string
		args []string
		runs bool
	}{
		{"metadata", []string{"list", "-json", "./..."}, false},
		{"module preparation", []string{"mod", "edit", "-json"}, false},
		{"build", []string{"build", "./..."}, false},
		{"test compile", []string{"test", "-c", "./..."}, false},
		{"explicit compile", []string{"test", "-c=true", "./..."}, false},
		{"inventory", []string{"test", "-list=.", "./..."}, false},
		{"split inventory", []string{"test", "-list", ".", "./..."}, false},
		{"ordinary execution", []string{"test", "-timeout=10m", "./..."}, true},
		{"full-only execution", []string{"test", "-timeout=30m", "./..."}, true},
		{"empty list", []string{"test", "-list=", "./..."}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if goCommandRunsTests(row.args) != row.runs {
				t.Fatal("Go command received the wrong deadline owner", row.args)
			}
		})
	}
}
