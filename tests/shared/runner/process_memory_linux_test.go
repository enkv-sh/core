//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func writeLinuxMemoryStatus(t *testing.T, base, name, body string) {
	t.Helper()
	path := filepath.Join(base, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestLinuxProcessMemoryRetainsLiveThreadAddressSpace(t *testing.T) {
	for _, state := range []string{"R", "Z"} {
		t.Run(state, func(t *testing.T) {
			base := t.TempDir()
			writeLinuxMemoryStatus(t, base, "status", "State:\t"+state+"\n")
			writeLinuxMemoryStatus(t, base, "task/101/status", "State:\t"+state+"\n")
			// Both live threads observe one shared address space: 3 KiB
			// resident plus 2 KiB swapped, counted once as 5120 bytes.
			for _, name := range []string{"task/102/status", "task/103/status"} {
				writeLinuxMemoryStatus(t, base, name, "State:\tS\nVmRSS:\t3 kB\nVmSwap:\t2 kB\n")
			}
			amount, err := linuxThreadGroupMemory(base)
			if err != nil || amount != 5120 {
				t.Fatal("exited leader lost or duplicated live-thread memory", amount, err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		status string
		want   uint64
	}{
		{"complete_leader", "VmRSS:\t3 kB\nVmSwap:\t2 kB\n", 5120},
		{"zero_memory_leader", "VmRSS:\t0 kB\nVmSwap:\t0 kB\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			writeLinuxMemoryStatus(t, base, "status", tc.status)
			// A complete leader observation needs no fallback task listing.
			amount, err := linuxThreadGroupMemory(base)
			if err != nil || amount != tc.want {
				t.Fatal("complete address-space observation changed", amount, err)
			}
		})
	}
}

// full_only: false
func TestLinuxProcessMemoryAcceptsReleasedAddressSpace(t *testing.T) {
	for _, state := range []string{"R", "Z"} {
		t.Run(state, func(t *testing.T) {
			base := t.TempDir()
			writeLinuxMemoryStatus(t, base, "status", "State:\t"+state+"\n")
			writeLinuxMemoryStatus(t, base, "task/101/status", "State:\t"+state+"\n")
			// This task exits between the directory listing and status read.
			if err := os.Mkdir(filepath.Join(base, "task/102"), 0700); err != nil {
				t.Fatal(err)
			}
			amount, err := linuxThreadGroupMemory(base)
			if err != nil || amount != 0 {
				t.Fatal("released address space was treated as an observation failure", amount, err)
			}
		})
	}
	t.Run("all_tasks_disappeared", func(t *testing.T) {
		base := t.TempDir()
		writeLinuxMemoryStatus(t, base, "status", "State:\tR\n")
		if err := os.MkdirAll(filepath.Join(base, "task/102"), 0700); err != nil {
			t.Fatal(err)
		}
		amount, err := linuxThreadGroupMemory(base)
		if err != nil || amount != 0 {
			t.Fatal("departed task retained an address space", amount, err)
		}
	})
}

// full_only: false
func TestLinuxProcessMemoryRejectsIncompleteObservation(t *testing.T) {
	for _, status := range []struct {
		name string
		body string
	}{
		{"rss_missing", "VmSwap:\t0 kB\n"},
		{"swap_missing", "VmRSS:\t1 kB\n"},
		{"invalid_rss", "VmRSS:\tbad kB\nVmSwap:\t0 kB\n"},
		{"invalid_swap_unit", "VmRSS:\t1 kB\nVmSwap:\t0 B\n"},
	} {
		for _, scope := range []string{"leader", "sibling"} {
			t.Run(scope+"/"+status.name, func(t *testing.T) {
				base := t.TempDir()
				if scope == "leader" {
					writeLinuxMemoryStatus(t, base, "status", status.body)
				} else {
					writeLinuxMemoryStatus(t, base, "status", "State:\tZ\n")
					writeLinuxMemoryStatus(t, base, "task/102/status", status.body)
				}
				if amount, err := linuxThreadGroupMemory(base); err == nil || amount != 0 {
					t.Fatal("partial or malformed memory observation was accepted", amount, err)
				}
			})
		}
	}
	for _, name := range []string{"missing_leader", "leader_read_failed", "missing_task_list", "task_list_read_failed", "task_status_read_failed", "invalid_task_name", "task_limit"} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			if name != "missing_leader" && name != "leader_read_failed" {
				writeLinuxMemoryStatus(t, base, "status", "State:\tZ\n")
			}
			switch name {
			case "leader_read_failed":
				if err := os.Mkdir(filepath.Join(base, "status"), 0700); err != nil {
					t.Fatal(err)
				}
			case "task_list_read_failed":
				writeLinuxMemoryStatus(t, base, "task", "not a task directory")
			case "task_status_read_failed":
				if err := os.MkdirAll(filepath.Join(base, "task/102/status"), 0700); err != nil {
					t.Fatal(err)
				}
			case "invalid_task_name":
				writeLinuxMemoryStatus(t, base, "task/not-a-tid/status", "State:\tZ\n")
			case "task_limit":
				for i := 1; i <= processMemoryMaxProcesses+1; i++ {
					if err := os.MkdirAll(filepath.Join(base, "task", strconv.Itoa(i)), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			amount, err := linuxThreadGroupMemory(base)
			if err == nil || amount != 0 {
				t.Fatal("failed memory observation was accepted", amount, err)
			}
			if (name == "missing_leader" || name == "missing_task_list") && !errors.Is(err, syscall.ESRCH) {
				t.Fatal("disappeared-process identity was lost", err)
			}
		})
	}
}

// full_only: false
func TestLinuxProcessMemoryObservesWorkerAfterLeaderExit(t *testing.T) {
	directory := t.TempDir()
	source, binary := filepath.Join(directory, "worker.c"), filepath.Join(directory, "worker")
	const program = `#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static void *worker(void *argument) {
 char **paths = argument;
 volatile unsigned char *memory = malloc(8 * 1024 * 1024);
 if (!memory) _exit(20);
 for (size_t offset = 0; offset < 8 * 1024 * 1024; offset += 4096)
  memory[offset] = 1;
 FILE *ready = fopen(paths[1], "w");
 if (!ready) _exit(21);
 if (fprintf(ready, "%ld\n", (long)getpid()) < 0 || fclose(ready)) _exit(22);
 struct timespec pause = {0, 1000000};
 while (access(paths[2], F_OK)) {
  if (errno != ENOENT || nanosleep(&pause, NULL)) _exit(23);
 }
 free((void *)memory);
 return NULL;
}

int main(int argc, char **argv) {
 pthread_t thread;
 if (argc != 3 || pthread_create(&thread, NULL, worker, argv)) return 24;
 pthread_exit(NULL);
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("native C compiler is required", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var output bytes.Buffer
	compiled := runProcessOutput(ctx, compiler, directory, []string{"-pthread", "-O0", "-o", binary, source}, nil, 15*time.Second, &output, &output)
	if compiled.Status != "passed" || !compiled.Started || !compiled.Joined {
		t.Fatal("native worker compiler did not pass and join", compiled, output.String())
	}
	marker, release := filepath.Join(directory, "ready"), filepath.Join(directory, "release")
	command := exec.Command(binary, marker, release)
	done := make(chan processResult, 1)
	go func() { done <- superviseProcess(ctx, command) }()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			result := <-done
			if !result.Joined || command.ProcessState == nil {
				t.Error("native worker cleanup did not join", result)
			}
		}
	})
	pid := waitProcessMarker(t, ctx, marker)
	for {
		identity, err := nativeProcessIdentity(pid)
		if err != nil {
			t.Fatal("native leader identity disappeared before observation", err)
		}
		if identity.state == 'Z' {
			break
		}
		select {
		case result := <-done:
			finished = true
			t.Fatal("native worker ended before leader exit observation", result)
		case <-ctx.Done():
			t.Fatal("native leader did not exit", ctx.Err())
		case <-time.After(processGroupPollInterval):
		}
	}
	observed, err := nativeProcessMemory(pid)
	// The only live thread touched 8 MiB. A 4 MiB floor allows the kernel's
	// approximate RSS counters while detecting a missing address space.
	if err != nil || observed.identity.pid != pid || observed.bytes < 4<<20 {
		t.Fatal("zombie leader hid its live worker's address space", observed, err)
	}
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		finished = true
		if result.Status != "passed" || !result.Started || !result.Joined || command.ProcessState == nil {
			t.Fatal("released native worker did not pass and join", result)
		}
	case <-ctx.Done():
		t.Fatal("released native worker did not finish", ctx.Err())
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("native worker PID remains after positive Wait", pid, err)
	}
}
