//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func nativePhysicalMemory() (uint64, error) {
	body, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			break
		}
		amount, err := strconv.ParseUint(fields[1], 10, 64)
		return amount * 1024, err
	}
	return 0, fmt.Errorf("physical memory is absent from /proc/meminfo")
}

func nativeProcessIdentity(pid int) (processIdentityInfo, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return processIdentityInfo{}, linuxProcessError(err)
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return processIdentityInfo{}, fmt.Errorf("process %d stat is incomplete", pid)
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return processIdentityInfo{}, fmt.Errorf("process %d stat has no start time", pid)
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return processIdentityInfo{}, err
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return processIdentityInfo{}, err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processIdentityInfo{}, err
	}
	return processIdentityInfo{identity: processIdentity{pid: pid, start: start},
		parent: parent, group: group, state: fields[0][0]}, nil
}

func nativeProcessMemory(pid int) (processMemoryInfo, error) {
	identity, err := nativeProcessIdentity(pid)
	if err != nil {
		return processMemoryInfo{}, err
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	amount, err := linuxThreadGroupMemory(base)
	if err != nil {
		return processMemoryInfo{}, fmt.Errorf("process %d memory: %w", pid, err)
	}
	after, err := nativeProcessIdentity(pid)
	if err != nil {
		return processMemoryInfo{}, err
	}
	if after.identity != identity.identity {
		return processMemoryInfo{}, syscall.ESRCH
	}
	return processMemoryInfo{processIdentityInfo: identity, bytes: amount}, nil
}

func linuxThreadGroupMemory(base string) (amount uint64, retErr error) {
	amount, hasMemory, err := linuxTaskMemory(filepath.Join(base, "status"))
	if err != nil || hasMemory {
		return amount, err
	}
	// Linux clears a task's mm before publishing its zombie state. The
	// leader can also exit while sibling threads retain the shared mm.
	tasksPath := filepath.Join(base, "task")
	directory, err := os.Open(tasksPath)
	if err != nil {
		return 0, linuxProcessError(err)
	}
	defer func() { retErr = errors.Join(retErr, directory.Close()) }()
	tasks, err := directory.Readdirnames(processMemoryMaxProcesses + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, linuxProcessError(err)
	}
	if len(tasks) > processMemoryMaxProcesses {
		return 0, errors.New("process has too many tasks for memory census")
	}
	for _, task := range tasks {
		if tid, err := strconv.Atoi(task); err != nil || tid <= 0 {
			return 0, errors.New("process task name is invalid")
		}
		amount, hasMemory, err = linuxTaskMemory(filepath.Join(tasksPath, task, "status"))
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if hasMemory {
			// Threads share the same address space; count it once.
			return amount, nil
		}
	}
	return 0, nil
}

func linuxTaskMemory(path string) (uint64, bool, error) {
	status, err := os.ReadFile(path)
	if err != nil {
		return 0, false, linuxProcessError(err)
	}
	var rss, swap uint64
	var gotRSS, gotSwap bool
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			rss, err = linuxMemoryLine(line)
			gotRSS = err == nil
		} else if strings.HasPrefix(line, "VmSwap:") {
			swap, err = linuxMemoryLine(line)
			gotSwap = err == nil
		}
		if err != nil {
			return 0, false, err
		}
	}
	if gotRSS != gotSwap {
		return 0, false, errors.New("process memory status is incomplete")
	}
	return rss + swap, gotRSS, nil
}

func nativeProcessChildren(pid int) (children []int, retErr error) {
	tasksPath := filepath.Join("/proc", strconv.Itoa(pid), "task")
	tasksDirectory, err := os.Open(tasksPath)
	if err != nil {
		return nil, linuxProcessError(err)
	}
	defer func() { retErr = errors.Join(retErr, tasksDirectory.Close()) }()
	tasks, err := tasksDirectory.Readdirnames(processMemoryMaxProcesses + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, linuxProcessError(err)
	}
	if len(tasks) > processMemoryMaxProcesses {
		return nil, fmt.Errorf("process %d has too many tasks for memory census", pid)
	}
	seen := make(map[int]struct{})
	readTasks := 0
	for _, task := range tasks {
		if _, err := strconv.Atoi(task); err != nil {
			return nil, fmt.Errorf("process %d task name: %w", pid, err)
		}
		childrenFile, err := os.Open(filepath.Join(tasksPath, task, "children"))
		if os.IsNotExist(err) {
			// A task may exit after ReadDir. Its process tree is checked
			// again at the next sample if the process survives.
			continue
		}
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(childrenFile, processMemoryMaxProcesses*32+1))
		closeErr := childrenFile.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		if len(body) > processMemoryMaxProcesses*32 {
			return nil, fmt.Errorf("process %d has too many children for memory census", pid)
		}
		readTasks++
		for _, field := range strings.Fields(string(body)) {
			child, err := strconv.Atoi(field)
			if err != nil {
				return nil, err
			}
			seen[child] = struct{}{}
			if len(seen) > processMemoryMaxProcesses {
				return nil, fmt.Errorf("process %d has too many children for memory census", pid)
			}
		}
	}
	if readTasks == 0 {
		return nil, syscall.ESRCH
	}
	out := make([]int, 0, len(seen))
	for child := range seen {
		out = append(out, child)
	}
	sort.Ints(out)
	return out, nil
}

func linuxMemoryLine(line string) (uint64, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[2] != "kB" {
		return 0, fmt.Errorf("invalid process memory line")
	}
	value, err := strconv.ParseUint(fields[1], 10, 64)
	return value * 1024, err
}

func linuxProcessError(err error) error {
	if os.IsNotExist(err) {
		return syscall.ESRCH
	}
	return err
}
