//go:build (darwin || linux) && cgo

package generatorhost

/*
#define _GNU_SOURCE
#include <spawn.h>
#include <stdlib.h>
#include <errno.h>

#if defined(__linux__)
#ifndef __GLIBC__
#error native process launch requires glibc 2.34 or later
#elif !__GLIBC_PREREQ(2, 34)
#error native process launch requires glibc 2.34 or later
#endif
#endif

static int spawn_native_child(pid_t *pid, const char *path, const char *directory, const char *entrypoint, const int *files, int count, int *cleanup, int *attempted) {
 posix_spawn_file_actions_t actions;
 posix_spawnattr_t attributes;
 int result = posix_spawn_file_actions_init(&actions);
 if (result != 0) return result;
 result = posix_spawnattr_init(&attributes);
 if (result != 0) {
  cleanup[0] = posix_spawn_file_actions_destroy(&actions);
  return result;
 }
 #if defined(__APPLE__)
 result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
 #endif
 if (result == 0) result = posix_spawn_file_actions_addchdir_np(&actions, directory);
 for (int i = 0; result == 0 && i < count; i++) result = posix_spawn_file_actions_adddup2(&actions, files[i], i);
 // All sources are private duplicates above the child's assigned vector.
 for (int i = 0; result == 0 && i < count; i++) result = posix_spawn_file_actions_addclose(&actions, files[i]);
 #if defined(__linux__)
 if (result == 0) result = posix_spawn_file_actions_addclosefrom_np(&actions, count);
 #endif
 if (result == 0) {
  char *arguments[] = {(char *)path, (char *)entrypoint, NULL};
  char *environment[] = {NULL};
  attempted[0] = 1;
  result = posix_spawn(pid, path, &actions, &attributes, arguments, environment);
 }
 cleanup[0] = posix_spawn_file_actions_destroy(&actions);
 cleanup[1] = posix_spawnattr_destroy(&attributes);
 return result;
}
*/
import "C"

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

type nativeChild struct {
	Process      *os.Process
	ProcessState *os.ProcessState
}

type nativeStartFailure struct{ cause error }

func (e *nativeStartFailure) Error() string { return e.cause.Error() }
func (e *nativeStartFailure) Unwrap() error { return e.cause }

func (child *nativeChild) Wait() error {
	state, err := child.Process.Wait()
	child.ProcessState = state
	if err != nil {
		return err
	}
	if !state.Success() {
		return &exec.ExitError{ProcessState: state}
	}
	return nil
}

func startNativeChild(ctx context.Context, path, directory, entrypoint string, files []*os.File) (child *nativeChild, resultErr error) {
	var descriptors [7]C.int
	var duplicates [7]*os.File
	owned := 0
	notStarted, clean := true, true
	defer func() {
		for i := 0; i < owned; i++ {
			if err := duplicates[i].Close(); err != nil {
				clean = false
				resultErr = errors.Join(resultErr, err)
			}
		}
		runtime.KeepAlive(files)
		if child != nil && resultErr != nil {
			killErr := child.Process.Kill()
			if errors.Is(killErr, os.ErrProcessDone) {
				killErr = nil
			}
			resultErr = errors.Join(resultErr, killErr, child.Wait())
			child = nil
		}
		if resultErr != nil && notStarted && clean {
			resultErr = &nativeStartFailure{cause: resultErr}
		}
	}()
	if len(files) < 3 || len(files) > 7 {
		return nil, ErrAdmission
	}
	for i, file := range files {
		if file == nil {
			return nil, ErrAdmission
		}
		connection, err := file.SyscallConn()
		if err != nil {
			return nil, err
		}
		for {
			if ctx != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var fd int
			var duplicateErr error
			controlErr := connection.Control(func(source uintptr) {
				fd, duplicateErr = unix.FcntlInt(source, unix.F_DUPFD_CLOEXEC, len(files))
			})
			err := errors.Join(controlErr, duplicateErr)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return nil, err
			}
			duplicates[i] = os.NewFile(uintptr(fd), "native launch duplicate")
			descriptors[i] = C.int(fd)
			owned++
			break
		}
	}
	executable := C.CString(path)
	defer C.free(unsafe.Pointer(executable))
	workingDirectory := C.CString(directory)
	defer C.free(unsafe.Pointer(workingDirectory))
	argument := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(argument))
	var pid C.pid_t = -1
	var cleanup [2]C.int
	var attempted C.int
	result := C.spawn_native_child(&pid, executable, workingDirectory, argument, &descriptors[0], C.int(len(files)), &cleanup[0], &attempted)
	notStarted = attempted == 0
	if result != 0 {
		resultErr = unix.Errno(result)
	}
	for _, code := range cleanup {
		if code != 0 {
			clean = false
			resultErr = errors.Join(resultErr, unix.Errno(code))
		}
	}
	if result == 0 && pid > 0 {
		process, err := os.FindProcess(int(pid))
		if err != nil {
			killErr := unix.Kill(int(pid), unix.SIGKILL)
			for {
				_, waitErr := unix.Wait4(int(pid), nil, 0, nil)
				if waitErr == unix.EINTR {
					continue
				}
				return nil, errors.Join(resultErr, err, killErr, waitErr)
			}
		}
		child = &nativeChild{Process: process}
	}
	if resultErr != nil {
		return child, resultErr
	}
	if child == nil {
		return nil, ErrProcess
	}
	if ctx != nil && ctx.Err() != nil {
		return child, ctx.Err()
	}
	return child, nil
}
