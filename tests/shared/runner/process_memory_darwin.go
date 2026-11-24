//go:build darwin && cgo

package main

/*
#include <errno.h>
#include <libproc.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/sysctl.h>

static int enkv_children(int pid, pid_t *out, int bytes, int *failure) {
	errno = 0;
	int n = proc_listchildpids(pid, out, bytes);
	*failure = n <= 0 ? errno : 0;
	return n;
}

static int enkv_process(int pid, struct proc_bsdinfo *out, int *failure) {
	errno = 0;
	int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, out, sizeof(*out));
	*failure = n <= 0 ? errno : 0;
	if (n != 0 || *failure != ESRCH) return n;

	// libproc hides exited children before their parent reaps them.
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
	struct kinfo_proc entry = {0};
	size_t size = sizeof(entry);
	if (sysctl(mib, 4, &entry, &size, NULL, 0) != 0) {
		*failure = errno;
		return 0;
	}
	if (size == 0) return 0;
	if (size != sizeof(entry) || entry.kp_proc.p_pid != pid) {
		*failure = EIO;
		return 0;
	}
	out->pbi_status = entry.kp_proc.p_stat;
	out->pbi_ppid = entry.kp_eproc.e_ppid;
	out->pbi_pgid = entry.kp_eproc.e_pgid;
	out->pbi_start_tvsec = entry.kp_proc.p_starttime.tv_sec;
	out->pbi_start_tvusec = entry.kp_proc.p_starttime.tv_usec;
	*failure = 0;
	return sizeof(*out);
}

static int enkv_usage(int pid, struct rusage_info_v4 *out, int *failure) {
	errno = 0;
	int n = proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)out);
	*failure = n < 0 ? errno : 0;
	return n;
}

static int enkv_physical_memory(uint64_t *out, int *failure) {
	size_t size = sizeof(*out);
	errno = 0;
	int n = sysctlbyname("hw.memsize", out, &size, NULL, 0);
	*failure = n < 0 ? errno : 0;
	return n == 0 && size == sizeof(*out) ? 0 : -1;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"syscall"
)

func nativePhysicalMemory() (uint64, error) {
	var size C.uint64_t
	var failure C.int
	if C.enkv_physical_memory(&size, &failure) != 0 {
		return 0, nativeMemoryError(failure)
	}
	return uint64(size), nil
}

func nativeProcessIdentity(pid int) (processIdentityInfo, error) {
	var bsd C.struct_proc_bsdinfo
	var failure C.int
	read := C.enkv_process(C.int(pid), &bsd, &failure)
	if read == 0 {
		return processIdentityInfo{}, nativeMemoryError(failure)
	}
	if read != C.int(C.sizeof_struct_proc_bsdinfo) {
		return processIdentityInfo{}, nativeMemoryError(failure)
	}
	var state byte
	switch bsd.pbi_status {
	case C.SSTOP:
		state = 'T'
	case C.SZOMB:
		state = 'Z'
	}
	return processIdentityInfo{identity: processIdentity{pid: pid,
		start: uint64(bsd.pbi_start_tvsec)*1_000_000 + uint64(bsd.pbi_start_tvusec)},
		parent: int(bsd.pbi_ppid), group: int(bsd.pbi_pgid), state: state}, nil
}

func nativeProcessMemory(pid int) (processMemoryInfo, error) {
	identity, err := nativeProcessIdentity(pid)
	if err != nil {
		return processMemoryInfo{}, err
	}
	var usage C.struct_rusage_info_v4
	var failure C.int
	if C.enkv_usage(C.int(pid), &usage, &failure) != 0 {
		return processMemoryInfo{}, nativeMemoryError(failure)
	}
	after, err := nativeProcessIdentity(pid)
	if err != nil {
		return processMemoryInfo{}, err
	}
	if after.identity != identity.identity {
		return processMemoryInfo{}, syscall.ESRCH
	}
	return processMemoryInfo{processIdentityInfo: identity,
		bytes: uint64(usage.ri_phys_footprint)}, nil
}

func nativeProcessChildren(pid int) ([]int, error) {
	var failure C.int
	count := C.enkv_children(C.int(pid), nil, 0, &failure)
	if count < 0 || (count == 0 && failure != 0) {
		return nil, nativeMemoryError(failure)
	}
	for attempt := 0; attempt < 12; attempt++ {
		if count > processMemoryMaxProcesses {
			return nil, fmt.Errorf("process %d has too many children for memory census", pid)
		}
		capacity := int(count) + 8
		if capacity < 8 {
			capacity = 8
		}
		children := make([]C.pid_t, capacity)
		read := C.enkv_children(C.int(pid), &children[0], C.int(len(children)*int(C.sizeof_pid_t)), &failure)
		if read < 0 || (read == 0 && failure != 0) {
			return nil, nativeMemoryError(failure)
		}
		if int(read) >= len(children) {
			count = read * 2
			continue
		}
		out := make([]int, 0, int(read))
		for _, child := range children[:int(read)] {
			out = append(out, int(child))
		}
		return out, nil
	}
	return nil, fmt.Errorf("process %d child census changed during bounded retries", pid)
}

func nativeMemoryError(code C.int) error {
	if code == 0 {
		return errors.New("native process memory information is incomplete")
	}
	return syscall.Errno(code)
}
