//go:build !darwin && !linux

package main

import "errors"

var errNativeMemoryUnavailable = errors.New("process memory sampling is unavailable on this platform")

func nativePhysicalMemory() (uint64, error) { return 0, errNativeMemoryUnavailable }
func nativeProcessMemory(int) (processMemoryInfo, error) {
	return processMemoryInfo{}, errNativeMemoryUnavailable
}

func nativeProcessIdentity(int) (processIdentityInfo, error) {
	return processIdentityInfo{}, errNativeMemoryUnavailable
}
func nativeProcessChildren(int) ([]int, error) { return nil, errNativeMemoryUnavailable }
