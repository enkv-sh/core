//go:build !darwin && !linux

package configuration

import "os"

func nativeChange(v os.FileInfo) string { return "" }

func sameNativeOwner(a, b os.FileInfo) bool { return false }
