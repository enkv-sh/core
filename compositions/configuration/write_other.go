//go:build !darwin && !linux

package configuration

import "os"

func releaseEditLock(*os.File) error                    { return ErrNativeEdit }
func syncEditFile(*os.File) error                       { return ErrNativeEdit }
func openNativeLock(string, bool) (*os.File, error)     { return nil, ErrNativeEdit }
func lockNativeFile(*os.File, bool) error               { return ErrNativeEdit }
func fileIdentity(os.FileInfo) (nativeIdentity, bool)   { return nativeIdentity{}, false }
func singleLink(os.FileInfo) bool                       { return false }
func availableEditBytes(string) (uint64, uint64, error) { return 0, 0, ErrNativeEdit }

func renameEditAbsent(string, string) error { return ErrNativeEdit }

func openNativeInstallation(string) (*os.File, error) { return nil, ErrNativeEdit }

func openNativeScratch(string) (*os.File, error) { return nil, ErrNativeEdit }
