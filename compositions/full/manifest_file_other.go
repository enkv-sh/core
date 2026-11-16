//go:build !darwin && !linux

package compositionfull

func nativeManifestFileIO() manifestFileIO { return manifestFileIO{} }
