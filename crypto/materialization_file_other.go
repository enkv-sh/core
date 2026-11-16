//go:build !darwin && !linux

package crypto

func nativeMaterializationFileIO() materializationFileIO { return materializationFileIO{} }
