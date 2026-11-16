//go:build darwin || linux

package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"

	"enkv.sh/core/contract"
)

func nativeMaterializationFileIO() materializationFileIO {
	return materializationFileIO{
		create: func(parent string) (*os.File, error) {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return nil, err
			}
			path := filepath.Join(parent, materializationCandidatePrefix+hex.EncodeToString(nonce[:]))
			return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		},
		open:     func(path string, _ contract.MaterializationStage) (*os.File, error) { return os.Open(path) },
		lstat:    os.Lstat,
		stat:     func(f *os.File, _ contract.MaterializationStage) (os.FileInfo, error) { return f.Stat() },
		chmod:    func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) },
		write:    func(f *os.File, p []byte) (int, error) { return f.Write(p) },
		read:     func(f *os.File, p []byte, _ contract.MaterializationStage) (int, error) { return f.Read(p) },
		syncFile: syncMaterializationFile,
		syncDir:  func(f *os.File) error { return f.Sync() },
		close:    func(f *os.File, _ contract.MaterializationStage) error { return f.Close() },
		rename:   renameMaterializationFile,
		remove:   os.Remove,
	}
}

func renameMaterializationFile(from, to string) (contract.MaterializationReplacement, error) {
	err := os.Rename(from, to)
	if err == nil {
		return contract.MaterializationReplaced, nil
	}
	// A mounted filesystem can report an error after a rename took effect.
	// Without a qualified no-effect observation the replacement remains unknown.
	return contract.MaterializationReplacementUnknown, err
}
