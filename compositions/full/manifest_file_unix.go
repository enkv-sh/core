//go:build darwin || linux

package compositionfull

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

func nativeManifestFileIO() manifestFileIO {
	return manifestFileIO{
		create: func(parent string) (*os.File, error) {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return nil, err
			}
			path := filepath.Join(parent, manifestCandidatePrefix+hex.EncodeToString(nonce[:]))
			return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		},
		open:     func(path string, _ ManifestFileStage) (*os.File, error) { return os.Open(path) },
		lstat:    os.Lstat,
		stat:     func(file *os.File, _ ManifestFileStage) (os.FileInfo, error) { return file.Stat() },
		chmod:    func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) },
		write:    func(file *os.File, p []byte) (int, error) { return file.Write(p) },
		read:     func(file *os.File, p []byte, _ ManifestFileStage) (int, error) { return file.Read(p) },
		syncFile: syncManifestFile,
		syncDir:  func(file *os.File) error { return file.Sync() },
		close:    func(file *os.File, _ ManifestFileStage) error { return file.Close() },
		rename:   renameManifestFile,
		remove:   os.Remove,
	}
}

func renameManifestFile(from, to string) (ManifestReplacement, error) {
	if err := os.Rename(from, to); err != nil {
		// A filesystem can report an error after the rename took effect.
		return ManifestReplacementUnknown, err
	}
	return ManifestReplaced, nil
}
