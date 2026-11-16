package core

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	records "enkv.sh/core/internal/testrecords"
	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/sys/unix"
)

const maximumLiveOutputCredentialSourceBytes = 64 << 10

var errLiveOutputCredentialFile = errors.New("live output credential file refused")

// One fixture owns the snapshot namespace. A loader borrows Path for reading
// and must return before Close; other callers must not mutate this namespace.
// Identity checks detect observed replacements, not concurrent same-user edits.
type liveOutputCredentialFile struct {
	Path              string
	Identity          os.FileInfo
	directory         *os.File
	directoryIdentity os.FileInfo
	snapshotIdentity  os.FileInfo
}

func liveOutputCredentialOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}

func liveOutputCredentialPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	_, err := records.SafePath(string(filepath.Separator), strings.TrimPrefix(path, string(filepath.Separator)))
	return err == nil
}

func liveOutputCredentialStable(before, after, path os.FileInfo) bool {
	return before != nil && after != nil && path != nil && before.Mode().IsRegular() && after.Mode().IsRegular() && path.Mode().IsRegular() &&
		liveOutputCredentialOwned(before) && liveOutputCredentialOwned(after) && liveOutputCredentialOwned(path) &&
		records.SameLocalFile(before, after) && records.SameLocalFile(after, path) && before.Mode() == after.Mode() && after.Mode() == path.Mode() &&
		before.Size() == after.Size() && after.Size() == path.Size() && before.ModTime() == after.ModTime() && after.ModTime() == path.ModTime()
}

func liveOutputCredentialMetadataStable(before, after, path unix.Stat_t) bool {
	return before.Ctim == after.Ctim && after.Ctim == path.Ctim
}

func captureLiveOutputCredentialFile(path string, maximum int64) (result *liveOutputCredentialFile, resultErr error) {
	if maximum < 1 || maximum > maximumLiveOutputCredentialSourceBytes || !liveOutputCredentialPath(path) {
		return nil, errLiveOutputCredentialFile
	}
	original, err := os.Lstat(path)
	if err != nil || !original.Mode().IsRegular() || !liveOutputCredentialOwned(original) || original.Size() < 1 || original.Size() > maximum {
		return nil, errLiveOutputCredentialFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLiveOutputCredentialFile
	}
	source := os.NewFile(uintptr(fd), path)
	defer func() {
		if source.Close() != nil {
			resultErr = errors.Join(resultErr, errLiveOutputCredentialFile)
			if result != nil {
				resultErr = errors.Join(resultErr, result.Close())
				result = nil
			}
		}
	}()
	var metadataBefore unix.Stat_t
	if unix.Fstat(fd, &metadataBefore) != nil {
		return nil, errLiveOutputCredentialFile
	}
	before, err := source.Stat()
	if err != nil || !liveOutputCredentialStable(original, before, original) {
		return nil, errLiveOutputCredentialFile
	}
	body, err := io.ReadAll(io.LimitReader(source, maximum+1))
	defer clear(body)
	if err != nil || len(body) < 1 || int64(len(body)) > maximum {
		return nil, errLiveOutputCredentialFile
	}
	var metadataAfter, pathMetadata unix.Stat_t
	if unix.Fstat(fd, &metadataAfter) != nil || unix.Lstat(path, &pathMetadata) != nil || !liveOutputCredentialMetadataStable(metadataBefore, metadataAfter, pathMetadata) {
		return nil, errLiveOutputCredentialFile
	}
	after, err := source.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || int64(len(body)) != before.Size() || !liveOutputCredentialStable(before, after, pathAfter) || !liveOutputCredentialPath(path) {
		return nil, errLiveOutputCredentialFile
	}
	directory, err := os.MkdirTemp("", "enkv-live-output-credential-")
	if err != nil {
		return nil, errLiveOutputCredentialFile
	}
	// The system temporary root can have a symlink spelling on macOS.
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, errors.Join(errLiveOutputCredentialFile, os.Remove(directory))
	}
	snapshot := &liveOutputCredentialFile{Path: filepath.Join(canonical, "credential"), Identity: before}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, snapshot.Close())
		}
	}()
	snapshot.directory, snapshot.directoryIdentity, err = openLiveOutputCredentialDirectory(canonical)
	if err != nil {
		return nil, errors.Join(errLiveOutputCredentialFile, os.Remove(canonical))
	}
	if err := writeLiveOutputCredentialFile(snapshot.Path, body); err != nil {
		return nil, err
	}
	snapshot.snapshotIdentity, err = os.Lstat(snapshot.Path)
	if err != nil {
		return nil, errLiveOutputCredentialFile
	}
	return snapshot, nil
}

func openLiveOutputCredentialDirectory(path string) (*os.File, os.FileInfo, error) {
	if !liveOutputCredentialPath(path) {
		return nil, nil, errLiveOutputCredentialFile
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !liveOutputCredentialOwned(info) {
		return nil, nil, errLiveOutputCredentialFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, errLiveOutputCredentialFile
	}
	directory := os.NewFile(uintptr(fd), path)
	opened, err := directory.Stat()
	if err != nil || !records.SameLocalFile(info, opened) || !opened.IsDir() || opened.Mode().Perm() != 0700 || !liveOutputCredentialOwned(opened) {
		return nil, nil, errors.Join(errLiveOutputCredentialFile, directory.Close())
	}
	return directory, opened, nil
}

func (file *liveOutputCredentialFile) Close() error {
	if file == nil || file.directory == nil {
		return nil
	}
	directory := file.directory
	file.directory = nil
	var result error
	pathInfo, err := os.Lstat(directory.Name())
	if err != nil || !records.SameLocalFile(file.directoryIdentity, pathInfo) {
		result = errLiveOutputCredentialFile
	} else {
		if file.snapshotIdentity != nil {
			fd, err := unix.Openat(int(directory.Fd()), filepath.Base(file.Path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				result = errLiveOutputCredentialFile
			} else {
				current := os.NewFile(uintptr(fd), file.Path)
				info, statErr := current.Stat()
				closeErr := current.Close()
				if statErr != nil || closeErr != nil || !records.SameLocalFile(file.snapshotIdentity, info) {
					result = errLiveOutputCredentialFile
				} else if unix.Unlinkat(int(directory.Fd()), filepath.Base(file.Path), 0) != nil {
					result = errLiveOutputCredentialFile
				}
			}
		}
		if result == nil && os.Remove(directory.Name()) != nil {
			result = errLiveOutputCredentialFile
		}
	}
	return errors.Join(result, directory.Close())
}

// The caller owns this private directory and serializes route creation and
// cleanup. It must join every route user before removing the directory.
func writeLiveOutputCredentialRoute(route liveOutputCredentialRoute, body []byte) (resultErr error) {
	if route.ID.IsZero() || !liveOutputCredentialPath(route.Path) || len(body) < 1 || len(body) > protocol.MaximumCredentialBytes-36 {
		return errLiveOutputCredentialFile
	}
	return writeLiveOutputCredentialFile(route.Path, body)
}

func writeLiveOutputCredentialFile(path string, body []byte) (resultErr error) {
	directory, identity, err := openLiveOutputCredentialDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() {
		if directory.Close() != nil {
			resultErr = errors.Join(resultErr, errLiveOutputCredentialFile)
		}
	}()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errLiveOutputCredentialFile
	}
	file := os.NewFile(uintptr(fd), path)
	var created unix.Stat_t
	identityErr := unix.Fstat(fd, &created)
	defer func() {
		if resultErr != nil {
			var current unix.Stat_t
			if identityErr != nil || unix.Fstatat(int(directory.Fd()), filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW) != nil || created.Ino != current.Ino || unix.Unlinkat(int(directory.Fd()), filepath.Base(path), 0) != nil {
				resultErr = errors.Join(resultErr, errLiveOutputCredentialFile)
			}
		}
	}()
	n, writeErr := file.Write(body)
	syncErr := file.Sync()
	info, statErr := file.Stat()
	closeErr := file.Close()
	parent, parentErr := os.Lstat(directory.Name())
	current, currentErr := os.Lstat(path)
	if identityErr != nil || statErr != nil || currentErr != nil || !liveOutputCredentialStable(info, current, current) || writeErr != nil || n != len(body) || syncErr != nil || closeErr != nil || parentErr != nil || !records.SameLocalFile(identity, parent) || parent.Mode().Perm() != 0700 || !liveOutputCredentialOwned(parent) || !liveOutputCredentialPath(path) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !liveOutputCredentialOwned(info) || info.Size() != int64(len(body)) {
		return errLiveOutputCredentialFile
	}
	return nil
}
