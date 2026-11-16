package configuration

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

type nativeIdentity struct{ device, inode uint64 }
type pathLock struct {
	path, name string
	file       *os.File
	identity   nativeIdentity
}
type pathLocks struct {
	locks       []pathLock
	absent      []string
	directories map[string]os.FileInfo
	aliases     map[string]os.FileInfo
	closed      bool
}

func localPathValid(path string) bool {
	return len(path) <= 4096 && utf8.ValidString(path) && !strings.ContainsRune(path, 0) && filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) != string(filepath.Separator)
}

func canonicalDestination(path string) (string, error) {
	if !localPathValid(path) {
		return "", errors.Join(ErrEdit, ErrSourceInvalid)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", errors.Join(ErrEdit, err)
	}
	canonical := filepath.Join(parent, filepath.Base(path))
	if !localPathValid(canonical) {
		return "", errors.Join(ErrEditBounds, ErrSourceInvalid)
	}
	return canonical, nil
}

func coordinationPath(path, directory string) string {
	return filepath.Join(filepath.Dir(path), directory, filepath.Base(path))
}

func openPathLocks(paths []string, shared, create bool) (set *pathLocks, resultErr error) {
	if len(paths) == 0 || len(paths) > 4 || shared && create {
		return nil, ErrEdit
	}
	set = &pathLocks{directories: make(map[string]os.FileInfo), aliases: make(map[string]os.FileInfo)}
	complete := false
	defer func(owner *pathLocks) {
		if !complete {
			resultErr = errors.Join(resultErr, owner.close())
			set = nil
		}
	}(set)
	seenPaths := make(map[string]bool)
	for _, path := range paths {
		if !localPathValid(path) {
			return nil, ErrEdit
		}
		if seenPaths[path] {
			continue
		}
		seenPaths[path] = true
		parent := filepath.Dir(path)
		if err := set.pinDirectory(parent); err != nil {
			return nil, err
		}
		lockDirectory := filepath.Join(parent, ".enkv-locks")
		if create {
			if err := ensureEditDirectory(lockDirectory, syncEditDirectory); err != nil {
				return nil, err
			}
		}
		if err := set.pinDirectory(lockDirectory); err != nil {
			if !create && errors.Is(err, os.ErrNotExist) {
				set.absent = append(set.absent, coordinationPath(path, ".enkv-locks"))
				continue
			}
			return nil, err
		}
		name := coordinationPath(path, ".enkv-locks")
		existing, inspectErr := os.Lstat(name)
		if inspectErr == nil {
			if !existing.Mode().IsRegular() || existing.Size() != 0 {
				return nil, errors.Join(ErrEdit, ErrSourceInvalid)
			}
			if _, valid := fileIdentity(existing); !valid {
				return nil, ErrEdit
			}
			if !singleLink(existing) {
				return nil, errors.Join(ErrEdit, ErrSourceInvalid)
			}
		} else if !errors.Is(inspectErr, os.ErrNotExist) {
			return nil, errors.Join(ErrEdit, inspectErr)
		}
		file, err := openNativeLock(name, create)
		if err != nil {
			if !create && errors.Is(err, os.ErrNotExist) {
				set.absent = append(set.absent, name)
				continue
			}
			return nil, err
		}
		info, err := file.Stat()
		identity, valid := fileIdentity(info)
		if err != nil || !valid {
			return nil, errors.Join(ErrEdit, err, file.Close())
		}
		if !info.Mode().IsRegular() || !singleLink(info) || info.Size() != 0 {
			return nil, errors.Join(ErrEdit, ErrSourceInvalid, file.Close())
		}
		set.locks = append(set.locks, pathLock{path: path, name: name, file: file, identity: identity})
	}
	sort.Slice(set.locks, func(i, j int) bool {
		a, b := set.locks[i].identity, set.locks[j].identity
		return a.device < b.device || a.device == b.device && a.inode < b.inode
	})
	var previous *nativeIdentity
	for i := range set.locks {
		lock := &set.locks[i]
		if previous != nil && *previous == lock.identity {
			// Native aliases must share one descriptor and one flock owner.
			if err := lock.file.Close(); err != nil {
				return nil, errors.Join(ErrEdit, err)
			}
			lock.file = nil
			continue
		}
		if err := lockNativeFile(lock.file, shared); err != nil {
			return nil, err
		}
		previous = &lock.identity
	}
	if err := set.check(false); err != nil {
		return nil, err
	}
	complete = true
	return set, nil
}

func inspectEditDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrEdit, ErrSourceInvalid)
	}
	return info, nil
}

func (set *pathLocks) pinDirectory(path string) error {
	info, err := inspectEditDirectory(path)
	if err != nil {
		return err
	}
	if old := set.directories[path]; old != nil && !os.SameFile(old, info) {
		return ErrEdit
	}
	set.directories[path] = info
	return nil
}

func (set *pathLocks) check(finalAbsence bool) error {
	if set == nil || set.closed {
		return ErrEdit
	}
	for alias, old := range set.aliases {
		current, err := os.Stat(alias)
		if err != nil || !current.IsDir() || !os.SameFile(old, current) {
			return errors.Join(ErrEdit, err)
		}
	}
	for path, old := range set.directories {
		current, err := os.Lstat(path)
		if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(old, current) || old.Mode() != current.Mode() || !sameNativeOwner(old, current) {
			return errors.Join(ErrEdit, err)
		}
	}
	for _, lock := range set.locks {
		info, err := os.Lstat(lock.name)
		identity, ok := fileIdentity(info)
		if err != nil || !ok || identity != lock.identity || !info.Mode().IsRegular() || !singleLink(info) || info.Size() != 0 {
			return errors.Join(ErrEdit, err)
		}
	}
	if finalAbsence {
		for _, path := range set.absent {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.Join(ErrEdit, err)
			}
		}
	}
	return nil
}

func (set *pathLocks) close() error {
	if set == nil || set.closed {
		return nil
	}
	set.closed = true
	var err error
	for i := len(set.locks) - 1; i >= 0; i-- {
		if file := set.locks[i].file; file != nil {
			err = errors.Join(err, releaseEditLock(file))
		}
	}
	return err
}

func refusePending(paths []string) error {
	for _, path := range paths {
		if _, err := inspectEditDirectory(filepath.Dir(path)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return errors.Join(ErrCapture, err)
		}
		directory := filepath.Join(filepath.Dir(path), ".enkv-pending")
		_, err := inspectEditDirectory(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return errors.Join(ErrCapture, err)
		}
		if _, err := os.Lstat(coordinationPath(path, ".enkv-pending")); err == nil {
			return errors.Join(ErrCapture, ErrPendingEdit)
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrCapture, err)
		}
	}
	return nil
}

func (set *pathLocks) pinAlias(alias, canonical string) error {
	info, err := os.Stat(alias)
	original := set.directories[canonical]
	if err != nil || original == nil || !info.IsDir() || !os.SameFile(info, original) {
		return errors.Join(ErrEdit, err)
	}
	set.aliases[alias] = info
	return nil
}

func localDirectoryPathValid(path string) bool {
	return path == string(filepath.Separator) || localPathValid(path)
}
func temporaryDirectory() (string, bool) {
	directory := os.TempDir()
	if len(directory) > 4096 {
		return "", false
	}
	directory = strings.TrimRight(directory, string(filepath.Separator))
	if directory == "" {
		directory = string(filepath.Separator)
	}
	return directory, localDirectoryPathValid(directory) && len(directory)+64 <= 4096
}
