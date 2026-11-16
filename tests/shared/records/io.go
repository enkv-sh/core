package records

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const MaximumJSONBytes = 32 << 20

var (
	errRecord    = errors.New("local record refused")
	runIDPattern = regexp.MustCompile(`^(?:[a-f0-9]{32}|[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9_-]{1,32}|legacy-baseline)$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,95}$`)
)

// SameLocalFile compares native observations under a trusted local path. Mount numbers
// can change across boots; path, owner, mode and content checks remain separate.
func SameLocalFile(first, second os.FileInfo) bool {
	if first == nil || second == nil {
		return false
	}
	a, aok := first.Sys().(*syscall.Stat_t)
	b, bok := second.Sys().(*syscall.Stat_t)
	return aok && bok && a.Ino != 0 && a.Ino == b.Ino && a.Uid == b.Uid && first.Mode().Type() == second.Mode().Type()
}

func ValidRunID(id string) bool { return runIDPattern.MatchString(id) }

// SafePath checks each existing component before a caller reads or creates it.
// The root must already use its canonical spelling, without symlink aliases.
func SafePath(root, relative string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.Contains(relative, `\`) {
		return "", errRecord
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == ".." {
			return "", errRecord
		}
	}
	path := filepath.Join(root, relative)
	if err := safeAbsolute(path); err != nil {
		return "", err
	}
	return path, nil
}

func safeAbsolute(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errRecord
	}
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator))
	for index, component := range parts {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (index < len(parts)-1 && !info.IsDir()) {
			return errRecord
		}
	}
	return nil
}

func ReadJSON(path string, value any) error {
	return ReadJSONLimit(path, value, MaximumJSONBytes)
}

// ReadJSONLimit applies a caller's smaller bound to the opened file and stream.
func ReadJSONLimit(path string, value any, limit int64) error {
	body, err := ReadJSONBytes(path, limit)
	if err != nil {
		return err
	}
	return decodeJSON(body, value)
}

// ReadJSONBytes preserves the exact bounded bytes for a caller that hashes its
// decoded record. It uses the same path and opened-file checks as ReadJSONLimit.
func ReadJSONBytes(path string, limit int64) (body []byte, err error) {
	if limit <= 0 || limit > MaximumJSONBytes || safeAbsolute(path) != nil {
		return nil, errRecord
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, errRecord
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errRecord
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			body = nil
			err = errors.Join(err, errRecord, closeErr)
		}
	}()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() > limit || !SameLocalFile(before, after) {
		return nil, errRecord
	}
	body, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errRecord
	}
	return body, nil
}

func decodeJSON(body []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errRecord
	}
	return nil
}

// WriteJSON replaces one private record after its bytes reach the local file.
// Its directory must exist; callers own creation of their private layout.
func WriteJSON(path string, value any, mode os.FileMode) (err error) {
	if mode != 0o400 && mode != 0o600 || safeAbsolute(path) != nil {
		return errRecord
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() || err != nil && !errors.Is(err, os.ErrNotExist) {
		return errRecord
	}
	body, err := json.Marshal(value)
	if err != nil || len(body)+1 > MaximumJSONBytes {
		return errRecord
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".record-*")
	if err != nil {
		return errRecord
	}
	defer func() { err = removeTemporaryRecord(file.Name(), err) }()
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(append(body, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || safeAbsolute(path) != nil || os.Rename(file.Name(), path) != nil {
		return errRecord
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errRecord
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil || closeErr != nil {
		return errRecord
	}
	return nil
}

// WriteJSONExclusive publishes one complete, synced private record without
// replacing an existing name. A failed first assertion cannot be retried by a
// later assertion with a different cause.
func WriteJSONExclusive(path string, value any, limit int64) (err error) {
	if limit <= 0 || limit > MaximumJSONBytes || safeAbsolute(path) != nil {
		return errRecord
	}
	body, err := json.Marshal(value)
	if err != nil || int64(len(body)+1) > limit {
		return errRecord
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 {
		return errRecord
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".failure-*")
	if err != nil {
		return errRecord
	}
	defer func() { err = removeTemporaryRecord(file.Name(), err) }()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(append(body, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || safeAbsolute(path) != nil || os.Link(file.Name(), path) != nil {
		return errRecord
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errRecord
	}
	err = parent.Sync()
	closeErr = parent.Close()
	if err != nil || closeErr != nil {
		return errRecord
	}
	return nil
}

func removeTemporaryRecord(path string, err error) error {
	removeErr := os.Remove(path)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		return err
	}
	return errors.Join(err, removeErr)
}

func directory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}
