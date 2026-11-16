package plugininstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func directory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	return nil
}

func configurationDirectory(path string) (string, error) {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) {
		return "", ErrInvalid
	}
	parts := strings.FieldsFunc(path, func(character rune) bool { return character == filepath.Separator })
	path = string(filepath.Separator) + strings.Join(parts, string(filepath.Separator))
	var missing []string
	for {
		canonical, err := canonicalDirectory(path)
		if err == nil {
			if err := directory(canonical); err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				canonical = filepath.Join(canonical, missing[index])
			}
			if len(canonical) > 4096 {
				return "", ErrInvalid
			}
			if err := ensureDirectory(canonical); err != nil {
				return "", err
			}
			return canonical, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", err
		}
		missing = append(missing, filepath.Base(path))
		path = parent
	}
}

func ensureDirectory(path string) error {
	parent := filepath.Dir(path)
	if parent != path {
		if err := ensureDirectory(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return directory(path)
}

func readFile(ctx context.Context, path string, limit int64) (body []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			body = nil
		}
	}()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.Join(ErrInvalid, err)
	}
	body, err = io.ReadAll(io.LimitReader(ctxReader{ctx, file}, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || int64(len(body)) != info.Size() || int64(len(body)) > limit {
		return nil, errors.Join(ErrInvalid, err)
	}
	return body, nil
}

type ctxReader struct {
	context.Context
	io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func missing(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrMissing, err)
	}
	return err
}

type heldMember struct {
	name string
	file *os.File
}
type stage struct {
	parent     *os.Root
	root       *os.Root
	dir        *os.File
	name, path string
	members    []heldMember
	published  bool
}

func makeStage(parent string) (*stage, error) {
	if err := ensureDirectory(parent); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	name := ".stage-" + hex.EncodeToString(nonce[:])
	if err := root.Mkdir(name, 0700); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, errors.Join(err, root.Remove(name), root.Close())
	}
	dir, err := child.Open(".")
	if err != nil {
		return nil, errors.Join(err, child.Close(), root.Remove(name), root.Close())
	}
	return &stage{parent: root, root: child, dir: dir, name: name, path: filepath.Join(parent, name)}, nil
}

func sameMember(root *os.Root, name string, file *os.File) error {
	before, err := file.Stat()
	if err != nil {
		return err
	}
	after, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return ErrIdentity
	}
	return nil
}

func (s *stage) check() error {
	held, err := s.dir.Stat()
	if err != nil {
		return err
	}
	current, err := s.parent.Lstat(s.name)
	if err != nil {
		return err
	}
	if !current.IsDir() || !os.SameFile(held, current) {
		return ErrIdentity
	}
	return nil
}

func (s *stage) write(ctx context.Context, name string, reader io.Reader, length int64, mode os.FileMode) error {
	if err := s.check(); err != nil {
		return err
	}
	f, err := s.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	s.members = append(s.members, heldMember{name, f})
	n, err := io.Copy(f, io.LimitReader(ctxReader{ctx, reader}, length+1))
	if err != nil {
		return err
	}
	if n != length {
		return ErrIdentity
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return sameMember(s.root, name, f)
}

func (s *stage) writeBytes(ctx context.Context, name string, body []byte) error {
	return s.write(ctx, name, bytes.NewReader(body), int64(len(body)), 0400)
}

func (s *stage) adopt(name string, identity os.FileInfo) error {
	if err := s.check(); err != nil {
		return err
	}
	file, err := s.root.Open(name)
	if err != nil {
		return err
	}
	held, statErr := file.Stat()
	if statErr != nil || !os.SameFile(identity, held) {
		return errors.Join(ErrIdentity, statErr, file.Close())
	}
	s.members = append(s.members, heldMember{name, file})
	return sameMember(s.root, name, file)
}

func (s *stage) finish() error {
	if s == nil {
		return nil
	}
	var result error
	owned := s.published || s.check() == nil
	for _, member := range s.members {
		if !s.published && owned {
			if err := sameMember(s.root, member.name, member.file); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					result = errors.Join(result, err)
				}
			} else {
				result = errors.Join(result, s.root.Remove(member.name))
			}
		}
		result = errors.Join(result, member.file.Close())
	}
	if !s.published {
		if owned {
			result = errors.Join(result, s.parent.Remove(s.name))
		} else {
			result = errors.Join(result, ErrIdentity)
		}
	}
	return errors.Join(result, s.dir.Close(), s.root.Close(), s.parent.Close())
}

func publishStage(ctx context.Context, s *stage, target string, verify func(string) error) (err error) {
	unlock, err := lock(ctx, filepath.Join(filepath.Dir(s.path), ".publish.lock"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := s.check(); err != nil {
		return err
	}
	if _, statErr := s.parent.Lstat(target); statErr == nil {
		if err := verify(filepath.Join(filepath.Dir(s.path), target)); err != nil {
			if !errors.Is(err, ErrMissing) {
				return err
			}
			if err := restoreMissing(ctx, s, target); err != nil {
				return err
			}
			return verify(filepath.Join(filepath.Dir(s.path), target))
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := verify(s.path); err != nil {
		return err
	}
	if err := errors.Join(ctx.Err(), s.dir.Sync(), s.check()); err != nil {
		return err
	}
	if err := s.parent.Rename(s.name, target); err != nil {
		return err
	}
	s.published = true
	parent, err := s.parent.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

func restoreMissing(ctx context.Context, s *stage, target string) (result error) {
	root, err := s.parent.OpenRoot(target)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	heldDirectory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, heldDirectory.Close()) }()
	checkDirectory := func() error {
		held, err := heldDirectory.Stat()
		if err != nil {
			return err
		}
		current, err := s.parent.Lstat(target)
		if err != nil {
			return err
		}
		if !current.IsDir() || !os.SameFile(held, current) {
			return ErrIdentity
		}
		return nil
	}
	if err := checkDirectory(); err != nil {
		return err
	}
	names, readErr := heldDirectory.ReadDir(len(s.members) + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if len(names) > len(s.members) {
		return ErrIdentity
	}
	allowed := map[string]*os.File{}
	for _, m := range s.members {
		allowed[m.name] = m.file
	}
	for _, entry := range names {
		expected, ok := allowed[entry.Name()]
		if !ok {
			return ErrIdentity
		}
		actual, err := root.Open(entry.Name())
		if err != nil {
			return err
		}
		info, statErr := root.Lstat(entry.Name())
		held, heldErr := actual.Stat()
		if statErr != nil || heldErr != nil || !info.Mode().IsRegular() || !os.SameFile(info, held) {
			return errors.Join(ErrIdentity, statErr, heldErr, actual.Close())
		}
		wanted, err := expected.Stat()
		if err != nil {
			return errors.Join(err, actual.Close())
		}
		if info.Size() != wanted.Size() || info.Mode().Perm() != wanted.Mode().Perm() {
			return errors.Join(ErrIdentity, actual.Close())
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(ctxReader{ctx, actual}, wanted.Size()+1))
		identityErr := sameMember(root, entry.Name(), actual)
		closeErr := actual.Close()
		if copyErr != nil || closeErr != nil || identityErr != nil {
			return errors.Join(copyErr, closeErr, identityErr)
		}
		if n != wanted.Size() {
			return ErrIdentity
		}
		want := sha256.New()
		if _, err := io.Copy(want, ctxReader{ctx, io.NewSectionReader(expected, 0, wanted.Size())}); err != nil {
			return err
		}
		if !bytes.Equal(h.Sum(nil), want.Sum(nil)) {
			return ErrIdentity
		}
		delete(allowed, entry.Name())
	}
	for name, file := range allowed {
		if err := sameMember(s.root, name, file); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := checkDirectory(); err != nil {
			return err
		}
		if err := copyMissingMember(ctx, root, name, file); err != nil {
			return err
		}
	}
	return errors.Join(checkDirectory(), heldDirectory.Sync())
}

func copyMissingMember(ctx context.Context, root *os.Root, name string, source *os.File) (err error) {
	info, err := source.Stat()
	if err != nil {
		return err
	}
	file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if identityErr := sameMember(root, name, file); identityErr != nil {
				err = errors.Join(err, identityErr)
			} else {
				err = errors.Join(err, root.Remove(name))
			}
		}
		err = errors.Join(err, file.Close())
	}()
	n, err := io.Copy(file, ctxReader{ctx, io.NewSectionReader(source, 0, info.Size())})
	if err != nil {
		return err
	}
	if n != info.Size() {
		return ErrIdentity
	}
	return errors.Join(file.Sync(), sameMember(root, name, file))
}

func atomicRecord(ctx context.Context, path string, body []byte, beforeReplace func() error) (published bool, err error) {
	parent := filepath.Dir(path)
	s, err := makeStage(parent)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, s.finish()) }()
	if err := s.writeBytes(ctx, "record", body); err != nil {
		return false, err
	}
	if err := errors.Join(ctx.Err(), s.check()); err != nil {
		return false, err
	}
	if beforeReplace != nil {
		if err := beforeReplace(); err != nil {
			return false, err
		}
	}
	if err := errors.Join(ctx.Err(), s.check(), sameMember(s.root, "record", s.members[0].file)); err != nil {
		return false, err
	}
	staged, err := io.ReadAll(ctxReader{ctx, io.NewSectionReader(s.members[0].file, 0, int64(len(body))+1)})
	if err != nil || !bytes.Equal(staged, body) {
		return false, errors.Join(ErrIdentity, err)
	}
	if err := errors.Join(ctx.Err(), s.check(), sameMember(s.root, "record", s.members[0].file)); err != nil {
		return false, err
	}
	// The caller holds the record's OS lock and has performed its final source
	// and predecessor checks. Move the staged file, never the predecessor inode.
	if err := s.parent.Rename(filepath.Join(s.name, "record"), filepath.Base(path)); err != nil {
		return false, err
	}
	published = true
	members := s.members
	s.members = nil
	for _, m := range members {
		err = errors.Join(err, m.file.Close())
	}
	parentFile, openErr := s.parent.Open(".")
	if openErr != nil {
		return true, errors.Join(err, openErr)
	}
	return true, errors.Join(err, parentFile.Sync(), parentFile.Close())
}

func plainPath(path string) error {
	for part := filepath.Clean(path); ; part = filepath.Dir(part) {
		if err := directory(part); err != nil {
			return err
		}
		if filepath.Dir(part) == part {
			return nil
		}
	}
}

func safeRelative(s string) bool {
	return s != "" && !filepath.IsAbs(s) && filepath.Clean(s) == s && s != ".." && !strings.HasPrefix(s, ".."+string(filepath.Separator))
}
