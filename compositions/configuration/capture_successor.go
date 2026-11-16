package configuration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// SuccessorOutputCapture fixes one existing protected output, or its absence,
// before source capture. Parsed target selects the read operation even if a
// later source or argument check fails. It grants no domain authority.
type SuccessorOutputCapture struct {
	path        string
	parent      *pathLocks
	aliasParent string
	format      Format
	directory   os.FileInfo
	pair        *Pair
	model       *Model
	target      ReplacementTarget
	closed      bool
	closeErr    error
}
type SuccessorOutputRefusal struct {
	Target ReplacementTarget
	cause  error
}

func (e *SuccessorOutputRefusal) Error() string { return "successor output refused" }
func (e *SuccessorOutputRefusal) Unwrap() error { return e.cause }

// SuccessorOutputPathValid checks the bounded file-location shape shared by
// command admission, capture and result projection; it performs no filesystem I/O.
func SuccessorOutputPathValid(path string) bool {
	return len(path) <= 4096 && utf8.ValidString(path) && !strings.ContainsRune(path, 0) &&
		filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func CaptureSuccessorOutput(ctx context.Context, path string, encoding Format) (capture *SuccessorOutputCapture, resultErr error) {
	if ctx == nil || !SuccessorOutputPathValid(path) || encoding != JSON && encoding != YAML {
		return nil, ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	aliasParent := strings.Clone(filepath.Dir(path))
	path, err := canonicalDestination(path)
	if err != nil {
		return nil, err
	}
	if err := checkEditableParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	// Reuse the shared native directory and alias checks without opening locks.
	// Existing-output observation remains read-only.
	parent := &pathLocks{directories: make(map[string]os.FileInfo), aliases: make(map[string]os.FileInfo)}
	if err := parent.pinDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := parent.pinAlias(aliasParent, filepath.Dir(path)); err != nil {
		return nil, err
	}
	c := &SuccessorOutputCapture{path: path, format: encoding, directory: parent.directories[filepath.Dir(path)], parent: parent, aliasParent: aliasParent}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := c.checkDirectory(); err != nil {
			return nil, err
		}
		return c, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrEdit, err)
	}
	pair, err := Capture(ctx, path, encoding)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			resultErr = errors.Join(resultErr, pair.Close())
		}
	}()
	model, err := Parse(ctx, pair)
	if err != nil {
		return nil, err
	}
	if !model.Resolved || model.Replacement == nil {
		return nil, ErrEdit
	}
	c.pair, c.model, c.target = pair, model, model.Replacement.Request.Target
	if err := c.CheckUnchanged(ctx); err != nil {
		return nil, &SuccessorOutputRefusal{Target: c.target, cause: err}
	}
	complete = true
	return c, nil
}
func (c *SuccessorOutputCapture) Target() (ReplacementTarget, bool) {
	if c == nil {
		return "", false
	}
	switch c.target {
	case ReplaceAuthority, ReplaceRecovery, ReplaceRecipient:
		return c.target, true
	}
	return "", false
}
func (c *SuccessorOutputCapture) CheckUnchanged(ctx context.Context) error {
	if c == nil || c.closed || ctx == nil {
		return ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrEdit, err)
	}
	if err := c.checkDirectory(); err != nil {
		return err
	}
	if c.pair != nil {
		if err := c.pair.CheckUnchanged(ctx); err != nil {
			return err
		}
	} else if _, err := os.Lstat(c.path); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrEdit, err)
	}
	return c.checkDirectory()
}
func (c *SuccessorOutputCapture) checkDirectory() error {
	if c == nil || c.closed || c.parent == nil {
		return ErrEdit
	}
	return c.parent.check(false)
}

func (c *SuccessorOutputCapture) Close() error {
	if c == nil {
		return nil
	}
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	if c.pair != nil {
		c.closeErr = c.pair.Close()
	}
	c.closeErr = errors.Join(c.closeErr, c.parent.close())
	c.pair, c.model = nil, nil
	return c.closeErr
}
