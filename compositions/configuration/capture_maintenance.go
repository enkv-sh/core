package configuration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// MaintenanceOutputCapture fixes one existing protected output, or its absence,
// before source capture. Parsed target selects the read operation even if a
// later source or argument check fails. It grants no domain authority.
type MaintenanceOutputCapture struct {
	path        string
	parent      *pathLocks
	aliasParent string
	format      Format
	directory   os.FileInfo
	pair        *Pair
	model       *Model
	request     MaintenanceRequest
	closed      bool
	closeErr    error
}
type MaintenanceOutputRefusal struct {
	Request MaintenanceRequest
	cause   error
}

func (e *MaintenanceOutputRefusal) Error() string { return "maintenance output refused" }
func (e *MaintenanceOutputRefusal) Unwrap() error { return e.cause }

func CaptureMaintenanceOutput(ctx context.Context, path string, encoding Format) (capture *MaintenanceOutputCapture, resultErr error) {
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
	c := &MaintenanceOutputCapture{path: path, format: encoding, directory: parent.directories[filepath.Dir(path)], parent: parent, aliasParent: aliasParent}
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
	if !model.Resolved || model.Maintenance == nil {
		return nil, ErrEdit
	}
	c.pair, c.model, c.request = pair, model, model.Maintenance.Request
	if err := c.CheckUnchanged(ctx); err != nil {
		return nil, &MaintenanceOutputRefusal{Request: c.request, cause: err}
	}
	complete = true
	return c, nil
}
func (c *MaintenanceOutputCapture) Request() (MaintenanceRequest, bool) {
	if c == nil || !c.request.valid() {
		return MaintenanceRequest{}, false
	}
	return c.request, true
}
func (c *MaintenanceOutputCapture) CheckUnchanged(ctx context.Context) error {
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
func (c *MaintenanceOutputCapture) checkDirectory() error {
	if c == nil || c.closed || c.parent == nil {
		return ErrEdit
	}
	return c.parent.check(false)
}

func (c *MaintenanceOutputCapture) Close() error {
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
