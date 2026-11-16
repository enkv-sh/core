package configuration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// ErrSourceChanged identifies a positively observed difference from captured
// source bytes or native identity. Unavailable inspection alone does not carry it.
var ErrSourceChanged = errors.New("captured configuration source changed")

// CheckUnchanged checks the original files against this captured pair. The
// caller must keep the pair open and unchanged until this call returns.
// Unrelated generated members may be added without replacing the directory.
func (p *Pair) CheckUnchanged(ctx context.Context) (resultErr error) {
	if ctx == nil {
		return ErrCapture
	}
	if err := p.validateCaptured(); err != nil {
		return err
	}
	if p.ownedLocks != nil {
		return p.checkWithLocks(ctx, p.ownedLocks)
	}
	paths := p.sourcePaths()
	locks, err := openPathLocks(paths, true, false)
	if err != nil {
		return p.sourceCheckFailure(ctx, err)
	}
	defer func() { resultErr = errors.Join(resultErr, locks.close()) }()
	if p.aliasParent != "" {
		if err := locks.pinAlias(p.aliasParent, filepath.Dir(p.Editable.path)); err != nil {
			return p.sourceCheckFailure(ctx, err)
		}
	}
	return p.checkWithLocks(ctx, locks)
}

func (p *Pair) sourcePaths() []string {
	paths := []string{p.Editable.path}
	if p.Generated != nil {
		paths = append(paths, p.Generated.path)
	}
	return paths
}

func (p *Pair) checkWithLocks(ctx context.Context, locks *pathLocks) error {
	if ctx == nil {
		return ErrCapture
	}
	if err := p.validateCaptured(); err != nil {
		return err
	}
	if err := locks.check(false); err != nil {
		return p.sourceCheckFailure(ctx, err)
	}
	if err := refusePending(p.sourcePaths()); err != nil {
		return p.sourceCheckFailure(ctx, err)
	}
	if err := p.checkExact(ctx); err != nil {
		return err
	}
	if err := refusePending(p.sourcePaths()); err != nil {
		return p.sourceCheckFailure(ctx, err)
	}
	if err := locks.check(true); err != nil {
		return p.sourceCheckFailure(ctx, err)
	}
	return nil
}

func (p *Pair) sourceCheckFailure(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() == nil && !errors.Is(err, ErrPendingEdit) && !errors.Is(err, ErrEditLocked) && !errors.Is(err, ErrSourceChanged) {
		if observed := p.checkCapturedDirectories(); errors.Is(observed, ErrSourceChanged) {
			err = errors.Join(err, observed)
		}
	}
	return captureCause(err)
}

func captureCauseIf(err error) error {
	if err == nil {
		return nil
	}
	return captureCause(err)
}

func (p *Pair) checkExact(ctx context.Context) error {
	if ctx == nil {
		return ErrCapture
	}
	if err := p.validateCaptured(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return captureCause(err)
	}
	if err := p.checkCapturedDirectories(); err != nil {
		return err
	}
	for _, image := range []*Image{p.Editable, p.Generated} {
		if image != nil {
			if err := compareEditImage(ctx, image.path, image, true); err != nil {
				return captureCause(err)
			}
		}
	}
	if err := p.checkGeneratedDirectory(); err != nil {
		return err
	}
	return captureCauseIf(ctx.Err())
}

func (p *Pair) checkCapturedDirectories() error {
	if p.aliasParent != "" {
		if p.aliasDirectory == nil {
			return ErrCapture
		}
		current, err := os.Stat(p.aliasParent)
		if err != nil {
			return sourceInspectionFailure(err)
		}
		if !current.IsDir() || !os.SameFile(p.aliasDirectory, current) {
			return captureCause(ErrSourceChanged)
		}
	}
	if err := p.checkGeneratedDirectory(); err != nil {
		return err
	}
	if p.sourceDirectory != nil {
		current, err := os.Lstat(filepath.Dir(p.Editable.path))
		if err != nil {
			return sourceInspectionFailure(err)
		}
		if !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(p.sourceDirectory, current) || p.sourceDirectory.Mode() != current.Mode() || !sameNativeOwner(p.sourceDirectory, current) {
			return captureCause(ErrSourceChanged)
		}
	}
	return nil
}

func sourceInspectionFailure(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		err = errors.Join(ErrSourceChanged, err)
	}
	return captureCause(err)
}

func (p *Pair) checkGeneratedDirectory() error {
	if p.Generated == nil {
		return nil
	}
	original := p.generatedDirectory
	if original == nil {
		return ErrCapture
	}
	current, err := os.Lstat(filepath.Dir(p.Generated.path))
	if err != nil {
		return sourceInspectionFailure(err)
	}
	if !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(original, current) || original.Mode() != current.Mode() || !sameNativeOwner(original, current) {
		return captureCause(ErrSourceChanged)
	}
	return nil
}
