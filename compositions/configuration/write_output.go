package configuration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// OccupiedEditTarget is a destination observed present when native delivery
// requires absence. It contains no path or authority to replace that image.
type OccupiedEditTarget struct{ Generated bool }

func (e *OccupiedEditTarget) Error() string { return "configuration edit target occupied" }
func (e *OccupiedEditTarget) Unwrap() error { return ErrEdit }

func checkEditDestinationAbsent(path string, generated bool) error {
	if _, err := inspectEditDirectory(filepath.Dir(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrEdit, err)
	}
	return &OccupiedEditTarget{Generated: generated}
}

// beginPairOutput admits an absent pair while holding the exact source and
// output namespaces. The source remains borrowed by the caller.
func beginPairOutput(ctx context.Context, source *Pair, path string, format Format, name string) (*EditSession, error) {
	if ctx == nil || source.validateCaptured() != nil || format != source.Format || !localPathValid(path) {
		return nil, ErrEdit
	}
	originalParent := filepath.Dir(path)
	path, err := canonicalDestination(path)
	if err != nil {
		return nil, err
	}
	if err := checkEditableParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	model, err := parseEditableMode(ctx, source.Editable, source.Format, true, nil)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = model.DomainName
	}
	if !domainNameValid(name) {
		return nil, ErrEdit
	}
	temporary, valid := temporaryDirectory()
	if !valid {
		return nil, ErrEditBounds
	}
	if err := preflightEditDisk([]string{filepath.Dir(path), temporary}, nativeEditIO()); err != nil {
		return nil, err
	}
	directory := filepath.Join(filepath.Dir(path), ".enkv")
	if err := ensureEditDirectory(directory, syncEditDirectory); err != nil {
		return nil, err
	}
	if err := preflightEditDisk([]string{filepath.Dir(path), directory, temporary}, nativeEditIO()); err != nil {
		return nil, err
	}
	reference := generatedPath(name)
	generated := filepath.Join(filepath.Dir(path), reference)
	paths := source.sourcePaths()
	for index, destination := range []string{path, generated} {
		for _, original := range paths {
			if destination == original {
				return nil, ErrEdit
			}
		}
		if err := checkEditDestinationAbsent(destination, index == 1); err != nil {
			return nil, err
		}
	}
	paths = append(paths, path, generated)
	locks, err := openPathLocks(paths, false, true)
	if err != nil {
		return nil, err
	}
	if err := locks.pinAlias(originalParent, filepath.Dir(path)); err != nil {
		return nil, errors.Join(err, locks.close())
	}
	if source.aliasParent != "" {
		if err := locks.pinAlias(source.aliasParent, filepath.Dir(source.Editable.path)); err != nil {
			return nil, errors.Join(err, locks.close())
		}
	}
	session := &EditSession{path: path, temporaryDirectory: temporary, format: format, predecessor: source, reference: reference, sourceName: model.DomainName, targetName: name, locks: locks, borrowed: true, io: nativeEditIO()}
	if err := session.prepareDirectories(); err != nil {
		return nil, errors.Join(err, session.Close())
	}
	if err := session.CheckUnchanged(ctx); err != nil {
		return nil, errors.Join(err, locks.close())
	}
	return session, nil
}

// CheckUnchanged checks a session's borrowed source and admitted destinations
// through its existing exclusive lock owner.
func (s *EditSession) CheckUnchanged(ctx context.Context) error {
	if s == nil || s.closed || s.locks == nil || ctx == nil {
		return ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrEdit, err)
	}
	if s.predecessor != nil {
		if err := s.predecessor.checkWithLocks(ctx, s.locks); err != nil {
			return err
		}
	}
	if s.borrowed || s.predecessor == nil {
		for index, path := range []string{s.path, filepath.Join(filepath.Dir(s.path), s.reference)} {
			if err := checkEditDestinationAbsent(path, index == 1); err != nil {
				return err
			}
		}
	}
	if err := refusePending(s.lockPaths()); err != nil {
		return err
	}
	return s.locks.check(false)
}

func (s *EditSession) lockPaths() []string {
	paths := make([]string, 0, 4)
	for _, lock := range s.locks.locks {
		paths = append(paths, lock.path)
	}
	return paths
}

func (s *EditSession) captureDelivery(ctx context.Context, delivery *PairDelivery) (*Pair, *Model, error) {
	return s.captureDeliveryMode(ctx, delivery, false)
}

func (s *EditSession) captureDeliveryMode(ctx context.Context, delivery *PairDelivery, preparation bool) (*Pair, *Model, error) {
	if s == nil || s.closed || delivery == nil || delivery.cleanupFailed || s.transaction == nil {
		return nil, nil, ErrEdit
	}
	pair, _, err := capturePairOwned(ctx, s.path, s.format, s.locks, s.temporaryDirectory)
	if err != nil {
		return nil, nil, err
	}
	pair.ownedLocks = s.locks
	if err := sealPair(pair); err != nil {
		return nil, nil, errors.Join(err, pair.Close())
	}
	if pair.Editable.path != delivery.editable || pair.Editable.digest != delivery.editableDigest || pair.Generated == nil && delivery.generated != "" || pair.Generated != nil && (pair.Generated.path != delivery.generated || pair.Generated.digest != delivery.generatedDigest) {
		return nil, nil, errors.Join(ErrEdit, pair.Close())
	}
	for index, image := range []*Image{pair.Editable, pair.Generated} {
		if image == nil {
			continue
		}
		native, err := nativeFact(image.sourceInfo)
		matched := false
		for _, row := range s.transaction.Description.Paths {
			if row.Candidate != index || row.Path != image.path {
				continue
			}
			digest, decodeErr := decodeDigest(row.New.Digest)
			matched = err == nil && decodeErr == nil && row.New.Present && row.New.Native == native && row.New.Length == uint64(image.size) && digest == image.digest
		}
		if !matched {
			return nil, nil, errors.Join(ErrEdit, pair.Close())
		}
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		return nil, nil, errors.Join(err, pair.Close())
	}
	model, err := parseSource(ctx, pair, nil, preparation)
	if err != nil {
		return nil, nil, errors.Join(err, pair.Close())
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		releaseReconstructionModel(model)
		return nil, nil, errors.Join(err, pair.Close())
	}
	return pair, model, nil
}
