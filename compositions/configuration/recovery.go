package configuration

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"

	"enkv.sh/telemetry"
)

func openMetadata(path string, limit int64) (*os.File, error) {
	if !localPathValid(path) {
		return nil, ErrEdit
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrEdit, err)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || !singleLink(before) || before.Size() < 0 || before.Size() > limit {
		return nil, errors.Join(ErrEdit, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, editError(err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !sameMetadata(before, opened) {
		return nil, errors.Join(ErrEdit, err, file.Close())
	}
	return file, nil
}

func readMarker(ctx context.Context, path string) (marker pendingMarker, resultErr error) {
	file, err := openMetadata(path, maxMarkerBytes)
	if err != nil {
		return marker, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	p := newParser(ctx, io.LimitReader(file, maxMarkerBytes+1), JSON)
	mask := 0
	p.object(2, func(key string) {
		switch key {
		case "record":
			mask |= 1
			marker.Record = p.text(4096, false, false)
		case "digest":
			mask |= 2
			marker.Digest = p.text(64, false, false)
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 3)
	if err := p.done(); err != nil {
		return marker, editError(err)
	}
	if !localPathValid(marker.Record) || filepath.Base(filepath.Dir(marker.Record)) != ".enkv-transactions" || filepath.Base(marker.Record) != marker.Digest+".json" {
		return marker, ErrEdit
	}
	if _, err := decodeDigest(marker.Digest); err != nil {
		return marker, err
	}
	return marker, nil
}

func readRecord(ctx context.Context, path string) (record *pendingRecord, resultErr error) {
	file, err := openMetadata(path, maxPendingBytes)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	p := newParser(ctx, io.LimitReader(file, maxPendingBytes+1), JSON)
	record = &pendingRecord{}
	mask := 0
	p.object(4, func(key string) {
		switch key {
		case "schema":
			mask |= 1
			record.Schema = p.text(32, false, false)
		case "description":
			mask |= 2
			record.Description = parseTransactionDescription(p)
		case "digest":
			mask |= 4
			record.Digest = p.text(64, false, false)
		case "phase":
			mask |= 8
			record.Phase = p.text(16, false, false)
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 15)
	if err := p.done(); err != nil {
		return nil, editError(err)
	}
	return record, nil
}

func parseTransactionDescription(p *parser) transactionDescription {
	description := transactionDescription{Paths: make([]transactionPath, 0, 4), Images: make([]savedImage, 0, 2)}
	mask := 0
	p.object(9, func(key string) {
		switch key {
		case "format":
			mask |= 1
			value := p.integer()
			if value != uint64(JSON) && value != uint64(YAML) {
				p.fail("unsupported-format")
			}
			description.Format = Format(value)
		case "file_id":
			mask |= 2
			description.FileID = p.text(64, false, false)
		case "domain_id":
			mask |= 4
			description.DomainID = p.text(64, false, false)
		case "source":
			mask |= 8
			value := p.integer()
			if value > 3 {
				p.fail("invalid-source")
			}
			description.Source = uint8(value)
		case "directory":
			mask |= 16
			description.Directory = parseDiskIdentity(p)
		case "scratch":
			mask |= 128
			description.Scratch = p.text(4096, false, false)
		case "scratch_native":
			mask |= 256
			description.ScratchNative = parseDiskIdentity(p)
		case "paths":
			mask |= 32
			p.array(4, func(_ int) { description.Paths = append(description.Paths, parseTransactionPath(p)) })
		case "images":
			mask |= 64
			p.array(2, func(_ int) {
				image := savedImage{}
				seen := 0
				p.object(3, func(key string) {
					switch key {
					case "path":
						seen |= 1
						image.Path = p.text(4096, false, false)
					case "fact":
						seen |= 2
						image.Fact = parseImageFact(p)
					case "install":
						seen |= 4
						image.Install = parseDiskIdentity(p)
					default:
						p.fail("unknown-field")
					}
				})
				required(p, seen, 7)
				description.Images = append(description.Images, image)
			})
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 511)
	return description
}

func parseTransactionPath(p *parser) transactionPath {
	row := transactionPath{}
	mask := 0
	p.object(8, func(key string) {
		switch key {
		case "path":
			mask |= 1
			row.Path = p.text(4096, false, false)
		case "directory":
			mask |= 2
			row.Directory = parseDiskIdentity(p)
		case "lock":
			mask |= 4
			row.Lock = parseDiskIdentity(p)
		case "pending":
			mask |= 8
			row.Pending = parseDiskIdentity(p)
		case "marker_scratch":
			mask |= 128
			row.MarkerScratch = parseDiskIdentity(p)
		case "old":
			mask |= 16
			row.Old = parseImageFact(p)
		case "new":
			mask |= 32
			row.New = parseImageFact(p)
		case "candidate":
			mask |= 64
			value := p.atom()
			if value != "-1" && value != "0" && value != "1" {
				p.fail("invalid-candidate")
			}
			row.Candidate, _ = strconv.Atoi(value)
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 255)
	return row
}

func parseDiskIdentity(p *parser) diskIdentity {
	identity := diskIdentity{}
	mask := 0
	p.object(2, func(key string) {
		switch key {
		case "device":
			mask |= 1
			identity.Device = p.integer()
		case "inode":
			mask |= 2
			identity.Inode = p.integer()
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 3)
	return identity
}

func parseImageFact(p *parser) imageFact {
	fact := imageFact{}
	mask := 0
	p.object(4, func(key string) {
		switch key {
		case "present":
			mask |= 1
			fact.Present = p.boolean()
		case "length":
			mask |= 2
			fact.Length = p.integer()
		case "digest":
			mask |= 4
			fact.Digest = p.text(64, false, false)
		case "native":
			mask |= 8
			fact.Native = parseDiskIdentity(p)
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 15)
	return fact
}

// RecoverEdit completes only the exact candidate named by the selected source's
// pending marker. It neither captures a second predecessor nor invokes Crypto.
func RecoverEdit(ctx context.Context, path string, format Format) (*PairDelivery, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	delivery, err := func() (delivery *PairDelivery, resultErr error) {
		if ctx == nil || !localPathValid(path) || format != JSON && format != YAML {
			return nil, ErrEdit
		}
		originalParent := filepath.Dir(path)
		path, err := canonicalDestination(path)
		if err != nil {
			return nil, err
		}
		marker, err := readMarker(ctx, coordinationPath(path, ".enkv-pending"))
		if err != nil {
			return nil, err
		}
		record, err := readRecord(ctx, marker.Record)
		if err != nil {
			return nil, err
		}
		if record.Digest != marker.Digest || record.Description.Format != format {
			return nil, ErrEdit
		}
		if err := validateRecord(record, path, marker.Record); err != nil {
			return nil, err
		}
		released, err := releasedTransactionPaths(ctx, record)
		if err != nil {
			return nil, err
		}
		paths := make([]string, 0, 4)
		for _, row := range record.Description.Paths {
			if !released[row.Path] {
				paths = append(paths, row.Path)
			}
		}
		locks, err := openPathLocks(paths, false, false)
		if err != nil {
			return nil, err
		}
		defer func() { resultErr = errors.Join(resultErr, locks.close()) }()
		if err := locks.pinAlias(originalParent, filepath.Dir(path)); err != nil {
			return nil, err
		}
		currentReleased, err := releasedTransactionPaths(ctx, record)
		if err != nil || !maps.Equal(released, currentReleased) {
			return nil, errors.Join(ErrEdit, err)
		}
		session := &EditSession{path: record.source(), locks: locks, io: nativeEditIO(), transaction: record, releasedPaths: released}
		if err := session.validatePendingOwner(ctx, record, marker); err != nil {
			return nil, err
		}
		if err := session.preflight(false); err != nil {
			return nil, err
		}
		delivery, err = session.completePending(ctx, record)
		if err != nil {
			return delivery, &PendingEdit{recovery: confirmedPendingIdentity(record), cause: err}
		}
		return delivery, nil
	}()
	finishEditCall(call, err)
	return delivery, err
}

func releasedTransactionPaths(ctx context.Context, record *pendingRecord) (map[string]bool, error) {
	if record.Phase != "verified" {
		return nil, nil
	}
	var obsolete []transactionPath
	for _, row := range record.Description.Paths {
		if row.Old.Present && !row.New.Present && row.Candidate < 0 && row.Path != record.source() {
			obsolete = append(obsolete, row)
		}
	}
	if len(obsolete) == 0 {
		return nil, nil
	}
	cleanupPaths := []string{record.Description.Scratch}
	for _, image := range record.Description.Images {
		cleanupPaths = append(cleanupPaths, image.Path, image.installPath())
	}
	for _, row := range record.Description.Paths {
		cleanupPaths = append(cleanupPaths, record.markerScratchDirectory(row))
	}
	for _, path := range cleanupPaths {
		if err := ctx.Err(); err != nil {
			return nil, editError(err)
		}
		if _, err := os.Lstat(path); err == nil {
			return nil, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, editError(err)
		}
	}
	released := make(map[string]bool)
	marker := pendingMarker{Record: record.path(), Digest: record.Digest}
	for _, row := range obsolete {
		current, err := readMarker(ctx, coordinationPath(row.Path, ".enkv-pending"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if errors.Is(err, os.ErrNotExist) || current != marker {
			released[row.Path] = true
		}
	}
	if len(released) != 0 {
		for _, row := range record.Description.Paths {
			if row.Candidate >= 0 {
				matched, err := matchesFact(ctx, row.Path, row.New, false)
				if err != nil || !matched {
					return nil, errors.Join(ErrEdit, err)
				}
			}
		}
	}
	return released, nil
}

func (s *EditSession) validatePendingOwner(ctx context.Context, record *pendingRecord, marker pendingMarker) error {
	info, err := os.Lstat(filepath.Dir(record.path()))
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || identity != record.Description.Directory || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrEdit, err, identityErr)
	}
	if err := s.locks.pinDirectory(filepath.Dir(record.path())); err != nil {
		return err
	}
	scratch, err := os.Lstat(record.Description.Scratch)
	if errors.Is(err, os.ErrNotExist) && record.Phase == "verified" {
	} else {
		identity, identityErr := nativeFact(scratch)
		if err != nil || identityErr != nil || identity != record.Description.ScratchNative || !scratch.IsDir() || scratch.Mode()&os.ModeSymlink != 0 {
			return errors.Join(ErrEdit, err, identityErr)
		}
		if err := s.locks.pinDirectory(record.Description.Scratch); err != nil {
			return err
		}
	}
	for _, row := range record.Description.Paths {
		if s.releasedPaths[row.Path] {
			continue
		}
		parent, err := nativeFact(s.locks.directories[filepath.Dir(row.Path)])
		if err != nil || parent != row.Directory {
			return errors.Join(ErrEdit, err)
		}
		matched := false
		for _, lock := range s.locks.locks {
			matched = matched || lock.path == row.Path && row.Lock == (diskIdentity{lock.identity.device, lock.identity.inode})
		}
		if !matched {
			return ErrEdit
		}
		pendingDirectory := filepath.Join(filepath.Dir(row.Path), ".enkv-pending")
		if err := s.locks.pinDirectory(pendingDirectory); err != nil {
			return err
		}
		pending, err := nativeFact(s.locks.directories[pendingDirectory])
		if err != nil || pending != row.Pending {
			return errors.Join(ErrEdit, err)
		}
		workspace := record.markerScratchDirectory(row)
		if info, err := os.Lstat(workspace); errors.Is(err, os.ErrNotExist) && record.Phase == "verified" {
		} else {
			identity, identityErr := nativeFact(info)
			if err != nil || identityErr != nil || identity != row.MarkerScratch || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.Join(ErrEdit, err, identityErr)
			}
			if err := s.locks.pinDirectory(workspace); err != nil {
				return err
			}
		}
		current, err := readMarker(ctx, coordinationPath(row.Path, ".enkv-pending"))
		if !errors.Is(err, os.ErrNotExist) && (err != nil || current != marker) {
			return errors.Join(ErrEdit, err)
		}
	}
	if err := s.checkVisible(ctx, record, false); err != nil {
		return err
	}
	if record.Phase == "verified" {
		for _, row := range record.Description.Paths {
			if row.Candidate >= 0 {
				match, err := matchesFact(ctx, row.Path, row.New, false)
				if err != nil || !match {
					return errors.Join(ErrEdit, err)
				}
			}
		}
	}
	for index, saved := range record.Description.Images {
		if info, err := os.Lstat(saved.installPath()); err == nil {
			identity, identityErr := nativeFact(info)
			if identityErr != nil || identity != saved.Install || !info.Mode().IsRegular() || !singleLink(info) || info.Size() < 0 || uint64(info.Size()) > saved.Fact.Length {
				return errors.Join(ErrEdit, identityErr)
			}
		} else if errors.Is(err, os.ErrNotExist) {
			installed := false
			for _, row := range record.Description.Paths {
				if row.Candidate == index {
					match, err := matchesFact(ctx, row.Path, row.New, false)
					if err != nil {
						return err
					}
					installed = match
				}
			}
			if !installed {
				return ErrEdit
			}
		} else {
			return editError(err)
		}
		match, err := matchesFact(ctx, saved.Path, saved.Fact, true)
		if err != nil {
			return err
		}
		if match {
			continue
		}
		if record.Phase != "verified" {
			return ErrEdit
		}
		if _, err := os.Lstat(saved.Path); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrEdit, err)
		}
		for _, row := range record.Description.Paths {
			if row.Candidate >= 0 {
				match, err := matchesFact(ctx, row.Path, row.New, false)
				if err != nil || !match {
					return errors.Join(ErrEdit, err)
				}
			}
		}
	}
	return s.validateSavedPair(ctx, record)
}

func (s *EditSession) validateSavedPair(ctx context.Context, record *pendingRecord) (resultErr error) {
	pair := &Pair{Format: record.Description.Format}
	defer func() {
		for _, image := range []*Image{pair.Editable, pair.Generated} {
			if image != nil && image.file != nil {
				resultErr = errors.Join(resultErr, image.file.Close())
			}
		}
	}()
	for _, row := range record.Description.Paths {
		if row.Candidate < 0 {
			continue
		}
		saved := record.Description.Images[row.Candidate]
		if _, err := os.Lstat(saved.Path); errors.Is(err, os.ErrNotExist) && record.Phase == "verified" {
			saved.Path = row.Path
			saved.Fact = row.New
			info, err := os.Lstat(row.Path)
			if err != nil {
				return err
			}
			saved.Fact.Native, err = nativeFact(info)
			if err != nil {
				return err
			}
		}
		image, err := openSaved(ctx, saved)
		if err != nil {
			return err
		}
		image.path = row.Path
		if row.Candidate == 0 {
			pair.Editable = image
		} else {
			pair.Generated = image
		}
	}
	if err := sealPair(pair); err != nil {
		return err
	}
	model, err := ParseForPreparation(ctx, pair)
	if err != nil {
		return err
	}
	defer releaseReconstructionModel(model)
	if hex.EncodeToString(model.FileID[:]) != record.Description.FileID || hex.EncodeToString(model.DomainID[:]) != record.Description.DomainID {
		return ErrEdit
	}
	if pair.Generated != nil && filepath.Join(filepath.Dir(record.source()), model.Generated) != pair.Generated.path {
		return ErrEdit
	}
	return nil
}

type pendingIdentity struct {
	source string
	digest string
}

func confirmedPendingIdentity(record *pendingRecord) pendingIdentity {
	if record == nil {
		return pendingIdentity{}
	}
	marker, err := readMarker(context.Background(), coordinationPath(record.source(), ".enkv-pending"))
	if err != nil || marker.Digest != record.Digest || marker.Record != record.path() {
		return pendingIdentity{}
	}
	return pendingIdentity{source: record.source(), digest: record.Digest}
}

type PendingEdit struct {
	recovery pendingIdentity
	cause    error
}

func (e *PendingEdit) Error() string { return ErrPendingEdit.Error() }
func (e *PendingEdit) Unwrap() error { return errors.Join(ErrPendingEdit, e.cause) }
func (e *PendingEdit) RecoverySource() (string, bool) {
	if e == nil {
		return "", false
	}
	return e.recovery.source, e.recovery.source != "" && e.recovery.digest != ""
}

func (e *UnknownEdit) RecoverySource() (string, bool) {
	if e == nil {
		return "", false
	}
	return e.recovery.source, e.recovery.source != "" && e.recovery.digest != ""
}

func (d *PairDelivery) CleanupFailed() bool { return d != nil && d.cleanupFailed }
func (d *PairDelivery) RecoverySource() (string, bool) {
	if d == nil || d.recoverySource == "" {
		return "", false
	}
	return d.recoverySource, true
}
