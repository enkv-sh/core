package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxPendingBytes = 256 << 10
const maxMarkerBytes = 32 << 10

type diskIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type imageFact struct {
	Present bool         `json:"present"`
	Length  uint64       `json:"length"`
	Digest  string       `json:"digest"`
	Native  diskIdentity `json:"native"`
}
type transactionPath struct {
	Path          string       `json:"path"`
	Directory     diskIdentity `json:"directory"`
	Lock          diskIdentity `json:"lock"`
	Pending       diskIdentity `json:"pending"`
	MarkerScratch diskIdentity `json:"marker_scratch"`
	Old           imageFact    `json:"old"`
	New           imageFact    `json:"new"`
	Candidate     int          `json:"candidate"`
}
type savedImage struct {
	Path    string       `json:"path"`
	Fact    imageFact    `json:"fact"`
	Install diskIdentity `json:"install"`
}
type transactionDescription struct {
	Format        Format            `json:"format"`
	FileID        string            `json:"file_id"`
	DomainID      string            `json:"domain_id"`
	Source        uint8             `json:"source"`
	Directory     diskIdentity      `json:"directory"`
	Scratch       string            `json:"scratch"`
	ScratchNative diskIdentity      `json:"scratch_native"`
	Paths         []transactionPath `json:"paths"`
	Images        []savedImage      `json:"images"`
}
type pendingRecord struct {
	Schema      string                 `json:"schema"`
	Description transactionDescription `json:"description"`
	Digest      string                 `json:"digest"`
	Phase       string                 `json:"phase"`
}
type pendingMarker struct {
	Record string `json:"record"`
	Digest string `json:"digest"`
}

func nativeFact(info os.FileInfo) (diskIdentity, error) {
	id, ok := fileIdentity(info)
	if !ok {
		return diskIdentity{}, ErrEdit
	}
	return diskIdentity{id.device, id.inode}, nil
}

func factForImage(image *Image, original bool) imageFact {
	if image == nil {
		return imageFact{}
	}
	fact := imageFact{Present: true, Length: uint64(image.size), Digest: hex.EncodeToString(image.digest[:])}
	if original && image.sourceInfo != nil {
		fact.Native, _ = nativeFact(image.sourceInfo)
	}
	return fact
}

func recordDigest(description transactionDescription) (string, error) {
	encoded, err := json.Marshal(description)
	if err != nil || len(encoded) > maxPendingBytes {
		return "", errors.Join(ErrEditBounds, err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (record *pendingRecord) path() string {
	return filepath.Join(filepath.Dir(record.source()), ".enkv-transactions", record.Digest+".json")
}

func (s *EditSession) checkpoint(phase string) error {
	if s.io.phase == nil {
		return nil
	}
	return editError(s.io.phase(phase))
}

func (s *EditSession) preparePending(ctx context.Context, candidate *EditCandidate) error {
	if err := s.CheckUnchanged(ctx); err != nil {
		return err
	}
	if err := s.preflight(true); err != nil {
		return err
	}
	if err := s.checkpoint("before-candidate-flush"); err != nil {
		return err
	}
	for _, image := range []*Image{candidate.pair.Generated, candidate.pair.Editable} {
		if image != nil {
			if err := s.flushCandidate(image); err != nil {
				return err
			}
			if err := s.io.syncDir(filepath.Dir(image.file.Name())); err != nil {
				return editError(err)
			}
		}
	}
	if err := s.checkpoint("candidate-flushed"); err != nil {
		return err
	}
	var err error
	description := transactionDescription{Format: candidate.pair.Format, FileID: hex.EncodeToString(candidate.fileID[:]), DomainID: hex.EncodeToString(candidate.domainID[:]), Paths: make([]transactionPath, 0, 4), Images: make([]savedImage, 0, 2)}
	transactionDirectory := filepath.Join(filepath.Dir(s.path), ".enkv-transactions")
	if err := ensureEditDirectory(transactionDirectory, s.io.syncDir); err != nil {
		return err
	}
	if err := s.locks.pinDirectory(transactionDirectory); err != nil {
		return err
	}
	description.Directory, err = nativeFact(s.locks.directories[transactionDirectory])
	if err != nil {
		return err
	}
	scratch, err := os.MkdirTemp(transactionDirectory, ".enkv-transaction-*")
	if err != nil {
		return editError(err)
	}
	candidate.scratch = scratch
	stat, statErr := os.Lstat(scratch)
	candidate.scratchNative, err = nativeFact(stat)
	if err != nil || statErr != nil {
		return errors.Join(ErrEdit, err, statErr)
	}
	if err := s.locks.pinDirectory(scratch); err != nil {
		return err
	}
	description.Scratch = scratch
	description.ScratchNative, err = nativeFact(s.locks.directories[scratch])
	if err != nil {
		return err
	}
	if err := s.io.syncDir(transactionDirectory); err != nil {
		return editError(err)
	}
	for _, image := range []*Image{candidate.pair.Editable, candidate.pair.Generated} {
		if image == nil {
			continue
		}
		info, err := image.file.Stat()
		if err != nil || !singleLink(info) {
			return errors.Join(ErrEdit, err)
		}
		fact := factForImage(image, false)
		fact.Native, err = nativeFact(info)
		if err != nil {
			return err
		}
		saved := savedImage{Path: image.file.Name(), Fact: fact}
		installation := saved.installPath()
		if !localPathValid(installation) {
			return ErrEditBounds
		}
		reservation, err := os.OpenFile(installation, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return editError(err)
		}
		stat, statErr := reservation.Stat()
		saved.Install, err = nativeFact(stat)
		candidate.installations[len(description.Images)] = saved.Install
		if err := errors.Join(err, statErr, s.io.syncFile(reservation), s.io.close(reservation), s.io.syncDir(filepath.Dir(installation))); err != nil {
			return editError(err)
		}
		description.Images = append(description.Images, saved)
	}
	for _, lock := range s.locks.locks {
		path := lock.path
		pendingDirectory := filepath.Join(filepath.Dir(path), ".enkv-pending")
		if err := ensureEditDirectory(pendingDirectory, s.io.syncDir); err != nil {
			return err
		}
		if err := s.locks.pinDirectory(pendingDirectory); err != nil {
			return err
		}
		row := transactionPath{Path: path, Candidate: -1, Lock: diskIdentity{lock.identity.device, lock.identity.inode}}
		row.Directory, err = nativeFact(s.locks.directories[filepath.Dir(path)])
		if err != nil {
			return err
		}
		row.Pending, err = nativeFact(s.locks.directories[pendingDirectory])
		if err != nil {
			return err
		}
		if s.predecessor != nil {
			for _, old := range []*Image{s.predecessor.Editable, s.predecessor.Generated} {
				if old != nil && old.path == path {
					row.Old = factForImage(old, true)
					row.New = row.Old
				}
			}
		}
		for index, image := range description.Images {
			var target string
			if index == 0 {
				target = candidate.pair.Editable.path
			} else {
				target = candidate.pair.Generated.path
			}
			if target == path {
				row.New = image.Fact
				row.New.Native = image.Install
				if sameImageFacts(row.Old, row.New) {
					row.New.Native = row.Old.Native
				}
				row.Candidate = index
			}
		}
		if path == s.renameOld {
			row.New = imageFact{}
		}
		if row.Path == s.path {
			description.Source = uint8(len(description.Paths))
		}
		description.Paths = append(description.Paths, row)
	}
	record := &pendingRecord{Schema: "enkv/local-edit/v1", Description: description, Phase: "prepared"}
	candidate.pending = record
	for index := range record.Description.Paths {
		row := &record.Description.Paths[index]
		directory := record.markerScratchDirectory(*row)
		if !localPathValid(directory) {
			return ErrEditBounds
		}
		if err := os.Mkdir(directory, 0700); err != nil {
			return editError(err)
		}
		if err := s.locks.pinDirectory(directory); err != nil {
			return err
		}
		row.MarkerScratch, err = nativeFact(s.locks.directories[directory])
		if err != nil {
			return err
		}
		if err := s.io.syncDir(filepath.Dir(directory)); err != nil {
			return editError(err)
		}
	}

	record.Digest, err = recordDigest(record.Description)
	if err != nil {
		return err
	}
	if err := validateRecord(record, record.source(), record.path()); err != nil {
		return err
	}
	if err := s.checkVisible(ctx, record, true); err != nil {
		return err
	}
	if err := s.checkpoint("before-record"); err != nil {
		return err
	}
	s.transaction = record
	if err := s.writeRecord(ctx, record, false); err != nil {
		return err
	}
	return s.installMarkers(ctx, record)
}

func (s *EditSession) writeRecord(ctx context.Context, record *pendingRecord, replace bool) error {
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > maxPendingBytes {
		return errors.Join(ErrEditBounds, err)
	}
	return s.writeMetadata(ctx, record.path(), encoded, replace)
}

func (s *EditSession) writeMetadata(ctx context.Context, path string, encoded []byte, replace bool) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return editError(err)
	}
	if s.transaction == nil {
		return ErrEdit
	}
	slot, directory, expected, err := s.transaction.metadataSlot(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || identity != expected || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrEdit, err, identityErr)
	}
	file, err := openNativeScratch(slot)
	if err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !singleLink(opened) || !sameNativeOwner(info, opened) {
		return errors.Join(ErrEdit, err, file.Close())
	}
	if s.candidate != nil && !s.candidate.durable && path == s.transaction.path() {
		identity, err := nativeFact(opened)
		if err != nil {
			return errors.Join(err, file.Close())
		}
		s.candidate.recordNative = identity
	}
	if err := file.Truncate(0); err != nil {
		return errors.Join(ErrEdit, err, file.Close())
	}
	temporary := slot
	n, writeErr := s.io.write(file, encoded)
	if n != len(encoded) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	if err := errors.Join(writeErr, s.io.syncFile(file), s.io.close(file)); err != nil {
		return editError(err)
	}
	if err := s.locks.check(false); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return editError(err)
	}
	if replace {
		err = s.io.replace(temporary, path)
	} else {
		err = s.io.installAbsent(temporary, path)
	}
	sourceMarker := s.candidate != nil && path == coordinationPath(s.transaction.source(), ".enkv-pending")
	if err != nil {
		if sourceMarker {
			if checkErr := s.locks.check(false); checkErr != nil {
				s.candidate.retainPending()
				return errors.Join(editError(err), checkErr)
			}
			// Cancellation cannot prove that the preceding install had no effect.
			marker, readErr := readMarker(context.Background(), path)
			unreadable := readErr != nil && !errors.Is(readErr, os.ErrNotExist)
			if unreadable || readErr == nil && marker == (pendingMarker{Record: s.transaction.path(), Digest: s.transaction.Digest}) {
				s.candidate.retainPending()
			}
			if unreadable {
				return errors.Join(editError(err), readErr)
			}
		}
		return editError(err)
	}
	if sourceMarker {
		// The source marker makes the saved candidate reachable even when the
		// following directory synchronization reports failure.
		s.candidate.retainPending()
	}
	return editError(s.io.syncDir(filepath.Dir(path)))
}

func (s *EditSession) installMarkers(ctx context.Context, record *pendingRecord) error {
	marker := pendingMarker{Record: record.path(), Digest: record.Digest}
	encoded, err := json.Marshal(marker)
	if err != nil || len(encoded) > maxMarkerBytes {
		return errors.Join(ErrEditBounds, err)
	}
	// Installing the selected source marker first keeps partial installation
	// reachable through the explicit recovery boundary.
	for pass := 0; pass < 2; pass++ {
		for _, row := range record.Description.Paths {
			if (row.Path == record.source()) != (pass == 0) {
				continue
			}
			path := coordinationPath(row.Path, ".enkv-pending")
			current, err := readMarker(ctx, path)
			if errors.Is(err, os.ErrNotExist) {
				if err := s.checkVisible(ctx, record, false); err != nil {
					return err
				}
				if err := s.writeMetadata(ctx, path, encoded, false); err != nil {
					return err
				}
			} else if err != nil || current != marker {
				return errors.Join(ErrEdit, err)
			}
			if pass == 0 {
				if s.candidate != nil && !s.candidate.durable {
					s.candidate.retainPending()
				}
				if err := s.checkpoint("record-durable"); err != nil {
					return err
				}
			}
			if err := s.checkpoint("marker-durable"); err != nil {
				return err
			}
		}
	}
	return s.checkpoint("markers-durable")
}

func (s *EditSession) setPhase(ctx context.Context, record *pendingRecord, phase string) error {
	record.Phase = phase
	return s.writeRecord(ctx, record, true)
}

func (s *EditSession) completePending(ctx context.Context, record *pendingRecord) (*PairDelivery, error) {
	if err := s.locks.check(false); err != nil {
		return nil, err
	}
	if err := s.checkVisible(ctx, record, false); err != nil {
		return nil, err
	}
	if record.Phase != "verified" {
		if err := s.installMarkers(ctx, record); err != nil {
			return nil, err
		}
	}
	for _, index := range []int{1, 0} {
		if record.Phase == "verified" {
			break
		}
		if index >= len(record.Description.Images) {
			continue
		}
		for _, row := range record.Description.Paths {
			if row.Candidate != index {
				continue
			}
			phase := "generated"
			if index == 0 {
				phase = "editable"
			}
			if err := s.checkpoint("before-" + phase + "-install"); err != nil {
				return nil, err
			}
			if err := s.checkVisible(ctx, record, false); err != nil {
				return nil, err
			}
			matches, err := matchesFact(ctx, row.Path, row.New, false)
			if err != nil {
				return nil, err
			}
			if !matches {
				if sameImageFacts(row.Old, row.New) {
					return nil, ErrEdit
				}
				if err := s.installSaved(ctx, record.Description.Images[index], row.Path, !row.Old.Present); err != nil {
					return nil, err
				}
			}
			if err := s.setPhase(ctx, record, phase); err != nil {
				return nil, err
			}
			if err := s.checkpoint(phase + "-installed"); err != nil {
				return nil, err
			}
		}
	}
	delivery := &PairDelivery{editable: record.source()}
	for _, row := range record.Description.Paths {
		if row.Candidate < 0 {
			continue
		}
		matches, err := matchesFact(ctx, row.Path, row.New, false)
		if err != nil || !matches {
			return nil, errors.Join(ErrEdit, err)
		}
		if err := s.io.syncDir(filepath.Dir(row.Path)); err != nil {
			return nil, err
		}
		digest, _ := decodeDigest(row.New.Digest)
		if row.Candidate == 0 {
			delivery.editable, delivery.editableDigest = row.Path, digest
		} else {
			delivery.generated, delivery.generatedDigest = row.Path, digest
		}
	}
	if record.Phase != "verified" {
		if err := s.setPhase(ctx, record, "verified"); err != nil {
			return incompleteDelivery(record, delivery, err)
		}
	}
	if err := s.checkpoint("pair-verified"); err != nil {
		return incompleteDelivery(record, delivery, err)
	}
	if err := s.cleanupPending(ctx, record); err != nil {
		return incompleteDelivery(record, delivery, err)
	}
	return delivery, nil
}

func incompleteDelivery(record *pendingRecord, delivery *PairDelivery, err error) (*PairDelivery, error) {
	delivery.cleanupFailed = true
	delivery.recoverySource = confirmedPendingIdentity(record).source
	return delivery, err
}

func (saved savedImage) installPath() string { return saved.Path + ".install" }

func (s *EditSession) installSaved(ctx context.Context, saved savedImage, path string, absent bool) (resultErr error) {
	image, err := openSaved(ctx, saved)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, image.file.Close()) }()
	temporary := saved.installPath()
	file, err := openNativeInstallation(temporary)
	if err != nil {
		return err
	}
	stream := &Image{file: file, path: temporary}
	defer func() {
		if stream.file != nil {
			resultErr = errors.Join(resultErr, stream.file.Close())
		}
	}()
	info, err := file.Stat()
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || identity != saved.Install || !singleLink(info) || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > saved.Fact.Length {
		return errors.Join(ErrEdit, err, identityErr)
	}
	if err := file.Truncate(0); err != nil {
		return editError(err)
	}
	if err := s.checkpoint("installation-truncated"); err != nil {
		return err
	}
	hash := sha256.New()
	writer := &candidateWriter{ctx: ctx, remaining: int64(saved.Fact.Length), image: stream, hash: hash, writer: candidateFileWriter{file: file, write: s.io.write}}
	if _, err := image.CopyTo(writer); err != nil {
		return err
	}
	if writer.err != nil {
		return writer.err
	}
	copy(stream.digest[:], hash.Sum(nil))
	if err := s.checkpoint("installation-copied"); err != nil {
		return err
	}
	if stream.digest != image.digest || stream.size != image.size {
		return ErrEdit
	}
	if err := s.io.syncFile(file); err != nil {
		return editError(err)
	}
	closeErr := s.io.close(file)
	stream.file = nil
	if closeErr != nil {
		return editError(closeErr)
	}
	if err := ctx.Err(); err != nil {
		return editError(err)
	}
	if err := s.locks.check(false); err != nil {
		return err
	}
	info, err = os.Lstat(temporary)
	identity, identityErr = nativeFact(info)
	if err != nil || identityErr != nil || identity != saved.Install || !singleLink(info) {
		return errors.Join(ErrEdit, err, identityErr)
	}
	if absent {
		err = s.io.installAbsent(temporary, path)
	} else {
		err = s.io.replace(temporary, path)
	}
	if err != nil {
		return editError(err)
	}
	s.relinquishInstallation(temporary)
	if err := s.io.syncDir(filepath.Dir(path)); err != nil {
		return editError(err)
	}
	return s.io.readback(ctx, path, image, false)
}

func (s *EditSession) cleanupPending(ctx context.Context, record *pendingRecord) error {
	if err := s.checkVisible(ctx, record, false); err != nil {
		return err
	}
	for _, row := range record.Description.Paths {
		if !s.releasedPaths[row.Path] && row.Old.Present && !row.New.Present {
			if err := s.checkpoint("before-obsolete-cleanup"); err != nil {
				return err
			}
			match, err := matchesFact(ctx, row.Path, row.Old, true)
			if err != nil {
				return err
			}
			if match {
				if err := s.io.remove(row.Path); err != nil {
					return editError(err)
				}
				if err := s.io.syncDir(filepath.Dir(row.Path)); err != nil {
					return editError(err)
				}
			}
			if err := s.checkpoint("obsolete-cleaned"); err != nil {
				return err
			}
		}
	}
	for _, image := range record.Description.Images {
		installation := image.installPath()
		if info, err := os.Lstat(installation); err == nil {
			identity, identityErr := nativeFact(info)
			if identityErr != nil || identity != image.Install || !singleLink(info) || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > image.Fact.Length {
				return errors.Join(ErrEdit, identityErr)
			}
			if err := s.io.remove(installation); err != nil {
				return editError(err)
			}
			s.relinquishInstallation(installation)
			if err := s.io.syncDir(filepath.Dir(installation)); err != nil {
				return editError(err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return editError(err)
		}
		match, err := matchesFact(ctx, image.Path, image.Fact, true)
		if err != nil {
			return err
		}
		if match {
			if err := s.io.remove(image.Path); err != nil {
				return editError(err)
			}
			s.relinquishImage(image.Path)
			if err := s.io.syncDir(filepath.Dir(image.Path)); err != nil {
				return editError(err)
			}
		} else if _, err := os.Lstat(image.Path); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrEdit, err)
		}
		if err := s.checkpoint("staging-cleaned"); err != nil {
			return err
		}
	}
	if err := s.cleanupScratch(record); err != nil {
		return err
	}
	for pass := 0; pass < 2; pass++ {
		for _, row := range record.Description.Paths {
			if s.releasedPaths[row.Path] || (row.Path == record.source()) != (pass == 1) {
				continue
			}
			path := coordinationPath(row.Path, ".enkv-pending")
			marker, err := readMarker(ctx, path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || marker.Record != record.path() || marker.Digest != record.Digest {
				return errors.Join(ErrEdit, err)
			}
			if err := s.io.remove(path); err != nil {
				return editError(err)
			}
			if err := s.io.syncDir(filepath.Dir(path)); err != nil {
				return editError(err)
			}
			if err := s.checkpoint("marker-cleaned"); err != nil {
				return err
			}
		}
	}
	if err := s.checkpoint("markers-cleared"); err != nil {
		return err
	}
	if err := s.io.remove(record.path()); err != nil {
		return editError(err)
	}
	if err := s.io.syncDir(filepath.Dir(record.path())); err != nil {
		return editError(err)
	}
	s.relinquishPending()
	return s.checkpoint("record-cleaned")
}

func (s *EditSession) checkVisible(ctx context.Context, record *pendingRecord, oldOnly bool) error {
	if err := s.locks.check(false); err != nil {
		return err
	}
	for _, row := range record.Description.Paths {
		if s.releasedPaths[row.Path] {
			continue
		}
		old, err := matchesFact(ctx, row.Path, row.Old, true)
		if err != nil {
			return err
		}
		if old {
			continue
		}
		if oldOnly {
			return ErrEdit
		}
		new, err := matchesFact(ctx, row.Path, row.New, false)
		if err != nil || !new {
			return errors.Join(ErrEdit, err)
		}
	}
	return nil
}

func decodeDigest(text string) ([32]byte, error) {
	var digest [32]byte
	if len(text) != 64 {
		return digest, ErrEdit
	}
	n, err := hex.Decode(digest[:], []byte(text))
	if err != nil || n != 32 || hex.EncodeToString(digest[:]) != text {
		return [32]byte{}, ErrEdit
	}
	return digest, nil
}

func matchesFact(ctx context.Context, path string, fact imageFact, native bool) (matched bool, resultErr error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return !fact.Present, nil
	}
	if err != nil {
		return false, editError(err)
	}
	if !fact.Present {
		return false, nil
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || info.Size() < 0 || uint64(info.Size()) != fact.Length {
		return false, nil
	}
	identity, err := nativeFact(info)
	if err != nil || (native || fact.Native != (diskIdentity{})) && identity != fact.Native {
		return false, err
	}
	digest, err := decodeDigest(fact.Digest)
	if err != nil {
		return false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return false, editError(err)
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !sameMetadata(info, opened) {
		return false, errors.Join(ErrEdit, err)
	}
	hash := sha256.New()
	buffer := make([]byte, WindowBytes)
	remaining := int64(fact.Length)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return false, editError(err)
		}
		n := min(remaining, int64(len(buffer)))
		if _, err := io.ReadFull(file, buffer[:n]); err != nil {
			return false, editError(err)
		}
		_, _ = hash.Write(buffer[:n])
		remaining -= n
	}
	after, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(opened, current) || !sameMetadata(opened, after) || !sameMetadata(opened, current) {
		return false, errors.Join(ErrEdit, err, pathErr)
	}
	return equalDigest(digest, hash.Sum(nil)), nil
}

func openSaved(ctx context.Context, saved savedImage) (*Image, error) {
	match, err := matchesFact(ctx, saved.Path, saved.Fact, true)
	if err != nil || !match {
		return nil, errors.Join(ErrEdit, err)
	}
	file, err := os.Open(saved.Path)
	if err != nil {
		return nil, editError(err)
	}
	info, err := file.Stat()
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || identity != saved.Fact.Native {
		return nil, errors.Join(ErrEdit, err, identityErr, file.Close())
	}
	digest, _ := decodeDigest(saved.Fact.Digest)
	return &Image{file: file, path: saved.Path, sourceInfo: info, size: int64(saved.Fact.Length), digest: digest}, nil
}

func sameImageFacts(a, b imageFact) bool {
	return a.Present == b.Present && a.Length == b.Length && a.Digest == b.Digest
}

func validFact(fact imageFact) bool {
	if !fact.Present {
		return fact == (imageFact{})
	}
	_, err := decodeDigest(fact.Digest)
	return err == nil && fact.Length <= uint64(MaxPairBytes)
}

func validateRecord(record *pendingRecord, selected, path string) error {
	if record == nil || record.Schema != "enkv/local-edit/v1" || !localPathValid(selected) || !localPathValid(record.source()) || record.Description.Format != JSON && record.Description.Format != YAML || !localPathValid(record.Description.Scratch) || record.Description.ScratchNative == (diskIdentity{}) || filepath.Dir(record.Description.Scratch) != filepath.Dir(record.path()) || len(record.Description.Paths) == 0 || len(record.Description.Paths) > 4 || len(record.Description.Images) == 0 || len(record.Description.Images) > 2 {
		return ErrEdit
	}
	if record.Phase != "prepared" && record.Phase != "generated" && record.Phase != "editable" && record.Phase != "verified" {
		return ErrEdit
	}
	for _, text := range []string{record.Description.FileID, record.Description.DomainID} {
		if _, err := decodeDigest(text); err != nil {
			return err
		}
	}
	digest, err := recordDigest(record.Description)
	if err != nil || digest != record.Digest || path != record.path() {
		return errors.Join(ErrEdit, err)
	}
	var foundSelected, foundSource bool
	seen := make(map[string]bool)
	var oldSize, newSize uint64
	var candidates [2]bool
	for _, row := range record.Description.Paths {
		if !localPathValid(row.Path) || seen[row.Path] || !validFact(row.Old) || !validFact(row.New) || row.Candidate < -1 || row.Candidate >= len(record.Description.Images) {
			return ErrEdit
		}
		seen[row.Path] = true
		foundSelected = foundSelected || row.Path == selected
		foundSource = foundSource || row.Path == record.source()
		oldSize += row.Old.Length
		if row.Candidate >= 0 {
			if candidates[row.Candidate] || row.Candidate == 0 && row.Path != record.source() {
				return ErrEdit
			}
			candidates[row.Candidate] = true
			if !sameImageFacts(row.New, record.Description.Images[row.Candidate].Fact) {
				return ErrEdit
			}
			newSize += row.New.Length
		}
	}
	if !candidates[0] || len(record.Description.Images) == 2 && !candidates[1] {
		return ErrEdit
	}
	if !foundSelected || !foundSource || oldSize > uint64(MaxPairBytes) || newSize > uint64(MaxPairBytes) {
		return ErrEditBounds
	}
	for _, saved := range record.Description.Images {
		if !localPathValid(saved.Path) || seen[saved.Path] || !validFact(saved.Fact) || !saved.Fact.Present || saved.Fact.Native == (diskIdentity{}) || saved.Install == (diskIdentity{}) || !localPathValid(saved.installPath()) {
			return ErrEdit
		}
		seen[saved.Path] = true
		// Staging is private and colocated with its visible image. The record
		// cannot redirect recovery to arbitrary caller-selected files.
		parentAllowed := false
		for _, row := range record.Description.Paths {
			parentAllowed = parentAllowed || filepath.Dir(saved.Path) == filepath.Dir(row.Path)
		}
		base := filepath.Base(saved.Path)
		if !parentAllowed || !strings.HasPrefix(base, ".enkv-editable-") && !strings.HasPrefix(base, ".enkv-generated-") {
			return ErrEdit
		}
	}
	return nil
}

func (record *pendingRecord) source() string {
	if record == nil || int(record.Description.Source) >= len(record.Description.Paths) {
		return ""
	}
	return record.Description.Paths[record.Description.Source].Path
}

func (record *pendingRecord) markerScratchDirectory(row transactionPath) string {
	digest := sha256.Sum256([]byte(record.Description.Images[0].Path + "\x00" + row.Path))
	return filepath.Join(filepath.Dir(row.Path), ".enkv-pending", ".enkv-slot-"+hex.EncodeToString(digest[:]))
}

func (record *pendingRecord) metadataSlot(path string) (string, string, diskIdentity, error) {
	if path == record.path() {
		return filepath.Join(record.Description.Scratch, "record"), record.Description.Scratch, record.Description.ScratchNative, nil
	}
	for _, row := range record.Description.Paths {
		if path == coordinationPath(row.Path, ".enkv-pending") {
			directory := record.markerScratchDirectory(row)
			return filepath.Join(directory, "marker"), directory, row.MarkerScratch, nil
		}
	}
	return "", "", diskIdentity{}, ErrEdit
}

func (s *EditSession) cleanupScratchDirectory(directory string, expected diskIdentity, name string, allowMissing bool) error {
	if expected == (diskIdentity{}) {
		return nil
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil
	}
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || identity != expected || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrEdit, err, identityErr)
	}
	path := filepath.Join(directory, name)
	if file, err := os.Lstat(path); err == nil {
		if !file.Mode().IsRegular() || !singleLink(file) || !sameNativeOwner(info, file) {
			return ErrEdit
		}
		if err := s.io.remove(path); err != nil {
			return editError(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return editError(err)
	}
	if err := s.io.remove(directory); err != nil {
		return editError(err)
	}
	delete(s.locks.directories, directory)
	return editError(s.io.syncDir(filepath.Dir(directory)))
}

func (s *EditSession) cleanupScratch(record *pendingRecord) error {
	for _, row := range record.Description.Paths {
		if s.releasedPaths[row.Path] {
			continue
		}
		if err := s.cleanupScratchDirectory(record.markerScratchDirectory(row), row.MarkerScratch, "marker", true); err != nil {
			return err
		}
	}
	return s.cleanupScratchDirectory(record.Description.Scratch, record.Description.ScratchNative, "record", true)
}
