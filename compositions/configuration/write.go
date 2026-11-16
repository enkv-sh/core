package configuration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

var (
	ErrEdit        = errors.New("configuration edit refused")
	ErrEditLocked  = errors.New("configuration editor already active")
	ErrEditBounds  = errors.New("configuration candidate exceeds pair limit")
	ErrNativeEdit  = errors.New("configuration native persistence unavailable")
	ErrPendingEdit = errors.New("configuration edit requires exact recovery")
	ErrArtifact    = errors.New("initialization artifact delivery refused")
)

type editIO struct {
	write         func(*os.File, []byte) (int, error)
	syncFile      func(*os.File) error
	close         func(*os.File) error
	installAbsent func(string, string) error
	replace       func(string, string) error
	syncDir       func(string) error
	readback      func(context.Context, string, *Image, bool) error
	remove        func(string) error
	phase         func(string) error
	freeBytes     func(string) (uint64, uint64, error)
}

func nativeEditIO() editIO {
	return editIO{
		write:    func(f *os.File, p []byte) (int, error) { return f.Write(p) },
		syncFile: syncEditFile, close: func(f *os.File) error { return f.Close() },
		installAbsent: renameEditAbsent, replace: os.Rename, syncDir: syncEditDirectory, readback: compareEditImage,
		remove: os.Remove, phase: func(string) error { return nil }, freeBytes: availableEditBytes,
	}
}

// EditSession owns its lock and frozen predecessor until Close. The borrowed
// Pair must not be closed or changed by the caller. Complete selected admission
// and release its semantic owners before Stage accepts confidential output.
type EditSession struct {
	path                      string
	temporaryDirectory        string
	format                    Format
	locks                     *pathLocks
	reference                 string
	targetName                string
	sourceName                string
	borrowed                  bool
	renameOld                 string
	transaction               *pendingRecord
	releasedPaths             map[string]bool
	predecessor               *Pair
	candidate                 *EditCandidate
	io                        editIO
	staged, attempted, closed bool
}

// EditCandidate owns fixed candidate bytes. Stage returns the normalized model
// separately; changing that model cannot change the bytes or artifact facts.
type EditCandidate struct {
	session                     *EditSession
	pair                        *Pair
	editableTemp, generatedTemp string
	descriptor                  contract.GenesisArtifactFact
	manifestID                  contract.ID
	durable                     bool
	fileID, domainID            contract.ID
	installations               [2]diskIdentity
	pending                     *pendingRecord
	recordNative                diskIdentity
	scratch                     string
	scratchNative               diskIdentity
}

// PairDelivery records confirmed exact native readback. It grants no Core
// admission and makes no claim about a particular device's power-loss behavior.
type PairDelivery struct {
	editable, generated             string
	editableDigest, generatedDigest [32]byte
	cleanupFailed                   bool
	recoverySource                  string
}

func (d *PairDelivery) Paths() (string, string) {
	if d == nil {
		return "", ""
	}
	return d.editable, d.generated
}

// EditObservation owns local image handles after an interrupted edit. Close
// releases those handles and private files that have no pending owner. Durable
// recovery images remain owned by the pending record. Paths grant no edit retry.
type EditObservation struct {
	predecessor         *Pair
	candidate           *EditCandidate
	editable, generated string
}

func (o *EditObservation) Paths() []string {
	if o == nil {
		return nil
	}
	paths := []string{o.editable, o.generated}
	if o.candidate != nil {
		paths = append(paths, o.candidate.editableTemp)
		if o.candidate.pair.Generated != nil {
			paths = append(paths, o.candidate.generatedTemp)
		}
	}
	return paths
}

func (o *EditObservation) Close() error {
	if o == nil {
		return nil
	}
	err := o.predecessor.Close()
	if o.candidate != nil {
		err = errors.Join(err, o.candidate.close())
	}
	o.predecessor, o.candidate = nil, nil
	return err
}

// UnknownEdit reports interrupted local delivery. Native readback and recovery
// facts survive observation disposal and grant no replacement retry.
type UnknownEdit struct {
	Observation *EditObservation
	recovery    pendingIdentity
	readback    *PairDelivery
	cause       error
}

func (e *UnknownEdit) Error() string {
	return "configuration edit outcome unknown; explicit local recovery may be required"
}
func (e *UnknownEdit) Unwrap() error { return e.cause }

// Readback returns confirmed native pair delivery, when available. It grants
// no operation-specific persistence receipt or qualified successor delivery.
func (e *UnknownEdit) Readback() (*PairDelivery, bool) {
	if e == nil || e.readback == nil {
		return nil, false
	}
	return e.readback, true
}

func finishEditCall(call *telemetry.Call, err error) {
	result := telemetry.ResultSuccess
	var unknown *UnknownEdit
	switch {
	case errors.As(err, &unknown), errors.Is(err, ErrPendingEdit):
		result = telemetry.ResultWriteUnknown
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		result = telemetry.ResultCancelled
	case errors.Is(err, ErrEditLocked):
		result = telemetry.ResultContention
	case errors.Is(err, ErrEditBounds):
		result = telemetry.ResultCapacityExceeded
	case err != nil:
		result = telemetry.ResultWriteRefused
	}
	call.Finish(result)
}

func BeginEdit(ctx context.Context, path string, format Format) (*EditSession, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	s, err := beginEdit(editCallContext(ctx, call), path, format)
	finishEditCall(call, err)
	return s, err
}

func beginEdit(ctx context.Context, path string, format Format) (*EditSession, error) {
	return beginEditForName(ctx, path, format, "")
}

func beginEditForName(ctx context.Context, path string, format Format, newName string) (*EditSession, error) {
	if ctx == nil || ctx.Err() != nil || !localPathValid(path) || format != JSON && format != YAML {
		return nil, ErrEdit
	}
	originalParent := strings.Clone(filepath.Dir(path))
	path, err := canonicalDestination(path)
	if err != nil {
		return nil, err
	}
	if err := refusePending([]string{path}); err != nil {
		return nil, err
	}
	if err := checkEditableParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	temporary, valid := temporaryDirectory()
	if !valid {
		return nil, ErrEditBounds
	}
	if err := preflightEditDisk([]string{filepath.Dir(path), temporary}, nativeEditIO()); err != nil {
		return nil, err
	}
	discovery, err := captureInDirectory(ctx, path, MaxPairBytes, temporary)
	if err != nil {
		return nil, err
	}
	model, parseErr := parseEditableMode(ctx, discovery, format, true, nil)
	if err := errors.Join(parseErr, discovery.Close()); err != nil {
		return nil, err
	}
	directory := filepath.Join(filepath.Dir(path), ".enkv")
	if err := ensureEditDirectory(directory, syncEditDirectory); err != nil {
		return nil, err
	}
	if err := preflightEditDisk([]string{filepath.Dir(path), directory, temporary}, nativeEditIO()); err != nil {
		return nil, err
	}
	reference := generatedPath(model.DomainName)
	paths := []string{path, filepath.Join(filepath.Dir(path), reference)}
	oldGenerated := ""
	if newName != "" {
		if !domainNameValid(newName) || newName == model.DomainName {
			return nil, ErrEdit
		}
		oldGenerated = filepath.Join(filepath.Dir(path), reference)
		reference = generatedPath(newName)
		paths = append(paths, filepath.Join(filepath.Dir(path), reference))
	}
	locks, err := openPathLocks(paths, false, true)
	if err != nil {
		return nil, err
	}
	if err := locks.pinAlias(originalParent, filepath.Dir(path)); err != nil {
		return nil, errors.Join(err, locks.close())
	}
	if newName != "" {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(path), reference)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrEdit, err, locks.close())
		}
	}
	pair, current, err := capturePairOwned(ctx, path, format, locks, temporary)
	if err == nil {
		err = refusePending(paths)
	}
	if err != nil {
		return nil, errors.Join(err, pair.Close(), locks.close())
	}
	err = ctx.Err()
	if err != nil {
		err = &Diagnostic{Line: 1, Column: 1, Reason: "cancelled", cause: err}
	}
	if err != nil || current.domainName != model.DomainName || current.generated != model.Generated {
		return nil, errors.Join(ErrEdit, err, pair.Close(), locks.close())
	}
	pair.aliasParent = originalParent
	pair.aliasDirectory = locks.aliases[originalParent]
	pair.ownedLocks = locks
	if err := sealPair(pair); err != nil {
		return nil, errors.Join(err, pair.Close(), locks.close())
	}
	session := &EditSession{path: path, temporaryDirectory: temporary, format: format, locks: locks, reference: reference, targetName: newName, sourceName: model.DomainName, renameOld: oldGenerated, predecessor: pair, io: nativeEditIO()}
	if err := session.prepareDirectories(); err != nil {
		return nil, errors.Join(err, session.Close())
	}
	return session, nil
}

func checkEditableParent(parent string) error {
	for current := parent; current != filepath.Dir(current); current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return errors.Join(ErrEdit, err)
		}
		for _, name := range []string{".enkv", ".enkv-locks", ".enkv-pending", ".enkv-transactions"} {
			reserved, err := os.Stat(filepath.Join(filepath.Dir(current), name))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return errors.Join(ErrEdit, err)
			}
			if os.SameFile(info, reserved) {
				return errors.Join(ErrEdit, ErrSourceInvalid)
			}
		}
	}
	return nil
}

func (s *EditSession) prepareDirectories() error {
	for _, lock := range s.locks.locks {
		directory := filepath.Join(filepath.Dir(lock.path), ".enkv-pending")
		if err := ensureEditDirectory(directory, s.io.syncDir); err != nil {
			return err
		}
		if err := s.locks.pinDirectory(directory); err != nil {
			return err
		}
	}
	directory := filepath.Join(filepath.Dir(s.path), ".enkv-transactions")
	if err := ensureEditDirectory(directory, s.io.syncDir); err != nil {
		return err
	}
	if err := s.locks.pinDirectory(directory); err != nil {
		return err
	}
	return s.preflight(true)
}

func (s *EditSession) preflight(temporary bool) error {
	if temporary && (!localDirectoryPathValid(s.temporaryDirectory) || len(s.temporaryDirectory)+64 > 4096) {
		return ErrEditBounds
	}
	type filesystemNeed struct {
		directory string
		bytes     uint64
	}
	needs := make(map[uint64]filesystemNeed)
	add := func(directory string, bytes uint64) error {
		if !localDirectoryPathValid(directory) {
			return ErrEditBounds
		}
		info, err := os.Stat(directory)
		native, ok := fileIdentity(info)
		if err != nil || !ok || !info.IsDir() {
			return errors.Join(ErrEdit, err)
		}
		if previous, exists := needs[native.device]; !exists || previous.bytes < bytes {
			needs[native.device] = filesystemNeed{directory, bytes}
		}
		return nil
	}
	for _, lock := range s.locks.locks {
		if err := add(filepath.Dir(lock.path), uint64(3*MaxPairBytes)+655360); err != nil {
			return err
		}
	}
	if temporary {
		if err := add(s.temporaryDirectory, uint64(3*MaxPairBytes)+655360); err != nil {
			return err
		}
	}
	for directory := range s.locks.directories {
		if err := add(directory, 655360); err != nil {
			return err
		}
	}
	for _, need := range needs {
		free, block, err := s.io.freeBytes(need.directory)
		if err != nil {
			return editError(err)
		}
		if block == 0 || block > 1<<30 || free < need.bytes+32*block {
			return ErrEditBounds
		}
	}
	return nil
}

func preflightEditDisk(directories []string, operations editIO) error {
	seen := make(map[nativeIdentity]bool)
	for _, directory := range directories {
		if !localDirectoryPathValid(directory) {
			return ErrEditBounds
		}
		info, err := os.Stat(directory)
		identity, valid := fileIdentity(info)
		if err != nil || !valid {
			return errors.Join(ErrEdit, err)
		}
		identity.inode = 0
		if seen[identity] {
			continue
		}
		seen[identity] = true
		free, block, err := operations.freeBytes(directory)
		if err != nil {
			return errors.Join(ErrEdit, err)
		}
		if block == 0 || block > 1<<30 || free < uint64(3*MaxPairBytes)+655360+32*block {
			return ErrEditBounds
		}
	}
	return nil
}

func (s *EditSession) Pair() *Pair {
	if s == nil || s.closed {
		return nil
	}
	return s.predecessor
}

// Stage calls each emitter once through an aggregate-bounded writer. A nil
// generated emitter reuses the exact predecessor dependency. The editable
// emitter receives its exact reference and should use CopyEdits for preservation.
// The caller checks the intended change in the returned model before Commit.
func (s *EditSession) Stage(ctx context.Context, generated func(io.Writer) error, editable func(io.Writer, string) error) (*EditCandidate, *Model, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	candidate, model, err := s.stage(editCallContext(ctx, call), generated, editable)
	finishEditCall(call, err)
	return candidate, model, err
}

// StageForPreparation validates a complete candidate and enumerates positively
// absent supplied inputs. Ordinary Stage continues to require a complete pair.
// The operation must qualify the candidate's exact missing set before Commit.
func (s *EditSession) StageForPreparation(ctx context.Context, generated func(io.Writer) error, editable func(io.Writer, string) error) (*EditCandidate, *Model, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	candidate, model, err := s.stageConsumed(editCallContext(ctx, call), generated, editable, nil, true)
	finishEditCall(call, err)
	return candidate, model, err
}

func (s *EditSession) stage(ctx context.Context, generated func(io.Writer) error, editable func(io.Writer, string) error) (candidate *EditCandidate, model *Model, err error) {
	return s.stageConsumed(ctx, generated, editable, nil, false)
}

func (s *EditSession) stageConsumed(ctx context.Context, generated func(io.Writer) error, editable func(io.Writer, string) error, consumed *Model, preparation bool) (candidate *EditCandidate, model *Model, err error) {
	defer func() { releaseReconstructionModel(consumed) }()
	if s == nil || s.closed || s.staged || ctx == nil || ctx.Err() != nil || editable == nil {
		return nil, nil, ErrEdit
	}
	if s.locks == nil || s.locks.check(false) != nil || s.predecessor != nil && s.predecessor.validateCaptured() != nil {
		return nil, nil, ErrEdit
	}
	if s.predecessor == nil {
		if generated == nil {
			return nil, nil, ErrEdit
		}
		if err := s.CheckUnchanged(ctx); err != nil {
			return nil, nil, err
		}
	}
	if err := s.preflight(true); err != nil {
		return nil, nil, err
	}
	s.staged = true
	c := &EditCandidate{session: s, pair: &Pair{Format: s.format}}
	complete := false
	defer func() {
		if !complete {
			err = errors.Join(err, c.close())
		}
	}()
	ref := ""
	if generated == nil && s.predecessor != nil && s.predecessor.Generated != nil {
		generated = func(w io.Writer) error { _, err := s.predecessor.Generated.CopyTo(w); return err }
	}
	if generated != nil {
		dir := filepath.Join(filepath.Dir(s.path), ".enkv")
		if err := ensureEditDirectory(dir, s.io.syncDir); err != nil {
			return nil, nil, err
		}
		c.pair.Generated, err = s.emit(ctx, dir, ".enkv-generated-*", MaxPairBytes, generated)
		if err != nil {
			return nil, nil, err
		}
		c.generatedTemp = c.pair.Generated.file.Name()
		ref = s.reference
		c.pair.Generated.path = filepath.Join(filepath.Dir(s.path), ref)
	}

	limit := MaxPairBytes
	if c.pair.Generated != nil {
		limit -= c.pair.Generated.size
	}
	c.pair.Editable, err = s.emit(ctx, filepath.Dir(s.path), ".enkv-editable-*", limit, func(w io.Writer) error { return editable(w, ref) })
	if err != nil {
		return nil, nil, err
	}
	c.editableTemp = c.pair.Editable.file.Name()
	c.pair.Editable.path = s.path
	releaseReconstructionModel(consumed)
	consumed = nil
	if err := sealPair(c.pair); err != nil {
		return nil, nil, err
	}
	m, err := parseSource(ctx, c.pair, nil, preparation)
	if err != nil {
		return nil, nil, err
	}
	expectedName := s.sourceName
	if s.targetName != "" {
		expectedName = s.targetName
	}
	if m.DomainName != expectedName {
		return nil, nil, ErrEdit
	}
	c.fileID, c.domainID = m.FileID, m.DomainID
	if m.Generated != ref {
		return nil, nil, ErrEdit
	}
	if len(m.Basis.Descriptor) != 0 {
		if d, decodeErr := contract.DecodeGenesisDescriptorCore(m.Basis.Descriptor); decodeErr == nil {
			c.descriptor = contract.GenesisArtifactFact{Kind: 1, ArtifactID: d.DescriptorArtifactID, BodyDigest: contract.Hash(m.Basis.Descriptor), BodyLength: uint64(len(m.Basis.Descriptor)), DurabilityProfile: 1, Outcome: 1}
			c.manifestID = d.ManifestArtifactID
		}
	}
	s.candidate = c
	complete = true
	return c, m, nil
}

type candidateWriter struct {
	ctx       context.Context
	remaining int64
	image     *Image
	hash      hash.Hash
	writer    io.Writer
	err       error
}

func (w *candidateWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if err := w.ctx.Err(); err != nil {
		w.err = errors.Join(ErrEdit, err)
		return 0, w.err
	}
	if int64(len(p)) > w.remaining {
		w.err = ErrEditBounds
		return 0, w.err
	}
	n, err := w.writer.Write(p)
	if n < 0 || n > len(p) {
		w.err = ErrEdit
		return 0, w.err
	}
	w.remaining -= int64(n)
	w.image.size += int64(n)
	_, _ = w.hash.Write(p[:n])
	if n != len(p) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	w.err = err
	return n, err
}

type candidateFileWriter struct {
	file  *os.File
	write func(*os.File, []byte) (int, error)
}

func (w candidateFileWriter) Write(p []byte) (int, error) {
	n, err := w.write(w.file, p)
	if n < 0 || n > len(p) {
		return 0, errors.Join(ErrEdit, err)
	}
	if n != len(p) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	return n, err
}

func (s *EditSession) emit(ctx context.Context, dir, pattern string, limit int64, emit func(io.Writer) error) (image *Image, err error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	image = &Image{file: f}
	complete := false
	defer func() {
		if !complete {
			err = errors.Join(err, closeEditImage(image, f.Name()))
			image = nil
		}
	}()
	if err := image.acquireName(); err != nil {
		return image, err
	}
	h := sha256.New()
	buffer := bufio.NewWriterSize(candidateFileWriter{file: f, write: s.io.write}, WindowBytes)
	w := &candidateWriter{ctx: ctx, remaining: limit, image: image, hash: h, writer: buffer}
	if err := emit(w); err != nil {
		return image, errors.Join(ErrEdit, err)
	}
	if w.err != nil {
		return image, errors.Join(ErrEdit, w.err)
	}
	if ctx.Err() != nil {
		return image, errors.Join(ErrEdit, ctx.Err())
	}
	if err := buffer.Flush(); err != nil {
		return image, errors.Join(ErrEdit, err)
	}
	if ctx.Err() != nil {
		return image, errors.Join(ErrEdit, ctx.Err())
	}
	copy(image.digest[:], h.Sum(nil))
	complete = true
	return image, nil
}

func (s *EditSession) Commit(ctx context.Context, candidate *EditCandidate) (*PairDelivery, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	delivery, err := s.commit(editCallContext(ctx, call), candidate, call)
	finishEditCall(call, err)
	return delivery, err
}

func (s *EditSession) commit(ctx context.Context, c *EditCandidate, call *telemetry.Call) (*PairDelivery, error) {
	if s == nil || s.closed || s.attempted || c == nil || c != s.candidate || c.session != s || ctx == nil || s.locks == nil || c.pair.validateCaptured() != nil {
		return nil, ErrEdit
	}
	s.attempted = true
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	call.Checkpoint(telemetry.DiagnosticCandidatePersistence, telemetry.DiagnosticReasonNone)
	if err := s.preparePending(ctx, c); err != nil {
		if c.durable {
			return nil, s.unknown(c, err)
		}
		return nil, err
	}
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	delivery, err := s.completePending(ctx, s.transaction)
	if err != nil {
		unknown := s.unknown(c, err)
		unknown.readback = delivery
		return delivery, unknown
	}
	c.durable = false
	return delivery, nil
}

func (s *EditSession) unknown(c *EditCandidate, cause error) *UnknownEdit {
	generated := ""
	if c.pair.Generated != nil {
		generated = c.pair.Generated.path
	}
	o := &EditObservation{predecessor: s.predecessor, candidate: c, editable: s.path, generated: generated}
	if s.borrowed {
		o.predecessor = nil
	}
	s.predecessor, s.candidate = nil, nil
	if c.durable {
		cause = errors.Join(ErrPendingEdit, cause)
	}
	recovery := pendingIdentity{}
	if c.durable {
		recovery = confirmedPendingIdentity(s.transaction)
	}
	return &UnknownEdit{Observation: o, recovery: recovery, cause: cause}
}

func (s *EditSession) flushCandidate(image *Image) error {
	if image == nil || image.file == nil {
		return ErrEdit
	}
	if err := image.checkName(); err != nil {
		return err
	}
	f := image.file
	if err := s.io.syncFile(f); err != nil {
		return errors.Join(ErrEdit, err)
	}
	closeErr := s.io.close(f)
	image.file = nil
	if closeErr != nil {
		return errors.Join(ErrEdit, closeErr)
	}
	read, err := os.Open(f.Name())
	if err != nil {
		return errors.Join(ErrEdit, err)
	}
	image.file = read
	opened, err := read.Stat()
	identity, identityErr := nativeFact(opened)
	if err != nil || identityErr != nil || identity != image.temporary {
		return errors.Join(ErrEdit, err, identityErr)
	}
	if err := image.checkName(); err != nil {
		return err
	}
	if s.candidate != nil {
		return sealPair(s.candidate.pair)
	}
	return nil
}

func (s *EditSession) installInitializationArtifact(ctx context.Context, image *Image) error {
	dir, err := os.Lstat(filepath.Dir(image.path))
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrEdit, err)
	}
	if err := s.io.installAbsent(image.file.Name(), image.path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return errors.Join(ErrEdit, err)
		}
		return s.syncExistingInitializationArtifact(ctx, image)
	}
	image.named = false
	return editError(s.io.syncDir(filepath.Dir(image.path)))
}

func (s *EditSession) syncExistingInitializationArtifact(ctx context.Context, image *Image) error {
	dir, err := os.Lstat(filepath.Dir(image.path))
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrEdit, err)
	}
	if err := compareEditImage(ctx, image.path, image, false); err != nil {
		return errors.Join(ErrEdit, err)
	}
	f, err := os.Open(image.path)
	if err != nil {
		return errors.Join(ErrEdit, err)
	}
	if err := errors.Join(s.io.syncFile(f), s.io.close(f)); err != nil {
		return errors.Join(ErrEdit, err)
	}
	return editError(s.io.syncDir(filepath.Dir(image.path)))
}

func editError(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(ErrEdit, err)
}

func editCallContext(ctx context.Context, call *telemetry.Call) context.Context {
	if ctx == nil {
		return nil
	}
	return telemetry.CallContext(ctx, call)
}

func ensureEditDirectory(path string, syncDir func(string) error) error {
	err := os.Mkdir(path, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return errors.Join(ErrEdit, err)
	}
	if _, e := inspectEditDirectory(path); e != nil {
		return e
	}
	if err == nil {
		return editError(syncDir(filepath.Dir(path)))
	}
	return nil
}

func syncEditDirectory(path string) (err error) {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func compareEditImage(ctx context.Context, path string, image *Image, predecessor bool) (resultErr error) {
	if ctx == nil || image == nil || image.file == nil {
		return ErrEdit
	}
	if predecessor && image.sourceInfo == nil {
		return ErrEdit
	}
	changed := ErrEdit
	if predecessor {
		changed = errors.Join(ErrEdit, ErrSourceChanged)
	}
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.Join(changed, err)
		}
		return errors.Join(ErrEdit, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || !singleLink(before) || before.Size() != image.size {
		return changed
	}
	if predecessor && (!os.SameFile(before, image.sourceInfo) || !sameMetadata(before, image.sourceInfo)) {
		return changed
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.Join(ErrEdit, err)
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	opened, err := f.Stat()
	if err != nil {
		return errors.Join(ErrEdit, err)
	}
	if !os.SameFile(before, opened) || !sameMetadata(before, opened) {
		return changed
	}
	buffer := make([]byte, WindowBytes)
	actual, expected := buffer[:WindowBytes/2], buffer[WindowBytes/2:]
	h := sha256.New()
	for off := int64(0); off < image.size; {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrEdit, err)
		}
		n := int(min(image.size-off, int64(len(actual))))
		if _, err := io.ReadFull(f, actual[:n]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return errors.Join(changed, err)
			}
			return errors.Join(ErrEdit, err)
		}
		if _, err := io.ReadFull(io.NewSectionReader(image, off, int64(n)), expected[:n]); err != nil {
			return errors.Join(ErrEdit, err)
		}
		if !bytes.Equal(actual[:n], expected[:n]) {
			return changed
		}
		_, _ = h.Write(actual[:n])
		off += int64(n)
	}
	if n, err := f.Read(actual[:1]); n != 0 || err != io.EOF {
		if n != 0 {
			return errors.Join(changed, err)
		}
		return errors.Join(ErrEdit, err)
	}
	after, err := f.Stat()
	if err != nil {
		return errors.Join(ErrEdit, err)
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.Join(changed, err)
		}
		return errors.Join(ErrEdit, err)
	}
	if !os.SameFile(opened, pathAfter) || !sameMetadata(opened, after) || !sameMetadata(opened, pathAfter) || !equalDigest(image.digest, h.Sum(nil)) {
		return changed
	}
	return nil
}

func closeEditImage(image *Image, path string) error {
	if image == nil {
		return nil
	}
	if image.named && image.file != nil && path != image.file.Name() {
		return ErrEdit
	}
	return image.Close()
}
func (c *EditCandidate) close() error {
	if c == nil {
		return nil
	}
	if c.durable {
		var err error
		for _, image := range []*Image{c.pair.Editable, c.pair.Generated} {
			if image != nil && image.file != nil {
				err = errors.Join(err, image.file.Close())
				image.file = nil
			}
		}
		return err
	}
	var err error
	for index, identity := range c.installations {
		if identity == (diskIdentity{}) {
			continue
		}
		path := c.editableTemp
		if index == 1 {
			path = c.generatedTemp
		}
		if removeErr := removeOwnedTemporary(path+".install", identity, os.Remove); removeErr != nil {
			err = errors.Join(err, removeErr)
		} else {
			c.installations[index] = diskIdentity{}
		}
	}
	if c.pending != nil {
		if c.recordNative != (diskIdentity{}) {
			if cleanupErr := removeOwnedTemporary(c.pending.path(), c.recordNative, c.session.io.remove); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			} else if cleanupErr := c.session.io.syncDir(filepath.Dir(c.pending.path())); cleanupErr != nil {
				err = errors.Join(err, editError(cleanupErr))
			} else {
				c.recordNative = diskIdentity{}
			}
		}
		if cleanupErr := c.session.cleanupScratch(c.pending); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		} else {
			c.pending = nil
			c.scratch = ""
			c.scratchNative = diskIdentity{}
		}
	} else if c.scratch != "" {
		if cleanupErr := c.session.cleanupScratchDirectory(c.scratch, c.scratchNative, "record", true); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		} else {
			c.scratch = ""
			c.scratchNative = diskIdentity{}
		}
	}
	err = errors.Join(err, closeEditImage(c.pair.Editable, c.editableTemp))
	if c.pair.Generated != nil {
		err = errors.Join(err, closeEditImage(c.pair.Generated, c.generatedTemp))
	}
	return err
}

// Close completes private cleanup before unlocking. On UnknownEdit ownership
// has already moved to its Observation, so Close preserves those exact images.
func (s *EditSession) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var err error
	if !s.borrowed {
		err = s.predecessor.Close()
	}
	if s.candidate != nil {
		err = errors.Join(err, s.candidate.close())
	}
	if s.locks != nil {
		err = errors.Join(err, s.locks.close())
		s.locks = nil
	}
	return err
}
