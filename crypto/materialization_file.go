package crypto

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

var (
	ErrMaterializationTarget  = errors.New("materialization file target refused")
	ErrMaterializationProfile = errors.New("materialization native profile unavailable")
	ErrMaterializationFileIO  = errors.New("materialization file inspection unavailable")
)

const materializationCandidatePrefix = ".enkv-materialize-"
const materializationCandidateNameBytes = len(materializationCandidatePrefix) + 32

type materializationProtectedPath struct {
	path string
	info os.FileInfo
}

type materializationReservedPath struct {
	original, path string
	info           os.FileInfo
}

type materializationFileIO struct {
	create   func(string) (*os.File, error)
	open     func(string, contract.MaterializationStage) (*os.File, error)
	lstat    func(string) (os.FileInfo, error)
	stat     func(*os.File, contract.MaterializationStage) (os.FileInfo, error)
	chmod    func(*os.File, os.FileMode) error
	write    func(*os.File, []byte) (int, error)
	read     func(*os.File, []byte, contract.MaterializationStage) (int, error)
	syncFile func(*os.File) error
	syncDir  func(*os.File) error
	close    func(*os.File, contract.MaterializationStage) error
	rename   func(string, string) (contract.MaterializationReplacement, error)
	remove   func(string) error
}

// MaterializationFileTarget fixes one trusted native destination and its source
// exclusions. It exposes no plaintext writer and can be installed only once.
type MaterializationFileTarget struct {
	target    contract.MaterializationTarget
	path      string
	protected []materializationProtectedPath
	reserved  []materializationReservedPath
	io        materializationFileIO
	mu        sync.Mutex
	started   bool
}

// NewMaterializationFileTarget admits an existing trusted parent and at most the
// captured source pair. Source-owned candidates and transaction directories are excluded.
// It retains no file handles; construction creates no candidate.
func NewMaterializationFileTarget(target contract.MaterializationTarget, protectedPaths []string) (*MaterializationFileTarget, error) {
	if len(protectedPaths) > 2 || !materializationNativePathValid(target.Path) || target.SurfaceID.IsZero() {
		return nil, ErrMaterializationTarget
	}
	for _, path := range protectedPaths {
		if !materializationNativePathValid(path) {
			return nil, ErrMaterializationTarget
		}
	}
	if target.Format != contract.MaterializationDotenvFormat || target.NativeProfile != contract.MaterializationNativeFileProfile ||
		(runtime.GOOS != "darwin" || runtime.GOARCH != "arm64") && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
		return nil, ErrMaterializationProfile
	}
	path, err := materializationCanonicalPath(target.Path)
	if err != nil {
		return nil, err
	}
	if len(filepath.Dir(path))+1+materializationCandidateNameBytes > contract.MaterializationMaxPath {
		return nil, ErrMaterializationTarget
	}
	t := &MaterializationFileTarget{target: target, path: path, io: nativeMaterializationFileIO()}
	for _, source := range protectedPaths {
		canonical, err := materializationCanonicalPath(source)
		if err != nil {
			return nil, ErrMaterializationFileIO
		}
		info, err := os.Stat(canonical)
		if err != nil {
			return nil, ErrMaterializationFileIO
		}
		t.protected = append(t.protected, materializationProtectedPath{path: canonical, info: info})
		for _, name := range [...]string{".enkv", ".enkv-locks", ".enkv-pending", ".enkv-transactions"} {
			original := filepath.Join(filepath.Dir(canonical), name)
			reserved, err := filepath.EvalSymlinks(original)
			if errors.Is(err, os.ErrNotExist) {
				reserved = original
			} else if err != nil {
				return nil, ErrMaterializationFileIO
			}
			info, err := os.Stat(reserved)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, ErrMaterializationFileIO
			}
			t.reserved = append(t.reserved, materializationReservedPath{original: original, path: reserved, info: info})
		}
	}
	if err := t.checkTarget(); err != nil {
		return nil, err
	}
	return t, nil
}

func materializationNativePathValid(path string) bool {
	return len(path) > 0 && len(path) <= contract.MaterializationMaxPath && utf8.ValidString(path) && !strings.ContainsRune(path, 0) && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func materializationCanonicalPath(path string) (string, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrInvalid) || errors.Is(err, syscall.ENOTDIR) {
			return "", ErrMaterializationTarget
		}
		return "", ErrMaterializationFileIO
	}
	info, err := os.Stat(parent)
	if err != nil {
		return "", ErrMaterializationFileIO
	}
	if !info.IsDir() {
		return "", ErrMaterializationTarget
	}
	canonical := filepath.Join(parent, filepath.Base(path))
	if !materializationNativePathValid(canonical) {
		return "", ErrMaterializationTarget
	}
	return canonical, nil
}

func (t *MaterializationFileTarget) Target() contract.MaterializationTarget {
	if t == nil {
		return contract.MaterializationTarget{}
	}
	return t.target
}
func (t *MaterializationFileTarget) Identity() contract.ID { return t.Target().SurfaceID }
func (t *MaterializationFileTarget) matches(target contract.MaterializationTarget) bool {
	return t != nil && t.target.Valid() && t.target == target
}

func (t *MaterializationFileTarget) checkTarget() error {
	path, err := materializationCanonicalPath(t.target.Path)
	if err != nil {
		return err
	}
	if path != t.path {
		return ErrMaterializationTarget
	}
	info, err := t.io.lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrMaterializationFileIO
	}
	if err == nil && !info.Mode().IsRegular() {
		return ErrMaterializationTarget
	}
	var sourceParents [2]os.FileInfo
	parentCount := 0
	for _, protected := range t.protected {
		if protected.info != nil {
			current, err := os.Stat(protected.path)
			if err != nil {
				return ErrMaterializationFileIO
			}
			if info != nil && os.SameFile(info, current) {
				return ErrMaterializationTarget
			}
			parent, err := os.Stat(filepath.Dir(protected.path))
			if err != nil {
				return ErrMaterializationFileIO
			}
			sourceParents[parentCount] = parent
			parentCount++
		}
		if path == protected.path || strings.HasPrefix(path, protected.path+string(filepath.Separator)) || info != nil && protected.info != nil && os.SameFile(info, protected.info) {
			return ErrMaterializationTarget
		}
	}
	reservedIdentities := make([]os.FileInfo, 0, 2*len(t.reserved))
	for _, reserved := range t.reserved {
		if reserved.info != nil {
			reservedIdentities = append(reservedIdentities, reserved.info)
		}
		current, err := filepath.EvalSymlinks(reserved.original)
		if errors.Is(err, os.ErrNotExist) {
			current = reserved.original
		} else if err != nil {
			return ErrMaterializationFileIO
		}
		for _, reservedPath := range [...]string{reserved.original, reserved.path, current} {
			if path == reservedPath || strings.HasPrefix(path, reservedPath+string(filepath.Separator)) {
				return ErrMaterializationTarget
			}
		}
		info, err := os.Stat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrMaterializationFileIO
		}
		if info != nil {
			reservedIdentities = append(reservedIdentities, info)
		}
	}
	if len(reservedIdentities) > 0 {
		for ancestor := filepath.Dir(path); ; ancestor = filepath.Dir(ancestor) {
			info, err := os.Stat(ancestor)
			if err != nil {
				return ErrMaterializationFileIO
			}
			for _, reserved := range reservedIdentities {
				if os.SameFile(info, reserved) {
					return ErrMaterializationTarget
				}
			}
			if ancestor == filepath.Dir(ancestor) {
				break
			}
		}
	}
	return t.checkArtifactNamespace(sourceParents[:parentCount])
}

func (t *MaterializationFileTarget) checkArtifactNamespace(sourceParents []os.FileInfo) error {
	if len(sourceParents) == 0 {
		return nil
	}
	for _, path := range [...]string{t.target.Path, t.path} {
		for coordinate := path; coordinate != filepath.Dir(coordinate); coordinate = filepath.Dir(coordinate) {
			if !materializationReservedComponent(filepath.Base(coordinate)) {
				continue
			}
			parent, err := os.Stat(filepath.Dir(coordinate))
			if err != nil {
				return ErrMaterializationFileIO
			}
			for _, sourceParent := range sourceParents {
				if os.SameFile(parent, sourceParent) {
					return ErrMaterializationTarget
				}
			}
		}
	}
	return nil
}

func materializationReservedComponent(name string) bool {
	for _, prefix := range [...]string{".enkv-editable-", ".enkv-generated-"} {
		if materializationASCIIPrefix(name, prefix) {
			return true
		}
	}
	for _, directory := range [...]string{".enkv", ".enkv-locks", ".enkv-pending", ".enkv-transactions"} {
		if len(name) == len(directory) && materializationASCIIPrefix(name, directory) {
			return true
		}
	}
	return false
}

func materializationASCIIPrefix(name, prefix string) bool {
	if len(name) < len(prefix) {
		return false
	}
	for at := range len(prefix) {
		b := name[at]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != prefix[at] {
			return false
		}
	}
	return true
}

type materializationFileRun struct {
	target        *MaterializationFileTarget
	ctx           context.Context
	call          *telemetry.Call
	env           materializationEnv
	completion    contract.MaterializationCompletion
	candidate     *os.File
	candidatePath string
	candidateInfo os.FileInfo
	identity      *os.File
	directory     *os.File
}

func (t *MaterializationFileTarget) install(ctx context.Context, env materializationEnv, call *telemetry.Call) (completion contract.MaterializationCompletion) {
	r := materializationFileRun{target: t, ctx: ctx, env: env, call: call, completion: contract.MaterializationCompletion{StateResult: contract.MaterializationUnavailable, Facts: contract.InitialMaterializationFacts()}}
	if t == nil || ctx == nil || env.encodedLength <= 0 {
		r.fail(contract.MaterializationRefused, contract.MaterializationAdmissionStage, contract.MaterializationInvalidAdmission)
		return r.completion
	}
	t.mu.Lock()
	started := t.started
	t.started = true
	t.mu.Unlock()
	if started || !t.target.Valid() {
		r.fail(contract.MaterializationRefused, contract.MaterializationAdmissionStage, contract.MaterializationInvalidAdmission)
		return r.completion
	}
	if r.canceled(contract.MaterializationStaging) {
		return r.completion
	}
	if err := t.checkTarget(); err != nil {
		if errors.Is(err, ErrMaterializationTarget) {
			r.fail(contract.MaterializationRefused, contract.MaterializationAdmissionStage, contract.MaterializationInvalidTarget)
		} else {
			r.fail(contract.MaterializationUnavailable, contract.MaterializationAdmissionStage, contract.MaterializationIOFailure)
		}
		return r.completion
	}
	defer func() {
		r.finish()
		completion = r.completion
	}()
	if r.canceled(contract.MaterializationStaging) {
		return r.completion
	}
	call.Checkpoint(telemetry.DiagnosticLocalStaging, telemetry.DiagnosticReasonNone)
	r.completion.Facts.NativeCompletion = contract.MaterializationIncomplete
	f, err := t.io.create(filepath.Dir(t.path))
	if err != nil || f == nil {
		r.failIO(contract.MaterializationStaging, err)
		return r.completion
	}
	r.candidate, r.candidatePath = f, f.Name()
	r.completion.Facts.Cleanup = contract.MaterializationCandidateCleanupUnknown
	r.completion.Facts.Disclosure = contract.MaterializationDisclosureUnknown
	r.candidateInfo, err = t.io.stat(f, contract.MaterializationStaging)
	if err != nil || !r.candidateInfo.Mode().IsRegular() {
		r.failIO(contract.MaterializationStaging, err)
		return r.completion
	}
	if r.canceled(contract.MaterializationStaging) {
		return r.completion
	}
	if err := t.io.chmod(f, 0600); err != nil {
		r.failIO(contract.MaterializationStaging, err)
		return r.completion
	}
	if !r.pinCandidateIdentity() {
		return r.completion
	}
	if err := env.writeTo(ctx, materializationFileWriter{run: &r}); err != nil {
		r.failIO(contract.MaterializationStaging, err)
		return r.completion
	}
	if r.canceled(contract.MaterializationCandidateSync) {
		return r.completion
	}
	if err := t.io.syncFile(f); err != nil {
		r.failIO(contract.MaterializationCandidateSync, err)
		return r.completion
	}
	if r.canceled(contract.MaterializationCandidateClose) {
		return r.completion
	}
	r.candidate = nil
	if err := t.io.close(f, contract.MaterializationCandidateClose); err != nil {
		r.failIO(contract.MaterializationCandidateClose, err)
		return r.completion
	}
	if !r.verify(r.candidatePath, contract.MaterializationCandidateVerification) || r.canceled(contract.MaterializationRename) {
		return r.completion
	}
	if err := t.checkTarget(); err != nil {
		r.failIO(contract.MaterializationRename, err)
		return r.completion
	}
	if r.canceled(contract.MaterializationRename) {
		return r.completion
	}
	replacement, err := t.io.rename(r.candidatePath, t.path)
	r.completion.Facts.Replacement = replacement
	if replacement == contract.MaterializationReplaced {
		r.completion.Facts.Cleanup = contract.MaterializationCandidateRenamed
	}
	call.Checkpoint(telemetry.DiagnosticLocalReplacement, materializationFileDiagnosticReason(replacement, err))
	if err != nil || replacement != contract.MaterializationReplaced {
		r.failIO(contract.MaterializationRename, err)
		return r.completion
	}
	if r.canceled(contract.MaterializationDirectorySync) {
		return r.completion
	}
	r.directory, err = t.io.open(filepath.Dir(t.path), contract.MaterializationDirectorySync)
	if err != nil {
		r.failIO(contract.MaterializationDirectorySync, err)
		return r.completion
	}
	if r.canceled(contract.MaterializationDirectorySync) {
		return r.completion
	}
	if err := t.io.syncDir(r.directory); err != nil {
		r.failIO(contract.MaterializationDirectorySync, err)
		return r.completion
	}
	if !r.verify(t.path, contract.MaterializationInstalledVerification) {
		return r.completion
	}
	r.canceled(contract.MaterializationDirectoryClose)
	return r.completion
}

// The separate handle pins native identity across the required writer and
// readback closes. FileInfo alone cannot distinguish a recycled inode.
func (r *materializationFileRun) pinCandidateIdentity() bool {
	if r.canceled(contract.MaterializationStaging) {
		return false
	}
	file, err := r.target.io.open(r.candidatePath, contract.MaterializationStaging)
	if err != nil {
		r.failIO(contract.MaterializationStaging, err)
		return false
	}
	transferred := false
	defer func() {
		if !transferred {
			r.close(file, contract.MaterializationSinkClose)
		}
	}()
	if r.canceled(contract.MaterializationStaging) {
		return false
	}
	info, err := r.target.io.stat(file, contract.MaterializationStaging)
	if err != nil {
		r.failIO(contract.MaterializationStaging, err)
		return false
	}
	if r.canceled(contract.MaterializationStaging) {
		return false
	}
	if !info.Mode().IsRegular() || info.Mode() != 0600 || !os.SameFile(r.candidateInfo, info) {
		r.failIO(contract.MaterializationStaging, nil)
		return false
	}
	r.identity, transferred = file, true
	return true
}

func (r *materializationFileRun) fail(state contract.MaterializationStateResult, stage contract.MaterializationStage, reason contract.MaterializationFailureReason) {
	if r.completion.Facts.Failure == nil {
		r.completion.StateResult = state
		r.completion.Facts.Failure = &contract.MaterializationFailure{Stage: stage, Reason: reason}
	}
}
func materializationFileReason(err error) contract.MaterializationFailureReason {
	switch {
	case errors.Is(err, context.Canceled):
		return contract.MaterializationCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return contract.MaterializationDeadlineExceeded
	default:
		return contract.MaterializationIOFailure
	}
}
func (r *materializationFileRun) failIO(stage contract.MaterializationStage, err error) {
	r.fail(contract.MaterializationUnavailable, stage, materializationFileReason(err))
}
func (r *materializationFileRun) canceled(stage contract.MaterializationStage) bool {
	if err := r.ctx.Err(); err != nil {
		r.failIO(stage, err)
		return true
	}
	return false
}
func (r *materializationFileRun) close(f *os.File, stage contract.MaterializationStage) {
	if err := r.target.io.close(f, stage); err != nil {
		failure := &contract.MaterializationFailure{Stage: stage, Reason: materializationFileReason(err)}
		if r.completion.Facts.Failure == nil {
			r.fail(contract.MaterializationUnavailable, failure.Stage, failure.Reason)
		} else if r.completion.Facts.CleanupFailure == nil {
			r.completion.Facts.CleanupFailure = failure
		}
	}
}

func (r *materializationFileRun) verify(path string, stage contract.MaterializationStage) (verified bool) {
	if r.canceled(stage) {
		return false
	}
	verification := &r.completion.Facts.CandidateVerification
	closeStage := contract.MaterializationCandidateClose
	if stage == contract.MaterializationInstalledVerification {
		verification = &r.completion.Facts.InstalledVerification
		closeStage = contract.MaterializationInstalledClose
	}
	*verification = contract.MaterializationVerificationFailed
	info, err := r.target.io.lstat(path)
	if err != nil {
		r.failIO(stage, err)
		return false
	}
	if r.canceled(stage) {
		return false
	}
	if !info.Mode().IsRegular() || info.Mode() != 0600 || info.Size() != int64(r.env.encodedLength) || !os.SameFile(r.candidateInfo, info) {
		r.verificationMismatch(stage, info)
		return false
	}
	f, err := r.target.io.open(path, stage)
	if err != nil {
		r.failIO(stage, err)
		return false
	}
	defer func() {
		r.close(f, closeStage)
		if r.completion.Facts.Failure != nil {
			verified = false
		}
	}()
	if r.canceled(stage) {
		return false
	}
	info, err = r.target.io.stat(f, stage)
	if err != nil {
		r.failIO(stage, err)
		return false
	}
	if r.canceled(stage) {
		return false
	}
	if !info.Mode().IsRegular() || info.Mode() != 0600 || info.Size() != int64(r.env.encodedLength) || !os.SameFile(r.candidateInfo, info) {
		r.verificationMismatch(stage, info)
		return false
	}
	matched, err := r.env.matches(r.ctx, materializationFileReader{run: r, file: f, stage: stage})
	if err != nil {
		r.failIO(stage, err)
		return false
	}
	if matched {
		*verification = contract.MaterializationVerified
		r.completion.Facts.Disclosure = contract.MaterializationDisclosureOccurred
	}
	if r.canceled(stage) {
		return false
	}
	if !matched {
		r.verificationMismatch(stage, info)
		return false
	}
	return true
}

func (r *materializationFileRun) verificationMismatch(stage contract.MaterializationStage, info os.FileInfo) {
	if stage == contract.MaterializationInstalledVerification && !os.SameFile(r.candidateInfo, info) {
		r.fail(contract.MaterializationUnavailable, stage, contract.MaterializationCompetingReplacement)
		return
	}
	r.fail(contract.MaterializationPositiveDefect, stage, contract.MaterializationVerificationMismatch)
}

func (r *materializationFileRun) finish() {
	if r.identity != nil && r.candidate != nil {
		r.close(r.candidate, contract.MaterializationSinkClose)
		r.candidate = nil
	}
	if r.directory != nil {
		r.close(r.directory, contract.MaterializationDirectoryClose)
		r.directory = nil
	}
	if r.completion.Facts.Failure == nil {
		r.canceled(contract.MaterializationDirectoryClose)
	}
	if r.candidatePath != "" && r.completion.Facts.Replacement != contract.MaterializationReplaced {
		r.cleanupCandidate()
	}
	// A failed identity acquisition leaves the writer as the only live pin.
	if r.candidate != nil {
		r.close(r.candidate, contract.MaterializationSinkClose)
		r.candidate = nil
	}
	if r.identity != nil {
		r.close(r.identity, contract.MaterializationSinkClose)
		r.identity = nil
	}
	if r.completion.Facts.Failure == nil {
		r.canceled(contract.MaterializationSinkClose)
	}
	if r.completion.Facts.Failure == nil {
		r.completion.StateResult = contract.MaterializationSuccess
		r.completion.Facts.NativeCompletion = contract.MaterializationComplete
	}
	reason := telemetry.DiagnosticReasonNone
	if r.completion.Facts.Failure != nil {
		reason = telemetry.DiagnosticReasonEvidenceUnavailable
		if r.completion.Facts.Failure.Reason == contract.MaterializationCanceled || r.completion.Facts.Failure.Reason == contract.MaterializationDeadlineExceeded {
			reason = telemetry.DiagnosticReasonCancelled
		}
	}
	r.call.Checkpoint(telemetry.DiagnosticLocalCompletion, reason)
}

func (r *materializationFileRun) cleanupCandidate() {
	facts := &r.completion.Facts
	info, err := r.target.io.lstat(r.candidatePath)
	if errors.Is(err, os.ErrNotExist) && facts.Replacement == contract.MaterializationNotReplaced {
		facts.Cleanup = contract.MaterializationCandidateRemoved
		return
	}
	if err != nil || r.candidateInfo == nil || !info.Mode().IsRegular() || !os.SameFile(r.candidateInfo, info) {
		facts.Cleanup = contract.MaterializationCandidateCleanupUnknown
	} else if err := r.target.io.remove(r.candidatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		facts.Cleanup = contract.MaterializationCandidateCleanupFailed
	} else {
		facts.Cleanup = contract.MaterializationCandidateRemoved
		return
	}
	facts.ResiduePath = r.candidatePath
	failure := &contract.MaterializationFailure{Stage: contract.MaterializationCleanup, Reason: contract.MaterializationCleanupFailure}
	if facts.Failure == nil {
		r.fail(contract.MaterializationUnavailable, failure.Stage, failure.Reason)
	} else if facts.CleanupFailure == nil {
		facts.CleanupFailure = failure
	}
}

type materializationFileWriter struct{ run *materializationFileRun }

func (w materializationFileWriter) Write(p []byte) (int, error) {
	n, err := w.run.target.io.write(w.run.candidate, p)
	if n > 0 {
		w.run.completion.Facts.Disclosure = contract.MaterializationDisclosureOccurred
	}
	return n, err
}

type materializationFileReader struct {
	run   *materializationFileRun
	file  *os.File
	stage contract.MaterializationStage
}

func (r materializationFileReader) Read(p []byte) (int, error) {
	return r.run.target.io.read(r.file, p, r.stage)
}

func materializationFileDiagnosticReason(replacement contract.MaterializationReplacement, err error) telemetry.DiagnosticReason {
	if replacement == contract.MaterializationReplacementUnknown {
		return telemetry.DiagnosticReasonUncertain
	}
	if err != nil {
		return telemetry.DiagnosticReasonEvidenceUnavailable
	}
	return telemetry.DiagnosticReasonNone
}

var _ io.Writer = materializationFileWriter{}
