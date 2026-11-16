package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/telemetry"
)

const (
	manifestMaxPath            = 4096
	manifestReadbackBytes      = 64 * 1024
	manifestCandidatePrefix    = ".enkv-manifest-"
	manifestCandidateNameBytes = len(manifestCandidatePrefix) + 32
)

type manifestProtectedPath struct {
	original string
	path     string
	info     os.FileInfo
	parent   os.FileInfo
}

type manifestReservedPath struct {
	original, path string
	info           os.FileInfo
}

type manifestFileIO struct {
	create   func(string) (*os.File, error)
	open     func(string, ManifestFileStage) (*os.File, error)
	lstat    func(string) (os.FileInfo, error)
	stat     func(*os.File, ManifestFileStage) (os.FileInfo, error)
	chmod    func(*os.File, os.FileMode) error
	write    func(*os.File, []byte) (int, error)
	read     func(*os.File, []byte, ManifestFileStage) (int, error)
	syncFile func(*os.File) error
	syncDir  func(*os.File) error
	close    func(*os.File, ManifestFileStage) error
	rename   func(string, string) (ManifestReplacement, error)
	remove   func(string) error
}

type manifestFileTarget struct {
	original    string
	path        string
	parent      os.FileInfo
	protected   []manifestProtectedPath
	reserved    []manifestReservedPath
	checkSource func(context.Context) error
	io          manifestFileIO
	mu          sync.Mutex
	started     bool
}

func newManifestFileTarget(path string, protectedPaths []string, checkSource func(context.Context) error) (*manifestFileTarget, ManifestDelivery) {
	facts := initialManifestDelivery()
	refuse := func(reason ManifestFileReason) (*manifestFileTarget, ManifestDelivery) {
		facts.Failure = &ManifestFileFailure{Stage: ManifestPreflightStage, Reason: reason}
		return nil, facts
	}
	if !manifestPathValid(path) {
		return refuse(ManifestInvalidTarget)
	}
	path = strings.Clone(path)
	facts.TargetPath = path
	if len(protectedPaths) > 2 || (runtime.GOOS != "darwin" || runtime.GOARCH != "arm64") && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
		return refuse(ManifestInvalidTarget)
	}
	for _, source := range protectedPaths {
		if !manifestPathValid(source) {
			return refuse(ManifestInvalidTarget)
		}
	}
	canonical, reason := manifestCanonicalPath(path)
	if reason != "" {
		return refuse(reason)
	}
	if len(filepath.Dir(canonical))+1+manifestCandidateNameBytes > manifestMaxPath {
		return refuse(ManifestInvalidTarget)
	}
	facts.TargetPath = canonical
	parent, err := os.Stat(filepath.Dir(canonical))
	if err != nil {
		return refuse(ManifestIOFailure)
	}
	t := &manifestFileTarget{original: path, path: canonical, parent: parent, checkSource: checkSource, io: nativeManifestFileIO()}
	for _, source := range protectedPaths {
		resolved, reason := manifestCanonicalPath(source)
		if reason != "" {
			return refuse(reason)
		}
		info, err := os.Lstat(resolved)
		if err != nil {
			return refuse(ManifestIOFailure)
		}
		if !info.Mode().IsRegular() {
			return refuse(ManifestInvalidTarget)
		}
		parent, err := os.Stat(filepath.Dir(resolved))
		if err != nil {
			return refuse(ManifestIOFailure)
		}
		t.protected = append(t.protected, manifestProtectedPath{original: source, path: resolved, info: info, parent: parent})
		for _, name := range [...]string{".enkv", ".enkv-locks", ".enkv-pending", ".enkv-transactions"} {
			original := filepath.Join(filepath.Dir(resolved), name)
			reserved, err := filepath.EvalSymlinks(original)
			if errors.Is(err, os.ErrNotExist) {
				reserved = original
			} else if err != nil {
				return refuse(ManifestIOFailure)
			}
			info, err := os.Stat(reserved)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return refuse(ManifestIOFailure)
			}
			t.reserved = append(t.reserved, manifestReservedPath{original: original, path: reserved, info: info})
		}
	}
	if reason := t.checkTarget(); reason != "" {
		return refuse(reason)
	}
	return t, facts
}

func manifestPathValid(path string) bool {
	return len(path) > 0 && len(path) <= manifestMaxPath && utf8.ValidString(path) && !strings.ContainsRune(path, 0) && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func manifestCanonicalPath(path string) (string, ManifestFileReason) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrInvalid) || errors.Is(err, syscall.ENOTDIR) {
			return "", ManifestInvalidTarget
		}
		return "", ManifestIOFailure
	}
	info, err := os.Stat(parent)
	if err != nil {
		return "", ManifestIOFailure
	}
	canonical := filepath.Join(parent, filepath.Base(path))
	if !info.IsDir() || !manifestPathValid(canonical) {
		return "", ManifestInvalidTarget
	}
	return canonical, ""
}

func (t *manifestFileTarget) checkTarget() ManifestFileReason {
	canonical, reason := manifestCanonicalPath(t.original)
	if reason != "" {
		return reason
	}
	if canonical != t.path {
		return ManifestInvalidTarget
	}
	parent, err := os.Stat(filepath.Dir(t.path))
	if err != nil {
		return ManifestIOFailure
	}
	if !os.SameFile(t.parent, parent) {
		return ManifestInvalidTarget
	}
	info, err := t.io.lstat(t.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ManifestIOFailure
	}
	if err == nil && !info.Mode().IsRegular() {
		return ManifestInvalidTarget
	}
	for _, source := range t.protected {
		if t.path == source.path || t.original == source.original || info != nil && os.SameFile(info, source.info) {
			return ManifestSourceAlias
		}
		resolved, reason := manifestCanonicalPath(source.original)
		if reason != "" {
			return reason
		}
		if resolved != source.path {
			return ManifestInvalidTarget
		}
		current, err := os.Lstat(source.path)
		if err != nil {
			return ManifestIOFailure
		}
		if info != nil && os.SameFile(info, current) {
			return ManifestSourceAlias
		}
		currentParent, err := os.Stat(filepath.Dir(source.path))
		if err != nil {
			return ManifestIOFailure
		}
		if !current.Mode().IsRegular() || !os.SameFile(source.info, current) || !os.SameFile(source.parent, currentParent) {
			return ManifestInvalidTarget
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
			return ManifestIOFailure
		}
		for _, path := range [...]string{reserved.original, reserved.path, current} {
			if t.path == path || strings.HasPrefix(t.path, path+string(filepath.Separator)) {
				return ManifestReservedPath
			}
		}
		info, err := os.Stat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ManifestIOFailure
		}
		if info != nil {
			reservedIdentities = append(reservedIdentities, info)
		}
	}
	if len(reservedIdentities) > 0 {
		for ancestor := filepath.Dir(t.path); ; ancestor = filepath.Dir(ancestor) {
			info, err := os.Stat(ancestor)
			if err != nil {
				return ManifestIOFailure
			}
			for _, reserved := range reservedIdentities {
				if os.SameFile(info, reserved) {
					return ManifestReservedPath
				}
			}
			if ancestor == filepath.Dir(ancestor) {
				break
			}
		}
	}
	for _, path := range [...]string{t.original, t.path} {
		for coordinate := path; coordinate != filepath.Dir(coordinate); coordinate = filepath.Dir(coordinate) {
			if !manifestReservedComponent(filepath.Base(coordinate)) {
				continue
			}
			parent, err := os.Stat(filepath.Dir(coordinate))
			if err != nil {
				return ManifestIOFailure
			}
			for _, source := range t.protected {
				if os.SameFile(parent, source.parent) {
					return ManifestReservedPath
				}
			}
		}
	}
	return ""
}

func manifestReservedComponent(name string) bool {
	for _, prefix := range [...]string{".enkv-editable-", ".enkv-generated-", ".enkv", ".enkv-locks", ".enkv-pending", ".enkv-transactions"} {
		if len(name) < len(prefix) || len(name) != len(prefix) && prefix != ".enkv-editable-" && prefix != ".enkv-generated-" {
			continue
		}
		matches := true
		for at := range len(prefix) {
			b := name[at]
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b != prefix[at] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

type manifestFileRun struct {
	target        *manifestFileTarget
	ctx           context.Context
	artifact      []byte
	readback      []byte
	call          *telemetry.Call
	facts         ManifestDelivery
	writer        *os.File
	identity      *os.File
	directory     *os.File
	candidatePath string
	candidateInfo os.FileInfo
}

func (t *manifestFileTarget) install(ctx context.Context, identity ManifestArtifact, artifact []byte, call *telemetry.Call) (facts ManifestDelivery) {
	r := manifestFileRun{target: t, ctx: ctx, artifact: artifact, call: call, facts: initialManifestDelivery()}
	if t != nil {
		r.facts.TargetPath = t.path
	}
	if len(artifact) > 0 && uint64(len(artifact)) <= manifest.MaxArtifactBytes && !identity.RendererArtifactID.IsZero() && identity.FormatContractID != "" && len(identity.FormatContractID) <= manifest.MaxContractBytes && utf8.ValidString(identity.FormatContractID) {
		digest := sha256.Sum256(artifact)
		r.facts.Artifact = &ManifestArtifact{RendererArtifactID: identity.RendererArtifactID, FormatContractID: strings.Clone(identity.FormatContractID), Length: uint64(len(artifact)), Digest: contract.ID(digest)}
	}
	if t == nil || ctx == nil || r.facts.Artifact == nil {
		r.fail(ManifestPreflightStage, ManifestInvalidTarget)
		return r.facts
	}
	t.mu.Lock()
	started := t.started
	t.started = true
	t.mu.Unlock()
	if started {
		r.fail(ManifestPreflightStage, ManifestInvalidTarget)
		return r.facts
	}
	defer func() {
		r.finish()
		facts = r.facts
	}()
	if !r.preflight() {
		return r.facts
	}
	var err error
	r.directory, err = t.io.open(filepath.Dir(t.path), ManifestPreflightStage)
	if err != nil || r.directory == nil {
		r.failIO(ManifestPreflightStage, err)
		return r.facts
	}
	if r.canceled(ManifestPreflightStage) {
		return r.facts
	}
	parent, err := t.io.stat(r.directory, ManifestPreflightStage)
	if err != nil {
		r.failIO(ManifestPreflightStage, err)
		return r.facts
	}
	if !parent.IsDir() || !os.SameFile(t.parent, parent) {
		r.fail(ManifestPreflightStage, ManifestInvalidTarget)
		return r.facts
	}
	if r.canceled(ManifestCandidateCreateStage) {
		return r.facts
	}
	call.Checkpoint(telemetry.DiagnosticLocalStaging, telemetry.DiagnosticReasonNone)
	r.writer, err = t.io.create(filepath.Dir(t.path))
	if r.writer != nil {
		r.candidatePath = r.writer.Name()
		r.facts.CandidateCleanup = ManifestCandidateCleanupUnknown
		r.facts.ResiduePath = r.candidatePath
		r.facts.Replacement = ManifestNotReplaced
	}
	if err != nil || r.writer == nil {
		r.failIO(ManifestCandidateCreateStage, err)
		return r.facts
	}
	info, err := t.io.stat(r.writer, ManifestCandidateCreateStage)
	if err != nil {
		r.failIO(ManifestCandidateCreateStage, err)
		return r.facts
	}
	r.candidateInfo = info
	if !info.Mode().IsRegular() || filepath.Dir(r.candidatePath) != filepath.Dir(t.path) || !manifestPathValid(r.candidatePath) {
		r.fail(ManifestCandidateCreateStage, ManifestInvalidTarget)
		return r.facts
	}
	if r.canceled(ManifestCandidateCreateStage) {
		return r.facts
	}
	if err := t.io.chmod(r.writer, 0600); err != nil {
		r.failIO(ManifestCandidateCreateStage, err)
		return r.facts
	}
	if !r.pinCandidate() || r.canceled(ManifestCandidateWriteStage) {
		return r.facts
	}
	n, err := t.io.write(r.writer, artifact)
	if err != nil || n != len(artifact) {
		r.failIO(ManifestCandidateWriteStage, err)
		return r.facts
	}
	if r.canceled(ManifestCandidateSyncStage) {
		return r.facts
	}
	if err := t.io.syncFile(r.writer); err != nil {
		r.failIO(ManifestCandidateSyncStage, err)
		return r.facts
	}
	if r.canceled(ManifestCloseStage) {
		return r.facts
	}
	writer := r.writer
	r.writer = nil
	if !r.close(writer) || r.canceled(ManifestCloseStage) || !r.verify(r.candidatePath, ManifestCandidateVerifyStage) {
		return r.facts
	}
	if !r.preflight() || r.canceled(ManifestRenameStage) {
		return r.facts
	}
	info, err = t.io.lstat(r.candidatePath)
	if err != nil {
		r.failIO(ManifestRenameStage, err)
		return r.facts
	}
	if !r.matchesInfo(info) {
		r.fail(ManifestRenameStage, ManifestVerificationMismatch)
		return r.facts
	}
	if r.canceled(ManifestRenameStage) {
		return r.facts
	}
	replacement, err := t.io.rename(r.candidatePath, t.path)
	switch replacement {
	case ManifestReplaced, ManifestNotReplaced, ManifestReplacementUnknown:
		r.facts.Replacement = replacement
	default:
		r.facts.Replacement = ManifestReplacementUnknown
	}
	if r.facts.Replacement == ManifestReplaced {
		r.facts.CandidateCleanup = ManifestCandidateRenamed
		r.facts.ResiduePath = ""
	}
	reason := telemetry.DiagnosticReasonNone
	if r.facts.Replacement == ManifestReplacementUnknown {
		reason = telemetry.DiagnosticReasonUncertain
	} else if err != nil {
		reason = telemetry.DiagnosticReasonEvidenceUnavailable
	}
	call.Checkpoint(telemetry.DiagnosticLocalReplacement, reason)
	if err != nil || r.facts.Replacement != ManifestReplaced {
		r.failIO(ManifestRenameStage, err)
		return r.facts
	}
	if r.canceled(ManifestDirectorySyncStage) {
		return r.facts
	}
	if err := t.io.syncDir(r.directory); err != nil {
		r.failIO(ManifestDirectorySyncStage, err)
		return r.facts
	}
	if !r.verify(t.path, ManifestInstalledVerifyStage) {
		return r.facts
	}
	return r.facts
}

func (r *manifestFileRun) preflight() bool {
	if r.canceled(ManifestPreflightStage) {
		return false
	}
	if r.target.checkSource != nil {
		if err := r.target.checkSource(r.ctx); err != nil {
			r.failIO(ManifestPreflightStage, err)
			return false
		}
	}
	if r.canceled(ManifestPreflightStage) {
		return false
	}
	if reason := r.target.checkTarget(); reason != "" {
		r.fail(ManifestPreflightStage, reason)
		return false
	}
	return !r.canceled(ManifestPreflightStage)
}

// The separate live descriptor prevents inode reuse after the writer and
// candidate verification reader have completed their required closes.
func (r *manifestFileRun) pinCandidate() bool {
	if r.canceled(ManifestCandidateCreateStage) {
		return false
	}
	file, err := r.target.io.open(r.candidatePath, ManifestCandidateCreateStage)
	if err != nil || file == nil {
		r.failIO(ManifestCandidateCreateStage, err)
		return false
	}
	r.identity = file
	if r.canceled(ManifestCandidateCreateStage) {
		return false
	}
	info, err := r.target.io.stat(file, ManifestCandidateCreateStage)
	if err != nil {
		r.failIO(ManifestCandidateCreateStage, err)
		return false
	}
	if !info.Mode().IsRegular() || info.Mode() != 0600 || !os.SameFile(r.candidateInfo, info) {
		r.fail(ManifestCandidateCreateStage, ManifestVerificationMismatch)
		return false
	}
	return !r.canceled(ManifestCandidateCreateStage)
}

func (r *manifestFileRun) matchesInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode() == 0600 && info.Size() == int64(len(r.artifact)) && os.SameFile(r.candidateInfo, info)
}

func (r *manifestFileRun) verify(path string, stage ManifestFileStage) (verified bool) {
	if r.canceled(stage) {
		return false
	}
	verdict := &r.facts.CandidateVerification
	if stage == ManifestInstalledVerifyStage {
		verdict = &r.facts.InstalledVerification
	}
	mismatch := func(info os.FileInfo) bool {
		*verdict = ManifestVerificationFailed
		reason := ManifestVerificationMismatch
		if stage == ManifestInstalledVerifyStage && info != nil && !os.SameFile(r.candidateInfo, info) {
			reason = ManifestCompetingReplacement
		}
		r.fail(stage, reason)
		return false
	}
	info, err := r.target.io.lstat(path)
	if err != nil {
		r.failIO(stage, err)
		return false
	}
	if !r.matchesInfo(info) {
		return mismatch(info)
	}
	if r.canceled(stage) {
		return false
	}
	file, err := r.target.io.open(path, stage)
	if err != nil || file == nil {
		r.failIO(stage, err)
		return false
	}
	defer func() {
		if !r.close(file) || r.canceled(ManifestCloseStage) {
			verified = false
		}
	}()
	if r.canceled(stage) {
		return false
	}
	info, err = r.target.io.stat(file, stage)
	if err != nil {
		r.failIO(stage, err)
		return false
	}
	if !r.matchesInfo(info) {
		return mismatch(info)
	}
	matched, err := r.matches(file, stage)
	if err != nil {
		r.failIO(stage, err)
		return false
	}
	if !matched {
		return mismatch(info)
	}
	*verdict = ManifestVerified
	return !r.canceled(stage)
}

func (r *manifestFileRun) matches(file *os.File, stage ManifestFileStage) (bool, error) {
	if r.readback == nil {
		r.readback = make([]byte, manifestReadbackBytes)
	}
	at := 0
	for {
		if err := r.ctx.Err(); err != nil {
			return false, err
		}
		count := min(len(r.artifact)-at, len(r.readback))
		if count == 0 {
			count = 1
		}
		n, err := r.target.io.read(file, r.readback[:count], stage)
		if n < 0 || n > count {
			return false, io.ErrNoProgress
		}
		if n > len(r.artifact)-at || !bytes.Equal(r.readback[:n], r.artifact[at:at+n]) {
			return false, nil
		}
		at += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				return at == len(r.artifact), nil
			}
			return false, err
		}
		if n == 0 {
			return false, io.ErrNoProgress
		}
	}
}

func (r *manifestFileRun) fail(stage ManifestFileStage, reason ManifestFileReason) {
	if r.facts.Failure == nil {
		r.facts.Failure = &ManifestFileFailure{Stage: stage, Reason: reason}
	}
}

func (r *manifestFileRun) failIO(stage ManifestFileStage, err error) {
	reason := ManifestIOFailure
	if errors.Is(err, context.Canceled) {
		reason = ManifestCanceled
	} else if errors.Is(err, context.DeadlineExceeded) {
		reason = ManifestDeadlineExceeded
	}
	r.fail(stage, reason)
}

func (r *manifestFileRun) canceled(stage ManifestFileStage) bool {
	if err := r.ctx.Err(); err != nil {
		r.failIO(stage, err)
		return true
	}
	return false
}

func (r *manifestFileRun) close(file *os.File) bool {
	if err := r.target.io.close(file, ManifestCloseStage); err != nil {
		r.failIO(ManifestCloseStage, err)
		return false
	}
	return true
}

func (r *manifestFileRun) finish() {
	if r.writer != nil && r.identity != nil {
		r.close(r.writer)
		r.writer = nil
	}
	if r.directory != nil {
		r.close(r.directory)
		r.directory = nil
	}
	if r.candidatePath != "" && r.facts.Replacement != ManifestReplaced {
		r.cleanupCandidate()
	}
	// When identity acquisition failed, keep the writer open through cleanup.
	if r.writer != nil {
		r.close(r.writer)
		r.writer = nil
	}
	if r.identity != nil {
		r.close(r.identity)
		r.identity = nil
	}
	r.canceled(ManifestCloseStage)
	if r.facts.Failure == nil {
		r.facts.NativeCompletion = ManifestNativeComplete
	}
	reason := telemetry.DiagnosticReasonNone
	if r.facts.Failure != nil {
		reason = telemetry.DiagnosticReasonEvidenceUnavailable
		if r.facts.Failure.Reason == ManifestCanceled || r.facts.Failure.Reason == ManifestDeadlineExceeded {
			reason = telemetry.DiagnosticReasonCancelled
		}
	}
	r.call.Checkpoint(telemetry.DiagnosticLocalCompletion, reason)
}

func (r *manifestFileRun) cleanupCandidate() {
	parent, err := os.Stat(filepath.Dir(r.candidatePath))
	if err != nil || !os.SameFile(r.target.parent, parent) {
		r.facts.CandidateCleanup = ManifestCandidateCleanupUnknown
		r.facts.ResiduePath = r.candidatePath
		r.fail(ManifestCleanupStage, ManifestCleanupFailure)
		return
	}
	info, err := r.target.io.lstat(r.candidatePath)
	if errors.Is(err, os.ErrNotExist) && r.facts.Replacement == ManifestNotReplaced {
		r.facts.CandidateCleanup = ManifestCandidateRemoved
		r.facts.ResiduePath = ""
		return
	}
	if err != nil || r.candidateInfo == nil || !info.Mode().IsRegular() || !os.SameFile(r.candidateInfo, info) {
		r.facts.CandidateCleanup = ManifestCandidateCleanupUnknown
	} else if err := r.target.io.remove(r.candidatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.facts.CandidateCleanup = ManifestCandidateCleanupFailed
	} else {
		r.facts.CandidateCleanup = ManifestCandidateRemoved
		r.facts.ResiduePath = ""
		return
	}
	r.facts.ResiduePath = r.candidatePath
	r.fail(ManifestCleanupStage, ManifestCleanupFailure)
}
