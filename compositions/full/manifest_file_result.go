package compositionfull

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

const manifestFileCompactResultLimit = 2277380 + 2048

// These maxima include readable layout and the native source singleton.
const MaxManifestFileResultJSONBytes = 67 * manifestFileCompactResultLimit
const MaxManifestIssuanceResultJSONBytes = 67 * contract.MaxManifestResultJSONBytes

type ManifestSourceCleanup string

const (
	ManifestSourceNotObserved ManifestSourceCleanup = "not-observed"
	ManifestSourceComplete    ManifestSourceCleanup = "complete"
	ManifestSourceFailed      ManifestSourceCleanup = "failed"
	ManifestSourceUnknown     ManifestSourceCleanup = "unknown"
)

type ManifestResultDelivery string

const (
	ManifestResultNotObserved ManifestResultDelivery = "not-observed"
	ManifestResultComplete    ManifestResultDelivery = "complete"
	ManifestResultFailed      ManifestResultDelivery = "failed"
	ManifestResultUnknown     ManifestResultDelivery = "unknown"
)

// ManifestFileResult retains issuance and independently settled native facts.
// ResultDelivery is not-observed in a rendered record; the caller settles it.
type ManifestFileResult struct {
	SourceFailure  *ConfigurationSourceFailure
	Issuance       core.PublicManifestResult
	Delivery       ManifestDelivery
	SourceCleanup  ManifestSourceCleanup
	ResultDelivery ManifestResultDelivery
}

func NewManifestFileResult(issuance core.PublicManifestResult) ManifestFileResult {
	return ManifestFileResult{Issuance: issuance, Delivery: initialManifestDelivery(), SourceCleanup: ManifestSourceNotObserved, ResultDelivery: ManifestResultNotObserved}
}

var ErrManifestFileResult = errors.New("manifest file result rendering refused")

func validManifestTerminal(source ManifestSourceCleanup, delivery ManifestResultDelivery) bool {
	switch source {
	case ManifestSourceNotObserved, ManifestSourceComplete, ManifestSourceFailed, ManifestSourceUnknown:
	default:
		return false
	}
	switch delivery {
	case ManifestResultNotObserved, ManifestResultComplete, ManifestResultFailed, ManifestResultUnknown:
		return true
	}
	return false
}
func validManifestFileFailure(f *ManifestFileFailure) bool {
	if f == nil {
		return true
	}
	switch f.Stage {
	case ManifestPreflightStage, ManifestCandidateCreateStage, ManifestCandidateWriteStage, ManifestCandidateSyncStage, ManifestCandidateVerifyStage, ManifestRenameStage, ManifestDirectorySyncStage, ManifestInstalledVerifyStage, ManifestCloseStage, ManifestCleanupStage:
	default:
		return false
	}
	switch f.Reason {
	case ManifestInvalidTarget, ManifestSourceAlias, ManifestReservedPath, ManifestCanceled, ManifestDeadlineExceeded, ManifestIOFailure, ManifestVerificationMismatch, ManifestCompetingReplacement, ManifestCleanupFailure:
		return true
	}
	return false
}
func validManifestVerification(v ManifestVerification) bool {
	return v == ManifestVerificationNotObserved || v == ManifestVerified || v == ManifestVerificationFailed
}
func validManifestFileResult(r ManifestFileResult) bool {
	if !validConfigurationAdmissionSourceFailure(r.SourceFailure, r.Issuance.PreAdmission, contract.ID{}, r.Issuance.Result) || r.SourceFailure != nil && (r.Issuance.Payload != nil || r.Issuance.Observation != nil || len(r.Issuance.Artifact) != 0) {
		return false
	}
	d := r.Delivery
	if r.SourceFailure != nil && (d.Artifact != nil || d.NativeCompletion != ManifestNativeIncomplete || d.CandidateVerification != ManifestVerificationNotObserved || d.InstalledVerification != ManifestVerificationNotObserved || d.ResiduePath != "") {
		return false
	}
	if !validManifestTerminal(r.SourceCleanup, r.ResultDelivery) || !validManifestFileFailure(d.Failure) || !validManifestVerification(d.CandidateVerification) || !validManifestVerification(d.InstalledVerification) || r.Issuance.Artifact != nil {
		return false
	}
	if d.TargetPath != "" && !manifestPathValid(d.TargetPath) || d.ResiduePath != "" && (!manifestPathValid(d.ResiduePath) || d.TargetPath == "" || filepath.Dir(d.ResiduePath) != filepath.Dir(d.TargetPath) || !strings.HasPrefix(filepath.Base(d.ResiduePath), manifestCandidatePrefix) || len(filepath.Base(d.ResiduePath)) != manifestCandidateNameBytes) {
		return false
	}
	if d.NativeCompletion != ManifestNativeIncomplete && d.NativeCompletion != ManifestNativeComplete {
		return false
	}
	switch d.Replacement {
	case ManifestReplacementNotAttempted, ManifestNotReplaced, ManifestReplaced, ManifestReplacementUnknown:
	default:
		return false
	}
	switch d.CandidateCleanup {
	case ManifestCandidateNotCreated, ManifestCandidateRemoved, ManifestCandidateRenamed, ManifestCandidateCleanupFailed, ManifestCandidateCleanupUnknown:
	default:
		return false
	}
	if d.CandidateCleanup == ManifestCandidateCleanupFailed || d.CandidateCleanup == ManifestCandidateCleanupUnknown {
		if d.ResiduePath == "" {
			return false
		}
	} else if d.ResiduePath != "" {
		return false
	}
	if r.Issuance.StateResult != contract.ReaderSuccess {
		return d.Artifact == nil && d.Replacement == ManifestReplacementNotAttempted && d.CandidateVerification == ManifestVerificationNotObserved && d.InstalledVerification == ManifestVerificationNotObserved && d.NativeCompletion == ManifestNativeIncomplete && d.CandidateCleanup == ManifestCandidateNotCreated && d.Failure == nil
	}
	p := r.Issuance.Payload
	if p == nil || d.Artifact == nil || d.Artifact.RendererArtifactID != p.Renderer.ArtifactID || d.Artifact.FormatContractID != p.FormatContractID || d.Artifact.Length != p.ArtifactLength || d.Artifact.Digest != p.ArtifactDigest {
		return false
	}
	if d.Replacement != ManifestReplacementNotAttempted && d.TargetPath == "" {
		return false
	}
	if d.Replacement == ManifestReplacementNotAttempted && (d.CandidateVerification != ManifestVerificationNotObserved || d.InstalledVerification != ManifestVerificationNotObserved || d.CandidateCleanup != ManifestCandidateNotCreated) {
		return false
	}
	if d.Replacement != ManifestReplaced && (d.InstalledVerification != ManifestVerificationNotObserved || d.CandidateCleanup == ManifestCandidateRenamed) {
		return false
	}
	if d.Replacement == ManifestNotReplaced && d.CandidateCleanup == ManifestCandidateNotCreated {
		return false
	}
	if d.Replacement == ManifestReplaced && (d.CandidateVerification != ManifestVerified || d.CandidateCleanup != ManifestCandidateRenamed) {
		return false
	}
	if d.Replacement == ManifestReplacementUnknown && d.CandidateVerification != ManifestVerified {
		return false
	}
	if d.NativeCompletion == ManifestNativeComplete {
		return d.TargetPath != "" && d.Replacement == ManifestReplaced && d.CandidateVerification == ManifestVerified && d.InstalledVerification == ManifestVerified && d.CandidateCleanup == ManifestCandidateRenamed && d.Failure == nil
	}
	if d.Failure == nil {
		return false
	}
	switch d.Failure.Stage {
	case ManifestPreflightStage, ManifestCandidateCreateStage:
		return d.Replacement == ManifestReplacementNotAttempted || d.Replacement == ManifestNotReplaced
	case ManifestCandidateWriteStage, ManifestCandidateSyncStage, ManifestCandidateVerifyStage:
		return d.Replacement == ManifestNotReplaced
	case ManifestRenameStage:
		return d.Replacement == ManifestNotReplaced || d.Replacement == ManifestReplacementUnknown
	case ManifestDirectorySyncStage, ManifestInstalledVerifyStage:
		return d.Replacement == ManifestReplaced
	}
	return true
}

func ManifestFileExitCode(r ManifestFileResult) int {
	if !validManifestFileResult(r) || r.SourceCleanup != ManifestSourceComplete || r.ResultDelivery != ManifestResultComplete {
		return 2
	}
	count := readerResultWriter{maximum: manifestFileCompactResultLimit}
	writeManifestResult(&count, r.Issuance, false)
	if count.failed {
		return 2
	}
	switch r.Issuance.StateResult {
	case contract.ReaderUnavailable, contract.ReaderContention:
		return 3
	case contract.ReaderSuccess:
		if r.Delivery.NativeCompletion == ManifestNativeComplete {
			return 0
		}
	}
	return 2
}
func RenderManifestFileJSON(r ManifestFileResult) ([]byte, error) {
	return renderManifestFile(r)
}
func RenderManifestFileHuman(r ManifestFileResult) ([]byte, error) {
	return renderManifestFileHuman(r)
}
func renderManifestFile(r ManifestFileResult) ([]byte, error) {
	if !validManifestFileResult(r) || r.ResultDelivery != ManifestResultNotObserved {
		return nil, ErrManifestFileResult
	}
	// Complete issuance plus two escaped native paths and 65536 wrapper bytes
	// fit the existing compact ceiling. The outer wrapper has depth below eight.
	body, err := renderReadableReaderResultBound(manifestFileCompactResultLimit, func(w *readerResultWriter) {
		w.literal(`{"schema":"ManifestFileResult/v2"`)
		if r.SourceFailure != nil {
			w.literal(`,"source_failure":`)
			w.json(r.SourceFailure, configurationSourceFailureJSONBytes)
		}
		w.literal(`,"issuance":`)
		writeManifestResult(w, r.Issuance, false)
		w.literal(`,"delivery":`)
		d := r.Delivery
		var target, residue *string
		if d.TargetPath != "" {
			target = &d.TargetPath
		}
		if d.ResiduePath != "" {
			residue = &d.ResiduePath
		}
		var artifact any
		if a := d.Artifact; a != nil {
			artifact = struct {
				RendererArtifactID string `json:"renderer_artifact_id"`
				FormatContractID   string `json:"format_contract_id"`
				Length             uint64 `json:"length"`
				Digest             string `json:"digest"`
			}{readerID(a.RendererArtifactID), a.FormatContractID, a.Length, readerID(a.Digest)}
		}
		var failure any
		if f := d.Failure; f != nil {
			failure = struct {
				Stage  ManifestFileStage  `json:"stage"`
				Reason ManifestFileReason `json:"reason"`
			}{f.Stage, f.Reason}
		}
		w.json(struct {
			Target      *string                  `json:"target_path"`
			Artifact    any                      `json:"artifact"`
			Replacement ManifestReplacement      `json:"replacement"`
			Candidate   ManifestVerification     `json:"candidate_verification"`
			Installed   ManifestVerification     `json:"installed_verification"`
			Native      ManifestNativeCompletion `json:"native_completion"`
			Cleanup     ManifestCandidateCleanup `json:"candidate_cleanup"`
			Residue     *string                  `json:"residue_path"`
			Failure     any                      `json:"failure"`
		}{target, artifact, d.Replacement, d.CandidateVerification, d.InstalledVerification, d.NativeCompletion, d.CandidateCleanup, residue, failure}, 65536)
		w.literal(`,"source_cleanup":`)
		w.json(r.SourceCleanup, 128)
		w.literal(`,"result_delivery":"not-observed"}`)
	})
	if err != nil {
		return nil, ErrManifestFileResult
	}
	return body, nil
}
func WriteManifestFileJSON(ctx context.Context, w io.Writer, r ManifestFileResult) error {
	return writeManifestFile(ctx, w, r, false)
}
func WriteManifestFileHuman(ctx context.Context, w io.Writer, r ManifestFileResult) error {
	return writeManifestFile(ctx, w, r, true)
}
func writeManifestFile(ctx context.Context, w io.Writer, r ManifestFileResult, human bool) error {
	if ctx == nil || w == nil {
		return ErrManifestFileResult
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var body []byte
	var err error
	if human {
		body, err = RenderManifestFileHuman(r)
	} else {
		body, err = RenderManifestFileJSON(r)
	}
	if err != nil {
		return err
	}
	defer clear(body)
	if err = ctx.Err(); err != nil {
		return err
	}
	n, err := w.Write(body)
	if err != nil {
		return err
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return ctx.Err()
}
