package compositionfull

import "enkv.sh/core/contract"

type ManifestReplacement string

const (
	ManifestReplacementNotAttempted ManifestReplacement = "not-attempted"
	ManifestNotReplaced             ManifestReplacement = "not-replaced"
	ManifestReplaced                ManifestReplacement = "replaced"
	ManifestReplacementUnknown      ManifestReplacement = "unknown"
)

type ManifestVerification string

const (
	ManifestVerificationNotObserved ManifestVerification = "not-observed"
	ManifestVerified                ManifestVerification = "verified"
	ManifestVerificationFailed      ManifestVerification = "failed"
)

type ManifestNativeCompletion string

const (
	ManifestNativeIncomplete ManifestNativeCompletion = "incomplete"
	ManifestNativeComplete   ManifestNativeCompletion = "complete"
)

type ManifestCandidateCleanup string

const (
	ManifestCandidateNotCreated     ManifestCandidateCleanup = "not-created"
	ManifestCandidateRemoved        ManifestCandidateCleanup = "removed"
	ManifestCandidateRenamed        ManifestCandidateCleanup = "renamed"
	ManifestCandidateCleanupFailed  ManifestCandidateCleanup = "failed"
	ManifestCandidateCleanupUnknown ManifestCandidateCleanup = "unknown"
)

type ManifestFileStage string

const (
	ManifestPreflightStage       ManifestFileStage = "preflight"
	ManifestCandidateCreateStage ManifestFileStage = "candidate-create"
	ManifestCandidateWriteStage  ManifestFileStage = "candidate-write"
	ManifestCandidateSyncStage   ManifestFileStage = "candidate-sync"
	ManifestCandidateVerifyStage ManifestFileStage = "candidate-verify"
	ManifestRenameStage          ManifestFileStage = "rename"
	ManifestDirectorySyncStage   ManifestFileStage = "directory-sync"
	ManifestInstalledVerifyStage ManifestFileStage = "installed-verify"
	ManifestCloseStage           ManifestFileStage = "close"
	ManifestCleanupStage         ManifestFileStage = "cleanup"
)

type ManifestFileReason string

const (
	ManifestInvalidTarget        ManifestFileReason = "invalid-target"
	ManifestSourceAlias          ManifestFileReason = "source-alias"
	ManifestReservedPath         ManifestFileReason = "reserved-path"
	ManifestCanceled             ManifestFileReason = "canceled"
	ManifestDeadlineExceeded     ManifestFileReason = "deadline-exceeded"
	ManifestIOFailure            ManifestFileReason = "io-failure"
	ManifestVerificationMismatch ManifestFileReason = "verification-mismatch"
	ManifestCompetingReplacement ManifestFileReason = "competing-replacement"
	ManifestCleanupFailure       ManifestFileReason = "cleanup-failure"
)

// ManifestArtifact identifies the complete issued bytes without retaining them.
type ManifestArtifact struct {
	RendererArtifactID contract.ID
	FormatContractID   string
	Length             uint64
	Digest             contract.ID
}

type ManifestFileFailure struct {
	Stage  ManifestFileStage
	Reason ManifestFileReason
}

// ManifestDelivery keeps independently observed native facts. An empty path is
// absent, and the result never owns artifact bytes.
type ManifestDelivery struct {
	TargetPath            string
	Artifact              *ManifestArtifact
	Replacement           ManifestReplacement
	CandidateVerification ManifestVerification
	InstalledVerification ManifestVerification
	NativeCompletion      ManifestNativeCompletion
	CandidateCleanup      ManifestCandidateCleanup
	ResiduePath           string
	Failure               *ManifestFileFailure
}

func initialManifestDelivery() ManifestDelivery {
	return ManifestDelivery{
		Replacement:           ManifestReplacementNotAttempted,
		CandidateVerification: ManifestVerificationNotObserved,
		InstalledVerification: ManifestVerificationNotObserved,
		NativeCompletion:      ManifestNativeIncomplete,
		CandidateCleanup:      ManifestCandidateNotCreated,
	}
}
