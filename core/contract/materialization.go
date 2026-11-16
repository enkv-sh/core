package contract

import (
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaterializationOperation         = "materialize"
	MaterializationPayloadSchema     = "MaterializationPayload/v1"
	MaterializationDotenvFormat      = "application-dotenv/v1"
	MaterializationNativeFileProfile = "native-atomic-file/v1"
	MaterializationMaxPath           = 4096
	MaterializationMaxEncodedBytes   = CryptoMaxRetainedSet + CryptoMaxValueEntries*(CryptoMaxName+4)
)

type MaterializationRequest struct {
	RequestNonce ID
	Names        []string
	RecipientID  ID
}

// OwnMaterializationRequest fixes the explicit selection. Output grammar is
// checked in private custody after selected membership has been authenticated.
func OwnMaterializationRequest(r MaterializationRequest) (MaterializationRequest, error) {
	if r.RequestNonce.IsZero() || len(r.Names) == 0 {
		return MaterializationRequest{}, ErrRecord
	}
	if len(r.Names) > CryptoMaxValueEntries {
		return MaterializationRequest{}, ErrRecordCapacity
	}
	for _, name := range r.Names {
		if len(name) > CryptoMaxName {
			return MaterializationRequest{}, ErrRecordCapacity
		}
		if !utf8.ValidString(name) {
			return MaterializationRequest{}, ErrRecord
		}
	}
	r.Names = slices.Clone(r.Names)
	for at := range r.Names {
		r.Names[at] = strings.Clone(r.Names[at])
	}
	slices.Sort(r.Names)
	for at := 1; at < len(r.Names); at++ {
		if r.Names[at-1] == r.Names[at] {
			return MaterializationRequest{}, ErrRecord
		}
	}
	return r, nil
}

type MaterializationTarget struct {
	Path                  string
	SurfaceID             ID
	Format, NativeProfile string
}

func materializationPathValid(path string) bool {
	return len(path) > 0 && len(path) <= MaterializationMaxPath && utf8.ValidString(path) && !strings.ContainsRune(path, 0) && filepath.IsAbs(path) && filepath.Clean(path) == path
}
func (t MaterializationTarget) Valid() bool {
	return materializationPathValid(t.Path) && !t.SurfaceID.IsZero() && t.Format == MaterializationDotenvFormat && t.NativeProfile == MaterializationNativeFileProfile
}

// MaterializationSourcePins transfers the captured pair's public identity from
// its installed source owner. Paths and file handles remain with that owner.
type MaterializationSourcePins struct {
	FileID                          ID
	Format                          uint8
	EditableDigest, GeneratedDigest ID
	EditableLength, GeneratedLength uint64
	HasGenerated                    bool
}

func (p MaterializationSourcePins) Valid() bool {
	return !p.FileID.IsZero() && (p.Format == 1 || p.Format == 2) && !p.EditableDigest.IsZero() && !p.GeneratedDigest.IsZero() && p.EditableLength != 0 && p.GeneratedLength != 0 && p.HasGenerated
}

type MaterializationEntry struct {
	Name   string
	Slot   uint16
	Entry  ValueEntry
	Secret *ConsumerSelection
}

// MaterializationAdmission contains public/encrypted selected facts only.
// It is issued through the installed trusted factory, not public request data.
// The private owner separately checks the exact route, target and Context.
type MaterializationAdmission struct {
	Purpose                                                    string
	RequestID, SessionID                                       ID
	DomainID, HEADDigest, HEADRevision, SnapshotID, AccessRoot ID
	CredentialRoute, PublicBasisDigest                         ID
	Store                                                      Descriptor
	Root                                                       Ref
	HEADToken                                                  Token
	SourcePins                                                 MaterializationSourcePins
	Recipient                                                  BindingTableRow
	Target                                                     MaterializationTarget
	ExpiresAt                                                  time.Time
	Entries                                                    []MaterializationEntry
}

type MaterializationAdmissionError struct{ Code CryptoResultCode }

func (MaterializationAdmissionError) Error() string {
	return "private materialization admission failed"
}

type MaterializationStateResult string

const (
	MaterializationSuccess             MaterializationStateResult = "success"
	MaterializationRootLossUnsupported MaterializationStateResult = "root-loss-unsupported"
	MaterializationRefused             MaterializationStateResult = "refused"
	MaterializationProfileBlocked      MaterializationStateResult = "profile-blocked"
	MaterializationUnavailable         MaterializationStateResult = "unavailable"
	MaterializationPositiveDefect      MaterializationStateResult = "positive-defect"
)

func (s MaterializationStateResult) Valid() bool {
	switch s {
	case MaterializationSuccess, MaterializationRootLossUnsupported, MaterializationRefused, MaterializationProfileBlocked, MaterializationUnavailable, MaterializationPositiveDefect:
		return true
	}
	return false
}

type MaterializationReplacement string

const (
	MaterializationNotReplaced        MaterializationReplacement = "not-replaced"
	MaterializationReplaced           MaterializationReplacement = "replaced"
	MaterializationReplacementUnknown MaterializationReplacement = "unknown"
)

type MaterializationVerification string

const (
	MaterializationNotObserved        MaterializationVerification = "not-observed"
	MaterializationVerified           MaterializationVerification = "verified"
	MaterializationVerificationFailed MaterializationVerification = "failed"
)

type MaterializationNativeCompletion string

const (
	MaterializationNativeNotObserved MaterializationNativeCompletion = "not-observed"
	MaterializationComplete          MaterializationNativeCompletion = "complete"
	MaterializationIncomplete        MaterializationNativeCompletion = "incomplete"
)

type MaterializationDisclosure string

const (
	MaterializationDisclosureNone     MaterializationDisclosure = "none"
	MaterializationDisclosureOccurred MaterializationDisclosure = "occurred"
	MaterializationDisclosureUnknown  MaterializationDisclosure = "unknown"
)

type MaterializationCandidateCleanup string

const (
	MaterializationCandidateNotCreated     MaterializationCandidateCleanup = "not-created"
	MaterializationCandidateRemoved        MaterializationCandidateCleanup = "removed"
	MaterializationCandidateRenamed        MaterializationCandidateCleanup = "renamed"
	MaterializationCandidateCleanupFailed  MaterializationCandidateCleanup = "failed"
	MaterializationCandidateCleanupUnknown MaterializationCandidateCleanup = "unknown"
)

type MaterializationStage string

const (
	MaterializationAdmissionStage        MaterializationStage = "admission"
	MaterializationLoad                  MaterializationStage = "load"
	MaterializationAuthentication        MaterializationStage = "authentication"
	MaterializationEncoding              MaterializationStage = "encoding"
	MaterializationStaging               MaterializationStage = "staging"
	MaterializationCandidateSync         MaterializationStage = "candidate-sync"
	MaterializationCandidateClose        MaterializationStage = "candidate-close"
	MaterializationCandidateVerification MaterializationStage = "candidate-verification"
	MaterializationRename                MaterializationStage = "rename"
	MaterializationDirectorySync         MaterializationStage = "directory-sync"
	MaterializationInstalledVerification MaterializationStage = "installed-verification"
	MaterializationInstalledClose        MaterializationStage = "installed-close"
	MaterializationDirectoryClose        MaterializationStage = "directory-close"
	MaterializationSinkClose             MaterializationStage = "sink-close"
	MaterializationCleanup               MaterializationStage = "cleanup"
)

func (s MaterializationStage) Valid() bool {
	switch s {
	case MaterializationAdmissionStage, MaterializationLoad, MaterializationAuthentication, MaterializationEncoding, MaterializationStaging, MaterializationCandidateSync, MaterializationCandidateClose, MaterializationCandidateVerification, MaterializationRename, MaterializationDirectorySync, MaterializationInstalledVerification, MaterializationInstalledClose, MaterializationDirectoryClose, MaterializationSinkClose, MaterializationCleanup:
		return true
	}
	return false
}

// BeforeStaging identifies failures that cannot carry native file progress.
func (s MaterializationStage) BeforeStaging() bool {
	return s == MaterializationAdmissionStage || s == MaterializationLoad || s == MaterializationAuthentication || s == MaterializationEncoding
}

type MaterializationFailureReason string

const (
	MaterializationInvalidRequest          MaterializationFailureReason = "invalid-request"
	MaterializationUnauthorizedSelection   MaterializationFailureReason = "unauthorized-selection"
	MaterializationMissingSelection        MaterializationFailureReason = "missing-selection"
	MaterializationRootLoss                MaterializationFailureReason = "root-loss"
	MaterializationChangingSelection       MaterializationFailureReason = "changing-selection"
	MaterializationRequiredReadUnavailable MaterializationFailureReason = "required-read-unavailable"
	MaterializationIntegrityContradiction  MaterializationFailureReason = "integrity-contradiction"
	MaterializationPrivateRouteUnavailable MaterializationFailureReason = "private-route-unavailable"
	MaterializationInvalidAdmission        MaterializationFailureReason = "invalid-admission"
	MaterializationUnrepresentableValue    MaterializationFailureReason = "unrepresentable-value"
	MaterializationCapacityLimit           MaterializationFailureReason = "capacity-limit"
	MaterializationProfileUnqualified      MaterializationFailureReason = "profile-unqualified"
	MaterializationInvalidTarget           MaterializationFailureReason = "invalid-target"
	MaterializationCanceled                MaterializationFailureReason = "canceled"
	MaterializationDeadlineExceeded        MaterializationFailureReason = "deadline-exceeded"
	MaterializationIOFailure               MaterializationFailureReason = "io-failure"
	MaterializationVerificationMismatch    MaterializationFailureReason = "verification-mismatch"
	MaterializationCompetingReplacement    MaterializationFailureReason = "competing-replacement"
	MaterializationCleanupFailure          MaterializationFailureReason = "cleanup-failure"
)

func (r MaterializationFailureReason) Valid() bool {
	switch r {
	case MaterializationInvalidRequest, MaterializationUnauthorizedSelection, MaterializationMissingSelection, MaterializationRootLoss, MaterializationChangingSelection, MaterializationRequiredReadUnavailable, MaterializationIntegrityContradiction, MaterializationPrivateRouteUnavailable, MaterializationInvalidAdmission, MaterializationUnrepresentableValue, MaterializationCapacityLimit, MaterializationProfileUnqualified, MaterializationInvalidTarget, MaterializationCanceled, MaterializationDeadlineExceeded, MaterializationIOFailure, MaterializationVerificationMismatch, MaterializationCompetingReplacement, MaterializationCleanupFailure:
		return true
	}
	return false
}

type MaterializationFailure struct {
	Stage  MaterializationStage
	Reason MaterializationFailureReason
}

func (f MaterializationFailure) Valid() bool { return f.Stage.Valid() && f.Reason.Valid() }

type MaterializationFacts struct {
	Replacement                                  MaterializationReplacement
	CandidateVerification, InstalledVerification MaterializationVerification
	NativeCompletion                             MaterializationNativeCompletion
	Disclosure                                   MaterializationDisclosure
	Cleanup                                      MaterializationCandidateCleanup
	Failure, CleanupFailure                      *MaterializationFailure
	ResiduePath                                  string
}

// InitialMaterializationFacts makes no native completion or disclosure claim.
func InitialMaterializationFacts() MaterializationFacts {
	return MaterializationFacts{Replacement: MaterializationNotReplaced, CandidateVerification: MaterializationNotObserved, InstalledVerification: MaterializationNotObserved, NativeCompletion: MaterializationNativeNotObserved, Disclosure: MaterializationDisclosureNone, Cleanup: MaterializationCandidateNotCreated}
}

type MaterializationCompletion struct {
	StateResult MaterializationStateResult
	Facts       MaterializationFacts
}

func (c MaterializationCompletion) Validate() error {
	f := c.Facts
	if !c.StateResult.Valid() || f.Replacement != MaterializationNotReplaced && f.Replacement != MaterializationReplaced && f.Replacement != MaterializationReplacementUnknown ||
		f.CandidateVerification != MaterializationNotObserved && f.CandidateVerification != MaterializationVerified && f.CandidateVerification != MaterializationVerificationFailed ||
		f.InstalledVerification != MaterializationNotObserved && f.InstalledVerification != MaterializationVerified && f.InstalledVerification != MaterializationVerificationFailed ||
		f.NativeCompletion != MaterializationNativeNotObserved && f.NativeCompletion != MaterializationComplete && f.NativeCompletion != MaterializationIncomplete ||
		f.Disclosure != MaterializationDisclosureNone && f.Disclosure != MaterializationDisclosureOccurred && f.Disclosure != MaterializationDisclosureUnknown ||
		f.Cleanup != MaterializationCandidateNotCreated && f.Cleanup != MaterializationCandidateRemoved && f.Cleanup != MaterializationCandidateRenamed && f.Cleanup != MaterializationCandidateCleanupFailed && f.Cleanup != MaterializationCandidateCleanupUnknown {
		return ErrRecord
	}
	if f.Failure != nil && !f.Failure.Valid() || f.CleanupFailure != nil && !f.CleanupFailure.Valid() {
		return ErrRecord
	}
	if f.CleanupFailure != nil {
		switch f.CleanupFailure.Stage {
		case MaterializationCandidateClose, MaterializationInstalledClose, MaterializationDirectoryClose, MaterializationSinkClose:
			if f.CleanupFailure.Stage == MaterializationCandidateClose && f.Cleanup == MaterializationCandidateNotCreated {
				return ErrRecord
			}
			if f.CleanupFailure.Stage == MaterializationInstalledClose && f.Replacement != MaterializationReplaced {
				return ErrRecord
			}
			switch f.CleanupFailure.Reason {
			case MaterializationIOFailure, MaterializationCanceled, MaterializationDeadlineExceeded:
			default:
				return ErrRecord
			}
		case MaterializationCleanup:
			if f.CleanupFailure.Reason != MaterializationCleanupFailure || f.Cleanup == MaterializationCandidateNotCreated {
				return ErrRecord
			}
		default:
			return ErrRecord
		}
	}
	if f.CandidateVerification == MaterializationVerified && f.Disclosure != MaterializationDisclosureOccurred {
		return ErrRecord
	}
	if (f.Replacement == MaterializationReplaced) != (f.Cleanup == MaterializationCandidateRenamed) {
		return ErrRecord
	}
	if f.Replacement != MaterializationNotReplaced && (f.CandidateVerification != MaterializationVerified || f.Disclosure == MaterializationDisclosureNone) {
		return ErrRecord
	}
	if f.InstalledVerification != MaterializationNotObserved && f.Replacement != MaterializationReplaced {
		return ErrRecord
	}
	if f.Cleanup == MaterializationCandidateNotCreated {
		if f.Replacement != MaterializationNotReplaced || f.Disclosure != MaterializationDisclosureNone || f.CandidateVerification != MaterializationNotObserved || f.InstalledVerification != MaterializationNotObserved {
			return ErrRecord
		}
	} else if f.Disclosure == MaterializationDisclosureNone {
		return ErrRecord
	}
	if f.ResiduePath != "" && (f.Cleanup != MaterializationCandidateCleanupFailed && f.Cleanup != MaterializationCandidateCleanupUnknown || !materializationPathValid(f.ResiduePath)) {
		return ErrRecord
	}
	if c.StateResult == MaterializationSuccess {
		if f.Replacement != MaterializationReplaced || f.CandidateVerification != MaterializationVerified || f.InstalledVerification != MaterializationVerified || f.NativeCompletion != MaterializationComplete || f.Disclosure != MaterializationDisclosureOccurred || f.Cleanup != MaterializationCandidateRenamed || f.Failure != nil || f.CleanupFailure != nil || f.ResiduePath != "" {
			return ErrRecord
		}
	} else if f.Failure == nil || f.NativeCompletion == MaterializationComplete {
		return ErrRecord
	}
	if c.StateResult != MaterializationSuccess {
		stage, reason := f.Failure.Stage, f.Failure.Reason
		if f.Replacement == MaterializationReplacementUnknown && stage != MaterializationRename {
			return ErrRecord
		}
		switch stage {
		case MaterializationCleanup:
			if f.Cleanup == MaterializationCandidateNotCreated {
				return ErrRecord
			}
		case MaterializationRename:
			if f.CandidateVerification != MaterializationVerified || f.Cleanup == MaterializationCandidateNotCreated {
				return ErrRecord
			}
		case MaterializationDirectorySync, MaterializationInstalledVerification:
			if f.Replacement != MaterializationReplaced {
				return ErrRecord
			}
		case MaterializationInstalledClose:
			if f.Replacement != MaterializationReplaced || f.InstalledVerification != MaterializationVerified {
				return ErrRecord
			}
		}
		switch c.StateResult {
		case MaterializationRootLossUnsupported:
			if reason != MaterializationRootLoss || !stage.BeforeStaging() {
				return ErrRecord
			}
		case MaterializationProfileBlocked:
			if reason != MaterializationProfileUnqualified {
				return ErrRecord
			}
		case MaterializationPositiveDefect:
			if reason != MaterializationIntegrityContradiction && reason != MaterializationVerificationMismatch {
				return ErrRecord
			}
		case MaterializationRefused:
			switch reason {
			case MaterializationInvalidRequest, MaterializationUnauthorizedSelection, MaterializationMissingSelection, MaterializationInvalidAdmission, MaterializationUnrepresentableValue, MaterializationCapacityLimit, MaterializationInvalidTarget, MaterializationDeadlineExceeded:
			default:
				return ErrRecord
			}
		case MaterializationUnavailable:
			switch reason {
			case MaterializationChangingSelection, MaterializationRequiredReadUnavailable, MaterializationPrivateRouteUnavailable, MaterializationCanceled, MaterializationDeadlineExceeded, MaterializationIOFailure, MaterializationVerificationMismatch, MaterializationCompetingReplacement, MaterializationCleanupFailure, MaterializationIntegrityContradiction:
			default:
				return ErrRecord
			}
		}
		if stage.BeforeStaging() {
			if f.Replacement != MaterializationNotReplaced || f.Cleanup != MaterializationCandidateNotCreated || f.Disclosure != MaterializationDisclosureNone || f.CandidateVerification != MaterializationNotObserved || f.InstalledVerification != MaterializationNotObserved || f.NativeCompletion != MaterializationNativeNotObserved {
				return ErrRecord
			}
		} else if stage != MaterializationStaging && f.NativeCompletion != MaterializationIncomplete {
			return ErrRecord
		}
		if f.NativeCompletion == MaterializationIncomplete || f.Cleanup != MaterializationCandidateNotCreated {
			if c.StateResult != MaterializationUnavailable && c.StateResult != MaterializationPositiveDefect {
				return ErrRecord
			}
		}
		if c.StateResult == MaterializationPositiveDefect && !stage.BeforeStaging() {
			candidateProof := stage == MaterializationCandidateVerification && f.CandidateVerification == MaterializationVerificationFailed
			installedProof := stage == MaterializationInstalledVerification && f.InstalledVerification == MaterializationVerificationFailed
			if !candidateProof && !installedProof {
				return ErrRecord
			}
		}

		if f.Cleanup != MaterializationCandidateNotCreated && f.NativeCompletion != MaterializationIncomplete {
			return ErrRecord
		}
		if stage == MaterializationStaging && reason == MaterializationIOFailure && f.NativeCompletion != MaterializationIncomplete {
			return ErrRecord
		}
		candidateStage := stage == MaterializationStaging || stage == MaterializationCandidateSync || stage == MaterializationCandidateClose || stage == MaterializationCandidateVerification
		if candidateStage && (f.Replacement != MaterializationNotReplaced || f.InstalledVerification != MaterializationNotObserved) {
			return ErrRecord
		}
		if candidateStage && stage != MaterializationStaging && f.Cleanup == MaterializationCandidateNotCreated {
			return ErrRecord
		}
		if reason == MaterializationVerificationMismatch && f.CandidateVerification != MaterializationVerificationFailed && f.InstalledVerification != MaterializationVerificationFailed {
			return ErrRecord
		}
		if f.Replacement != MaterializationNotReplaced {
			if c.StateResult != MaterializationUnavailable && c.StateResult != MaterializationPositiveDefect {
				return ErrRecord
			}
			switch reason {
			case MaterializationCanceled, MaterializationDeadlineExceeded, MaterializationIOFailure, MaterializationVerificationMismatch, MaterializationCompetingReplacement, MaterializationCleanupFailure, MaterializationIntegrityContradiction:
			default:
				return ErrRecord
			}
		}
	}
	if f.Cleanup == MaterializationCandidateCleanupFailed && f.CleanupFailure == nil && (f.Failure == nil || f.Failure.Stage != MaterializationCleanup) {
		return ErrRecord
	}
	return nil
}

type MaterializationEntryIdentity struct {
	Name                              string
	Slot                              uint16
	EntryIncarnationID, ValueStateID  ID
	ValueSource, ConfidentialityClass uint8
}

type MaterializationPayload struct {
	Schema                             string
	RequestIdentity                    ID
	DomainID, HEADRevision, SnapshotID ID
	Recipient                          BindingTableRow
	Target                             MaterializationTarget
	Entries                            []MaterializationEntryIdentity
	Facts                              MaterializationFacts
}

func (p MaterializationPayload) Validate(state MaterializationStateResult) error {
	if p.Schema != MaterializationPayloadSchema || !publicIDsValid(p.RequestIdentity, p.DomainID, p.HEADRevision, p.SnapshotID) || !p.Target.Valid() || p.Recipient.SubjectKind != OrdinaryWrapSubject || p.Recipient.SubjectID.IsZero() || len(p.Entries) == 0 || len(p.Entries) > CryptoMaxValueEntries {
		return ErrRecord
	}
	if _, err := PublicBindingDigest(p.Recipient.Binding); err != nil {
		return err
	}
	var slots [CryptoMaxValueEntries]bool
	for at, entry := range p.Entries {
		if entry.Slot >= CryptoMaxValueEntries || slots[entry.Slot] || len(entry.Name) > CryptoMaxName || !utf8.ValidString(entry.Name) || at > 0 && p.Entries[at-1].Name >= entry.Name || !publicIDsValid(entry.EntryIncarnationID, entry.ValueStateID) || !ValidatePublicEntryTags(entry.ValueSource, entry.ConfidentialityClass) {
			return ErrRecord
		}
		slots[entry.Slot] = true
	}
	return (MaterializationCompletion{StateResult: state, Facts: p.Facts}).Validate()
}
