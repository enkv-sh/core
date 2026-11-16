package contract

import (
	"math"
	"unicode/utf8"
)

const (
	PlanningOperation     = "plan-supplied-values"
	PlanningEvidenceLimit = "Fixed authenticated public settings, requested generated intent and supported supplied-secret relations only; future generated content is unavailable and public secret content is unchecked. Excludes apply admission or no-op, performed effects, output actions, remote state, and continued currentness."
)

type PlanningPurpose uint8

const (
	PlanningEquality PlanningPurpose = iota + 1
	PlanningDisplay
	PlanningRetirementFeasibility
)

type PlanningSourceForm string

const (
	PlanningSealed   PlanningSourceForm = "sealed"
	PlanningRetained PlanningSourceForm = "retained"
)

// PlanningSourcePair identifies the complete immutable captured pair. These
// facts are descriptive; only the installed source owner can admit them.
type PlanningSourcePair struct {
	FileIdentity, EditableDigest, GeneratedDigest ID
	EditableLength, GeneratedLength               uint64
}

func (p PlanningSourcePair) Valid() bool {
	return !p.FileIdentity.IsZero() && !p.EditableDigest.IsZero() && !p.GeneratedDigest.IsZero() &&
		p.EditableLength != 0 && p.GeneratedLength != 0 && p.EditableLength <= math.MaxUint64-p.GeneratedLength
}

type PlanningSources struct{ Trusted, Proposed PlanningSourcePair }

type PlanningOptions struct {
	Publish       bool
	Purpose       PlanningPurpose
	SelectedNames []string
	SinkID        ID
}

func (o PlanningOptions) Valid() bool {
	switch o.Purpose {
	case PlanningEquality, PlanningRetirementFeasibility:
		return len(o.SelectedNames) == 0 && o.SinkID.IsZero()
	case PlanningDisplay:
		if len(o.SelectedNames) == 0 || len(o.SelectedNames) > CryptoMaxValueEntries || o.SinkID.IsZero() {
			return false
		}
		seen := make(map[string]bool, len(o.SelectedNames))
		for _, name := range o.SelectedNames {
			if len(name) > CryptoMaxName || !utf8.ValidString(name) || seen[name] {
				return false
			}
			seen[name] = true
		}
		return true
	}
	return false
}

// PlanningInput carries only a sealed proposal or exact retained-current pins.
// It cannot carry plaintext or choose a private route.
type PlanningInput struct {
	Name        string
	Form        PlanningSourceForm
	SealedInput []byte
	Retained    RetainedSecretInput
}

type PlanningTarget struct {
	Input                                           PlanningInput
	ProposedRecipients                              []ID
	CurrentPresent                                  bool
	CurrentValueSource, CurrentConfidentialityClass uint8
	Current                                         *ConsumerSelection
}

// PlanningAdmission is issued by the installed read owner after complete public
// authentication. Core never receives private keys or plaintext through it.
// The Crypto owner separately pins the original Context cancellation/deadline.
type PlanningAdmission struct {
	RequestID, SessionID, DomainID, HEADDigest, HEADRevision, SnapshotID, AccessRoot, CredentialRoute ID
	Root                                                                                              Ref
	HEADToken                                                                                         Token
	Sources                                                                                           PlanningSources
	Control                                                                                           ControlCore
	Authority                                                                                         BindingTableRow
	Options                                                                                           PlanningOptions
	Retirement                                                                                        *PlanningRetirementBinding
	Targets                                                                                           []PlanningTarget
}

type PlanningPrivateRelation string

const (
	PlanningEqual     PlanningPrivateRelation = "equal"
	PlanningChanged   PlanningPrivateRelation = "changed"
	PlanningNew       PlanningPrivateRelation = "new"
	PlanningUnchecked PlanningPrivateRelation = "unchecked"
	PlanningFailed    PlanningPrivateRelation = "failed"
)

// PlanningRelation is an ordinary safe fact. Lengths and semantic commitments
// remain in private custody and never enter this result.
type PlanningRelation struct {
	Name     string
	Form     PlanningSourceForm
	Relation PlanningPrivateRelation
	Code     CryptoResultCode
}

type PlanningCheckResult struct {
	Rows     []PlanningRelation
	Complete bool
	Code     CryptoResultCode
}

// PlanningAdmissionError carries only a closed safe classification across the
// installed custody factory. Provider error text never enters Core diagnostics.
type PlanningAdmissionError struct{ Code CryptoResultCode }

func (PlanningAdmissionError) Error() string { return "private planning admission failed" }

type PlanningDelivery string

const (
	PlanningNotRequested       PlanningDelivery = "not-requested"
	PlanningDeliveryNone       PlanningDelivery = "none"
	PlanningDeliveryComplete   PlanningDelivery = "complete"
	PlanningDeliveryIncomplete PlanningDelivery = "incomplete"
)

type PlanningDisplayResult struct {
	OutputFailed                      bool
	Delivery                          PlanningDelivery
	SelectedRecords, CompletedRecords uint32
	Code                              CryptoResultCode
}

type PlanningPayload struct {
	ComparisonPayload
	PrivateEntries                    []PlanningRelation
	PrivateComplete                   bool
	DisplayDelivery                   PlanningDelivery
	SelectedRecords, CompletedRecords uint32
}
