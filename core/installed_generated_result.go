package core

import "enkv.sh/core/contract"

// GeneratedResultWarnings concerns the observed effect or work row. Permanent
// domain warnings and historical receipt warnings have separate owners.
type GeneratedResultWarnings struct {
	PossibleLiveResidue, LateEffect, InvalidationNotConfirmed bool
}

// GeneratedEffectFact owns public facts from an authenticated Attempt. ResourceID
// in Record is the planned identity; Target establishes an actual owned resource.
// A zero GenerationID means that no canonical generation relation is available.
type GeneratedEffectFact struct {
	Record                             contract.GeneratedAttemptRecord
	Action                             uint8
	Name                               string
	EntryIncarnationID                 contract.ID
	Epoch                              uint64
	PlannedValueSlotID, ResourceDigest contract.ID
	Target                             *contract.GeneratorTarget
	GenerationID                       contract.ID
	DutyID, HazardID                   contract.ID
	Reason                             uint8
	EvidenceCeiling                    uint16
	SummaryClass                       int
	Progress                           []contract.GeneratorProgress
	Warnings                           GeneratedResultWarnings
}

// Detached work does not necessarily retain its old canonical GenerationID or
// retirement policy. Their zero values explicitly mean unavailable.
type GeneratedDutyFact struct {
	Record          contract.GeneratedDutyRecord
	Target          *contract.GeneratorTarget
	GenerationID    contract.ID
	RetirementMode  uint8
	Progress        []contract.GeneratorProgress
	EvidenceCeiling uint16
	Warnings        GeneratedResultWarnings
}

type GeneratedHazardFact struct {
	CleanupResultContractID        contract.ID
	CleanupImplementationQualified bool
	Record                         contract.GeneratedHazardRecord
	Target                         *contract.GeneratorTarget
	GenerationID                   contract.ID
	RetirementMode                 uint8
	EvidenceCeiling                uint16
	Warnings                       GeneratedResultWarnings
}

// GeneratedInvocationResult describes one invocation. Related work is distinct
// from the complete current-domain identity lists in TransitionPayload.
// ReceiptObservation preserves historical compact evidence with explicitly
// unavailable vectors when the original operational support has ended.
type GeneratedInvocationResult struct {
	canonicalSelection                                generatedCanonicalSelectionProof
	OperationKind                                     uint16
	StateResult                                       string
	CanonicalOutcome                                  uint8
	EffectSummary, EvidenceCeiling                    uint16
	EffectsAvailable                                  bool
	Effects                                           []GeneratedEffectFact
	EffectsCommitment                                 *contract.GeneratorDescriptor
	SummaryCountsAvailable                            bool
	SummaryCounts                                     [contract.ReceiptSummaryCount]uint32
	AcknowledgedCount, ConfirmedCount, UnknownCount   uint32
	RelatedWorkAvailable                              bool
	RelatedDutyIDs, RelatedHazardIDs                  []contract.ID
	Duties                                            []GeneratedDutyFact
	Hazards                                           []GeneratedHazardFact
	RelatedDutiesCommitment, RelatedHazardsCommitment *contract.GeneratorDescriptor
	Warnings                                          GeneratedResultWarnings
	ReceiptObservation                                bool
}

// Each actual Attempt, including an inbox-release Attempt, has its own selected
// support record. Dormant templates are bounded separately for the active graph.
const (
	GeneratedResultSupportBytes  = uint64(contract.MaxChildPages) * (contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
	GeneratedResultAttemptLimit  = GeneratedResultSupportBytes / (contract.SupportRecordOverhead + contract.GeneratedAttemptRecordFixedLength)
	GeneratedResultEffectLimit   = GeneratedResultAttemptLimit + contract.GeneratorMaxTemplates
	GeneratedResultWorkLimit     = GeneratedResultSupportBytes / (contract.SupportRecordOverhead + contract.GeneratedDutyRecordFixedLength)
	generatedResultReleaseLimit  = GeneratedResultSupportBytes / (2*contract.SupportRecordOverhead + contract.GeneratedAttemptRecordFixedLength + contract.PendingInboxReleaseRecordBodyLength)
	GeneratedResultProgressLimit = GeneratedResultSupportBytes/(contract.SupportRecordOverhead+contract.GeneratorCarrierFixedLength+contract.GeneratorProgressLength) + 2*generatedResultReleaseLimit
)

func mergeGeneratedResultWarnings(a, b GeneratedResultWarnings) GeneratedResultWarnings {
	return GeneratedResultWarnings{PossibleLiveResidue: a.PossibleLiveResidue || b.PossibleLiveResidue,
		LateEffect: a.LateEffect || b.LateEffect, InvalidationNotConfirmed: a.InvalidationNotConfirmed || b.InvalidationNotConfirmed}
}
