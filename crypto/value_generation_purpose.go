package crypto

import (
	"enkv.sh/core/contract"
)

type generatedSessionAdmissionInput struct {
	Control             contract.ControlCore
	Bindings            []contract.BindingTableRow
	RouteID             contract.ID
	Graph               []byte
	BeforePublic        contract.PublicState
	Output              *contract.GeneratedOutputTransition
	Registry            *generatedRegistryAdmission
	SelectionPhase      *contract.GeneratedPhaseRecord
	BeforeAccess        *contract.CurrentAccessCore
	BeforeAccessRecords []contract.AccessRecord
}

type generatedPlanAdmissionInput struct {
	Declaration    []byte
	Canonical      []generatedCanonicalSelection
	LiveSourceUses []contract.GeneratorSourceUse
	CurrentIntents []contract.GeneratedCurrentIntentSelection
	CurrentValues  []contract.ConsumerSelection
}

type generatedReservationAdmissionInput struct {
	Session               generatedSessionAdmissionInput
	Plan                  generatedPlanAdmissionInput
	Accepted              map[contract.ID]contract.SealedInputCore
	Phase                 *contract.GeneratorPhaseIdentity
	Target                *contract.GeneratorTarget
	ControlledPredecessor *contract.GeneratedControlledPredecessor
}

type generatedAdoptionAdmissionInput struct {
	Session               generatedSessionAdmissionInput
	Plan                  generatedPlanAdmissionInput
	Phase                 contract.GeneratorPhaseIdentity
	Target                *contract.GeneratorTarget
	Material              contract.OperationMaterialRecord
	SeedAccess            []byte
	SourceProtections     []byte
	Result                generatedResultAdmission
	ControlledPredecessor *contract.GeneratedControlledPredecessor
}

type generatedFinalAdmissionInput struct {
	CanonicalAccess       []contract.ConsumerSelection
	Session               generatedSessionAdmissionInput
	Plan                  generatedPlanAdmissionInput
	Phase                 contract.GeneratorPhaseIdentity
	Target                *contract.GeneratorTarget
	Material              contract.OperationMaterialRecord
	SeedAccess            []byte
	SourceProtections     []byte
	Results               []generatedResultAdmission
	ResultBodies          [][]byte
	Preparation           *contract.GeneratedFinalPreparationRecord
	PreparationPhase      *contract.GeneratedPhaseRecord
	PreparedImage         []byte
	QualifyLegacy         bool
	CheckpointSupport     []contract.SupportRecord
	EntryAdmissions       []generatedEntryAdmission
	Membership            []generatedMembershipSelection
	ControlledPredecessor *contract.GeneratedControlledPredecessor
}

type generatedProducerPreparationAdmissionInput struct {
	Session               generatedSessionAdmissionInput
	Plan                  generatedPlanAdmissionInput
	Phase                 *contract.GeneratorPhaseIdentity
	Target                *contract.GeneratorTarget
	Material              contract.OperationMaterialRecord
	SeedAccess            []byte
	SourceProtections     []byte
	Producer              generatedProducerAdmissionInput
	ControlledPredecessor *contract.GeneratedControlledPredecessor
}

type generatedOriginalVerificationAdmissionInput struct {
	Owner      contract.SupportRecord
	Session    generatedSessionAdmissionInput
	Material   contract.OperationMaterialRecord
	SeedAccess []byte
	Result     generatedResultAdmission
	Target     *contract.GeneratorTarget
}

// generatedPlanState owns the checked plan inputs shared by the four plan
// purposes. Original-result verification deliberately has no access to them.
type generatedPlanState struct {
	sources               []generatedSource
	recipients            [][]contract.ID
	protections           []byte
	protection            contract.DigestLength
	intents               []contract.GeneratorDescriptor
	declaration           []byte
	canonicals            []generatedCanonicalSource
	liveSources           []contract.GeneratorSourceUse
	currentValues         []contract.ConsumerSelection
	controlledPredecessor *generatedControlledPredecessor
}

type generatedReservationState struct {
	plan    generatedPlanState
	streams [2]generatedStream
	phase   *contract.GeneratorPhaseIdentity
	phaseID contract.ID
	target  *contract.GeneratorTarget
}

type generatedAdoptionState struct {
	plan         generatedPlanState
	phase        contract.GeneratorPhaseIdentity
	phaseID      contract.ID
	target       *contract.GeneratorTarget
	results      []generatedResultAdmission
	validated    []contract.GeneratorResultReference
	localFailure *generatedLocalFailureAdmission
}

type generatedFinalPreparationState struct {
	canonicalAccess        []generatedCanonicalAccessPin
	plan                   generatedPlanState
	phase                  contract.GeneratorPhaseIdentity
	phaseID                contract.ID
	materializationPhaseID contract.ID
	preparedImage          *contract.GeneratedFinalPreparationImage
	qualificationImage     *contract.GeneratedFinalPreparationImage
	qualifyingLegacy       bool
	legacyExclusion        bool
	checkpointSupport      []contract.SupportRecord
	target                 *contract.GeneratorTarget
	results                []generatedResultAdmission
	resultBodies           [][]byte
	validated              []contract.GeneratorResultReference
	nonselecting           bool
	entryPreparations      []generatedEntryPreparation
	membership             []generatedMembershipSelection
	supplied               []generatedSuppliedPreparation
	suppliedNext           int
	suppliedBatch          uint32
	suppliedCount          int
	suppliedFinal          bool
	entryNext              int
	entryBatch             uint32
}

type generatedProducerPreparationState struct {
	plan        generatedPlanState
	phase       *contract.GeneratorPhaseIdentity
	phaseID     contract.ID
	target      *contract.GeneratorTarget
	producer    *generatedProducer
	returnOwner *generatedProducerReturnOwner
}

type generatedOriginalVerificationState struct {
	target contract.GeneratorTarget
	result generatedResultAdmission
}

// generatedPurposeState is a closed private sum. Admission installs exactly
// one concrete state and validates that it matches the encoded request purpose.
type generatedPurposeState struct {
	output       *contract.GeneratedOutputTransition
	reservation  *generatedReservationState
	adoption     *generatedAdoptionState
	final        *generatedFinalPreparationState
	producer     *generatedProducerPreparationState
	verification *generatedOriginalVerificationState
}

func (p generatedPurposeState) valid(purpose contract.CryptoGeneratedPurpose) bool {
	count := 0
	if p.reservation != nil {
		count++
	}
	if p.adoption != nil {
		count++
	}
	if p.final != nil {
		count++
	}
	if p.producer != nil {
		count++
	}
	if p.verification != nil {
		count++
	}
	if count != 1 {
		return false
	}
	switch purpose {
	case contract.CryptoGeneratedReservationPurpose:
		return p.reservation != nil
	case contract.CryptoGeneratedAdoptionPurpose:
		return p.adoption != nil
	case contract.CryptoGeneratedFinalPreparationPurpose:
		return p.final != nil
	case contract.CryptoGeneratedProducerPreparationPurpose:
		return p.producer != nil
	case contract.CryptoGeneratedOriginalVerificationPurpose:
		return p.verification != nil
	default:
		return false
	}
}

func (p generatedPurposeState) plan() *generatedPlanState {
	switch {
	case p.reservation != nil:
		return &p.reservation.plan
	case p.adoption != nil:
		return &p.adoption.plan
	case p.final != nil:
		return &p.final.plan
	case p.producer != nil:
		return &p.producer.plan
	default:
		return nil
	}
}

func (p generatedPurposeState) clear() {
	plan := p.plan()
	if plan != nil {
		for i := range plan.sources {
			clear(plan.sources[i].keys[:cap(plan.sources[i].keys)])
			clear(plan.sources[i].buffer[:cap(plan.sources[i].buffer)])
		}
		for i := range plan.canonicals {
			clear(plan.canonicals[i].buffer[:cap(plan.canonicals[i].buffer)])
			clear(plan.canonicals[i].wrap.RSACiphertext[:cap(plan.canonicals[i].wrap.RSACiphertext)])
			for j := range plan.canonicals[i].selectedAccess.Wraps {
				clear(plan.canonicals[i].selectedAccess.Wraps[j].RSACiphertext[:cap(plan.canonicals[i].selectedAccess.Wraps[j].RSACiphertext)])
			}
		}
		for _, selection := range plan.currentValues {
			clear(selection.Entry.ValueBytes[:cap(selection.Entry.ValueBytes)])
			for _, wrap := range selection.Access.Wraps {
				clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
			}
		}
		clear(plan.declaration[:cap(plan.declaration)])
		clear(plan.protections[:cap(plan.protections)])
		if plan.controlledPredecessor != nil {
			clear(plan.controlledPredecessor.Result[:cap(plan.controlledPredecessor.Result)])
			clear(plan.controlledPredecessor.SeedAccess[:cap(plan.controlledPredecessor.SeedAccess)])
			clear(plan.controlledPredecessor.source.Record.Body[:cap(plan.controlledPredecessor.source.Record.Body)])
			for _, row := range plan.controlledPredecessor.progress {
				clear(row[:cap(row)])
			}
		}
		*plan = generatedPlanState{}
	}
	if p.producer != nil {
		if p.producer.returnOwner != nil {
			p.producer.returnOwner.join()
			p.producer.returnOwner = nil
		}
		if producer := p.producer.producer; producer != nil {
			clear(producer.intent[:cap(producer.intent)])
			clear(producer.originalFacts[:cap(producer.originalFacts)])
			clear(producer.ownerRecord.Body[:cap(producer.ownerRecord.Body)])
			for _, row := range producer.consumers {
				clear(row[:cap(row)])
			}
			for _, row := range producer.progress {
				clear(row[:cap(row)])
			}
			p.producer.producer = nil
		}
	}
	if p.reservation != nil {
		*p.reservation = generatedReservationState{}
	}
	if p.adoption != nil {
		*p.adoption = generatedAdoptionState{}
	}
	if p.final != nil {
		for _, pin := range p.final.canonicalAccess {
			for _, wrap := range pin.access.Wraps {
				clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
			}
		}
		for _, row := range p.final.checkpointSupport {
			clear(row.Body[:cap(row.Body)])
		}
		if p.final.preparedImage != nil {
			p.final.preparedImage.Clear()
		}
		if p.final.qualificationImage != nil {
			p.final.qualificationImage.Clear()
		}
		for _, body := range p.final.resultBodies {
			clear(body[:cap(body)])
		}
		for _, row := range p.final.membership {
			for _, wrap := range row.Selection.Access.Wraps {
				clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
			}
		}
		*p.final = generatedFinalPreparationState{}
	}
	if p.producer != nil {
		*p.producer = generatedProducerPreparationState{}
	}
	if p.verification != nil {
		*p.verification = generatedOriginalVerificationState{}
	}
}
