package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

// The private parent installs one bounded return path. It is not a process or
// provider transport, and it never receives operation keys.
type generatedProducerAdmissionInput struct {
	retirementReturn      contract.RetirementReturnProof
	Expected              contract.GeneratorResultExpectation
	Preparation           contract.GeneratedProducerPreparation
	Intent, OriginalFacts []byte
	Duty                  contract.GeneratedDutyRecord
	Source                contract.SupportRecord
	Attempt               contract.GeneratedAttemptRecord
	Consumers             [][]byte
	Progress              [][]byte
	Probe                 func(context.Context, contract.GeneratedProducerCommand) []byte
	Return                func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn
	Process               generatorhost.Launcher
}

type generatedProducerReturn struct {
	Facts                   contract.GeneratorSafeFacts
	Secret                  []byte
	stage                   generatedFailureStage
	category                generatedFailureCategory
	effect                  generatedEffect
	settled                 bool
	executableCleanupFailed bool
}

type generatedProducerOutput struct {
	retirementAmbiguity      []byte
	resultDeadlineUnixMillis uint64
	Record                   []byte
	Facts                    contract.GeneratorSafeFacts
	code                     contract.CryptoResultCode
	stage                    generatedFailureStage
	category                 generatedFailureCategory
	effect                   generatedEffect
	executableCleanupFailed  bool
}

type generatedEffect string

const (
	generatedEffectNoSend        generatedEffect = "no_send"
	generatedEffectUnknown       generatedEffect = "unknown"
	generatedEffectComplete      generatedEffect = "complete"
	generatedEffectOwnedUnusable generatedEffect = "owned_unusable"
	generatedEffectNoEffect      generatedEffect = "no_effect"
	generatedEffectDeleteAck     generatedEffect = "delete_acknowledged"
)

func generatedEffectFromDisposition(disposition uint8) generatedEffect {
	switch disposition {
	case contract.GeneratorDispositionCompleteCreate:
		return generatedEffectComplete
	case contract.GeneratorDispositionOwnedUnusableCreate:
		return generatedEffectOwnedUnusable
	case contract.GeneratorDispositionRetirementAcknowledged:
		return generatedEffectDeleteAck
	case contract.GeneratorDispositionConfirmedNoEffect:
		return generatedEffectNoEffect
	default:
		return generatedEffectUnknown
	}
}

type generatedFailureStage string

const (
	generatedFailureEntry      generatedFailureStage = "entry"
	generatedFailureAuthority  generatedFailureStage = "authority"
	generatedFailureOwner      generatedFailureStage = "owner"
	generatedFailureReturn     generatedFailureStage = "return"
	generatedFailureDeadline   generatedFailureStage = "deadline"
	generatedFailurePipe       generatedFailureStage = "pipe"
	generatedFailureLaunch     generatedFailureStage = "launch"
	generatedFailureResultRead generatedFailureStage = "result_read"
	generatedFailureWait       generatedFailureStage = "wait"
	generatedFailureStatus     generatedFailureStage = "status"
	generatedFailureDecode     generatedFailureStage = "decode"
	generatedFailureBinding    generatedFailureStage = "binding"
	generatedFailureFacts      generatedFailureStage = "facts"
	generatedFailureSeal       generatedFailureStage = "seal"
)

type generatedFailureCategory string

const (
	generatedFailureInvalid     generatedFailureCategory = "invalid"
	generatedFailureUnavailable generatedFailureCategory = "unavailable"
	generatedFailureCancelled   generatedFailureCategory = "cancelled"
	generatedFailureExpired     generatedFailureCategory = "expired"
	generatedFailureProtocol    generatedFailureCategory = "protocol"
	generatedFailureUsed        generatedFailureCategory = "already_used"
)

// generatedProducerReturnOwner is installed only after the exact entry
// decision. It owns the transferred seed and return inputs independently of
// ordinary session cancellation until the fixed command deadline or return.
type generatedProducerReturnOwner struct {
	retirementProof *retirementReturnProof
	expected        contract.GeneratorResultExpectation
	command         contract.GeneratedProducerCommand
	material        contract.OperationMaterialRecord
	seed            []byte
	intent          []byte
	returnValue     func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn
	process         generatorhost.Launcher
	probe           func(context.Context, contract.GeneratedProducerCommand) []byte
	progress        [][]byte
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
}

func newGeneratedProducerReturnOwner(a *generatedAdmission, p *generatedProducer, command contract.GeneratedProducerCommand, caller context.Context) *generatedProducerReturnOwner {
	command.Intent, command.OriginalFacts = p.intent, p.originalFacts
	deadline := time.UnixMilli(int64(command.DeadlineUnixMillis))
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	ctx = telemetry.PrivateContext(ctx, caller)
	o := &generatedProducerReturnOwner{retirementProof: p.retirementProof, expected: p.expected, command: command, material: a.material,
		seed: a.seed, intent: p.intent, returnValue: p.returnValue, process: p.process, probe: p.probe,
		progress: p.progress, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	a.seed, p.intent, p.originalFacts, p.progress, p.retirementProof = nil, nil, nil, nil, nil
	p.returnValue, p.process, p.probe = nil, nil, nil
	return o
}

func (o *generatedProducerReturnOwner) finish(returned []byte) {
	if o.retirementProof != nil {
		o.retirementProof.Close()
		o.retirementProof = nil
	}
	clear(returned[:cap(returned)])
	clear(o.seed[:cap(o.seed)])
	clear(o.intent[:cap(o.intent)])
	clear(o.command.OriginalFacts[:cap(o.command.OriginalFacts)])
	o.command.Intent, o.command.OriginalFacts = nil, nil
	for _, row := range o.progress {
		clear(row[:cap(row)])
	}
	o.seed, o.intent, o.progress = nil, nil, nil
	o.returnValue, o.process, o.probe = nil, nil, nil
	o.cancel()
	close(o.done)
}

func (o *generatedProducerReturnOwner) join() {
	<-o.done
}

func (o *generatedProducerReturnOwner) expired() bool {
	if !time.Now().Before(time.UnixMilli(int64(o.command.DeadlineUnixMillis))) {
		return true
	}
	select {
	case <-o.ctx.Done():
		return true
	default:
		return false
	}
}

type generatedProducer struct {
	retirementProof    *retirementReturnProof
	expected           contract.GeneratorResultExpectation
	preparation        contract.GeneratedProducerPreparation
	intent             []byte
	originalFacts      []byte
	duty               contract.GeneratedDutyRecord
	ownerRecord        contract.SupportRecord
	ownerConsumers     contract.GeneratorDescriptor
	attempt            contract.GeneratedAttemptRecord
	consumers          [][]byte
	returnValue        func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn
	process            generatorhost.Launcher
	probe              func(context.Context, contract.GeneratedProducerCommand) []byte
	progress           [][]byte
	locator            contract.ID
	claimed, entryUsed bool
}

func (a *generatedAdmission) admitProducer(input *generatedProducerAdmissionInput) bool {
	state := a.purpose.producer
	if state == nil || input == nil || !a.expectedResultMatches(input.Expected) || !a.automaticAttemptAllowed(input.Expected.Template) {
		return false
	}
	paths := 0
	if input.Return != nil {
		paths++
	}
	if input.Process != nil {
		paths++
	}
	if input.Probe != nil {
		paths++
	}
	if paths != 1 {
		return false
	}
	x, c, d, v := input.Expected.Template, input.Preparation, input.Duty, input.Attempt
	row := input.Source
	if row.Kind == 0 {
		body, err := contract.EncodeGeneratedDutyRecord(d)
		if err != nil {
			return false
		}
		row = contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: d.DutyID, Body: body}
	} else if d != (contract.GeneratedDutyRecord{}) {
		return false
	}
	local := x.SemanticLifecycleMode() == contract.GeneratorLifecycleNone
	var source contract.GeneratedDeleteSource
	ownerRecord, ownerConsumers := row, d.Consumers
	if local {
		if input.Source.Kind != 0 || !input.Source.RecordID.IsZero() || len(input.Source.Body) != 0 || d.Schema != contract.GeneratedDutyRecordSchema || d.LifecycleMode != contract.GeneratorLifecycleNone || x.Action != contract.GeneratorActionCreate || d.DomainID != c.DomainID || d.DutyID != x.DutyID || d.OwnerID != x.DutyID || d.ResourceID != x.ResourceIncarnationID || d.DescriptorID != x.DescriptorID || d.ConfigContractID != x.ConfigContractID || d.ExecutorID != x.ExecutorID || d.CredentialRouteID != x.CredentialRouteID || d.ResourceContractID != x.ResourceContractID || d.ResultContractID != x.ResultContractID {
			return false
		}
	} else {
		var sourceErr error
		source, sourceErr = contract.InspectGeneratedDeleteSource(row)
		if sourceErr != nil {
			return false
		}
		ownerRecord, ownerConsumers = source.Record, source.Consumers
	}
	if x.CompletionClass == contract.GeneratedCompletionConfirmed && x.Action == contract.GeneratorActionDelete {
		progress, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorProgress, input.Progress)
		if err != nil || v.Progress != progress || state.plan.controlledPredecessor == nil ||
			state.plan.controlledPredecessor.source.Record.Kind != source.Record.Kind || state.plan.controlledPredecessor.source.SourceID != source.SourceID ||
			state.plan.controlledPredecessor.source.OwnerID != source.OwnerID || len(input.Progress) != len(state.plan.controlledPredecessor.progress) ||
			source.Record.Kind == contract.GeneratedDutySupportKind && (progress != d.Progress || d.Step != uint8(1+len(input.Progress))) {
			return false
		}
		if len(input.Progress) == 0 && input.Probe != nil || len(input.Progress) == 1 && input.Probe == nil || len(input.Progress) > 1 {
			return false
		}
		for i, body := range input.Progress {
			p, err := contract.InspectGeneratorProgress(body)
			if err != nil || p.RequiredSteps != contract.GeneratorConfirmedRequiredSteps || p.CompletedSteps != contract.GeneratorProgressAcknowledged || p.CompletionClass != x.CompletionClass || !bytes.Equal(body, state.plan.controlledPredecessor.progress[i]) {
				return false
			}
		}
		if len(input.Progress) == 1 {
			p, _ := contract.InspectGeneratorProgress(input.Progress[0])
			want := contract.GeneratorControlledRetirementProbeDigest(c.DomainID, x.ResourceIncarnationID, c.ResourceDigest, contract.GeneratorControlledRetirementScope(x.DescriptorID, x.ConfigContractID, x.ResultContractID), p.ResultID, p.Evidence.Digest)
			if c.RequestDigest != want {
				return false
			}
		}
	} else if input.Probe != nil || len(input.Progress) != 0 {
		return false
	}
	if input.Process != nil {
		if x.SemanticLifecycleMode() == contract.GeneratorLifecycleManaged && x.CompletionClass != contract.GeneratedCompletionAcknowledged {
			return false
		}
		implementation := input.Process.Implementation()
		if implementation.Validate() != nil || implementation.DescriptorID != x.DescriptorID ||
			implementation.ExecutorID != x.ExecutorID ||
			implementation.CredentialRouteID != x.CredentialRouteID {
			return false
		}
		resultContract, err := contract.GeneratedResultContractForReader(implementation, x.Action, x.CompletionClass, input.Expected.Use.MaxSecret, input.Expected.Use.MaxFacts, input.Expected.InputEncoding, x.ResultReaderID)
		if err != nil || resultContract != x.ResultContractID {
			return false
		}
	}
	if len(input.OriginalFacts) > contract.GeneratorSafeFactsEnvelopeLength {
		return false
	}
	if x.Action == contract.GeneratorActionCreate {
		if len(input.OriginalFacts) != 0 {
			return false
		}
	} else {
		original, err := contract.InspectGeneratorSafeFacts(input.OriginalFacts)
		if err != nil || original.Action != contract.GeneratorActionCreate || original.LifecycleMode != x.LifecycleMode || original.ResourceContractID != x.ResourceContractID || original.IntentDigest != x.IntentDigest || (original.Disposition != contract.GeneratorDispositionCompleteCreate && original.Disposition != contract.GeneratorDispositionOwnedUnusableCreate) {
			return false
		}
		resource, err := contract.GeneratorResourceDigest(original.GeneratorSafeFacts)
		if err != nil || resource != input.Expected.TargetResourceDigest || resource != c.ResourceDigest {
			return false
		}
	}
	digest, err := contract.GeneratorIntentDigest(input.Intent)
	if err != nil || digest != x.IntentDigest || len(input.Intent) > contract.GeneratorIntentMaxLength ||
		c.RequestIdentityDigest != a.request.Parent.RequestIdentityDigest || c.PlanGraphID != a.graph.UsePlan.PlanGraphID ||
		c.RequestDigest != input.Expected.RequestDigest || c.ResourceDigest != input.Expected.TargetResourceDigest {
		return false
	}
	seed, err := contract.EncodeAccessRecord(a.access)
	if err != nil {
		return false
	}
	// Reuse the full public request relation checks, then add private graph,
	// declaration, candidate and lifetime facts that the wire cannot establish.
	_, err = contract.EncodeCryptoGeneratedProducerRequest(contract.CryptoGeneratedProducerRequest{OperationRef: a.request.Context.AdmissionID,
		Context: a.request.Context, Template: x, Material: a.material, SeedAccess: seed, Preparation: c,
		Intent: contract.GeneratorDescriptor{Digest: digest, Length: uint64(len(input.Intent)), Count: 1}})
	if err != nil {
		return false
	}
	if _, err := contract.GeneratedAttemptRecordLength(v); err != nil {
		return false
	}
	template, err := contract.GeneratorTemplateID(x)
	if err != nil || v.DomainID != c.DomainID || v.OperationID != c.OperationID || v.LineageID != x.LineageID || v.AttemptID != x.AttemptID ||
		v.TemplateDigest != template || v.PredecessorAttemptID != x.PredecessorAttemptID || v.OwnerID != x.DutyID || v.ResourceID != x.ResourceIncarnationID ||
		v.TransmissionID != x.TransmissionID || v.ResultID != x.ResultID || v.InboxID != x.InboxID || v.DescriptorID != x.DescriptorID ||
		v.ConfigContractID != x.ConfigContractID || v.ExecutorID != x.ExecutorID || v.CredentialRouteID != x.CredentialRouteID ||
		v.ResourceContractID != x.ResourceContractID || v.ResultContractID != x.ResultContractID || v.RequestDigest != c.RequestDigest ||
		v.State != contract.GeneratedEffectTransmitted || v.LifecycleMode != x.LifecycleMode || v.CompletionClass != x.CompletionClass {
		return false
	}
	if !local && (source.DomainID != c.DomainID || source.OwnerID != x.DutyID || source.ResourceID != x.ResourceIncarnationID || source.DescriptorID != x.DescriptorID ||
		source.ConfigContractID != x.ConfigContractID || source.ExecutorID != x.ExecutorID || source.CredentialRouteID != x.CredentialRouteID ||
		source.ResourceContractID != x.ResourceContractID || source.CompletionClass != x.CompletionClass ||
		source.Record.Kind == contract.GeneratedDutySupportKind && d.Kind != contract.GeneratedDutyUnselectedCleanup && d.ResultContractID != x.ResultContractID) {
		return false
	}
	if x.Action == contract.GeneratorActionCreate && (ownerRecord.Kind != contract.GeneratedDutySupportKind || d.Kind != contract.GeneratedDutyCreate || d.OriginalOperationID != c.OperationID || d.OriginalAttemptID != x.AttemptID || d.Status != contract.GeneratedEffectTransmitted) || x.Action == contract.GeneratorActionDelete && d.Kind == contract.GeneratedDutyCreate || state.phase == nil && (x.Action != contract.GeneratorActionCreate || x.Branch != contract.GeneratorBranchInitial) {
		return false
	}
	if x.Action == contract.GeneratorActionDelete && (!a.deleteTargetSourceMatches(source, x) || state.target == nil || state.target.ResourceDigest != input.Expected.TargetResourceDigest) {
		return false
	}
	if d.Kind == contract.GeneratedDutyUnselectedCleanup {
		transmission, err := contract.GeneratorTransmissionID(d.OriginalAttemptID, contract.GeneratorActionCreate)
		if err != nil {
			return false
		}
		original, err := contract.GeneratorResultID(d.DomainID, d.OriginalOperationID, d.OriginalAttemptID, transmission, contract.GeneratorActionCreate)
		if err != nil || x.Action != contract.GeneratorActionDelete || x.TargetKind != contract.GeneratorTargetResultResourceSlot || x.TargetSourceID != original ||
			d.Status != contract.GeneratedEffectSucceeded || d.OriginalOperationID == c.OperationID {
			return false
		}
	}
	purpose := contract.GeneratorAuthorityReservation
	if x.Action == contract.GeneratorActionDelete {
		if source.Record.Kind == contract.GeneratedHazardSupportKind {
			purpose = contract.GeneratorAuthorityCleanupReserve
		} else {
			switch d.Kind {
			case contract.GeneratedDutyRetirement:
				purpose = contract.GeneratorAuthorityRetireReserve
			case contract.GeneratedDutyUnselectedCleanup:
				purpose = contract.GeneratorAuthorityCleanupReserve
			default:
				return false
			}
		}
	}
	if x.Action == contract.GeneratorActionCreate && x.Branch > contract.GeneratorBranchInitial && (x.Branch > contract.GeneratorBranchResidueThenNoEffect || state.phase == nil || state.phase.TransitionKind != contract.GeneratorAuthorityReservation) {
		return false
	}
	if state.phase != nil && state.phase.TransitionKind != purpose {
		return false
	}
	consumers, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, input.Consumers)
	if err != nil || consumers != ownerConsumers {
		return false
	}
	useContext, err := contract.GeneratorResultUseDigest(input.Expected.Use)
	if err != nil {
		return false
	}
	derive, adopt := false, false
	for _, body := range input.Consumers {
		row, err := contract.InspectGeneratorConsumer(body)
		if err != nil || row.OwnerID != ownerRecord.RecordID {
			return false
		}
		if row.SubjectKind != contract.GeneratorConsumerOriginalResult || row.SubjectID != x.ResultID {
			continue
		}
		if row.MaterialID != a.request.MaterialID || row.ContextDigest != useContext {
			return false
		}
		derive = derive || row.Purpose == contract.GeneratorConsumerDeriveSelectedResult
		adopt = adopt || row.Purpose == contract.GeneratorConsumerAdoptLateOriginalResult
	}
	if !adopt || x.Action == contract.GeneratorActionCreate && !derive {
		return false
	}
	ownerRecord.Body = bytes.Clone(ownerRecord.Body)
	var proof *retirementReturnProof
	if input.retirementReturn != nil {
		var ok bool
		proof, ok = input.retirementReturn.(*retirementReturnProof)
		if !ok || proof == nil || a.graph.Request.OperationKind != contract.OperationRetireGeneratedGeneration || x.Action != contract.GeneratorActionDelete || !proof.claim(a.graph.Request.CallerNonce) {
			return false
		}
	}
	p := &generatedProducer{retirementProof: proof, expected: input.Expected, preparation: c, intent: bytes.Clone(input.Intent), originalFacts: bytes.Clone(input.OriginalFacts), duty: d, ownerRecord: ownerRecord, ownerConsumers: ownerConsumers, attempt: v, returnValue: input.Return, process: input.Process}
	p.probe = input.Probe
	for _, row := range input.Progress {
		p.progress = append(p.progress, bytes.Clone(row))
	}
	for _, row := range input.Consumers {
		p.consumers = append(p.consumers, bytes.Clone(row))
	}
	state.producer = p
	return true
}

func (a *generatedAdmission) prepareProducer(v contract.CryptoGeneratedProducerRequestView, out *contract.CryptoResponse) contract.CryptoResultCode {
	state := a.purpose.producer
	if state == nil {
		return contract.CryptoInvalidAdmission
	}
	p := state.producer
	access, err := contract.DecodeAccessRecord(v.SeedAccess)
	if p == nil || err != nil || v.Template != p.expected.Template || v.Material != a.material || !sameAccessRecord(access, a.access) ||
		v.Preparation != p.preparation || v.Intent.Digest != p.expected.Template.IntentDigest || v.Intent.Length != uint64(len(p.intent)) || v.Intent.Count != 1 {
		return contract.CryptoInvalidAdmission
	}
	if _, err := rand.Read(p.locator[:]); err != nil || p.locator.IsZero() {
		return contract.CryptoCustodyUnavailable
	}
	out.Body, err = contract.EncodeCryptoGeneratedProducerResult(contract.CryptoGeneratedProducerResult{ProducerLocatorID: p.locator})
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	a.stage = contract.CryptoFreeze
	return contract.CryptoSuccess
}

func (a *generatedAdmission) candidateProducerMatches(c generatedCandidate) bool {
	state := a.purpose.producer
	if state == nil {
		return false
	}
	p := state.producer
	if p == nil || p.locator.IsZero() {
		return false
	}
	if state.phase != nil {
		x, s := p.expected.Template, c.Subject
		if state.phase.TransitionKind == contract.GeneratorAuthorityReservation && x.Action == contract.GeneratorActionCreate && x.Branch > contract.GeneratorBranchInitial {
			if !a.candidateSuccessorReservationProducer(c) {
				return false
			}
		} else if state.phase.TransitionKind == contract.GeneratorAuthorityNoEffectBranch {
			if !a.candidateNoEffectProducerPredecessor(c) {
				return false
			}
		} else if s.LineageID != x.LineageID || s.AttemptID != x.AttemptID || s.DescriptorID != x.DescriptorID || s.ConfigContractID != x.ConfigContractID ||
			s.ResultContractID != x.ResultContractID {
			return false
		}
	}
	foundOriginal := p.expected.Template.Action == contract.GeneratorActionCreate
	var originalResult contract.ID
	if !foundOriginal {
		target := a.deleteTarget()
		if target == nil {
			return false
		}
		transmission, err := contract.GeneratorTransmissionID(target.OriginalAttemptID, contract.GeneratorActionCreate)
		if err != nil {
			return false
		}
		originalResult, err = contract.GeneratorResultID(a.graph.Header.DomainID, target.OriginalOperationID, target.OriginalAttemptID, transmission, contract.GeneratorActionCreate)
		if err != nil {
			return false
		}
	}
	foundAttempt, foundDuty := false, false
	seen := make([]bool, len(p.consumers))
	for _, row := range c.SupportRecords {
		switch {
		case row.Kind == contract.GeneratedCreateEvidenceSupportKind && row.RecordID == originalResult:
			evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
			if err != nil || evidence.OriginalResultID != originalResult || !bytes.Equal(evidence.SafeFacts, p.originalFacts) {
				return false
			}
			foundOriginal = true
		case row.Kind == contract.GeneratedResultSupportKind && row.RecordID == originalResult:
			result, err := contract.InspectGeneratedResultRecord(row.Body)
			if err != nil || result.Core.ResultID != originalResult {
				return false
			}
			facts, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts.GeneratorSafeFacts)
			if err != nil || !bytes.Equal(facts, p.originalFacts) {
				return false
			}
			foundOriginal = true
		case row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == p.attempt.AttemptID:
			v, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil || v != p.attempt {
				return false
			}
			foundAttempt = true
		case row.Kind == p.ownerRecord.Kind && row.RecordID == p.ownerRecord.RecordID:
			if !bytes.Equal(row.Body, p.ownerRecord.Body) {
				return false
			}
			foundDuty = true
		case row.Kind == contract.GeneratorVectorSupportKind:
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return false
			}
			if v.OwnerKind != p.ownerRecord.Kind || v.OwnerID != p.ownerRecord.RecordID || v.VectorKind != contract.GeneratorVectorConsumers {
				continue
			}
			id, err := contract.GeneratorVectorCarrierID(v)
			if err != nil || id != row.RecordID || v.DomainID != c.Subject.DomainID || v.Vector != p.ownerConsumers ||
				int(v.Ordinal) >= len(seen) || seen[v.Ordinal] || !bytes.Equal(v.Row, p.consumers[v.Ordinal]) {
				return false
			}
			seen[v.Ordinal] = true
		}
	}
	for _, present := range seen {
		if !present {
			return false
		}
	}
	return foundAttempt && foundDuty && foundOriginal
}

func (a *generatedAdmission) candidateSuccessorReservationProducer(c generatedCandidate) bool {
	state := a.purpose.producer
	if state == nil || state.producer == nil || state.phase == nil {
		return false
	}
	x, subject := state.producer.expected.Template, c.Subject
	if x.Action != contract.GeneratorActionCreate || x.Branch == contract.GeneratorBranchInitial || x.Branch > contract.GeneratorBranchResidueThenNoEffect || subject.Purpose != contract.GeneratorAuthorityReservation ||
		subject.LineageID != x.LineageID || subject.AttemptID != x.AttemptID || subject.PredecessorAttemptID != x.PredecessorAttemptID ||
		subject.ResultID != x.ResultID || subject.DescriptorID != x.DescriptorID || subject.ConfigContractID != x.ConfigContractID ||
		subject.ResultContractID != x.ResultContractID || !subject.ResultDigest.IsZero() {
		return false
	}
	body, err := contract.EncodeGeneratorAttemptTemplate(x)
	if err != nil || state.phase.Evidence != (contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: uint64(len(body)), Count: 1}) {
		return false
	}
	var predecessor contract.GeneratorAttemptTemplate
	for _, lineage := range a.graph.Lineages {
		if lineage.LineageID != x.LineageID {
			continue
		}
		for _, candidate := range lineage.Templates[:lineage.TemplateCount] {
			if candidate.AttemptID == x.PredecessorAttemptID {
				predecessor = candidate
				break
			}
		}
	}
	if predecessor.AttemptID.IsZero() || predecessor.Action != contract.GeneratorActionCreate {
		return false
	}
	guard, outcome := uint8(contract.GeneratorGuardResidue), uint8(contract.GeneratedEffectClosedWithResidue)
	if x.Branch == contract.GeneratorBranchNoEffect || x.Branch == contract.GeneratorBranchResidueThenNoEffect {
		guard, outcome = contract.GeneratorGuardQualifiedNoEffect, contract.GeneratedEffectConfirmedNoEffect
	}
	branch, present, err := predecessor.SuccessorBranch(guard)
	if err != nil || !present || branch != x.Branch {
		return false
	}
	from, err := contract.GeneratorTemplateID(predecessor)
	if err != nil {
		return false
	}
	to, err := contract.GeneratorTemplateID(x)
	if err != nil {
		return false
	}
	noEffectUsed, residueUsed := uint8(0), uint8(0)
	if x.Branch == contract.GeneratorBranchNoEffect || x.Branch >= contract.GeneratorBranchNoEffectThenResidue {
		noEffectUsed = 1
	}
	if x.Branch >= contract.GeneratorBranchResidue {
		residueUsed = 1
	}
	edgeFound := false
	for _, edge := range a.graph.Edges {
		if edge.SourceTemplateID == from && edge.DestinationTemplateID == to && edge.Guard == guard &&
			edge.ResultSlotID == predecessor.ResultID && edge.RequiredAuthoritySet == x.RequiredAuthoritySet &&
			edge.NoEffectUsed == noEffectUsed && edge.ResidueUsed == residueUsed {
			edgeFound = true
		}
	}
	if !edgeFound {
		return false
	}
	selected := generatedSelectedRecord(c.SupportRecords, contract.GeneratedAttemptSupportKind, predecessor.AttemptID)
	p, err := contract.InspectGeneratedAttemptRecord(selected.Body)
	if err != nil || p.State != outcome || p.Stage != contract.GeneratedStageTerminal || p.OperationID != subject.OperationID ||
		p.LineageID != x.LineageID || p.RequestDigest != state.producer.attempt.RequestDigest {
		return false
	}
	if guard == contract.GeneratorGuardQualifiedNoEffect {
		packet := generatedSelectedRecord(c.SupportRecords, contract.GeneratedResultSupportKind, predecessor.ResultID)
		r, err := contract.InspectGeneratedResultRecord(packet.Body)
		return err == nil && r.Core.AttemptID == predecessor.AttemptID && r.SafeFacts.Disposition == contract.GeneratorDispositionConfirmedNoEffect
	}
	hazard := generatedSelectedRecord(c.SupportRecords, contract.GeneratedHazardSupportKind, predecessor.HazardID)
	h, err := contract.InspectGeneratedHazardRecord(hazard.Body)
	return err == nil && h.Fenced == 1 && h.OriginalOperationID == p.OperationID && h.OriginalAttemptID == p.AttemptID
}

func (a *generatedAdmission) candidateNoEffectProducerPredecessor(c generatedCandidate) bool {
	state := a.purpose.producer
	if state == nil || state.producer == nil || state.phase == nil {
		return false
	}
	x, subject := state.producer.expected.Template, c.Subject
	if x.Action != contract.GeneratorActionCreate || x.Branch != contract.GeneratorBranchNoEffect || x.PredecessorAttemptID.IsZero() || subject.Purpose != contract.GeneratorAuthorityNoEffectBranch ||
		subject.AttemptID != x.PredecessorAttemptID || subject.LineageID != x.LineageID || subject.DescriptorID != x.DescriptorID ||
		subject.ConfigContractID != x.ConfigContractID || subject.ResultContractID != x.ResultContractID {
		return false
	}
	var expected contract.GeneratorResultExpectation
	for _, lineage := range a.graph.Lineages {
		for _, prior := range lineage.Templates[:lineage.TemplateCount] {
			if prior.AttemptID != x.PredecessorAttemptID {
				continue
			}
			if prior.Action != contract.GeneratorActionCreate || prior.Branch != contract.GeneratorBranchInitial || prior.LineageID != x.LineageID {
				return false
			}
			for _, use := range a.graph.ResultUses {
				if use.AttemptID == prior.AttemptID {
					expected = contract.GeneratorResultExpectation{InputEncoding: state.producer.expected.InputEncoding, Plan: a.graph.UsePlan, Template: prior, Use: use, RequestDigest: state.producer.expected.RequestDigest}
				}
			}
		}
	}
	packet := generatedSelectedRecord(c.SupportRecords, contract.GeneratedResultSupportKind, expected.Template.ResultID)
	from, fromErr := contract.GeneratorTemplateID(expected.Template)
	to, toErr := contract.GeneratorTemplateID(x)
	edgeFound := false
	for _, edge := range a.graph.Edges {
		if edge.SourceTemplateID == from && edge.DestinationTemplateID == to && edge.Guard == contract.GeneratorGuardQualifiedNoEffect && edge.ResultSlotID == expected.Template.ResultID &&
			edge.NoEffectUsed == 1 && edge.ResidueUsed == 0 && edge.RequiredAuthoritySet == x.RequiredAuthoritySet {
			edgeFound = true
		}
	}
	if fromErr != nil || toErr != nil || !edgeFound {
		return false
	}
	r, err := contract.DecodeGeneratedResultRecord(packet.Body)
	if err != nil || contract.ValidateGeneratedResult(expected, a.material, r) != nil || subject.ResultID != r.Core.ResultID ||
		subject.ResultDigest != contract.Hash(packet.Body) || state.phase.Evidence != (contract.GeneratorDescriptor{Digest: contract.Hash(packet.Body), Length: uint64(len(packet.Body)), Count: 1}) ||
		r.SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect || len(r.SafeFacts.Target) != 0 || len(r.SafeFacts.ResourceData) != 0 {
		return false
	}
	plain, err := custody.OpenGeneratedResult(expected, a.material, a.seed, r)
	if err != nil {
		return false
	}
	clear(plain[:cap(plain)])
	return true
}

// This private entry is called only after the parent consumes its exact
// direct-ACK/readback permit. The locator and authority digest only identify
// preparation; neither is a public send capability. Work ownership is added
// before releasing the lock and survives cancellation until sealing ends.
func (r *Runtime) invokeGeneratedProducerOwned(ctx context.Context, id, locator, authority contract.ID) (out generatedProducerOutput) {
	return r.invokeGeneratedProducerAdmission(ctx, id, locator, authority, nil, nil)
}

func (r *Runtime) invokeGeneratedProducerAdmission(ctx context.Context, id, locator, authority contract.ID, expected *generatedAdmission, failure *generatedLocalFailureOutcome) (out generatedProducerOutput) {
	out.code = contract.CryptoInvalidAdmission
	out.stage, out.category = generatedFailureEntry, generatedFailureInvalid
	out.effect = generatedEffectNoSend
	if r == nil || ctx == nil {
		return out
	}
	telemetryContext := telemetry.PrivateContext(context.Background(), ctx)
	r.mu.Lock()
	a := r.generated
	if a == nil || a.id != id || expected != nil && a != expected {
		r.mu.Unlock()
		return out
	}
	state := a.purpose.producer
	if a.used || state != nil && state.producer != nil && state.producer.entryUsed {
		r.mu.Unlock()
		out.code = contract.CryptoAlreadyUsed
		out.category = generatedFailureUsed
		return out
	}
	var p *generatedProducer
	if state != nil {
		p = state.producer
	}
	if r.closed || p == nil || !p.claimed || a.busy || a.candidate == nil {
		r.mu.Unlock()
		return out
	}
	// A claimed owner's entry decision is spent even when its arguments or
	// caller context are invalid. Register its join before releasing the lock.
	p.entryUsed = true
	a.work.Add(1)
	wantAuthority := a.candidate.authorityDigest
	r.mu.Unlock()
	callerDone := ctx.Done()
	authorityDeadline := a.deadline
	if callerDeadline, finite := ctx.Deadline(); finite && callerDeadline.Before(authorityDeadline) {
		authorityDeadline = callerDeadline
	}
	finishRefusal := func() {
		a.work.Done()
		a.cancel()
	}
	if p.locator != locator || wantAuthority != authority {
		out.stage = generatedFailureAuthority
		finishRefusal()
		return out
	}
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		out.code = code
		out.category = generatedCategoryForCode(code)
		finishRefusal()
		return out
	}
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	r.mu.Lock()
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		r.mu.Unlock()
		out.code = code
		out.category = generatedCategoryForCode(code)
		finishRefusal()
		return out
	}
	if r.closed || r.generated != a || a.used || state.returnOwner != nil {
		r.mu.Unlock()
		out.stage = generatedFailureOwner
		finishRefusal()
		return out
	}
	now := time.Now()
	nowMillis := uint64(now.UnixMilli())
	deadlineMillis := min(a.request.Context.Expiry/uint64(time.Millisecond), nowMillis+contract.GeneratorMaximumChildCommandDurationMillis)
	if deadlineMillis <= nowMillis {
		r.mu.Unlock()
		out.code = contract.CryptoExpired
		out.stage, out.category = generatedFailureDeadline, generatedFailureExpired
		finishRefusal()
		return out
	}
	command := contract.GeneratedProducerCommand{GeneratedProducerPreparation: p.preparation, DeadlineUnixMillis: deadlineMillis}
	owner := newGeneratedProducerReturnOwner(a, p, command, telemetryContext)
	out.effect = generatedEffectUnknown
	state.returnOwner = owner
	failure.enter(callerDone, authorityDeadline)
	r.mu.Unlock()
	settle := telemetry.StartWithDetails(owner.ctx, telemetry.ProviderCrypto, telemetry.OpCryptoGeneratedReturnSettle,
		generatedAttemptDetails(owner.command.AttemptID))
	owner.ctx = telemetry.CallContext(owner.ctx, settle)
	defer func() { finishCryptoCall(settle, out.code) }()

	var returned generatedProducerReturn
	settled := owner.process == nil
	defer func() {
		owner.finish(returned.Secret)
		failure.record(out, settled)
		a.work.Done()
		a.cancel()
	}()

	if owner.process != nil {
		var code contract.CryptoResultCode
		returned, code = invokeGeneratedProcess(r.openResultPipe, owner.ctx, owner.process, owner.command, owner.intent)
		out.executableCleanupFailed = returned.executableCleanupFailed
		settled = returned.settled
		if code != contract.CryptoSuccess {
			out.code = code
			out.stage, out.category = returned.stage, returned.category
			out.effect = returned.effect
			if owner.command.LifecycleMode == contract.GeneratorLifecycleNone {
				if owner.expired() {
					out.code, out.category = contract.CryptoExpired, generatedFailureExpired
				} else if ctx.Err() != nil {
					out.code, out.category = contract.CryptoCancelled, generatedFailureCancelled
				}
			}
			return out
		}
	} else if owner.probe != nil {
		returned.Facts = controlledRetirementProbeFacts(owner, owner.probe(owner.ctx, owner.command))
	} else {
		returned = owner.returnValue(owner.ctx, owner.command, owner.intent)
	}
	if owner.expired() {
		out.code = contract.CryptoExpired
		out.stage, out.category = generatedFailureReturn, generatedFailureExpired
		return out
	}
	if owner.command.LifecycleMode == contract.GeneratorLifecycleNone && ctx.Err() != nil {
		out.code, out.stage, out.category = contract.CryptoCancelled, generatedFailureReturn, generatedFailureCancelled
		return out
	}
	seal := telemetry.StartWithDetails(owner.ctx, telemetry.ProviderCrypto, telemetry.OpCryptoGeneratedResultSeal,
		generatedAttemptDetails(owner.command.AttemptID))
	defer func() { finishCryptoCall(seal, out.code) }()
	factsBody, err := contract.EncodeGeneratorSafeFacts(returned.Facts)
	if err != nil || uint32(len(factsBody)) > owner.expected.Use.MaxFacts || returned.Facts.LifecycleMode != owner.command.LifecycleMode || returned.Facts.ResourceContractID != owner.command.ResourceContractID || returned.Facts.Action != owner.command.Action ||
		returned.Facts.RequestDigest != owner.command.RequestDigest || returned.Facts.IntentDigest != owner.expected.Template.IntentDigest ||
		(returned.Facts.LifecycleMode == contract.GeneratorLifecycleNone && returned.Facts.Disposition == contract.GeneratorDispositionUnknown && len(returned.Secret) != 0) {
		out.code = contract.CryptoCustodyUnavailable
		out.stage, out.category = generatedFailureFacts, generatedFailureInvalid
		return out
	}
	// Reparse to detach the small variable facts from the private return owner.
	facts, err := contract.InspectGeneratorSafeFacts(factsBody)
	if err != nil {
		out.code = contract.CryptoCustodyUnavailable
		out.stage, out.category = generatedFailureFacts, generatedFailureInvalid
		return out
	}
	ownedFacts, err := facts.Own()
	if err != nil {
		out.code = contract.CryptoCustodyUnavailable
		out.stage, out.category = generatedFailureFacts, generatedFailureInvalid
		return out
	}
	if owner.expired() {
		out.code = contract.CryptoExpired
		out.stage, out.category = generatedFailureReturn, generatedFailureExpired
		return out
	}
	if ownedFacts.Disposition == contract.GeneratorDispositionUnknown {
		if owner.retirementProof != nil {
			out.retirementAmbiguity, err = owner.retirementProof.seal(owner, factsBody)
			if err != nil {
				out.code = contract.CryptoCustodyUnavailable
				out.stage, out.category = generatedFailureSeal, generatedFailureUnavailable
				if owner.expired() {
					out.code, out.category = contract.CryptoExpired, generatedFailureExpired
				}
				return out
			}
			out.resultDeadlineUnixMillis = owner.command.DeadlineUnixMillis
		}
		out.Facts = ownedFacts
		out.code = contract.CryptoSuccess
		out.stage, out.category = "", ""
		out.effect = generatedEffectFromDisposition(ownedFacts.Disposition)
		return out
	}
	if owner.expired() {
		out.code = contract.CryptoExpired
		out.stage, out.category = generatedFailureReturn, generatedFailureExpired
		return out
	}
	record, err := custody.SealGeneratedResult(owner.expected, owner.material, ownedFacts, owner.seed, returned.Secret)
	if err != nil {
		out.code = contract.CryptoCustodyUnavailable
		out.stage, out.category = generatedFailureSeal, generatedFailureUnavailable
		return out
	}
	out.Record, err = contract.EncodeGeneratedResultRecord(record)
	if err != nil {
		out.code = contract.CryptoCustodyUnavailable
		out.stage, out.category = generatedFailureSeal, generatedFailureUnavailable
		return out
	}
	out.Facts = ownedFacts
	out.code = contract.CryptoSuccess
	out.stage, out.category = "", ""
	out.effect = generatedEffectFromDisposition(record.Disposition())
	if owner.command.LifecycleMode == contract.GeneratorLifecycleManaged {
		out.resultDeadlineUnixMillis = owner.command.DeadlineUnixMillis
	}
	return out
}
