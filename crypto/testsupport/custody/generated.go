package custody

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"enkv.sh/sdk/artifact"
	"reflect"
	"slices"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

type GeneratedCandidateEntry struct {
	Slot  uint16
	Entry contract.ValueEntry
}

type GeneratedCandidate struct {
	ActiveOwner, ActivePhase, ActiveGraph                contract.ID
	Subject                                              contract.GeneratorAuthoritySubject
	PublicState                                          contract.PublicState
	CurrentAccess                                        contract.CurrentAccessCore
	AccessRecords                                        []contract.AccessRecord
	SupportRecords                                       []contract.SupportRecord
	Entries                                              []GeneratedCandidateEntry
	HeadCore, Conditional, GrantWraps, SourceProtections []byte
	LiveSourceUses                                       []contract.GeneratorSourceUse
}

type GeneratedCanonicalSelection = contract.GeneratedCanonicalSelection
type GeneratedMembershipSelection struct {
	Selection contract.ConsumerSelection
}

type GeneratedVerificationInput struct {
	Owner        contract.SupportRecord
	Output       *contract.GeneratedOutputTransition
	Graph        []byte
	BeforePublic contract.PublicState
	Material     contract.OperationMaterialRecord
	SeedAccess   []byte
	Expected     contract.GeneratorResultExpectation
	Target       *contract.GeneratorTarget
}

type GeneratedControlledPredecessor = contract.GeneratedControlledPredecessor

func (f *Fixture) AdmitGeneratedVerification(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input GeneratedVerificationInput, deadline time.Time) error {
	if f == nil || q.Purpose != contract.CryptoGeneratedOriginalVerificationPurpose || control.AuthorityRecipientID != f.authority || control.Provider != f.family ||
		(control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return privatecrypto.ErrAdmission
	}
	session := privatecrypto.TestGeneratedSessionAdmissionInput{Control: control, Bindings: f.Bindings(), Graph: input.Graph,
		BeforePublic: input.BeforePublic, Output: input.Output}
	a := privatecrypto.TestGeneratedOriginalVerificationAdmissionInput{Session: session, Material: input.Material, Owner: input.Owner,
		SeedAccess: input.SeedAccess, Target: input.Target,
		Result: privatecrypto.TestGeneratedResultAdmission{Expected: input.Expected, Reference: q.OriginalResult}}
	f.mu.Lock()
	a.Session.RouteID = f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	return privatecrypto.TestAdmitGeneratedOriginalVerification(f.runtime, q, a, deadline)
}

// AdmitGeneratedPlan accepts public selected state and only source envelopes
// already admitted by this fixture's independent private source producer.
func (f *Fixture) AdmitGeneratedPlan(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, session GeneratedSessionInput, plan GeneratedPlanInput, deadline time.Time) error {
	return f.admitGeneratedPlan(q, control, session, plan, nil, nil, nil, deadline)
}

// AdmitGeneratedDeletePlan admits a fresh seed plan for one exact detached
// retirement or unselected-cleanup Duty. The phase is a private fact; request
// bytes alone cannot turn an ordinary initial plan into delete authority.
func (f *Fixture) AdmitGeneratedDeletePlan(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, session GeneratedSessionInput,
	plan GeneratedPlanInput, phase contract.GeneratorPhaseIdentity, target contract.GeneratorTarget, deadline time.Time) error {
	return f.admitGeneratedPlan(q, control, session, plan, &phase, &target, nil, deadline)
}

func (f *Fixture) AdmitGeneratedControlledDeletePlan(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, session GeneratedSessionInput, plan GeneratedPlanInput, phase contract.GeneratorPhaseIdentity, target contract.GeneratorTarget, predecessor GeneratedControlledPredecessor, deadline time.Time) error {
	return f.admitGeneratedPlan(q, control, session, plan, &phase, &target, &predecessor, deadline)
}

func (f *Fixture) admitGeneratedPlan(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, session GeneratedSessionInput,
	plan GeneratedPlanInput, phase *contract.GeneratorPhaseIdentity, target *contract.GeneratorTarget, predecessor *GeneratedControlledPredecessor, deadline time.Time) error {
	if f == nil || q.Purpose != contract.CryptoGeneratedReservationPurpose || control.AuthorityRecipientID != f.authority || control.Provider != f.family ||
		(control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return privatecrypto.ErrAdmission
	}
	d, err := contract.InspectGeneratorDeclaration(plan.Declaration)
	if err != nil {
		return privatecrypto.ErrAdmission
	}
	g, err := contract.DecodeGeneratorPlanBundle(session.Graph)
	if err != nil {
		return privatecrypto.ErrAdmission
	}
	plan.LiveSourceUses = g.SourceUses
	input := privatecrypto.TestGeneratedReservationAdmissionInput{Session: generatedSessionInput(control, f.Bindings(), session),
		Plan:     generatedPlanInput(plan),
		Accepted: make(map[contract.ID]contract.SealedInputCore), Phase: phase, Target: target, ControlledPredecessor: predecessor}
	f.mu.Lock()
	input.Session.RouteID = f.routes[control.AuthorityKMSBinding.BindingID]
	for i := 0; i < d.EntryCount(); i++ {
		entry, _, err := d.Entry(i)
		if err != nil {
			f.mu.Unlock()
			return privatecrypto.ErrAdmission
		}
		if entry.Kind != contract.GeneratorDeclarationSealed {
			continue
		}
		digest := contract.Hash(entry.Payload)
		core, ok := f.accepted[digest]
		if !ok {
			f.mu.Unlock()
			return privatecrypto.ErrAdmission
		}
		input.Accepted[digest] = core
	}
	f.mu.Unlock()
	return privatecrypto.TestAdmitGeneratedReservation(f.runtime, q, input, deadline)
}

func (f *Fixture) BindGeneratedCandidate(ctx context.Context, id contract.ID, candidate GeneratedCandidate) contract.CryptoResultCode {
	c := privatecrypto.TestGeneratedCandidate{ActiveOwner: candidate.ActiveOwner, ActivePhase: candidate.ActivePhase, ActiveGraph: candidate.ActiveGraph,
		Subject: candidate.Subject, PublicState: candidate.PublicState, CurrentAccess: candidate.CurrentAccess, AccessRecords: candidate.AccessRecords,
		SupportRecords: candidate.SupportRecords, HeadCore: candidate.HeadCore, GrantWraps: candidate.GrantWraps, Conditional: candidate.Conditional, SourceProtections: candidate.SourceProtections,
		LiveSourceUses: candidate.LiveSourceUses}
	for _, candidateEntry := range candidate.Entries {
		c.Entries = append(c.Entries, privatecrypto.TestGeneratedCandidateEntry(candidateEntry))
	}
	return privatecrypto.TestBindGeneratedCandidate(f.runtime, ctx, id, c)
}

func (f *Fixture) RetireGenerated() {
	privatecrypto.TestRetireGenerated(f.runtime)
	f.mu.Lock()
	f.generatedProcess = nil
	f.mu.Unlock()
}

type GeneratedSessionInput struct {
	Output              *contract.GeneratedOutputTransition
	Graph               []byte
	BeforePublic        contract.PublicState
	BeforeAccess        *contract.CurrentAccessCore
	BeforeAccessRecords []contract.AccessRecord
	SelectionPhase      *contract.GeneratedPhaseRecord
}

type GeneratedPlanInput struct {
	Declaration    []byte
	Canonical      []GeneratedCanonicalSelection
	LiveSourceUses []contract.GeneratorSourceUse
	CurrentIntents []contract.GeneratedCurrentIntentSelection
	CurrentValues  []contract.ConsumerSelection
}

type GeneratedCustodyInput struct {
	Material          contract.OperationMaterialRecord
	SeedAccess        []byte
	SourceProtections []byte
}

type GeneratedProducerInput struct {
	Session               GeneratedSessionInput
	Plan                  GeneratedPlanInput
	Custody               GeneratedCustodyInput
	Expected              contract.GeneratorResultExpectation
	Phase                 *contract.GeneratorPhaseIdentity
	Target                *contract.GeneratorTarget
	Preparation           contract.GeneratedProducerPreparation
	Intent, OriginalFacts []byte
	Duty                  contract.GeneratedDutyRecord
	Source                contract.SupportRecord
	Attempt               contract.GeneratedAttemptRecord
	Consumers             [][]byte
	BeforeReturn          func()
	Progress              [][]byte
	Probe                 func(context.Context, contract.GeneratedProducerCommand) []byte
	ControlledPredecessor *GeneratedControlledPredecessor
}

type GeneratedAdoptionInput struct {
	Session               GeneratedSessionInput
	Plan                  GeneratedPlanInput
	Custody               GeneratedCustodyInput
	Expected              contract.GeneratorResultExpectation
	Target                *contract.GeneratorTarget
	ControlledPredecessor *GeneratedControlledPredecessor
}

type GeneratedFinalInput struct {
	CanonicalAccess       []contract.ConsumerSelection
	CheckpointSupport     []contract.SupportRecord
	Preparation           *contract.GeneratedFinalPreparationRecord
	PreparationPhase      *contract.GeneratedPhaseRecord
	PreparedImage         []byte
	QualifyLegacy         bool
	Membership            []GeneratedMembershipSelection
	Session               GeneratedSessionInput
	Plan                  GeneratedPlanInput
	Custody               GeneratedCustodyInput
	ExpectedResults       []contract.GeneratorResultExpectation
	ResultBodies          [][]byte
	Target                *contract.GeneratorTarget
	ControlledPredecessor *GeneratedControlledPredecessor
}

const GeneratedTerminalFailure uint8 = 4
const GeneratedConfirmedNoEffect uint8 = 5

type GeneratedProcessConfig struct {
	ReportEnvironmentPipeClosed *GeneratedPipeFault
	ArtifactPath                string
	Artifact                    contract.GeneratorImplementation
	Metadata, Dependency        []byte
}

func generatedProcessHostConfig(config GeneratedProcessConfig, preparation contract.GeneratedProducerPreparation) (generatorhost.Config, error) {
	if len(config.Metadata) == 0 || len(config.Metadata) > artifact.MaxMetadataBytes || len(config.Dependency) == 0 || len(config.Dependency) > artifact.MaxDependencyBytes {
		return generatorhost.Config{}, privatecrypto.ErrAdmission
	}
	metadata, err := artifact.DecodeMetadata(slices.Clone(config.Metadata))
	if err != nil {
		return generatorhost.Config{}, privatecrypto.ErrAdmission
	}
	installed, err := generatorhost.NewInstallation(metadata, slices.Clone(config.Dependency))
	if err != nil {
		return generatorhost.Config{}, privatecrypto.ErrAdmission
	}
	row := installed.Artifact()
	if !reflect.DeepEqual(row, config.Artifact) || row.CredentialRouteID != preparation.CredentialRouteID || row.DescriptorID != preparation.DescriptorID || row.ExecutorID != preparation.ExecutorID {
		return generatorhost.Config{}, privatecrypto.ErrAdmission
	}
	return generatorhost.Config{ArtifactPath: config.ArtifactPath, Artifact: row, Installation: installed}, nil
}

type GeneratedEntryAdmission struct {
	Slot      uint16
	Generated contract.GeneratedEntryMetadata
}

func GeneratorProcessOwnedByteCeilings() (parent, child uint64) {
	return generatorhost.ParentFixedOwnedBytes, generatorhost.ChildFixedOwnedBytes
}

func generatedSessionInput(control contract.ControlCore, bindings []contract.BindingTableRow, input GeneratedSessionInput) privatecrypto.TestGeneratedSessionAdmissionInput {
	// This trusted test seam receives the authenticated predecessor Phase;
	// its private runtime field represents only a postselection anchor.
	phase := input.SelectionPhase
	if phase != nil && phase.SelectionPhaseID.IsZero() {
		phase = nil
	}
	return privatecrypto.TestGeneratedSessionAdmissionInput{Control: control, Bindings: bindings, Graph: input.Graph, BeforePublic: input.BeforePublic, Output: input.Output,
		BeforeAccess: input.BeforeAccess, BeforeAccessRecords: input.BeforeAccessRecords, SelectionPhase: phase}
}

func generatedPlanInput(input GeneratedPlanInput) privatecrypto.TestGeneratedPlanAdmissionInput {
	plan := privatecrypto.TestGeneratedPlanAdmissionInput{Declaration: input.Declaration, LiveSourceUses: input.LiveSourceUses, CurrentIntents: input.CurrentIntents, CurrentValues: input.CurrentValues}
	for _, source := range input.Canonical {
		plan.Canonical = append(plan.Canonical, privatecrypto.TestGeneratedCanonicalSelection(source))
	}
	return plan
}

// syntheticGeneratedCompleteReturn keeps provider history explicit. Crypto still
// owns sealing and complete result validation for this fixed test response.
func syntheticGeneratedCompleteReturn(expected contract.GeneratorResultExpectation, choice uint8) privatecrypto.TestGeneratedProducerReturn {
	x := expected.Template
	resource, provider := x.ResourceIncarnationID, []byte{3}
	if choice == SyntheticCloudflareValue {
		hex.Encode(resource[:], x.ResourceIncarnationID[:16])
		provider = []byte{31}
	}
	secret, _ := syntheticValue(choice)
	if expected.InputEncoding == contract.InputEncodingBase64 {
		retained := make([]byte, base64.StdEncoding.EncodedLen(len(secret)))
		base64.StdEncoding.Encode(retained, secret)
		clear(secret[:cap(secret)])
		secret = retained
	}
	facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate, LifecycleMode: x.LifecycleMode,
		ResourceContractID: x.ResourceContractID, Disposition: contract.GeneratorDispositionCompleteCreate, RequestDigest: expected.RequestDigest, IntentDigest: x.IntentDigest}
	if x.LifecycleMode == contract.GeneratorLifecycleManaged {
		facts.Target = []byte("synthetic-service/target")
		facts.ResourceData = bytes.Clone(resource[:])
		facts.ProviderFacts = provider
	}
	return privatecrypto.TestGeneratedProducerReturn{Secret: secret, Facts: facts}
}

// The synthetic provider response is constructed inside custody. Its secret is
// sealed by the real producer and cannot pass through the Core test assembly.
func (f *Fixture) AdmitGeneratedProducer(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input GeneratedProducerInput, choice uint8, deadline time.Time) error {
	if f == nil || q.Purpose != contract.CryptoGeneratedProducerPreparationPurpose || control.AuthorityRecipientID != f.authority || control.Provider != f.family ||
		(control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return privatecrypto.ErrAdmission
	}
	value, ok := syntheticValue(choice)
	if !ok && choice != GeneratedTerminalFailure && choice != GeneratedConfirmedNoEffect {
		return privatecrypto.ErrAdmission
	}
	clear(value[:cap(value)])
	x := input.Expected.Template
	beforeReturn := input.BeforeReturn
	requestDigest := input.Expected.RequestDigest
	original, originalErr := contract.InspectGeneratorSafeFacts(input.OriginalFacts)
	if x.Action == contract.GeneratorActionDelete && originalErr != nil {
		return privatecrypto.ErrAdmission
	}
	producer := &privatecrypto.TestGeneratedProducerAdmissionInput{Expected: input.Expected, Preparation: input.Preparation, Intent: input.Intent, OriginalFacts: input.OriginalFacts,
		Duty: input.Duty, Source: input.Source, Attempt: input.Attempt, Consumers: input.Consumers,
		Return: func(context.Context, contract.GeneratedProducerCommand, []byte) privatecrypto.TestGeneratedProducerReturn {
			if beforeReturn != nil {
				beforeReturn()
			}
			if choice == GeneratedConfirmedNoEffect {
				return privatecrypto.TestGeneratedProducerReturn{Facts: contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate, LifecycleMode: x.LifecycleMode, ResourceContractID: x.ResourceContractID,
					Disposition: contract.GeneratorDispositionConfirmedNoEffect, RequestDigest: requestDigest, IntentDigest: x.IntentDigest}}
			}
			if choice == GeneratedTerminalFailure {
				out := syntheticGeneratedCompleteReturn(input.Expected, HermeticCloudflareValue)
				clear(out.Secret[:cap(out.Secret)])
				out.Secret = nil
				out.Facts.Disposition, out.Facts.Reason = contract.GeneratorDispositionOwnedUnusableCreate, contract.GeneratorReasonMissingValue
				return out
			}
			if x.Action == contract.GeneratorActionDelete {
				return privatecrypto.TestGeneratedProducerReturn{Facts: contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionDelete, LifecycleMode: x.LifecycleMode, ResourceContractID: x.ResourceContractID,
					Disposition: contract.GeneratorDispositionRetirementAcknowledged, RequestDigest: requestDigest, IntentDigest: x.IntentDigest, Target: bytes.Clone(original.Target), ResourceData: bytes.Clone(original.ResourceData)}}
			}
			return syntheticGeneratedCompleteReturn(input.Expected, choice)
		}}
	producer.Progress = input.Progress
	if input.Probe != nil {
		producer.Return = nil
		producer.Probe = input.Probe
	}
	session := generatedSessionInput(control, f.Bindings(), input.Session)
	a := privatecrypto.TestGeneratedProducerPreparationAdmissionInput{Session: session,
		Plan:     generatedPlanInput(input.Plan),
		Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections,
		Phase: input.Phase, Target: input.Target, Producer: *producer, ControlledPredecessor: input.ControlledPredecessor}
	f.mu.Lock()
	a.Session.RouteID = f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	return privatecrypto.TestAdmitGeneratedProducer(f.runtime, q, a, deadline)
}

// AdmitGeneratedProcessProducer installs the native process return path. The
// child writes the raw result only to the Crypto-owned descriptor.
func (f *Fixture) AdmitGeneratedProcessProducer(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input GeneratedProducerInput, config GeneratedProcessConfig, deadline time.Time) error {
	if f == nil || q.Purpose != contract.CryptoGeneratedProducerPreparationPurpose || control.AuthorityRecipientID != f.authority || control.Provider != f.family ||
		(control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return privatecrypto.ErrAdmission
	}
	hostConfig, err := generatedProcessHostConfig(config, input.Preparation)
	if err != nil {
		return privatecrypto.ErrAdmission
	}
	launcher, err := generatorhost.NewNative(ctx, hostConfig)
	if err != nil {
		return privatecrypto.ErrAdmission
	}
	f.mu.Lock()
	f.generatedProcess = launcher
	f.mu.Unlock()
	producer := &privatecrypto.TestGeneratedProducerAdmissionInput{Expected: input.Expected, Preparation: input.Preparation, Intent: input.Intent, OriginalFacts: input.OriginalFacts,
		Duty: input.Duty, Source: input.Source, Attempt: input.Attempt, Consumers: input.Consumers, Process: launcher}
	session := generatedSessionInput(control, f.Bindings(), input.Session)
	a := privatecrypto.TestGeneratedProducerPreparationAdmissionInput{Session: session,
		Plan:     generatedPlanInput(input.Plan),
		Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections,
		Phase: input.Phase, Target: input.Target, Producer: *producer}
	f.mu.Lock()
	a.Session.RouteID = f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	return privatecrypto.TestAdmitGeneratedProducer(f.runtime, q, a, deadline)
}

func (f *Fixture) WaitGeneratedProcessCommand(ctx context.Context) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	launcher := f.generatedProcess
	f.mu.Unlock()
	return launcher != nil && launcher.WaitCommand(ctx)
}

type GeneratedProducerOutcome struct {
	ID                      contract.ID `json:"-"`
	Locator                 contract.ID `json:"-"`
	Authority               contract.ID `json:"-"`
	Code                    contract.CryptoResultCode
	Stage, Category, Effect string
	Qualified               bool
	Disposition, Reason     uint8
}

// InvokeGeneratedProducerOutcome returns the closed private observation for
// this exact call. Record bytes and SafeFacts remain separate return values.
func (f *Fixture) InvokeGeneratedProducerOutcome(ctx context.Context, id, locator, authority contract.ID) ([]byte, contract.GeneratorSafeFacts, GeneratedProducerOutcome) {
	out := privatecrypto.TestInvokeGeneratedProducerOutcome(f.runtime, ctx, id, locator, authority)
	observed := GeneratedProducerOutcome{ID: id, Locator: locator, Authority: authority,
		Code: out.Code, Stage: out.Stage, Category: out.Category, Effect: out.Effect}
	if out.Facts.Schema != 0 {
		observed.Qualified = true
		observed.Disposition = out.Facts.Disposition
		observed.Reason = out.Facts.Reason
	}
	return out.Record, out.Facts, observed
}

func (f *Fixture) InvokeGeneratedProducer(ctx context.Context, id, locator, authority contract.ID) ([]byte, contract.GeneratorSafeFacts, contract.CryptoResultCode) {
	record, facts, outcome := f.InvokeGeneratedProducerOutcome(ctx, id, locator, authority)
	return record, facts, outcome.Code
}

func (f *Fixture) AdmitGeneratedRecord(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input GeneratedAdoptionInput, phase contract.GeneratorPhaseIdentity, reference contract.GeneratorResultReference, deadline time.Time) error {
	if f == nil || q.Purpose != contract.CryptoGeneratedAdoptionPurpose || control.AuthorityRecipientID != f.authority || control.Provider != f.family ||
		(control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return privatecrypto.ErrAdmission
	}
	session := generatedSessionInput(control, f.Bindings(), input.Session)
	a := privatecrypto.TestGeneratedAdoptionAdmissionInput{Session: session,
		Plan:     generatedPlanInput(input.Plan),
		Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections,
		Phase: phase, Target: input.Target, Result: privatecrypto.TestGeneratedResultAdmission{Expected: input.Expected, Reference: reference},
		ControlledPredecessor: input.ControlledPredecessor}
	f.mu.Lock()
	a.Session.RouteID = f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	return privatecrypto.TestAdmitGeneratedAdoption(f.runtime, q, a, deadline)
}

// AdmitGeneratedValueEntries fixes the exact recorded results and generated entry
// metadata that a final-phase preparation can use. Public request bytes cannot
// replace these private facts.
func (f *Fixture) AdmitGeneratedValueEntries(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input GeneratedFinalInput, phase contract.GeneratorPhaseIdentity, references []contract.GeneratorResultReference, entryAdmissions []GeneratedEntryAdmission, deadline time.Time) error {
	expected := input.ExpectedResults
	if f == nil || q.Purpose != contract.CryptoGeneratedFinalPreparationPurpose || control.AuthorityRecipientID != f.authority || control.Provider != f.family ||
		(control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery ||
		len(references) != len(expected) || len(references) == 0 && len(entryAdmissions) != 0 {
		return privatecrypto.ErrAdmission
	}
	session := generatedSessionInput(control, f.Bindings(), input.Session)
	a := privatecrypto.TestGeneratedFinalAdmissionInput{Session: session, CanonicalAccess: input.CanonicalAccess,
		Plan:     generatedPlanInput(input.Plan),
		Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections,
		Phase: phase, Target: input.Target, ResultBodies: input.ResultBodies, ControlledPredecessor: input.ControlledPredecessor,
		Preparation: input.Preparation, PreparationPhase: input.PreparationPhase, PreparedImage: input.PreparedImage, QualifyLegacy: input.QualifyLegacy, CheckpointSupport: input.CheckpointSupport}
	for _, selection := range input.Membership {
		a.Membership = append(a.Membership, privatecrypto.TestGeneratedMembershipSelection{Selection: selection.Selection})
	}
	for i := range references {
		a.Results = append(a.Results, privatecrypto.TestGeneratedResultAdmission{Expected: expected[i], Reference: references[i]})
	}
	for i := range entryAdmissions {
		a.EntryAdmissions = append(a.EntryAdmissions, privatecrypto.TestGeneratedEntryAdmission{Slot: entryAdmissions[i].Slot, Generated: entryAdmissions[i].Generated})
	}
	f.mu.Lock()
	a.Session.RouteID = f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	return privatecrypto.TestAdmitGeneratedFinal(f.runtime, q, a, deadline)
}
