package crypto

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// GeneratedCustodyConstruction fixes the installation's private and public key
// routes. The accepted registry supplies identities, never these capabilities.
type GeneratedCustodyConstruction struct {
	RouteID, FileIdentity contract.ID
	Public                map[contract.ID]PublicKeyQualifier
}

type GeneratedCustody struct {
	runtime      *Runtime
	admission    *generatedAdmission
	closed       atomic.Bool
	closeOnce    sync.Once
	localFailure *generatedLocalFailureOutcome
}

func newGeneratedCustody(r *Runtime, install func() (*generatedAdmission, error)) (*GeneratedCustody, error) {
	if r == nil || install == nil {
		return nil, ErrAdmission
	}
	a, err := install()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	valid := !r.closed && a != nil && r.generated == a && r.slot == a.session
	var localFailure *generatedLocalFailureOutcome
	if valid {
		localFailure = newGeneratedLocalFailureOutcome(a)
	}
	r.mu.Unlock()
	if !valid {
		if a != nil {
			r.retireSession(a.session)
		}
		return nil, ErrAdmission
	}
	return &GeneratedCustody{runtime: r, admission: a, localFailure: localFailure}, nil
}

func generatedInstalledPlan(input contract.GeneratedPlanInput) generatedPlanAdmissionInput {
	return generatedPlanAdmissionInput{Declaration: input.Declaration, Canonical: input.Canonical, LiveSourceUses: input.LiveSourceUses, CurrentIntents: input.CurrentIntents, CurrentValues: input.CurrentValues}
}

func NewGeneratedReservationCustody(r *Runtime, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedReservationInput, deadline time.Time) (*GeneratedCustody, error) {
	return newGeneratedCustody(r, func() (*generatedAdmission, error) {
		session, err := r.generatedInstalledSession(q, control, construction, input.Session, input.Plan, false)
		if err != nil || construction.FileIdentity.IsZero() {
			return nil, ErrAdmission
		}
		declaration, err := contract.InspectGeneratorDeclaration(input.Plan.Declaration)
		if err != nil {
			return nil, ErrAdmission
		}
		accepted := make(map[contract.ID]contract.SealedInputCore)
		for i := 0; i < declaration.EntryCount(); i++ {
			entry, _, err := declaration.Entry(i)
			if err != nil {
				return nil, ErrAdmission
			}
			if entry.Kind != contract.GeneratorDeclarationSealed {
				continue
			}
			envelope, err := contract.InspectSealedInputEnvelope(entry.Payload)
			if err != nil || envelope.Core.FileIdentity != construction.FileIdentity {
				return nil, ErrAdmission
			}
			core, err := envelope.Core.Own()
			if err != nil {
				return nil, ErrAdmission
			}
			accepted[contract.Hash(entry.Payload)] = core
		}
		validated, _, err := r.validateGeneratedPlan(input.Session.Graph, input.Plan.Declaration, false)
		if err != nil {
			return nil, ErrAdmission
		}
		plan := generatedInstalledPlan(input.Plan)
		plan.LiveSourceUses = validated.graph.SourceUses
		return r.admitGeneratedReservationOwned(q, generatedReservationAdmissionInput{Session: session, Plan: plan, Accepted: accepted, Phase: input.Phase, Target: input.Target, ControlledPredecessor: input.ControlledPredecessor}, deadline)
	})
}

func NewGeneratedProducerCustody(r *Runtime, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedProducerInput, launcher generatorhost.Launcher, deadline time.Time) (*GeneratedCustody, error) {
	return newGeneratedCustody(r, func() (*generatedAdmission, error) {
		if launcher == nil {
			return nil, ErrAdmission
		}
		session, err := r.generatedInstalledSession(q, control, construction, input.Session, input.Plan, false)
		if err != nil {
			return nil, err
		}
		producer := generatedProducerAdmissionInput{retirementReturn: input.RetirementReturn, Expected: input.Expected, Preparation: input.Preparation, Intent: input.Intent, OriginalFacts: input.OriginalFacts, Duty: input.Duty, Source: input.Source, Attempt: input.Attempt, Consumers: input.Consumers, Progress: input.Progress, Process: launcher}
		return r.admitGeneratedProducerOwned(q, generatedProducerPreparationAdmissionInput{Session: session, Plan: generatedInstalledPlan(input.Plan), Phase: input.Phase, Target: input.Target, Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections, Producer: producer, ControlledPredecessor: input.ControlledPredecessor}, deadline)
	})
}

func NewGeneratedAdoptionCustody(r *Runtime, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedAdoptionInput, deadline time.Time) (*GeneratedCustody, error) {
	return newGeneratedCustody(r, func() (*generatedAdmission, error) {
		session, err := r.generatedInstalledSession(q, control, construction, input.Session, input.Plan, false)
		if err != nil {
			return nil, err
		}
		return r.admitGeneratedAdoptionOwned(q, generatedAdoptionAdmissionInput{Session: session, Plan: generatedInstalledPlan(input.Plan), Phase: input.Phase, Target: input.Target, Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections, Result: generatedResultAdmission(input.Result), ControlledPredecessor: input.ControlledPredecessor}, deadline)
	})
}

func NewGeneratedFinalCustody(r *Runtime, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedFinalInput, deadline time.Time) (*GeneratedCustody, error) {
	return newGeneratedCustody(r, func() (*generatedAdmission, error) {
		session, err := r.generatedInstalledSession(q, control, construction, input.Session, input.Plan, len(input.EntryAdmissions) != 0)
		if err != nil {
			return nil, err
		}
		a := generatedFinalAdmissionInput{Session: session, Plan: generatedInstalledPlan(input.Plan), Phase: input.Phase, Target: input.Target, Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections, CanonicalAccess: input.CanonicalAccess, ResultBodies: input.ResultBodies, Preparation: input.Preparation, PreparationPhase: input.PreparationPhase, PreparedImage: input.PreparedImage, QualifyLegacy: input.QualifyLegacy, CheckpointSupport: input.CheckpointSupport, ControlledPredecessor: input.ControlledPredecessor}
		for _, row := range input.Results {
			a.Results = append(a.Results, generatedResultAdmission(row))
		}
		for _, row := range input.EntryAdmissions {
			a.EntryAdmissions = append(a.EntryAdmissions, generatedEntryAdmission(row))
		}
		for _, row := range input.Membership {
			a.Membership = append(a.Membership, generatedMembershipSelection{Selection: row.Selection})
		}
		return r.admitGeneratedFinalOwned(q, a, deadline)
	})
}

func NewGeneratedVerificationCustody(r *Runtime, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedVerificationInput, deadline time.Time) (*GeneratedCustody, error) {
	return newGeneratedCustody(r, func() (*generatedAdmission, error) {
		if q.Purpose != contract.CryptoGeneratedOriginalVerificationPurpose {
			return nil, ErrAdmission
		}
		session, err := installedGeneratedSession(q, control, construction, input.Session, nil)
		if err != nil {
			return nil, err
		}
		body, err := generatedAdmissionBody(r, q, session, deadline)
		if err != nil {
			return nil, err
		}
		return r.admitGeneratedVerificationOwned(q, generatedOriginalVerificationAdmissionInput{Owner: input.Owner, Session: session, Material: input.Material, SeedAccess: input.SeedAccess, Result: generatedResultAdmission(input.Result), Target: input.Target}, body, deadline)
	})
}

func (c *GeneratedCustody) InstanceID() contract.ID {
	if c == nil || c.runtime == nil {
		return contract.ID{}
	}
	return c.runtime.InstanceID()
}

func (c *GeneratedCustody) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	out := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: c.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, cryptoOperation(q.Kind))
	defer func() { finishCryptoCall(call, out.ResultCode) }()
	if c == nil || c.runtime == nil || c.admission == nil || c.closed.Load() || ctx == nil || q.CustodyInstanceID != c.InstanceID() {
		return out
	}
	if q.Schema != contract.CryptoSchema || q.RequestID.IsZero() {
		out.ResultCode = contract.CryptoInvalidInput
		return out
	}
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	out = c.runtime.generatedExchangeOwned(telemetry.CallContext(ctx, call), q, out, c.admission)
	return out
}

func (c *GeneratedCustody) BindCandidate(ctx context.Context, input contract.GeneratedCandidateInput) (code contract.CryptoResultCode) {
	code = contract.CryptoInvalidAdmission
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoPrepare)
	defer func() { finishCryptoCall(call, code) }()
	if c == nil || c.runtime == nil || c.admission == nil || c.closed.Load() {
		return code
	}
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	candidate := generatedCandidate{ActiveOwner: input.ActiveOwner, ActivePhase: input.ActivePhase, ActiveGraph: input.ActiveGraph, Subject: input.Subject, PublicState: input.PublicState, CurrentAccess: input.CurrentAccess, AccessRecords: input.AccessRecords, SupportRecords: input.SupportRecords, HeadCore: input.HeadCore, GrantWraps: input.GrantWraps, Conditional: input.Conditional, SourceProtections: input.SourceProtections, LiveSourceUses: input.LiveSourceUses, Registry: input.Registry}
	for _, row := range input.Entries {
		candidate.Entries = append(candidate.Entries, generatedCandidateEntry(row))
	}
	return c.runtime.bindGeneratedCandidateOwned(telemetry.CallContext(ctx, call), c.admission.id, candidate, c.admission)
}

func (c *GeneratedCustody) InvokeProducer(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoGeneratedProducerEntry)
	code := contract.CryptoInvalidAdmission
	defer func() { finishCryptoCall(call, code) }()
	if c == nil || c.runtime == nil || c.admission == nil || c.closed.Load() || ctx == nil {
		return contract.GeneratedProducerResult{Code: code}
	}
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	out := c.runtime.invokeGeneratedProducerAdmission(telemetry.CallContext(ctx, call), c.admission.id, locator, authority, c.admission, c.localFailure)
	code = out.code
	return contract.GeneratedProducerResult{RetirementAmbiguity: out.retirementAmbiguity, Record: out.Record, Facts: out.Facts, Code: code, ExecutableCleanupFailed: out.executableCleanupFailed, ResultDeadlineUnixMillis: out.resultDeadlineUnixMillis}
}

func (c *GeneratedCustody) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.runtime != nil && c.admission != nil {
			c.runtime.retireSession(c.admission.session)
		}
		c.localFailure.closeJoined()
	})
}
