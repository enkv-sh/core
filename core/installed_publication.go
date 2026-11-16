package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type PublicationRequest struct {
	Names                                    []string
	DeleteCoordinates, RepublishAfterUnknown []contract.ID
}

type PublicPublicationResult struct {
	RequestID, DomainID, OperationID, RequestIdentity contract.ID
	Result                                            Result
	Output                                            *contract.PublicationOutcomeVector
	Descriptions                                      []PublicationTargetDescription
	Summary                                           uint8
	ExecutableCleanupFailed                           bool
	CleanupFailed                                     bool
}

// These installation inputs expose only the existing action-specific private
// boundary. Public requests contain none of these callbacks or custody owners.
type PublicationExecutionInput publicationExecutionInput
type PublicationActionFacts publicationActionFacts
type PublicationActionCheckInput publicationActionCheckInput
type PublicationPolicyActionInput publicationPolicyActionInput
type PublicationActionCheckFacts publicationActionCheckFacts
type PublicationPrivateOwner interface{ publicationPrivateOwner }
type PublicationOwnerInput struct {
	Projection                      contract.PublicationProjection
	DestinationID, ConfigContractID string
	Target                          contract.OutputTarget
	Coordinate                      contract.PublicationCoordinate
	Birth, UncertainCreate          *contract.PublicationMarker
	ActionCheck                     PublicationActionCheckFacts
	Deadline                        time.Time
}

type PublicationInstallation struct {
	SelectPolicyAction func(context.Context, PublicationPolicyActionInput) (uint8, error)
	ExpectedDomain     contract.ID
	ExpectedStore      contract.Descriptor
	PublicBasis        PublicBasis
	ExpectedControl    contract.ControlCore
	Store              contract.Store
	Trust              contract.Trust
	CompositionID      contract.ID
	Namespace          func(contract.ID, contract.OutputTarget) (contract.ID, error)
	Actions            func(context.Context, PublicationExecutionInput) (PublicationActionFacts, error)
	Check              func(context.Context, PublicationActionCheckInput) (PublicationActionCheckFacts, error)
	NewOwner           func(context.Context, PublicationOwnerInput) (PublicationPrivateOwner, error)
	CloseInstalled     func()
}

type InstalledPublication struct {
	mu           sync.Mutex
	installation PublicationInstallation
	activeDone   chan struct{}
	used, closed bool
	closeOnce    sync.Once
}

func NewInstalledPublication(i PublicationInstallation) (*InstalledPublication, error) {
	if i.ExpectedDomain.IsZero() || i.CompositionID.IsZero() || i.Store == nil || i.Trust == nil || i.Store.Descriptor() != i.ExpectedStore ||
		i.Namespace == nil || i.SelectPolicyAction == nil || i.Actions == nil || i.Check == nil || i.NewOwner == nil || i.CloseInstalled == nil {
		return nil, contract.ErrRecord
	}
	basis, err := i.PublicBasis.own()
	if err != nil {
		return nil, err
	}
	control, err := basis.ControlCore(i.ExpectedDomain, i.ExpectedStore)
	if err != nil || !CurrentControlMatches(i.ExpectedControl, control) || i.Trust.Identity() != control.NormalSigning.Binding.Trust || i.Trust.Family() != control.Provider {
		return nil, contract.ErrRecord
	}
	encoded, err := contract.EncodeControlCore(i.ExpectedControl)
	if err != nil {
		return nil, err
	}
	i.ExpectedControl, err = contract.DecodeControlCore(encoded)
	if err != nil {
		return nil, err
	}
	i.PublicBasis = basis
	return &InstalledPublication{installation: i}, nil
}

func (e *InstalledPublication) Publish(ctx context.Context, requestID contract.ID, request PublicationRequest) PublicPublicationResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePublicationExecute)
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	out := e.publish(telemetry.CallContext(ctx, call), requestID, request)
	if out.Output != nil {
		finishPublication(call, publicationOperationResult{state: out.Result, output: *out.Output, summary: out.Summary})
	} else {
		finishCore(call, out.Result)
	}
	return out
}

func publicationRequestValid(q PublicationRequest) bool {
	if len(q.Names)+len(q.DeleteCoordinates) == 0 || len(q.Names) > contract.CryptoMaxValueEntries || len(q.DeleteCoordinates) > contract.MaxPublicationCoordinates || len(q.RepublishAfterUnknown) > contract.MaxPublicationMarkers {
		return false
	}
	names := make(map[string]bool, len(q.Names))
	for _, name := range q.Names {
		if len(name) > contract.CryptoMaxName || !utf8.ValidString(name) || names[name] {
			return false
		}
		names[name] = true
	}
	for _, ids := range [][]contract.ID{q.DeleteCoordinates, q.RepublishAfterUnknown} {
		seen := make(map[contract.ID]bool, len(ids))
		for _, id := range ids {
			if id.IsZero() || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}

func (e *InstalledPublication) publish(ctx context.Context, requestID contract.ID, request PublicationRequest) PublicPublicationResult {
	out, _ := e.publishSelection(ctx, requestID, request, nil)
	return out
}

func (e *InstalledPublication) publishCaptured(ctx context.Context, requestID contract.ID, republish []contract.ID, h *applyPublicationHandoff, apply *InstalledApply) (PublicPublicationResult, string) {
	out := PublicPublicationResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	if e == nil || apply == nil || h == nil || h.closed || h.consumed || ctx == nil || ctx.Err() != nil {
		return out, "selection-unavailable"
	}
	apply.mu.Lock()
	a := apply.installation
	active := apply.activeDone != nil
	apply.mu.Unlock()
	e.mu.Lock()
	i := e.installation
	available := !e.used && !e.closed && e.activeDone == nil
	e.mu.Unlock()
	if !active || !available || a.ExpectedDomain != i.ExpectedDomain || a.ExpectedStore != i.ExpectedStore || a.CompositionID != i.CompositionID ||
		!CurrentControlMatches(a.ExpectedControl, i.ExpectedControl) || i.ExpectedDomain != h.domain || i.ExpectedControl.AuthorityRecipientID != h.acting ||
		a.Trust == nil || i.Trust == nil || a.Trust.Identity() != i.Trust.Identity() || a.Trust.Family() != i.Trust.Family() {
		return out, "selection-unavailable"
	}
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePublicationExecute)
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	out, reason := e.publishSelection(telemetry.CallContext(ctx, call), requestID, PublicationRequest{Names: h.names(), DeleteCoordinates: h.deletes(), RepublishAfterUnknown: republish}, h)
	if out.Output != nil {
		finishPublication(call, publicationOperationResult{state: out.Result, output: *out.Output, summary: out.Summary})
	} else {
		finishCore(call, out.Result)
	}
	return out, reason
}

func (e *InstalledPublication) publishSelection(ctx context.Context, requestID contract.ID, request PublicationRequest, captured *applyPublicationHandoff) (PublicPublicationResult, string) {
	out := PublicPublicationResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	if e == nil || ctx == nil || ctx.Err() != nil || requestID.IsZero() || !publicationRequestValid(request) && (captured == nil || len(request.Names)+len(request.DeleteCoordinates) != 0 || len(request.RepublishAfterUnknown) != 0) {
		return out, ""
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) {
		return out, ""
	}
	e.mu.Lock()
	if e.used || e.closed || e.activeDone != nil {
		e.mu.Unlock()
		return out, ""
	}
	if captured != nil {
		if captured.closed || captured.consumed || captured.deadline != deadline {
			e.mu.Unlock()
			return out, "selection-unavailable"
		}
		captured.consumed = true
	}
	e.used = true
	i := e.installation
	done := make(chan struct{})
	e.activeDone = done
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.activeDone = nil; close(done); e.mu.Unlock() }()
	out.DomainID = i.ExpectedDomain
	private := i.private()
	current := func(ctx context.Context) (*StateSession, contract.Trust, Result) { return i.current(ctx) }
	s, _, state := current(ctx)
	if s == nil {
		out.Result = state
		return out, ""
	}
	republish, state := s.publicationRepublish(request.RepublishAfterUnknown)
	if state.Outcome != 0 {
		out.Result = state
		return out, ""
	}
	plan, state := s.planPublication(ctx, publicationInput{names: slices.Clone(request.Names), deletes: slices.Clone(request.DeleteCoordinates), acting: s.root.CurrentAccess.Core.AuthorityRecipientID, republish: republish, deadline: deadline, captured: captured}, private)
	if plan == nil {
		out.Result = state
		if captured != nil && state.Reason == DifferentSelection {
			return out, "selection-conflict"
		}
		return out, ""
	}
	identity, err := plan.requestIdentity(ctx, private)
	if err != nil {
		out.Result = refused(InvalidRelation)
		if errors.Is(err, contract.ErrRecordCapacity) {
			out.Result = refused(CapacityExceeded)
		}
		return out, ""
	}
	out.OperationID, out.RequestIdentity = plan.operation, identity
	out.Descriptions = plan.descriptions
	result := plan.execute(ctx, private, current)
	out.Result, out.Output, out.Summary = result.state, &result.output, result.summary
	out.ExecutableCleanupFailed = result.executableCleanupFailed
	return out, ""
}

func (i PublicationInstallation) private() publicationPrivate {
	return publicationPrivate{
		SelectPolicyAction: func(ctx context.Context, input publicationPolicyActionInput) (uint8, error) {
			return i.SelectPolicyAction(ctx, PublicationPolicyActionInput(input))
		},
		Actions: func(ctx context.Context, input publicationExecutionInput) (publicationActionFacts, error) {
			v, err := i.Actions(ctx, PublicationExecutionInput(input))
			return publicationActionFacts(v), err
		},
		Check: func(ctx context.Context, input publicationActionCheckInput) (publicationActionCheckFacts, error) {
			v, err := i.Check(ctx, PublicationActionCheckInput(input))
			return publicationActionCheckFacts(v), err
		},
		NewOwner: func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
			return i.NewOwner(ctx, PublicationOwnerInput{Projection: input.Projection, DestinationID: input.DestinationID, ConfigContractID: input.ConfigContractID, Target: input.Target, Coordinate: input.Coordinate, Birth: input.Birth, UncertainCreate: input.UncertainCreate, ActionCheck: PublicationActionCheckFacts(input.ActionCheck), Deadline: input.Deadline})
		},
	}
}

func (i PublicationInstallation) current(ctx context.Context) (*StateSession, contract.Trust, Result) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) || deadline.After(time.Now().Add(15*time.Minute)) {
		return nil, nil, refused(AdmissionInvalid)
	}
	admitted, state := admitBorrowedPublicNormal(ctx, i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, i.Store, i.CompositionID, nil)
	if state.Outcome != ObservedCurrent {
		return nil, nil, state
	}
	// Each fresh publication admission retains the original operation deadline.
	admitted.admission.expires = deadline
	s, state := Open(ctx, admitted, i.Store)
	if s == nil {
		return nil, nil, state
	}
	s.admission.publicationPremise = i.Namespace
	return s, i.Trust, s.observed(ObservedCurrent)
}

func (s *StateSession) publicationRepublish(ids []contract.ID) (map[contract.ID][]contract.ID, Result) {
	selected, err := selectedPublicationRelation(s.selectedImage())
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	sets := make(map[contract.ID][]contract.ID)
	for _, id := range ids {
		marker, ok := selected.markers[id]
		if !ok || marker.State != contract.PublicationMayHaveEntered && marker.State != contract.PublicationUnknown {
			return nil, refused(InvalidIntent)
		}
		sets[marker.CoordinateID] = append(sets[marker.CoordinateID], id)
	}
	for coordinate, ids := range sets {
		slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		if !slices.Equal(ids, publicationBlockers(selected, coordinate)) {
			return nil, refused(InvalidIntent)
		}
	}
	return sets, Result{}
}

func (plan *publicationPlan) requestIdentity(ctx context.Context, private publicationPrivate) (contract.ID, error) {
	rows := make([]contract.PublicationRequestTarget, 0, len(plan.targets))
	noWork := true
	for _, p := range plan.targets {
		facts, err := private.Actions(ctx, p.executionInput())
		if err != nil {
			return contract.ID{}, err
		}
		if !publicationExecutionFactsValid(facts, p.configContractID) {
			return contract.ID{}, contract.ErrRecord
		}
		if p.facts.ProtocolID.IsZero() {
			p.facts = facts
		} else if p.facts != facts {
			return contract.ID{}, contract.ErrRecord
		}
		row := contract.PublicationRequestTarget{CoordinateID: p.coordinate, BindingIncarnationID: p.binding, EntryIncarnationID: p.target.EntryIncarnationID, TargetRowDigest: p.targetDigest, ValueBasisDigest: p.valueBasisDigest, PolicyDigest: p.policy, ServiceContractID: p.target.ServiceContractID, TargetContractID: p.target.TargetContractID, ProtocolID: facts.ProtocolID, ConfigContractDigest: facts.ConfigContractDigest, ArtifactContractID: facts.ArtifactContractID, ExecutorID: facts.ExecutorID, CredentialRouteID: facts.CredentialRouteID, BlockerIDs: p.blockers}
		birth := p.retained.OwnedBirthAttemptID
		if p.birth != nil {
			birth = p.birth.AttemptID
		} else if len(p.attempts) > 0 {
			birth = p.attempts[0]
		}
		for j, action := range p.actions {
			projection, err := plan.projection(p, action, birth)
			if err != nil {
				return contract.ID{}, err
			}
			row.Actions = append(row.Actions, contract.PublicationRequestAction{Projection: projection, AttemptID: p.attempts[j]})
		}
		noWork = noWork && len(row.Actions) == 0 && len(row.BlockerIDs) == 0
		rows = append(rows, row)
	}
	targets, err := contract.PublicationRequestTargetsDescriptor(plan.session.root.Domain, rows)
	if err != nil {
		return contract.ID{}, err
	}
	var nonce contract.ID
	if _, err = rand.Read(nonce[:]); err != nil || nonce.IsZero() {
		return contract.ID{}, contract.ErrRecord
	}
	s := plan.session
	h := s.head.Core
	token, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		return contract.ID{}, err
	}
	if noWork {
		request, err := contract.PublicationNoWorkRequestDigest(contract.PublicationNoWorkRequestCore{Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation, Epoch: h.Epoch, PreviousRevision: h.Revision, PreviousDigest: contract.Hash(s.body), PreviousToken: s.token, ActingRecipientID: plan.acting, Targets: targets})
		if err != nil {
			return contract.ID{}, err
		}
		return contract.PublicationNoWorkObservationIdentity(contract.PublicationNoWorkObservation{OperationID: plan.operation, DomainID: s.root.Domain, RequestCoreDigest: request, HEADRevisionID: h.Revision, HEADDigest: contract.Hash(s.body), TokenDigest: token, Snapshot: h.Root, Targets: targets, Nonce: nonce})
	}
	return contract.PublicationRequestIdentity(contract.PublicationRequestObservation{DomainID: s.root.Domain, OperationID: plan.operation, HEADRevisionID: h.Revision, HEADDigest: contract.Hash(s.body), TokenDigest: token, Snapshot: h.Root, SelectionDigest: plan.vector.SelectionDigest, ActingRecipientID: plan.acting, Targets: targets, Nonce: nonce})
}

func (e *InstalledPublication) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		done := e.activeDone
		e.mu.Unlock()
		if done != nil {
			<-done
		}
		e.installation.CloseInstalled()
	})
}
