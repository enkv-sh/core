package crypto

import (
	"context"
	"sync"
	"time"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/output"
)

// publicationNativeSink pins one admitted command and borrows Crypto's
// payload only during synchronous dispatch. Close cancels and joins dispatch
// before Crypto may clear that payload; it does not establish provider outcome.
type publicationNativeSink struct {
	mu                            sync.Mutex
	id                            contract.ID
	artifact                      outputhost.Artifact
	projection                    contract.PublicationProjection
	target                        contract.OutputTarget
	coordinate                    contract.PublicationCoordinate
	birth                         contract.PublicationMarker
	uncertainCreate               contract.PublicationMarker
	destination, configContractID string
	deadline                      time.Time
	dispatchCall                  func(context.Context, protocol.Command, protocol.Policy, []byte) (protocol.Result, error)
	pinned, closed, started       bool
	dispatch                      contract.PublicationDispatch
	command                       protocol.Command
	policy                        protocol.Policy
	cancel                        context.CancelFunc
	done                          chan struct{}
	fullResult                    contract.PublicationResult
	resultValid                   bool
	err                           error
}

func (s *publicationNativeSink) Identity() contract.ID { return s.id }

func (s *publicationNativeSink) pinDispatch(dispatch contract.PublicationDispatch, payloadLength uint32) error {
	if _, err := contract.EncodePublicationDispatch(dispatch); err != nil {
		return err
	}
	config, err := contract.OutputConfigContractDigest(s.configContractID)
	if err != nil {
		return err
	}
	request, err := contract.PublicationRequestContractDigest(contract.ID(s.artifact.ProtocolID), config, s.target.ServiceContractID, s.target.TargetContractID, s.projection.Action)
	if err != nil || request != s.projection.RequestContractDigest {
		return ErrAdmission
	}
	response, err := contract.PublicationResponseContractDigest(request, contract.ID(s.artifact.ArtifactContractID))
	if err != nil || dispatch.Projection != s.projection || dispatch.ExecutorID != publicationIDLabel(s.artifact.ExecutorID) || dispatch.CredentialRouteID != publicationIDLabel(s.artifact.CredentialRouteID) || dispatch.ResponseContractDigest != response {
		return ErrAdmission
	}
	digest, err := contract.PublicationDispatchContextDigest(dispatch)
	if err != nil {
		return err
	}
	p := dispatch.Projection
	policy := publicationPolicy(s.target, p.Action)
	command := protocol.Command{Schema: 1, Action: protocol.Action(p.Action), DomainID: protocol.ID(dispatch.DomainID), OperationID: protocol.ID(dispatch.OperationID), AttemptID: protocol.ID(dispatch.AttemptID), CoordinateID: protocol.ID(dispatch.CoordinateID), ProjectionCommitment: protocol.ID(dispatch.ProjectionCommitment), DispatchContextDigest: protocol.ID(digest), RequestContractDigest: protocol.ID(p.RequestContractDigest), ResponseContractDigest: protocol.ID(response), DescriptorID: s.artifact.DescriptorID, CredentialRouteID: s.artifact.CredentialRouteID, PolicyDigest: protocol.ID(p.PolicyDigest), BindingIncarnationID: protocol.ID(p.BindingIncarnationID), EntryIncarnationID: protocol.ID(p.EntryIncarnationID), TargetRowDigest: protocol.ID(p.TargetRowDigest), OwnedBirthAttemptID: protocol.ID(p.OwnedBirthAttemptID), UncertainCreateAttemptID: protocol.ID(p.UncertainCreateAttemptID), ExclusiveNamespaceDigest: protocol.ID(p.ExclusiveNamespaceDigest), ValueBasisDigest: protocol.ID(p.ValueBasisDigest), DeadlineUnixMillis: uint64(s.deadline.UnixMilli()), BindingDestinationID: s.destination, PolicyContractID: policy.ContractID, Target: publicationWireTarget(s.target)}
	if !p.OwnedBirthAttemptID.IsZero() {
		if err := publicationBirthMatches(p.DomainID, s.target, s.coordinate, &s.birth, p.Action == contract.PublicationDeleteOwned); err != nil || p.OwnedBirthAttemptID != s.birth.AttemptID {
			return ErrAdmission
		}
		command.OwnedInstance = s.birth.Evidence.SafeResourceID
		command.BirthTargetRowDigest = protocol.ID(s.birth.Projection.TargetRowDigest)
	}
	if p.Action == contract.PublicationDeleteReservedSlot && (s.uncertainCreate.AttemptID != p.UncertainCreateAttemptID || p.ExclusiveNamespaceDigest.IsZero() || publicationUncertainCreateMatches(p.DomainID, s.target, s.coordinate, &s.uncertainCreate) != nil) {
		return ErrAdmission
	}
	if p.Action == contract.PublicationCreateWithValue || p.Action == contract.PublicationWriteValue {
		command.PayloadLengthMode, command.PayloadLength = protocol.LengthExact, payloadLength
	} else if payloadLength != 0 {
		return ErrAdmission
	}
	if protocol.ValidatePolicy(command, policy) != nil {
		return ErrAdmission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pinned {
		return ErrAdmission
	}
	s.dispatch, s.command, s.policy, s.pinned = dispatch, command, policy, true
	return nil
}

// Send owns cancellation and joins the synchronous dispatcher before releasing
// its borrowed payload. The complete checked result remains for the facade.
func (s *publicationNativeSink) Send(ctx context.Context, dispatch contract.PublicationDispatch, payload []byte) (evidence contract.PublicationEvidence, err error) {
	if ctx == nil {
		return evidence, ErrAdmission
	}
	s.mu.Lock()
	value := s.command.Action == protocol.ActionCreateWithValue || s.command.Action == protocol.ActionWriteValue
	if s.closed || s.started || !s.pinned || dispatch != s.dispatch || uint32(len(payload)) != s.command.PayloadLength || value && payload == nil || !value && payload != nil || s.dispatchCall == nil {
		s.mu.Unlock()
		return evidence, ErrAdmission
	}
	s.started = true
	callCtx, cancel := context.WithCancel(ctx)
	s.cancel, s.done = cancel, make(chan struct{})
	command, policy, done := s.command, s.policy, s.done
	s.mu.Unlock()
	var full contract.PublicationResult
	valid := false
	defer func() {
		cancel()
		s.mu.Lock()
		s.fullResult, s.resultValid, s.err = full, valid, err
		close(done)
		s.mu.Unlock()
	}()
	wire, dispatchErr := s.dispatchCall(callCtx, command, policy, payload)
	if dispatchErr != nil && !outputhost.PreservesResult(wire, dispatchErr) {
		return evidence, dispatchErr
	}
	if err = protocol.ValidateResult(command, wire); err != nil {
		return evidence, err
	}
	full = contract.PublicationResult{Schema: 2, DomainID: contract.ID(wire.DomainID), OperationID: contract.ID(wire.OperationID), AttemptID: contract.ID(wire.AttemptID), CoordinateID: contract.ID(wire.CoordinateID), ProjectionCommitment: contract.ID(wire.ProjectionCommitment), DispatchContextDigest: contract.ID(wire.DispatchContextDigest), Evidence: contract.PublicationEvidence{Schema: 3, Entry: uint8(wire.Entry), Class: uint8(wire.Class), ResponseContractDigest: contract.ID(wire.ResponseContractDigest), NormalizedStatus: wire.NormalizedStatus, SafeRequestID: wire.SafeRequestID, SafeResourceID: wire.SafeResourceID, ConsumerLocator: wire.ConsumerLocator}}
	if err = contract.ValidatePublicationResult(dispatch, full); err != nil {
		full = contract.PublicationResult{}
		return evidence, err
	}
	valid = true
	return full.Evidence, dispatchErr
}

func (s *publicationNativeSink) preservesReportingFailure(evidence contract.PublicationEvidence, sendErr, closeErr error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A valid result with a reporting error can only come from the host's
	// exact qualification. Close returns that same immutable error value.
	return s.resultValid && s.fullResult.Evidence == evidence && s.err != nil && sendErr == s.err && closeErr == s.err
}

func (s *publicationNativeSink) result() (contract.PublicationResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fullResult, s.resultValid
}

func (s *publicationNativeSink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Cancellation is only a request. The dispatcher can still read payload
	// until Send publishes completion, so Close must wait even if canceled.
	if done != nil {
		<-done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
