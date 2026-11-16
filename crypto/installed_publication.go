package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/output"
)

// PublicationActionCheckInput borrows public target and retained ownership
// facts for one passive action check. Deadline bounds that check; none of these
// fields supplies payload, credentials or independent effect authority.
type PublicationActionCheckInput struct {
	DestinationID, ConfigContractID string
	DomainID                        contract.ID
	Action                          uint8
	Target                          contract.OutputTarget
	Coordinate                      contract.PublicationCoordinate
	Birth, UncertainCreate          *contract.PublicationMarker
	ExclusiveNamespaceDigest        contract.ID
	PayloadLength                   uint32
	Deadline                        time.Time
}

// CheckPublicationAction checks exact public ownership and target facts without
// opening a credential or payload channel.
func CheckPublicationAction(ctx context.Context, path string, installed *outputhost.Installation, in PublicationActionCheckInput) (protocol.ActionCheckResult, error) {
	if installed == nil {
		return protocol.ActionCheckResult{}, ErrAdmission
	}
	request, policy, err := publicationActionCheckRequest(in.DomainID, in.Action, in.Target, in.Coordinate, in.Birth, in.UncertainCreate, in.ExclusiveNamespaceDigest, in.PayloadLength, in.Deadline, installed.Artifact())
	if err != nil {
		return protocol.ActionCheckResult{}, err
	}
	validator, err := outputhost.NewPublicValidator(ctx, path, installed)
	if err != nil {
		return protocol.ActionCheckResult{}, err
	}
	return validator.CheckAction(ctx, request, policy)
}

// PublicationPolicyActionInput carries only public target and optional qualified
// prior policy identity. Core owns the qualification of that prior identity.
type PublicationPolicyActionInput struct {
	DomainID                contract.ID
	Target                  contract.OutputTarget
	HasPreviousPolicyDigest bool
	PreviousPolicyDigest    contract.ID
	Deadline                time.Time
}

func SelectPublicationPolicyAction(ctx context.Context, path string, installed *outputhost.Installation, in PublicationPolicyActionInput) (protocol.Action, error) {
	if installed == nil || !time.Now().Before(in.Deadline) || in.HasPreviousPolicyDigest == in.PreviousPolicyDigest.IsZero() {
		return 0, ErrAdmission
	}
	deadline := in.Deadline
	if limit := time.Now().Add(50 * time.Second); deadline.After(limit) {
		deadline = limit
	}
	policy := publicationPolicy(in.Target, contract.PublicationUpdatePolicy)
	digest, err := protocol.PolicyDigest(protocol.ID(in.DomainID), policy)
	if err != nil {
		return 0, err
	}
	request := protocol.PolicyActionRequest{Schema: 1, DeadlineUnixMillis: uint64(deadline.UnixMilli()), DomainID: protocol.ID(in.DomainID),
		DescriptorID: installed.Artifact().DescriptorID, PolicyDigest: digest, PolicyContractID: policy.ContractID, Target: publicationWireTarget(in.Target),
		HasPreviousPolicyDigest: in.HasPreviousPolicyDigest, PreviousPolicyDigest: protocol.ID(in.PreviousPolicyDigest)}
	validator, err := outputhost.NewPublicValidator(ctx, path, installed)
	if err != nil {
		return 0, err
	}
	response, err := validator.SelectPolicyAction(ctx, request, policy)
	return response.Action, err
}

func publicationPolicy(target contract.OutputTarget, action uint8) protocol.Policy {
	if action >= contract.PublicationDeleteOwned {
		return protocol.Policy{}
	}
	return protocol.Policy{ContractID: target.Policy.ContractID, Data: target.Policy.Data}
}
func publicationWireTarget(target contract.OutputTarget) protocol.Target {
	return protocol.Target{ServiceContractID: target.ServiceContractID, TargetContractID: target.TargetContractID,
		CanonicalTarget: target.CanonicalTarget, ConsumerLocator: target.ConsumerLocator, TargetData: target.TargetData,
		PayloadEncoding: target.PayloadEncoding, LocatorRequiresCreation: target.LocatorRequiresCreation, Capabilities: protocol.ActionCapabilities(target.Capabilities),
		CreateValueBounds: protocol.PayloadBounds{Minimum: target.CreateValueBounds.Minimum, Maximum: target.CreateValueBounds.Maximum},
		WriteValueBounds:  protocol.PayloadBounds{Minimum: target.WriteValueBounds.Minimum, Maximum: target.WriteValueBounds.Maximum}}
}
func publicationActionCheckRequest(domain contract.ID, action uint8, target contract.OutputTarget, coordinate contract.PublicationCoordinate, birth, uncertainCreate *contract.PublicationMarker, exclusiveNamespaceDigest contract.ID, payloadLength uint32, deadline time.Time, installed outputhost.Artifact) (protocol.ActionCheckRequest, protocol.Policy, error) {
	refuse := func() (protocol.ActionCheckRequest, protocol.Policy, error) {
		return protocol.ActionCheckRequest{}, protocol.Policy{}, ErrAdmission
	}
	if !time.Now().Before(deadline) || action != contract.PublicationDeleteReservedSlot && (uncertainCreate != nil || !exclusiveNamespaceDigest.IsZero()) {
		return refuse()
	}
	if limit := time.Now().Add(50 * time.Second); deadline.After(limit) {
		deadline = limit
	}
	if action >= contract.PublicationDeleteOwned && (target.Policy.ContractID != "" || len(target.Policy.Data) != 0) {
		return refuse()
	}
	policy := publicationPolicy(target, action)
	digest, err := protocol.PolicyDigest(protocol.ID(domain), policy)
	if err != nil {
		return refuse()
	}
	q := protocol.ActionCheckRequest{Schema: 1, Action: protocol.Action(action), DomainID: protocol.ID(domain), DescriptorID: installed.DescriptorID,
		PolicyDigest: digest, PolicyContractID: policy.ContractID, Target: publicationWireTarget(target), DeadlineUnixMillis: uint64(deadline.UnixMilli())}
	if action == contract.PublicationCreateWithValue || action == contract.PublicationWriteValue {
		q.PayloadLengthMode, q.PayloadLength = protocol.LengthExact, payloadLength
	} else if payloadLength != 0 {
		return refuse()
	}
	switch action {
	case contract.PublicationCreateEmpty, contract.PublicationCreateWithValue:
		if birth != nil {
			return refuse()
		}
	case contract.PublicationDeleteReservedSlot:
		if birth != nil || exclusiveNamespaceDigest.IsZero() || publicationUncertainCreateMatches(domain, target, coordinate, uncertainCreate) != nil {
			return refuse()
		}
		q.OwnershipMode, q.UncertainCreateAttemptID, q.ExclusiveNamespaceDigest = protocol.OwnershipUncertain, protocol.ID(uncertainCreate.AttemptID), protocol.ID(exclusiveNamespaceDigest)
	default:
		if err := publicationBirthMatches(domain, target, coordinate, birth, action == contract.PublicationDeleteOwned); err != nil {
			return refuse()
		}
		owned, err := contract.PublicationOwnedInstanceDigest(domain, birth.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
		if err != nil {
			return refuse()
		}
		q.OwnershipMode, q.OwnedInstance, q.OwnedInstanceDigest = protocol.OwnershipQualified, birth.Evidence.SafeResourceID, protocol.ID(owned)
	}
	if protocol.ValidateActionCheckPolicy(q, policy) != nil {
		return refuse()
	}
	return q, policy, nil
}

func publicationBirthMatches(domain contract.ID, target contract.OutputTarget, coordinate contract.PublicationCoordinate, birth *contract.PublicationMarker, retainedDeletion bool) error {
	id, err := contract.PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
	if err != nil || birth == nil || coordinate.DomainID != domain || coordinate.CoordinateID != id || coordinate.ServiceContractID != target.ServiceContractID || coordinate.CanonicalTarget != target.CanonicalTarget || !retainedDeletion && (coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedBirthAttemptID != birth.AttemptID) || birth.DomainID != domain || birth.CoordinateID != id || birth.State != contract.PublicationAcknowledged || birth.Evidence.Class != contract.PublicationRequestAcknowledged || birth.Evidence.Entry != contract.PublicationMayHaveEnteredEntry || (birth.Projection.Action != contract.PublicationCreateEmpty && birth.Projection.Action != contract.PublicationCreateWithValue) {
		return ErrAdmission
	}
	if _, err := contract.EncodePublicationMarker(*birth); err != nil {
		return err
	}
	if _, err := contract.EncodePublicationCoordinate(coordinate); err != nil {
		return err
	}
	if birth.BirthServiceContractID != target.ServiceContractID || birth.BirthTargetContractID != target.TargetContractID {
		return ErrAdmission
	}
	if !target.LocatorRequiresCreation && birth.Evidence.ConsumerLocator != target.ConsumerLocator || coordinate.OwnedBirthAttemptID == birth.AttemptID && birth.Evidence.ConsumerLocator != coordinate.DeletionConsumerLocator {
		return ErrAdmission
	}
	digest, err := contract.PublicationOwnedInstanceDigest(domain, id, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil || coordinate.OwnedBirthAttemptID == birth.AttemptID && digest != coordinate.OwnedInstanceDigest {
		return ErrAdmission
	}
	if retainedDeletion && !publicationCreateRetainedTargetMatches(domain, target, coordinate, birth) {
		return ErrAdmission
	}
	return nil
}

func publicationCreateRetainedTargetMatches(domain contract.ID, target contract.OutputTarget, coordinate contract.PublicationCoordinate, marker *contract.PublicationMarker) bool {
	if marker == nil || marker.DomainID != domain || marker.CoordinateID != coordinate.CoordinateID || marker.Projection.BindingIncarnationID != coordinate.LastBindingIncarnationID || marker.Projection.EntryIncarnationID != coordinate.LastEntryIncarnationID || marker.Projection.TargetRowDigest != coordinate.DeletionTargetRowDigest || marker.BirthServiceContractID != target.ServiceContractID || marker.BirthTargetContractID != target.TargetContractID {
		return false
	}
	return coordinate.DomainID == domain && coordinate.ServiceContractID == target.ServiceContractID && coordinate.CanonicalTarget == target.CanonicalTarget && coordinate.DeletionTargetContractID == target.TargetContractID && bytes.Equal(coordinate.DeletionTargetData, target.TargetData) && coordinate.LocatorRequiresCreation == target.LocatorRequiresCreation && (target.LocatorRequiresCreation && target.ConsumerLocator == "" || coordinate.DeletionConsumerLocator == target.ConsumerLocator) && coordinate.DeletionPayloadEncoding == target.PayloadEncoding
}

func publicationUncertainCreateMatches(domain contract.ID, target contract.OutputTarget, coordinate contract.PublicationCoordinate, marker *contract.PublicationMarker) error {
	if marker == nil || (marker.State != contract.PublicationMayHaveEntered && marker.State != contract.PublicationUnknown) || (marker.Projection.Action != contract.PublicationCreateEmpty && marker.Projection.Action != contract.PublicationCreateWithValue) || !publicationCreateRetainedTargetMatches(domain, target, coordinate, marker) {
		return ErrAdmission
	}
	if _, err := contract.EncodePublicationMarker(*marker); err != nil {
		return err
	}
	if _, err := contract.EncodePublicationCoordinate(coordinate); err != nil {
		return err
	}
	return nil
}

// PublicationCustodyInput fixes one exact selected action and installed host.
// It contains no payload and grants no marker or send permission.
type PublicationCustodyInput struct {
	Projection                      contract.PublicationProjection
	DestinationID, ConfigContractID string
	Target                          contract.OutputTarget
	Coordinate                      contract.PublicationCoordinate
	Birth, UncertainCreate          *contract.PublicationMarker
	Native                          *outputhost.Native
	Minimum, Maximum                uint32
	Deadline                        time.Time
}

// PublicationCustody owns one private runtime fork and joined native action.
type PublicationCustody struct {
	mu                       sync.Mutex
	runtime                  *Runtime
	sink                     *publicationNativeSink
	projection               contract.PublicationProjection
	destination              string
	target                   contract.OutputTarget
	deletion                 *publicationDeletionSelection
	minimum, maximum         uint32
	deadline                 time.Time
	admission                contract.ID
	prepared, armed, retired bool
	payloadLength            uint32
	dispatch                 contract.PublicationDispatch
	retireOnce               sync.Once
	retireErr                error
}

// NewPublicationCustody validates one selected native action, copies its
// target and coordinate backing, and owns a new runtime fork. It performs no
// send. The caller must Retire the owner on every path, including failed Prepare
// or Arm calls; the supplied Native must be reserved for this action.
func NewPublicationCustody(ctx context.Context, runtime *Runtime, in PublicationCustodyInput) (*PublicationCustody, error) {
	if ctx == nil || ctx.Err() != nil || runtime == nil || in.Native == nil || !time.Now().Before(in.Deadline) {
		return nil, ErrAdmission
	}
	installed := in.Native.Installation()
	a, target, p := installed.Artifact(), in.Target, in.Projection
	if in.Minimum > in.Maximum || in.Maximum > protocol.MaximumPayloadBytes || !target.Capabilities.Has(p.Action) {
		return nil, ErrAdmission
	}
	value := p.Action == contract.PublicationCreateWithValue || p.Action == contract.PublicationWriteValue
	expected := contract.OutputPayloadBounds{}
	switch p.Action {
	case contract.PublicationCreateWithValue:
		expected = target.CreateValueBounds
	case contract.PublicationWriteValue:
		expected = target.WriteValueBounds
	}
	if in.Minimum != expected.Minimum || in.Maximum != expected.Maximum || !value && (in.Minimum != 0 || in.Maximum != 0) {
		return nil, ErrAdmission
	}
	configDigest, err := contract.OutputConfigContractDigest(in.ConfigContractID)
	if err != nil {
		return nil, ErrAdmission
	}
	request, err := contract.PublicationRequestContractDigest(contract.ID(a.ProtocolID), configDigest, target.ServiceContractID, target.TargetContractID, p.Action)
	if err != nil || request != p.RequestContractDigest || p.Action >= contract.PublicationDeleteOwned && in.ConfigContractID != in.Coordinate.DeletionConfigContractID {
		return nil, ErrAdmission
	}
	if _, _, err := publicationActionCheckRequest(p.DomainID, p.Action, target, in.Coordinate, in.Birth, in.UncertainCreate, p.ExclusiveNamespaceDigest, in.Minimum, in.Deadline, a); err != nil {
		return nil, err
	}
	target, err = clonePublicationTarget(target)
	if err != nil {
		return nil, err
	}
	coordinate, err := in.Coordinate.Clone()
	if err != nil {
		return nil, err
	}
	fork, err := runtime.Fork()
	if err != nil {
		return nil, err
	}
	sink := &publicationNativeSink{id: contract.ID(a.ExecutorID), artifact: a, projection: p, target: target, coordinate: coordinate,
		destination: strings.Clone(in.DestinationID), configContractID: strings.Clone(in.ConfigContractID), deadline: in.Deadline, dispatchCall: in.Native.Dispatch}
	if in.Birth != nil {
		sink.birth = *in.Birth
	}
	if in.UncertainCreate != nil {
		sink.uncertainCreate = *in.UncertainCreate
	}
	owner := &PublicationCustody{runtime: fork, sink: sink, projection: p, destination: in.DestinationID, target: target, minimum: in.Minimum, maximum: in.Maximum, deadline: in.Deadline}
	if p.Action >= contract.PublicationDeleteOwned {
		owner.deletion = &publicationDeletionSelection{Coordinate: coordinate}
		if in.Birth != nil {
			owner.deletion.Birth = &sink.birth
		}
		if in.UncertainCreate != nil {
			owner.deletion.UncertainCreate = &sink.uncertainCreate
		}
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), owner.Retire(ctx))
	}
	return owner, nil
}

func clonePublicationTarget(target contract.OutputTarget) (contract.OutputTarget, error) {
	if _, err := contract.OutputTargetRowLength(target); err != nil {
		return contract.OutputTarget{}, err
	}
	target.ServiceContractID = strings.Clone(target.ServiceContractID)
	target.TargetContractID = strings.Clone(target.TargetContractID)
	target.CanonicalTarget = strings.Clone(target.CanonicalTarget)
	target.ConsumerLocator = strings.Clone(target.ConsumerLocator)
	target.TargetData = bytes.Clone(target.TargetData)
	target.Policy.ContractID = strings.Clone(target.Policy.ContractID)
	target.Policy.Data = bytes.Clone(target.Policy.Data)
	return target, nil
}

// InstanceID returns the owned runtime identity, or zero for a nil owner.
func (o *PublicationCustody) InstanceID() contract.ID {
	if o == nil {
		return contract.ID{}
	}
	return o.runtime.InstanceID()
}

// Prepare consumes the one preparation opportunity once it accepts a nonzero id.
// It borrows selected for the call, prepares the private payload and reports
// required key uses without sending. Value actions require a selection; metadata
// actions require nil. A failed call does not grant another preparation attempt.
func (o *PublicationCustody) Prepare(ctx context.Context, id contract.ID, selected *contract.ConsumerSelection, routeID contract.ID) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	if o == nil || id.IsZero() {
		return nil, contract.CryptoInvalidAdmission
	}
	o.mu.Lock()
	if o.retired || !o.admission.IsZero() {
		o.mu.Unlock()
		return nil, contract.CryptoInvalidAdmission
	}
	o.admission = id
	o.mu.Unlock()
	var value *publicationSelectedValue
	var route contract.ID
	valueAction := o.projection.Action == contract.PublicationCreateWithValue || o.projection.Action == contract.PublicationWriteValue
	if valueAction {
		if selected == nil {
			return nil, contract.CryptoInvalidAdmission
		}
		value = &publicationSelectedValue{}
		switch selected.Entry.ConfidentialityClass {
		case contract.Plain:
			value.Plain = &publicationPlainSelection{Slot: selected.Slot, EntryDigest: selected.EntryDigest, Entry: selected.Entry}
		case contract.Secret:
			if selected.Binding.SubjectID != o.projection.ActingRecipientID {
				return nil, contract.CryptoInvalidAdmission
			}
			route = routeID
			if route.IsZero() {
				return nil, contract.CryptoInvalidAdmission
			}
			value.Secret = selected
		default:
			return nil, contract.CryptoInvalidAdmission
		}
	} else if selected != nil {
		return nil, contract.CryptoInvalidAdmission
	}
	var payloadLength uint32
	if valueAction {
		rawLength := selected.Entry.ContentLength
		var err error
		payloadLength, err = contract.PublicationPayloadLength(o.target.PayloadEncoding, rawLength)
		if err != nil {
			if errors.Is(err, contract.ErrRecordCapacity) {
				return nil, contract.CryptoCapacityExceeded
			}
			return nil, contract.CryptoInvalidAdmission
		}
	}
	uses, code := o.runtime.preparePublication(ctx, id, o.sink.Identity(), route, o.projection, o.destination, o.target, o.deletion, value, int(o.minimum), int(o.maximum), o.sink, o.deadline)
	if code == contract.CryptoSuccess {
		o.mu.Lock()
		o.prepared, o.payloadLength = true, payloadLength
		o.mu.Unlock()
	}
	return uses, code
}

// Arm binds the prepared payload to the exact admitted dispatch. The caller
// must have completed Core's effect admission; arming alone does not send.
func (o *PublicationCustody) Arm(ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	if o == nil {
		return ErrAdmission
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired || !o.prepared || o.armed || id != o.admission {
		return ErrAdmission
	}
	if err := o.sink.pinDispatch(dispatch, o.payloadLength); err != nil {
		return err
	}
	if err := o.runtime.armPublication(ctx, id, dispatch); err != nil {
		return err
	}
	o.dispatch, o.armed = dispatch, true
	return nil
}

// Send consumes the armed native action. Success returns a checked, correlated
// plugin result, not independent proof of a provider effect. A missing or invalid
// result after possible entry remains unknown and grants no resend.
func (o *PublicationCustody) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	if o == nil {
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	o.mu.Lock()
	valid := !o.retired && o.armed && id == o.admission
	dispatch := o.dispatch
	o.mu.Unlock()
	if !valid {
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	evidence, code := o.runtime.sendPublication(ctx, id)
	if code != contract.CryptoSuccess {
		return contract.PublicationResult{}, code
	}
	result, ok := o.sink.result()
	if !ok || result.Evidence != evidence || contract.ValidatePublicationResult(dispatch, result) != nil {
		return contract.PublicationResult{}, contract.CryptoResponseUnknown
	}
	return result, contract.CryptoSuccess
}

// Retire bars new work, cancels and joins users, disposes private custody and
// closes the runtime fork. It waits for dispatch even if ctx is already canceled.
// Repeated calls return the same error; a nil owner needs no retirement.
func (o *PublicationCustody) Retire(ctx context.Context) error {
	if o == nil {
		return nil
	}
	o.retireOnce.Do(func() {
		o.mu.Lock()
		o.retired = true
		o.mu.Unlock()
		o.runtime.retirePublication(ctx)
		o.retireErr = o.sink.Close()
		o.runtime.Close()
	})
	return o.retireErr
}

func publicationIDLabel(id protocol.ID) string { return hex.EncodeToString(id[:]) }
