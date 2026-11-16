package crypto

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

// The private parent authenticates the selected Snapshot and supplies its
// exact current rows. This union never crosses into Core as plaintext.
type publicationPlainSelection struct {
	Slot        uint16
	EntryDigest contract.ID
	Entry       contract.ValueEntry
}

type publicationSelectedValue struct {
	Plain  *publicationPlainSelection
	Secret *contract.ConsumerSelection
}

type publicationCheckedValue struct {
	entry         contract.ValueEntry
	secret        *contract.ConsumerSelection
	wrapIndex     int
	packetContext contract.ID
	rawLength     uint32
}

func checkPublicationValue(projection contract.PublicationProjection, selected *publicationSelectedValue, family contract.Family) (publicationCheckedValue, contract.PublicationValueBasis, error) {
	if selected == nil {
		return publicationCheckedValue{}, contract.PublicationValueBasis{}, errPublicationPayload
	}
	if (selected.Plain == nil) == (selected.Secret == nil) {
		return publicationCheckedValue{}, contract.PublicationValueBasis{}, errPublicationPayload
	}
	if selected.Plain != nil {
		plain := selected.Plain
		if plain.Slot >= contract.CryptoMaxValueEntries || plain.Entry.ConfidentialityClass != contract.Plain ||
			!slices.Contains(plain.Entry.Recipients, projection.ActingRecipientID) {
			return publicationCheckedValue{}, contract.PublicationValueBasis{}, errPublicationPayload
		}
		if _, err := contract.ValueEntryLength(plain.Entry); err != nil {
			return publicationCheckedValue{}, contract.PublicationValueBasis{}, errPublicationPayload
		}
		digest, err := contract.PublicValueEntryDigest(projection.DomainID, plain.Slot, plain.Entry)
		if err != nil || digest != plain.EntryDigest {
			return publicationCheckedValue{}, contract.PublicationValueBasis{}, errPublicationPayload
		}
		entry := plain.Entry
		return publicationCheckedValue{entry: entry, rawLength: entry.ContentLength},
			contract.PublicationValueBasis{EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState,
				ContentLength: entry.ContentLength, InputEncoding: entry.InputEncoding, RetainedLength: entry.RetainedLength, ConfidentialityClass: contract.Plain, SemanticCommitment: digest}, nil
	}
	secret := selected.Secret
	index, packet, valid := checkConsumerSelection(*secret, family)
	if !valid || secret.DomainID != projection.DomainID || secret.Binding.SubjectID != projection.ActingRecipientID ||
		secret.Entry.ConfidentialityClass != contract.Secret {
		return publicationCheckedValue{}, contract.PublicationValueBasis{}, errPublicationPayload
	}
	entry := secret.Entry
	return publicationCheckedValue{entry: entry, secret: secret, wrapIndex: index, packetContext: packet, rawLength: secret.Payload.ContentLength},
		contract.PublicationValueBasis{EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState,
			ContentLength: secret.Payload.ContentLength, InputEncoding: entry.InputEncoding, RetainedLength: entry.RetainedLength, ConfidentialityClass: contract.Secret, SemanticCommitment: secret.Payload.SemanticCommitment}, nil
}

// Deletion borrows the exact selected coordinate and its distinct creation
// proof. Removed policy and value bodies are not part of this input.
type publicationDeletionSelection struct {
	Coordinate             contract.PublicationCoordinate
	Birth, UncertainCreate *contract.PublicationMarker
}

func publicationDeletionTargetMatches(projection contract.PublicationProjection, destinationID string, target contract.OutputTarget, deletion *publicationDeletionSelection) bool {
	if deletion == nil || target.Policy.ContractID != "" || len(target.Policy.Data) != 0 {
		return false
	}
	c := deletion.Coordinate
	if _, err := contract.EncodePublicationCoordinate(c); err != nil {
		return false
	}
	if c.DomainID != projection.DomainID || c.CoordinateID != projection.CoordinateID || c.ServiceContractID != target.ServiceContractID || c.CanonicalTarget != target.CanonicalTarget ||
		c.LastBindingIncarnationID != projection.BindingIncarnationID || c.LastEntryIncarnationID != projection.EntryIncarnationID ||
		c.DeletionTargetRowDigest != projection.TargetRowDigest || c.DeletionDestinationID != destinationID ||
		c.DeletionTargetContractID != target.TargetContractID || !bytes.Equal(c.DeletionTargetData, target.TargetData) || c.LocatorRequiresCreation != target.LocatorRequiresCreation ||
		(target.LocatorRequiresCreation && target.ConsumerLocator != "" || !target.LocatorRequiresCreation && c.DeletionConsumerLocator != target.ConsumerLocator) || c.DeletionPayloadEncoding != target.PayloadEncoding {
		return false
	}
	marker := deletion.Birth
	if projection.Action == contract.PublicationDeleteReservedSlot {
		if deletion.Birth != nil || deletion.UncertainCreate == nil || projection.ExclusiveNamespaceDigest.IsZero() {
			return false
		}
		marker = deletion.UncertainCreate
		if marker.AttemptID != projection.UncertainCreateAttemptID || (marker.State != contract.PublicationMayHaveEntered && marker.State != contract.PublicationUnknown) {
			return false
		}
	} else {
		if deletion.UncertainCreate != nil || marker == nil || marker.AttemptID != projection.OwnedBirthAttemptID || marker.State != contract.PublicationAcknowledged || marker.Evidence.Class != contract.PublicationRequestAcknowledged || marker.Evidence.Entry != contract.PublicationMayHaveEnteredEntry {
			return false
		}
	}
	if _, err := contract.EncodePublicationMarker(*marker); err != nil {
		return false
	}
	if marker.DomainID != projection.DomainID || marker.CoordinateID != projection.CoordinateID ||
		(marker.Projection.Action != contract.PublicationCreateEmpty && marker.Projection.Action != contract.PublicationCreateWithValue) ||
		marker.Projection.BindingIncarnationID != projection.BindingIncarnationID || marker.Projection.EntryIncarnationID != projection.EntryIncarnationID || marker.Projection.TargetRowDigest != projection.TargetRowDigest || marker.BirthServiceContractID != target.ServiceContractID || marker.BirthTargetContractID != target.TargetContractID {
		return false
	}
	if projection.Action == contract.PublicationDeleteOwned {
		if !target.LocatorRequiresCreation && marker.Evidence.ConsumerLocator != target.ConsumerLocator || c.OwnedBirthAttemptID == marker.AttemptID && marker.Evidence.ConsumerLocator != c.DeletionConsumerLocator {
			return false
		}
		digest, err := contract.PublicationOwnedInstanceDigest(marker.DomainID, marker.CoordinateID, marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID, marker.Projection.TargetRowDigest, marker.AttemptID, marker.Evidence.SafeResourceID)
		if err != nil || c.OwnedBirthAttemptID == marker.AttemptID && digest != c.OwnedInstanceDigest {
			return false
		}
	}
	return true
}

// The private parent supplies the exact authenticated target row. Preparation
// rechecks its commitment and selected value basis before any key operation.
func publicationTargetMatches(projection contract.PublicationProjection, destinationID string, target contract.OutputTarget, deletion *publicationDeletionSelection) bool {
	if _, err := contract.EncodePublicationProjection(projection); err != nil ||
		target.EntryIncarnationID != projection.EntryIncarnationID {
		return false
	}
	if _, err := contract.PublicationPayloadLength(target.PayloadEncoding, 0); err != nil {
		return false
	}
	coordinate, err := contract.PublicationCoordinateID(projection.DomainID, target.ServiceContractID, target.CanonicalTarget)
	if err != nil || coordinate != projection.CoordinateID {
		return false
	}
	if projection.Action >= contract.PublicationDeleteOwned {
		return publicationDeletionTargetMatches(projection, destinationID, target, deletion)
	}
	if deletion != nil {
		return false
	}
	row, err := contract.PublicationTargetRowDigest(projection.DomainID, destinationID, projection.BindingIncarnationID, target)
	if err != nil || row != projection.TargetRowDigest {
		return false
	}
	if projection.Action <= contract.PublicationUpdatePolicy {
		policy, err := contract.OutputPolicyDigest(projection.DomainID, target.Policy)
		if err != nil || policy != projection.PolicyDigest {
			return false
		}
	}
	return true
}

// preparePublicationValue returns nil payload only for metadata actions. A
// zero-length selected value returns a distinct owned, nonnil empty payload.
func preparePublicationValue(ctx context.Context, projection contract.PublicationProjection, destinationID string,
	target contract.OutputTarget, deletion *publicationDeletionSelection, selected *publicationSelectedValue, route KeyAccess,
	minimum, maximum int) ([]byte, []contract.KeyUseRow, contract.CryptoResultCode) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, contract.CryptoCancelled
	}
	if !publicationTargetMatches(projection, destinationID, target, deletion) ||
		minimum < 0 || maximum < minimum || maximum > maximumPublicationPayloadBytes {
		return nil, nil, contract.CryptoInvalidAdmission
	}
	valueAction := projection.Action == contract.PublicationCreateWithValue || projection.Action == contract.PublicationWriteValue
	if !valueAction {
		if selected != nil || route != nil || minimum != 0 || maximum != 0 {
			return nil, nil, contract.CryptoInvalidAdmission
		}
		return nil, nil, contract.CryptoSuccess
	}
	if selected == nil || selected.Secret == nil && route != nil {
		return nil, nil, contract.CryptoInvalidAdmission
	}
	family := contract.Family(0)
	if route != nil {
		family = route.Family()
	}
	checked, value, err := checkPublicationValue(projection, selected, family)
	if err != nil || value.EntryIncarnationID != target.EntryIncarnationID || checked.entry.OutputEncoding != target.PayloadEncoding {
		return nil, nil, contract.CryptoInvalidAdmission
	}
	basis, err := contract.PublicationValueBasisDigest(projection.DomainID, destinationID,
		projection.BindingIncarnationID, target, value)
	if err != nil || basis != projection.ValueBasisDigest {
		return nil, nil, contract.CryptoInvalidAdmission
	}
	encodedLength, err := contract.PublicationPayloadLength(target.PayloadEncoding, checked.rawLength)
	if err != nil {
		if errors.Is(err, contract.ErrRecordCapacity) {
			return nil, nil, contract.CryptoCapacityExceeded
		}
		return nil, nil, contract.CryptoInvalidAdmission
	}
	length := int(encodedLength)
	if length < minimum || length > maximum {
		return nil, nil, contract.CryptoCapacityExceeded
	}
	if checked.secret == nil {
		payload, err := encodePublicationPayload(checked.entry.InputEncoding, target.PayloadEncoding, checked.entry.ContentLength, checked.entry.ValueBytes)
		if err != nil || len(payload) != length {
			clear(payload[:cap(payload)])
			return nil, nil, contract.CryptoCapacityExceeded
		}
		if ctx.Err() != nil {
			clear(payload[:cap(payload)])
			return nil, nil, contract.CryptoCancelled
		}
		return payload, nil, contract.CryptoSuccess
	}
	if route == nil || route.CredentialRoute().IsZero() {
		return nil, nil, contract.CryptoInvalidAdmission
	}
	secret := checked.secret
	privateResult := route.Decrypt(ctx, secret.Binding.Binding, secret.Access.Wraps[checked.wrapIndex].RSACiphertext, contract.ValueMaterialPacketLength)
	evidence := contract.CryptoResponse{}
	if !appendKeyUses(&evidence, secret.Binding, contract.KeyUseMaterialOpen, privateResult.Uses, 1) {
		clear(privateResult.Packet[:cap(privateResult.Packet)])
		return nil, nil, contract.CryptoResponseUnknown
	}
	if ctx.Err() != nil {
		clear(privateResult.Packet[:cap(privateResult.Packet)])
		return nil, evidence.KeyUseRows, contract.CryptoCancelled
	}
	keys, code := privatePacketKeys(privateResult, 1, checked.packetContext, contract.CryptoStoredAuthenticationFailed)
	if code != contract.CryptoSuccess {
		clear(privateResult.Packet[:cap(privateResult.Packet)])
		return nil, evidence.KeyUseRows, code
	}
	plain, err := custody.OpenValue(secret.Core, secret.Payload, keys)
	clear(privateResult.Packet[:cap(privateResult.Packet)])
	if err != nil {
		return nil, evidence.KeyUseRows, contract.CryptoStoredAuthenticationFailed
	}
	defer clear(plain[:cap(plain)])
	if ctx.Err() != nil {
		return nil, evidence.KeyUseRows, contract.CryptoCancelled
	}
	payload, err := encodePublicationPayload(checked.entry.InputEncoding, target.PayloadEncoding, checked.entry.ContentLength, plain)
	if err != nil || len(payload) != length {
		clear(payload[:cap(payload)])
		return nil, evidence.KeyUseRows, contract.CryptoCapacityExceeded
	}
	if ctx.Err() != nil {
		clear(payload[:cap(payload)])
		return nil, evidence.KeyUseRows, contract.CryptoCancelled
	}
	return payload, evidence.KeyUseRows, contract.CryptoSuccess
}

// publicationSink is the one selected output child. The private parent owns
// its binding to an authenticated artifact and exact selected Attempt. Close
// must unblock and join Send before borrowed payload custody can be cleared.
type publicationSink interface {
	Identity() contract.ID
	Send(context.Context, contract.PublicationDispatch, []byte) (contract.PublicationEvidence, error)
	Close() error
}

type publicationAdmission struct {
	*session
	projection   contract.PublicationProjection
	sinkID       contract.ID
	sink         publicationSink
	payload      []byte
	dispatch     contract.PublicationDispatch
	ready, armed bool
	closeOnce    sync.Once
	closeErr     error
}

func (a *publicationAdmission) closeSink() {
	a.closeOnce.Do(func() { a.closeErr = a.sink.Close() })
}

// Preparation is synchronous: the parent keeps the authenticated selections
// unchanged until return. The installed session owns cancellation throughout
// key access and only retains the complete encoded payload on success.
func (r *Runtime) preparePublication(ctx context.Context, id, sinkID, routeID contract.ID, projection contract.PublicationProjection,
	destinationID string, target contract.OutputTarget, deletion *publicationDeletionSelection, selected *publicationSelectedValue,
	minimum, maximum int, sink publicationSink, deadline time.Time) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoPublicationPrepare)
	privateCtx := telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	uses, code := r.preparePublicationOwned(privateCtx, id, sinkID, routeID, projection,
		destinationID, target, deletion, selected, minimum, maximum, sink, deadline)
	finishCryptoCall(call, code)
	return uses, code
}

func (r *Runtime) preparePublicationOwned(ctx context.Context, id, sinkID, routeID contract.ID, projection contract.PublicationProjection,
	destinationID string, target contract.OutputTarget, deletion *publicationDeletionSelection, selected *publicationSelectedValue,
	minimum, maximum int, sink publicationSink, deadline time.Time) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	if r == nil || ctx == nil || ctx.Err() != nil || id.IsZero() || sinkID.IsZero() || sink == nil || sink.Identity() != sinkID ||
		!validDeadline(deadline) || projection.ActingRecipientID.IsZero() ||
		(projection.Action != contract.PublicationCreateWithValue && projection.Action != contract.PublicationWriteValue ||
			selected != nil && selected.Plain != nil) && !routeID.IsZero() {
		return nil, contract.CryptoInvalidAdmission
	}
	r.mu.Lock()
	if r.closed || r.slot != nil {
		r.mu.Unlock()
		return nil, contract.CryptoInvalidAdmission
	}
	route := r.routes[routeID]
	if route != nil && (route.Family() != r.family || route.CredentialRoute() != routeID) {
		r.mu.Unlock()
		return nil, contract.CryptoInvalidAdmission
	}
	a := &publicationAdmission{projection: projection, sinkID: sinkID, sink: sink}
	a.session = r.installSession(id, deadline, nil, func() {
		clear(a.payload[:cap(a.payload)])
		a.payload = nil
		a.sink = nil
		a.projection, a.dispatch = contract.PublicationProjection{}, contract.PublicationDispatch{}
		a.sinkID = contract.ID{}
	})
	if a.session == nil {
		r.mu.Unlock()
		return nil, contract.CryptoInvalidAdmission
	}
	r.publication = a
	a.work.Add(1)
	a.work.Add(1)
	context.AfterFunc(a.ctx, func() { defer a.work.Done(); a.closeSink() })
	r.mu.Unlock()
	defer a.work.Done()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	privateCtx := telemetry.PrivateContext(a.ctx, ctx)
	payload, uses, code := preparePublicationValue(privateCtx, projection, destinationID, target,
		deletion, selected, route, minimum, maximum)
	if code != contract.CryptoSuccess {
		r.finishSession(a.session)
		return uses, code
	}
	r.mu.Lock()
	if a.ctx.Err() != nil || r.closed {
		r.mu.Unlock()
		clear(payload[:cap(payload)])
		r.finishSession(a.session)
		return uses, contract.CryptoCancelled
	}
	a.payload, a.ready = payload, true
	r.mu.Unlock()
	return uses, contract.CryptoSuccess
}

// Only the private selected parent may arm a prepared owner after it has proved
// the exact may-have-entered marker selection. No public record or handle can
// call this private method.
func (r *Runtime) armPublication(ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoPublicationArm)
	err := ErrAdmission
	if ctx != nil {
		callerDone := ctx.Done()
		if ctx.Err() != nil {
			r.retirePreparedPublication(id)
		} else {
			var admitted *session
			admitted, err = r.armPublicationOwned(callerDone, id, dispatch)
			if ctx.Err() != nil {
				if admitted != nil {
					r.finishSession(admitted)
					r.retireSession(admitted)
				} else {
					r.retirePreparedPublication(id)
				}
				err = ErrAdmission
			}
		}
	}
	if err != nil {
		finishCryptoCall(call, contract.CryptoInvalidAdmission)
	} else {
		finishCryptoCall(call, contract.CryptoSuccess)
	}
	return err
}

// A refused or cancelled arm may retire its own prepared custody, but it must
// not retire a different or already armed admission.
func (r *Runtime) retirePreparedPublication(id contract.ID) {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.publication
	if a == nil || a.id != id || !a.ready || a.armed || a.used {
		a = nil
	} else {
		a.terminal = true
		a.cancel()
	}
	r.mu.Unlock()
	if a != nil {
		r.retireSession(a.session)
	}
}

func (r *Runtime) armPublicationOwned(callerDone <-chan struct{}, id contract.ID, dispatch contract.PublicationDispatch) (*session, error) {
	if r == nil {
		return nil, ErrAdmission
	}
	if _, err := contract.EncodePublicationDispatch(dispatch); err != nil {
		return nil, ErrAdmission
	}
	r.mu.Lock()
	a := r.publication
	if r.closed || a == nil || a.id != id || !a.ready || a.armed || a.used || a.terminal || a.ctx.Err() != nil ||
		dispatch.Projection != a.projection || dispatch.Projection.ActingRecipientID != a.projection.ActingRecipientID {
		r.mu.Unlock()
		return nil, ErrAdmission
	}
	if sessionCancellationObserved(callerDone, a.session) != contract.CryptoSuccess {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		r.retireSession(a.session)
		return nil, ErrAdmission
	}
	a.dispatch, a.armed = dispatch, true
	r.mu.Unlock()
	return a.session, nil
}

func (r *Runtime) sendPublication(ctx context.Context, id contract.ID) (contract.PublicationEvidence, contract.CryptoResultCode) {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoPublicationSend)
	evidence, code := r.sendPublicationOwned(telemetry.CallContext(ctx, call), id)
	if code != contract.CryptoSuccess {
		finishCryptoCall(call, code)
	} else {
		switch evidence.Class {
		case contract.PublicationRequestAcknowledged:
			call.Finish(telemetry.ResultSuccess)
		case contract.PublicationQualifiedNoEffect:
			call.Finish(telemetry.ResultUnchanged)
		default:
			call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonUncertain, 0))
			call.Finish(telemetry.ResultUnknown)
		}
	}
	return evidence, code
}

func (r *Runtime) sendPublicationOwned(ctx context.Context, id contract.ID) (contract.PublicationEvidence, contract.CryptoResultCode) {
	if r == nil || ctx == nil {
		return contract.PublicationEvidence{}, contract.CryptoInvalidAdmission
	}
	r.mu.Lock()
	a := r.publication
	if r.closed || a == nil || a.id != id || !a.ready || !a.armed || a.terminal {
		r.mu.Unlock()
		return contract.PublicationEvidence{}, contract.CryptoInvalidAdmission
	}
	if a.used {
		r.mu.Unlock()
		return contract.PublicationEvidence{}, contract.CryptoAlreadyUsed
	}
	if a.ctx.Err() != nil || !time.Now().Before(a.deadline) {
		r.mu.Unlock()
		return contract.PublicationEvidence{}, contract.CryptoExpired
	}
	a.used = true
	a.work.Add(1)
	sink, payload, dispatch := a.sink, a.payload, a.dispatch
	r.mu.Unlock()
	defer a.work.Done()
	defer r.finishSession(a.session)
	defer a.closeSink()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	if ctx.Err() != nil || a.ctx.Err() != nil {
		return contract.PublicationEvidence{}, contract.CryptoCancelled
	}
	privateCtx := telemetry.PrivateContext(a.ctx, ctx)
	evidence, err := sink.Send(privateCtx, dispatch, payload)
	a.closeSink()
	if ctx.Err() != nil || a.ctx.Err() != nil {
		return contract.PublicationEvidence{}, contract.CryptoCancelled
	}
	if err != nil || a.closeErr != nil {
		native, ok := sink.(*publicationNativeSink)
		if !ok || !native.preservesReportingFailure(evidence, err, a.closeErr) {
			return contract.PublicationEvidence{}, contract.CryptoResponseUnknown
		}
	}
	if evidence.ResponseContractDigest != dispatch.ResponseContractDigest {
		return contract.PublicationEvidence{}, contract.CryptoResponseUnknown
	}
	if _, err := contract.EncodePublicationEvidence(evidence); err != nil {
		return contract.PublicationEvidence{}, contract.CryptoResponseUnknown
	}
	return evidence, contract.CryptoSuccess
}

func (r *Runtime) retirePublication(ctx context.Context) {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoPublicationRetire)
	if r == nil {
		finishCryptoCall(call, contract.CryptoInvalidAdmission)
		return
	}
	r.retirePublicationOwned()
	finishCryptoCall(call, contract.CryptoSuccess)
}

func (r *Runtime) retirePublicationOwned() {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.publication
	r.mu.Unlock()
	if a != nil {
		r.retireSession(a.session)
	}
}
