package crypto

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

// consumerSink belongs to the private Crypto parent. Close must unblock and
// join any concurrent Accept, reject later Accept calls, and retain no borrowed
// plaintext after it returns. Neither interface nor implementation enters Core.
type consumerSink interface {
	Identity() contract.ID
	Accept(context.Context, []byte) error
	Close() error
}

type consumerDelivery uint8

const (
	consumerDeliveryNone consumerDelivery = iota
	consumerDeliveryComplete
	consumerDeliveryUnknown
)

type consumerResult struct {
	code     contract.CryptoResultCode
	delivery consumerDelivery
	keyUses  []contract.KeyUseRow
}

type consumerAdmission struct {
	*session
	purpose, sinkID, routeID contract.ID
	selection                contract.ConsumerSelection
	wrapIndex                int
	packetContext            contract.ID
	sink                     consumerSink
	closeOnce                sync.Once
	closed                   chan struct{}
	closeErr                 error
}

// admitConsumer is private parent entry. The parent must first authenticate
// the complete selected closure and independently pin its HEAD observation,
// caller, current binding, purpose, sink and original deadline. Public selected
// facts alone grant no authority. Refusal transfers no sink ownership.
func (r *Runtime) admitConsumer(id, purpose, sinkID, routeID contract.ID, selection contract.ConsumerSelection, sink consumerSink, deadline time.Time) error {
	if r == nil || id.IsZero() || purpose.IsZero() || sinkID.IsZero() || routeID.IsZero() || sink == nil || !validDeadline(deadline) || sink.Identity() != sinkID {
		return ErrAdmission
	}
	index, packetContext, ok := checkConsumerSelection(selection, r.family)
	if !ok {
		return ErrAdmission
	}
	return r.admitCheckedConsumer(id, purpose, sinkID, routeID, selection, index, packetContext, sink, deadline)
}

// Only typed selection validators can reach this owner after resolving the
// acting recipient's exact wrap. No caller can waive entry authorization.
func (r *Runtime) admitCheckedConsumer(id, purpose, sinkID, routeID contract.ID, selection contract.ConsumerSelection, index int, packetContext contract.ID, sink consumerSink, deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slot != nil {
		return ErrAdmission
	}
	route := r.routes[routeID]
	if route == nil || route.Family() != r.family || route.CredentialRoute() != routeID {
		return ErrAdmission
	}
	// Every retained variable owner is bounded and validated before these copies.
	selection.Entry.Name = strings.Clone(selection.Entry.Name)
	selection.Entry.Recipients = slices.Clone(selection.Entry.Recipients)
	selection.Entry.ValueBytes = slices.Clone(selection.Entry.ValueBytes)
	selection.Core.Name = strings.Clone(selection.Core.Name)
	selection.Payload.Ciphertext = slices.Clone(selection.Payload.Ciphertext)
	selection.Access.Wraps = slices.Clone(selection.Access.Wraps)
	for i := range selection.Access.Wraps {
		selection.Access.Wraps[i].RSACiphertext = slices.Clone(selection.Access.Wraps[i].RSACiphertext)
	}
	selection.Binding.Binding.SPKI = slices.Clone(selection.Binding.Binding.SPKI)
	selection.Binding.Binding.KeySelector = strings.Clone(selection.Binding.Binding.KeySelector)
	selection.HEADToken.Value = strings.Clone(selection.HEADToken.Value)
	a := &consumerAdmission{purpose: purpose, sinkID: sinkID, routeID: routeID, selection: selection, wrapIndex: index, packetContext: packetContext, sink: sink, closed: make(chan struct{})}
	a.session = r.installSession(id, deadline, nil, func() {
		a.sink = nil
		a.selection = contract.ConsumerSelection{}
		a.purpose, a.sinkID, a.routeID, a.packetContext = contract.ID{}, contract.ID{}, contract.ID{}, contract.ID{}
	})
	if a.session == nil {
		return ErrAdmission
	}
	r.consumer = a
	// Join the sink before session cleanup takes the runtime lock. A slow Close
	// must retain its owner without blocking other calls that need to refuse.
	a.work.Add(1)
	context.AfterFunc(a.ctx, func() {
		defer a.work.Done()
		a.closeSink()
	})
	return nil
}

func checkConsumerValueSelection(s contract.ConsumerSelection, family contract.Family) (int, contract.ID, bool) {
	for _, id := range []contract.ID{s.DomainID, s.SnapshotID, s.HEADDigest, s.AccessRoot, s.EntryDigest, s.HEADRevision} {
		if id.IsZero() {
			return 0, contract.ID{}, false
		}
	}
	if !s.Root.ValidFor(contract.CanonicalSchema) || s.Root.Kind != contract.RootKind || s.Root.Domain != s.DomainID || s.Root.Object != s.SnapshotID || !s.HEADToken.Valid() || s.HEADToken.Family != family || s.Binding.SubjectKind != contract.OrdinaryWrapSubject || s.Binding.SubjectID.IsZero() || s.Binding.Binding.Provider != family || s.Entry.ConfidentialityClass != contract.Secret {
		return 0, contract.ID{}, false
	}
	if _, err := contract.ValueEntryLength(s.Entry); err != nil {
		return 0, contract.ID{}, false
	}
	if _, err := contract.ValueCoreLength(s.Core); err != nil {
		return 0, contract.ID{}, false
	}
	if _, err := contract.CanonicalPayloadLength(s.Payload); err != nil {
		return 0, contract.ID{}, false
	}
	if _, err := contract.AccessRecordLength(s.Access); err != nil {
		return 0, contract.ID{}, false
	}
	c, m, p := s.Core, s.Entry, s.Payload
	actual, err := contract.ValueCoreForEntry(s.DomainID, contract.CompatibilityID(), m)
	if err != nil || c != actual || c.CompatibilityID != contract.CompatibilityID() || c.CryptoSupportID != contract.CryptoSupportID() {
		return 0, contract.ID{}, false
	}
	parsed, err := contract.InspectCanonicalPayload(m.ValueBytes)
	if err != nil || !sameConsumerPayload(contract.CanonicalPayload(parsed), p) {
		return 0, contract.ID{}, false
	}
	entryDigest, err := contract.PublicValueEntryDigest(s.DomainID, s.Slot, m)
	if err != nil || entryDigest != s.EntryDigest {
		return 0, contract.ID{}, false
	}
	wrapCore, err := custody.ValueWrapCore(c, s.Binding)
	if err != nil || s.Access.MaterialKind != contract.ValueMaterialKind || s.Access.MaterialID != c.ValueStateID || s.Access.MaterialContextDigest != wrapCore.MaterialContextDigest || s.Access.PackageCheck != p.PackageCheck {
		return 0, contract.ID{}, false
	}
	index := -1
	for i, wrap := range s.Access.Wraps {
		if wrap.SubjectKind != contract.OrdinaryWrapSubject {
			continue
		}
		if wrap.SubjectID == s.Binding.SubjectID {
			if wrap.BindingID != wrapCore.BindingID || wrap.BindingSerial != wrapCore.BindingSerial || wrap.PublicBindingDigest != wrapCore.PublicBindingDigest {
				return 0, contract.ID{}, false
			}
			index = i
		}
	}
	if index < 0 || !slices.Contains(m.Recipients, s.Binding.SubjectID) {
		return 0, contract.ID{}, false
	}
	packetContext, err := contract.RSAPacketContextDigest(wrapCore)
	return index, packetContext, err == nil
}

func checkConsumerSelection(s contract.ConsumerSelection, family contract.Family) (int, contract.ID, bool) {
	index, packet, ok := checkConsumerValueSelection(s, family)
	if !ok {
		return 0, contract.ID{}, false
	}
	return index, packet, consumerEntryWrapsPresent(s)
}

// Core authenticates the exact current/retained reader union. This owner checks
// every selected entry reader is covered; checkConsumerValueSelection separately
// requires the acting recipient to belong to that entry, not just its wraps.
func consumerEntryWrapsPresent(s contract.ConsumerSelection) bool {
	for _, id := range s.Entry.Recipients {
		found := false
		for _, wrap := range s.Access.Wraps {
			if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sameConsumerPayload(a, b contract.CanonicalPayload) bool {
	return a.Profile == b.Profile && a.CryptoSupportID == b.CryptoSupportID && a.DataKeyID == b.DataKeyID && a.DataKeyEpoch == b.DataKeyEpoch && a.CommitmentKeyID == b.CommitmentKeyID && a.CommitmentKeyEpoch == b.CommitmentKeyEpoch && a.ContentLength == b.ContentLength && a.InputEncoding == b.InputEncoding && a.RetainedLength == b.RetainedLength && a.Nonce == b.Nonce && a.SemanticCommitment == b.SemanticCommitment && a.PackageCheck == b.PackageCheck && bytes.Equal(a.Ciphertext, b.Ciphertext)
}

func (a *consumerAdmission) closeSink() {
	a.closeOnce.Do(func() { a.closeErr = a.sink.Close(); close(a.closed) })
}

func (r *Runtime) consumeSelected(ctx context.Context, id contract.ID) consumerResult {
	result := consumerResult{code: contract.CryptoInvalidAdmission}
	if r == nil || ctx == nil {
		return result
	}
	r.mu.Lock()
	a := r.consumer
	if r.closed || a == nil || a.id != id {
		r.mu.Unlock()
		return result
	}
	if a.terminal {
		r.mu.Unlock()
		result.code = contract.CryptoAlreadyUsed
		return result
	}
	if a.ctx.Err() != nil || !time.Now().Before(a.deadline) {
		r.mu.Unlock()
		result.code = contract.CryptoExpired
		return result
	}
	if a.used {
		r.mu.Unlock()
		result.code = contract.CryptoAlreadyUsed
		return result
	}
	a.used = true
	a.work.Add(1)
	route := r.routes[a.routeID]
	r.mu.Unlock()
	defer a.work.Done()
	defer r.finishSession(a.session)
	defer a.closeSink()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	privateCtx := telemetry.PrivateContext(a.ctx, ctx)
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		result.code = code
		return result
	}
	if route == nil || route.Family() != r.family || route.CredentialRoute() != a.routeID || a.sink.Identity() != a.sinkID {
		return result
	}
	plain, uses, code := openConsumerValue(ctx, a.session, route, a.selection, a.wrapIndex, a.packetContext)
	result.keyUses, result.code = uses, code
	if code != contract.CryptoSuccess {
		return result
	}
	// Close joins even a sink that failed after accepting a prefix. It must run
	// before clearing the plaintext owner and before releasing the common slot.
	defer func() { a.closeSink(); clear(plain[:cap(plain)]) }()
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		result.code = code
		return result
	}
	if a.sink.Identity() != a.sinkID {
		result.code = contract.CryptoInvalidAdmission
		return result
	}
	result.delivery = consumerDeliveryUnknown
	err := a.sink.Accept(privateCtx, plain)
	a.closeSink()
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		result.code = code
		return result
	}
	if err != nil || a.closeErr != nil {
		result.code = contract.CryptoResponseUnknown
		return result
	}
	result.code, result.delivery = contract.CryptoSuccess, consumerDeliveryComplete
	return result
}

// openConsumerValue is the one private value-authentication path for ordinary
// consumption and reconstruction verify/discard. It returns plaintext only to
// package-private owners, which must clear its complete capacity before exit.
func openConsumerValue(ctx context.Context, session *session, route KeyDecryptor, selected contract.ConsumerSelection, wrapIndex int, packetContext contract.ID) ([]byte, []contract.KeyUseRow, contract.CryptoResultCode) {
	privateCtx := telemetry.PrivateContext(session.ctx, ctx)
	private := route.Decrypt(privateCtx, selected.Binding.Binding, selected.Access.Wraps[wrapIndex].RSACiphertext, contract.ValueMaterialPacketLength)
	if private.Packet != nil {
		defer clear(private.Packet[:cap(private.Packet)])
	}
	var evidence contract.CryptoResponse
	if !appendKeyUses(&evidence, selected.Binding, contract.KeyUseMaterialOpen, private.Uses, 1) {
		return nil, nil, contract.CryptoResponseUnknown
	}
	uses := evidence.KeyUseRows
	if code := sessionCancellation(ctx, session); code != contract.CryptoSuccess {
		return nil, uses, code
	}
	keys, code := privatePacketKeys(private, 1, packetContext, contract.CryptoStoredAuthenticationFailed)
	if code != contract.CryptoSuccess {
		return nil, uses, code
	}
	plain, err := custody.OpenValue(selected.Core, selected.Payload, keys)
	if err != nil {
		return nil, uses, contract.CryptoStoredAuthenticationFailed
	}
	return plain, uses, contract.CryptoSuccess
}

func (r *Runtime) retireConsumer() {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.consumer
	r.mu.Unlock()
	if a != nil {
		r.retireSession(a.session)
	}
}
