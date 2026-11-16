package crypto

import (
	"context"
	"crypto/rand"
	"slices"
	"strings"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

const reconstructionVerifyPurposeLabel = "ENKV/CRYPTO/RECONSTRUCTION-VERIFY-DISCARD/v1\x00"

var reconstructionVerifyPurpose = contract.Hash([]byte(reconstructionVerifyPurposeLabel))

// ReconstructionVerifier belongs to the installed reconstruction composition.
// Its public pins are descriptive data, not proof of a complete selection.
// The composition must construct it only after Core's private complete reader
// has issued that selection. It has no sink, signing, or output-send method.
type ReconstructionVerifier struct {
	runtime            *Runtime
	session            *session
	runtimeID, routeID contract.ID
	purpose            contract.ID
	pins               contract.ReconstructionVerificationPins
	active, closed     bool // guarded by runtime.mu
}

// NewReconstructionVerifier installs one private, purpose-specific session.
// The caller is the trusted compiled reconstruction composition. The deadline
// is the original finite command deadline and cannot be extended by Verify.
func NewReconstructionVerifier(r *Runtime, routeID contract.ID, pins contract.ReconstructionVerificationPins, deadline time.Time) (*ReconstructionVerifier, error) {
	if r == nil || routeID.IsZero() || !validDeadline(deadline) || !reconstructionPinsValid(pins, r.family) {
		return nil, ErrAdmission
	}
	var id contract.ID
	if _, err := rand.Read(id[:]); err != nil {
		return nil, ErrAdmission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	route := r.routes[routeID]
	if r.closed || r.slot != nil || route == nil || route.Family() != r.family || route.CredentialRoute() != routeID {
		return nil, ErrAdmission
	}
	pins.HEADToken.Value = strings.Clone(pins.HEADToken.Value)
	pins.AuthorityBinding.Binding.KeySelector = strings.Clone(pins.AuthorityBinding.Binding.KeySelector)
	pins.AuthorityBinding.Binding.SPKI = slices.Clone(pins.AuthorityBinding.Binding.SPKI)
	v := &ReconstructionVerifier{runtime: r, runtimeID: r.id, routeID: routeID, purpose: reconstructionVerifyPurpose, pins: pins}
	v.session = r.installSession(id, deadline, nil, func() {
		v.pins = contract.ReconstructionVerificationPins{}
		v.routeID, v.runtimeID, v.purpose = contract.ID{}, contract.ID{}, contract.ID{}
	})
	if v.session == nil {
		return nil, ErrAdmission
	}
	return v, nil
}

func reconstructionPinsValid(p contract.ReconstructionVerificationPins, family contract.Family) bool {
	for _, id := range []contract.ID{p.DomainID, p.SnapshotID, p.HEADDigest, p.HEADRevision,
		p.AccessRoot, p.AuthorityRecipientID} {
		if id.IsZero() {
			return false
		}
	}
	if !p.Root.ValidFor(contract.CanonicalSchema) || p.Root.Kind != contract.RootKind || p.Root.Domain != p.DomainID ||
		p.Root.Object != p.SnapshotID || !p.HEADToken.Valid() || p.HEADToken.Family != family ||
		p.AuthorityBinding.SubjectKind != contract.OrdinaryWrapSubject || p.AuthorityBinding.SubjectID != p.AuthorityRecipientID ||
		p.AuthorityBinding.Binding.Provider != family {
		return false
	}
	_, err := contract.BindingTableLength([]contract.BindingTableRow{p.AuthorityBinding})
	return err == nil
}

// Verify authenticates one exact current secret and discards its plaintext
// before return. It returns only a typed status. Every unsuccessful call ends
// this session, so a later row cannot turn an incomplete batch into success.
func (v *ReconstructionVerifier) Verify(ctx context.Context, selected contract.ConsumerSelection) contract.CryptoResultCode {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoReconstructionVerify)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	code := v.verifySelected(ctx, selected)
	finishCryptoCall(call, code)
	return code
}

func (v *ReconstructionVerifier) verifySelected(ctx context.Context, selected contract.ConsumerSelection) (code contract.CryptoResultCode) {
	if v == nil || v.runtime == nil || v.session == nil {
		return contract.CryptoInvalidAdmission
	}
	r, a := v.runtime, v.session
	// Caller Context methods can invoke arbitrary code. Never call them while
	// holding Runtime.mu.
	if ctx == nil {
		v.end()
		return contract.CryptoInvalidAdmission
	}
	if ctx.Err() != nil {
		v.end()
		return contract.CryptoCancelled
	}
	callerDone := ctx.Done()
	r.mu.Lock()
	if r.closed || r.slot != a || v.closed {
		r.mu.Unlock()
		return contract.CryptoInvalidAdmission
	}
	if v.active {
		v.closed, a.terminal = true, true
		a.cancel()
		r.mu.Unlock()
		return contract.CryptoAlreadyUsed
	}
	if !time.Now().Before(a.deadline) {
		v.closed, a.terminal = true, true
		a.cancel()
		r.mu.Unlock()
		return contract.CryptoExpired
	}
	if v.runtimeID != r.id || v.purpose != reconstructionVerifyPurpose {
		v.closed, a.terminal = true, true
		a.cancel()
		r.mu.Unlock()
		return contract.CryptoInvalidAdmission
	}
	if a.ctx.Err() != nil {
		v.closed, a.terminal = true, true
		a.cancel()
		r.mu.Unlock()
		return contract.CryptoCancelled
	}
	v.active = true
	a.work.Add(1)
	route := r.routes[v.routeID]
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		v.active = false
		if code == contract.CryptoSuccess {
			code = sessionCancellationObserved(callerDone, a)
			if code == contract.CryptoSuccess && v.closed {
				code = contract.CryptoCancelled
			}
		}
		if code != contract.CryptoSuccess {
			v.closed, a.terminal = true, true
			a.cancel()
		}
		r.mu.Unlock()
		a.work.Done()
	}()
	cancelJoined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		a.cancel()
		close(cancelJoined)
	})
	defer func() {
		if !stop() {
			<-cancelJoined
		}
	}()
	if route == nil || route.Family() != r.family || route.CredentialRoute() != v.routeID ||
		!reconstructionSelectionMatches(v.pins, selected) {
		return contract.CryptoInvalidAdmission
	}
	index, packetContext, ok := checkConsumerSelection(selected, r.family)
	if !ok {
		return contract.CryptoInvalidAdmission
	}
	if code := sessionCancellation(ctx, a); code != contract.CryptoSuccess {
		return code
	}
	plain, _, code := openConsumerValue(ctx, a, route, selected, index, packetContext)
	if plain != nil {
		defer clear(plain[:cap(plain)])
	}
	if code != contract.CryptoSuccess {
		return code
	}
	return sessionCancellation(ctx, a)
}

func reconstructionSelectionMatches(p contract.ReconstructionVerificationPins, s contract.ConsumerSelection) bool {
	return s.DomainID == p.DomainID && s.SnapshotID == p.SnapshotID && s.HEADDigest == p.HEADDigest && s.HEADRevision == p.HEADRevision &&
		s.AccessRoot == p.AccessRoot && s.Root == p.Root && s.HEADToken == p.HEADToken &&
		s.Binding.SubjectKind == contract.OrdinaryWrapSubject && s.Binding.SubjectID == p.AuthorityRecipientID &&
		sameAccessBinding(s.Binding, p.AuthorityBinding) && slices.Contains(s.Entry.Recipients, p.AuthorityRecipientID)
}

func (v *ReconstructionVerifier) end() {
	if v == nil || v.runtime == nil || v.session == nil {
		return
	}
	v.runtime.mu.Lock()
	v.closed, v.session.terminal = true, true
	v.session.cancel()
	v.runtime.mu.Unlock()
}

// Close cancels and positively joins all private work. It is safe to repeat.
func (v *ReconstructionVerifier) Close() {
	if v == nil || v.runtime == nil || v.session == nil {
		return
	}
	v.end()
	v.runtime.retireSession(v.session)
}
