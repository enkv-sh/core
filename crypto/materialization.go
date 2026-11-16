package crypto

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// MaterializationCustody owns one complete selected set and its native delivery.
// Close cancels and joins entered work before releasing any private backing.
type MaterializationCustody struct {
	mu           sync.Mutex
	route        KeyDecryptor
	target       *MaterializationFileTarget
	admission    contract.MaterializationAdmission
	members      []materializationMember
	rawLength    int
	raw          []byte
	converted    [][]byte
	deadline     time.Time
	originalDone <-chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	work         sync.WaitGroup
	used, closed bool
}

type materializationMember struct {
	rawLength     int
	wrapIndex     int
	packetContext contract.ID
}

// NewMaterializationCustody is called by the trusted installed factory after
// Core authenticates selection. Descriptive admission fields do not authenticate
// themselves. The factory separately checks its captured source/public pins and
// constructs the exact Recipient route and native target, outside request data.
func NewMaterializationCustody(ctx context.Context, route KeyDecryptor, admission contract.MaterializationAdmission, target *MaterializationFileTarget) (*MaterializationCustody, error) {
	invalid := contract.MaterializationAdmissionError{Code: contract.CryptoInvalidAdmission}
	if ctx == nil || ctx.Done() == nil || target == nil {
		return nil, invalid
	}
	deadline, finite := ctx.Deadline()
	if !finite || deadline != admission.ExpiresAt || !target.matches(admission.Target) {
		return nil, invalid
	}
	if !time.Now().Before(deadline) {
		return nil, contract.MaterializationAdmissionError{Code: contract.CryptoExpired}
	}
	if ctx.Err() != nil {
		return nil, contract.MaterializationAdmissionError{Code: contract.CryptoCancelled}
	}
	if !validDeadline(deadline) {
		return nil, invalid
	}
	members, rawLength, code := checkMaterializationAdmission(route, admission)
	if code != contract.CryptoSuccess {
		return nil, contract.MaterializationAdmissionError{Code: code}
	}
	owned, err := ownMaterializationAdmission(admission)
	if err != nil {
		return nil, invalid
	}
	private, cancel := context.WithCancel(ctx)
	c := &MaterializationCustody{route: route, target: target, admission: owned, members: members, rawLength: rawLength,
		deadline: deadline, originalDone: ctx.Done(), ctx: private, cancel: cancel, done: make(chan struct{})}
	go c.observe()
	return c, nil
}

func checkMaterializationAdmission(route KeyDecryptor, a contract.MaterializationAdmission) ([]materializationMember, int, contract.CryptoResultCode) {
	invalid := contract.CryptoInvalidAdmission
	for _, id := range []contract.ID{a.RequestID, a.SessionID, a.DomainID, a.HEADDigest, a.HEADRevision, a.SnapshotID, a.AccessRoot, a.CredentialRoute, a.PublicBasisDigest} {
		if id.IsZero() {
			return nil, 0, invalid
		}
	}
	if len(a.Entries) > contract.CryptoMaxValueEntries {
		return nil, 0, contract.CryptoCapacityExceeded
	}
	if a.Purpose != contract.MaterializationOperation || len(a.Entries) == 0 || !a.SourcePins.Valid() || !a.Store.Valid() || !a.Target.Valid() ||
		!a.Root.ValidFor(contract.CanonicalSchema) || a.Root.Kind != contract.RootKind || a.Root.Domain != a.DomainID || a.Root.Object != a.SnapshotID ||
		!a.HEADToken.Valid() || a.HEADToken.Family != a.Store.Family || a.Recipient.SubjectKind != contract.OrdinaryWrapSubject || a.Recipient.SubjectID.IsZero() ||
		a.Recipient.Binding.Provider != a.Store.Family {
		return nil, 0, invalid
	}
	if _, err := contract.BindingTableLength([]contract.BindingTableRow{a.Recipient}); err != nil {
		return nil, 0, invalid
	}
	members := make([]materializationMember, len(a.Entries))
	var slots [contract.CryptoMaxValueEntries]bool
	rawLength, contentLength, deliveredLength, memberships, secrets := 0, 0, 0, 0, 0
	for i, entry := range a.Entries {
		if entry.Name != entry.Entry.Name || entry.Slot >= contract.CryptoMaxValueEntries || slots[entry.Slot] || i > 0 && a.Entries[i-1].Name >= entry.Name {
			return nil, 0, invalid
		}
		if _, err := contract.ValueEntryLength(entry.Entry); err != nil {
			if errors.Is(err, contract.ErrRecordCapacity) {
				return nil, 0, contract.CryptoCapacityExceeded
			}
			return nil, 0, invalid
		}
		if !slices.Contains(entry.Entry.Recipients, a.Recipient.SubjectID) {
			return nil, 0, invalid
		}
		memberships += len(entry.Entry.Recipients)
		if memberships > contract.CryptoMaxMemberships {
			return nil, 0, contract.CryptoCapacityExceeded
		}
		length := int(entry.Entry.RetainedLength)
		switch entry.Entry.ConfidentialityClass {
		case contract.Plain:
			if entry.Secret != nil {
				return nil, 0, invalid
			}
		case contract.Secret:
			if entry.Secret == nil {
				return nil, 0, invalid
			}
			s := entry.Secret
			index, packet, ok := checkConsumerSelection(*s, a.Store.Family)
			digest, err := contract.PublicValueEntryDigest(a.DomainID, entry.Slot, entry.Entry)
			if !ok || err != nil || digest != s.EntryDigest || s.Slot != entry.Slot || s.DomainID != a.DomainID || s.SnapshotID != a.SnapshotID ||
				s.HEADDigest != a.HEADDigest || s.HEADRevision != a.HEADRevision || s.AccessRoot != a.AccessRoot || s.Root != a.Root || s.HEADToken != a.HEADToken ||
				s.Binding.SubjectKind != a.Recipient.SubjectKind || s.Binding.SubjectID != a.Recipient.SubjectID || !sameApplyBinding(s.Binding.Binding, a.Recipient.Binding) {
				return nil, 0, invalid
			}
			length = int(s.Core.RetainedLength)
			members[i].wrapIndex, members[i].packetContext = index, packet
			secrets++
		default:
			return nil, 0, invalid
		}
		delivered, err := contract.DeliveredValueLength(entry.Entry.OutputEncoding, entry.Entry.ContentLength)
		if err != nil {
			return nil, 0, invalid
		}
		contentLength += int(entry.Entry.ContentLength)
		deliveredLength += int(delivered)
		if contentLength > contract.CryptoMaxRawSet || deliveredLength > contract.CryptoMaxRetainedSet || length > contract.CryptoMaxRetainedValue || length > contract.CryptoMaxRetainedSet-rawLength {
			return nil, 0, contract.CryptoCapacityExceeded
		}
		members[i].rawLength = length
		rawLength += length
		slots[entry.Slot] = true
	}
	if secrets == 0 {
		if route != nil {
			return nil, 0, invalid
		}
	} else if route == nil || a.CredentialRoute.IsZero() || route.Family() != a.Store.Family || route.CredentialRoute() != a.CredentialRoute {
		return nil, 0, invalid
	}
	return members, rawLength, contract.CryptoSuccess
}

func ownMaterializationAdmission(a contract.MaterializationAdmission) (contract.MaterializationAdmission, error) {
	a.Store.Prefix, a.Store.HeadKey = strings.Clone(a.Store.Prefix), strings.Clone(a.Store.HeadKey)
	a.HEADToken.Value = strings.Clone(a.HEADToken.Value)
	a.Recipient.Binding.SPKI = materializationOwnedBytes(a.Recipient.Binding.SPKI)
	a.Recipient.Binding.KeySelector = strings.Clone(a.Recipient.Binding.KeySelector)
	a.Target.Path = strings.Clone(a.Target.Path)
	entries := make([]contract.MaterializationEntry, len(a.Entries))
	copy(entries, a.Entries)
	a.Entries = entries
	for i := range a.Entries {
		e := &a.Entries[i]
		e.Name = strings.Clone(e.Name)
		e.Entry.Name = e.Name
		recipients := make([]contract.ID, len(e.Entry.Recipients))
		copy(recipients, e.Entry.Recipients)
		e.Entry.Recipients = recipients
		e.Entry.ValueBytes = materializationOwnedBytes(e.Entry.ValueBytes)
		if e.Secret == nil {
			continue
		}
		s := *e.Secret
		s.Entry, s.Binding, s.HEADToken, s.Core.Name = e.Entry, a.Recipient, a.HEADToken, e.Name
		payload, err := contract.InspectCanonicalPayload(e.Entry.ValueBytes)
		if err != nil {
			for _, owned := range a.Entries[:i+1] {
				clear(owned.Entry.ValueBytes[:cap(owned.Entry.ValueBytes)])
			}
			return contract.MaterializationAdmission{}, err
		}
		s.Payload = contract.CanonicalPayload(payload)
		wraps := make([]contract.WrapRow, len(s.Access.Wraps))
		copy(wraps, s.Access.Wraps)
		s.Access.Wraps = wraps
		for j := range s.Access.Wraps {
			s.Access.Wraps[j].RSACiphertext = materializationOwnedBytes(s.Access.Wraps[j].RSACiphertext)
		}
		e.Secret = &s
	}
	return a, nil
}

func materializationOwnedBytes(raw []byte) []byte {
	owned := make([]byte, len(raw))
	copy(owned, raw)
	return owned
}

func materializationBeforeStaging(state contract.MaterializationStateResult, stage contract.MaterializationStage, reason contract.MaterializationFailureReason) contract.MaterializationCompletion {
	facts := contract.InitialMaterializationFacts()
	facts.Failure = &contract.MaterializationFailure{Stage: stage, Reason: reason}
	return contract.MaterializationCompletion{StateResult: state, Facts: facts}
}

func materializationPrivateFailure(code contract.CryptoResultCode, stage contract.MaterializationStage) contract.MaterializationCompletion {
	state, reason := contract.MaterializationUnavailable, contract.MaterializationPrivateRouteUnavailable
	switch code {
	case contract.CryptoInvalidAdmission, contract.CryptoAlreadyUsed:
		state, reason = contract.MaterializationRefused, contract.MaterializationInvalidAdmission
	case contract.CryptoStoredAuthenticationFailed, contract.CryptoSourceAuthenticationFailed:
		state, reason = contract.MaterializationPositiveDefect, contract.MaterializationIntegrityContradiction
	case contract.CryptoCancelled:
		reason = contract.MaterializationCanceled
	case contract.CryptoExpired:
		reason = contract.MaterializationDeadlineExceeded
	case contract.CryptoCapacityExceeded:
		state, reason = contract.MaterializationRefused, contract.MaterializationCapacityLimit
	case contract.CryptoInvalidInput:
		state, reason = contract.MaterializationRefused, contract.MaterializationUnrepresentableValue
	}
	return materializationBeforeStaging(state, stage, reason)
}

// Materialize authenticates and validates every member before native staging.
// It returns only after native work and private disposal have positively joined.
func (c *MaterializationCustody) Materialize(ctx context.Context) (out contract.MaterializationCompletion) {
	code := contract.CryptoInvalidAdmission
	out = materializationPrivateFailure(code, contract.MaterializationAdmissionStage)
	if c == nil || c.ctx == nil || ctx == nil {
		return out
	}
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoMaterialize)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	defer func() { finishCryptoCall(call, code) }()
	deadline, finite := ctx.Deadline()
	callerDone := ctx.Done()
	c.mu.Lock()
	if c.used {
		c.mu.Unlock()
		code = contract.CryptoAlreadyUsed
		return materializationPrivateFailure(code, contract.MaterializationAdmissionStage)
	}
	if c.closed {
		c.mu.Unlock()
		code = c.cancellationCode()
		return materializationPrivateFailure(code, contract.MaterializationAdmissionStage)
	}
	c.used = true
	c.work.Add(1)
	c.mu.Unlock()
	defer func() { c.cancel(); c.work.Done(); <-c.done }()
	if !finite || deadline != c.deadline || callerDone != c.originalDone {
		return out
	}
	if code = c.cancellationCode(); code != contract.CryptoSuccess {
		return materializationPrivateFailure(code, contract.MaterializationAuthentication)
	}
	if !c.target.matches(c.admission.Target) || !c.routeMatches() {
		code = contract.CryptoInvalidAdmission
		return materializationPrivateFailure(code, contract.MaterializationAdmissionStage)
	}
	private := telemetry.PrivateContext(c.ctx, telemetry.CallContext(ctx, call))
	session := &session{id: c.admission.SessionID, ctx: c.ctx, deadline: c.deadline}
	c.raw = make([]byte, c.rawLength)
	values := make([]materializationValue, len(c.admission.Entries))
	offset := 0
	for i, entry := range c.admission.Entries {
		if code = c.cancellationCode(); code != contract.CryptoSuccess {
			return materializationPrivateFailure(code, contract.MaterializationAuthentication)
		}
		member := c.members[i]
		raw := c.raw[offset : offset+member.rawLength : offset+member.rawLength]
		if entry.Secret == nil {
			copy(raw, entry.Entry.ValueBytes)
		} else {
			if !c.routeMatches() {
				code = contract.CryptoInvalidAdmission
				return materializationPrivateFailure(code, contract.MaterializationAuthentication)
			}
			plain, _, opened := openConsumerValue(private, session, c.route, *entry.Secret, member.wrapIndex, member.packetContext)
			if opened == contract.CryptoSuccess && len(plain) != len(raw) {
				opened = contract.CryptoStoredAuthenticationFailed
			}
			if opened == contract.CryptoSuccess {
				copy(raw, plain)
			}
			clear(plain[:cap(plain)])
			if code = opened; code != contract.CryptoSuccess {
				return materializationPrivateFailure(code, contract.MaterializationAuthentication)
			}
		}
		delivered := raw
		if entry.Entry.InputEncoding != entry.Entry.OutputEncoding {
			var err error
			delivered, err = encodeDeliveryValue(entry.Entry.InputEncoding, entry.Entry.OutputEncoding, entry.Entry.ContentLength, raw)
			if err != nil {
				return materializationPrivateFailure(contract.CryptoInvalidInput, contract.MaterializationEncoding)
			}
			c.converted = append(c.converted, delivered)
		}
		values[i] = materializationValue{name: entry.Name, raw: delivered}
		offset += len(raw)
	}
	if code = c.cancellationCode(); code != contract.CryptoSuccess {
		return materializationPrivateFailure(code, contract.MaterializationEncoding)
	}
	env, err := prepareMaterializationEnv(values)
	if code = c.cancellationCode(); code != contract.CryptoSuccess {
		return materializationPrivateFailure(code, contract.MaterializationEncoding)
	}
	if err != nil {
		code = contract.CryptoInvalidInput
		if errors.Is(err, errMaterializationCapacity) {
			code = contract.CryptoCapacityExceeded
		}
		return materializationPrivateFailure(code, contract.MaterializationEncoding)
	}
	if !c.target.matches(c.admission.Target) || !c.routeMatches() {
		code = contract.CryptoInvalidAdmission
		return materializationPrivateFailure(code, contract.MaterializationAdmissionStage)
	}
	out = c.target.install(private, env, call)
	code = materializationCompletionCode(out)
	return out
}

func (c *MaterializationCustody) routeMatches() bool {
	return c.route == nil ||
		c.route.Family() == c.admission.Store.Family && c.route.CredentialRoute() == c.admission.CredentialRoute
}

func materializationCompletionCode(out contract.MaterializationCompletion) contract.CryptoResultCode {
	if out.StateResult == contract.MaterializationSuccess {
		return contract.CryptoSuccess
	}
	if out.StateResult == contract.MaterializationPositiveDefect {
		return contract.CryptoStoredAuthenticationFailed
	}
	if out.Facts.Failure != nil {
		switch out.Facts.Failure.Reason {
		case contract.MaterializationCanceled:
			return contract.CryptoCancelled
		case contract.MaterializationDeadlineExceeded:
			return contract.CryptoExpired
		case contract.MaterializationIntegrityContradiction:
			return contract.CryptoStoredAuthenticationFailed
		case contract.MaterializationInvalidAdmission, contract.MaterializationInvalidTarget:
			return contract.CryptoInvalidAdmission
		}
	}
	return contract.CryptoResponseUnknown
}

func (c *MaterializationCustody) cancellationCode() contract.CryptoResultCode {
	if !time.Now().Before(c.deadline) {
		return contract.CryptoExpired
	}
	if c.ctx.Err() != nil {
		return contract.CryptoCancelled
	}
	return contract.CryptoSuccess
}

func (c *MaterializationCustody) observe() {
	<-c.ctx.Done()
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.work.Wait()
	c.mu.Lock()
	clear(c.raw[:cap(c.raw)])
	for _, converted := range c.converted {
		clear(converted[:cap(converted)])
	}
	c.converted = nil
	clear(c.admission.Recipient.Binding.SPKI[:cap(c.admission.Recipient.Binding.SPKI)])
	for _, entry := range c.admission.Entries {
		clear(entry.Entry.ValueBytes[:cap(entry.Entry.ValueBytes)])
		if entry.Secret != nil {
			for _, wrap := range entry.Secret.Access.Wraps {
				clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
			}
		}
	}
	c.raw, c.members, c.route, c.target = nil, nil, nil, nil
	c.admission = contract.MaterializationAdmission{}
	c.mu.Unlock()
	close(c.done)
}

func (c *MaterializationCustody) Close() {
	if c != nil && c.cancel != nil {
		c.cancel()
		<-c.done
	}
}
