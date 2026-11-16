package crypto

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

// PlanningCustody owns one fixed read admission. It has no mutation runtime,
// public qualification route, or authority to prepare a value.
type PlanningCustody struct {
	mu           sync.Mutex
	route        KeyDecryptor
	admission    contract.PlanningAdmission
	targets      []planningTarget
	deadline     time.Time
	originalDone <-chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	work         sync.WaitGroup
	used, closed bool
	displayUsed  bool
	result       contract.PlanningCheckResult
}

type planningTarget struct {
	core          contract.SealedInputCore
	wrapIndex     int
	packetContext contract.ID
}

func NewPlanningCustody(ctx context.Context, route KeyDecryptor, admission contract.PlanningAdmission) (*PlanningCustody, error) {
	if ctx == nil || ctx.Done() == nil || ctx.Err() != nil || route == nil {
		return nil, ErrAdmission
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validDeadline(deadline) {
		return nil, ErrAdmission
	}
	admission.Options.SelectedNames = slices.Clone(admission.Options.SelectedNames)
	for i := range admission.Options.SelectedNames {
		admission.Options.SelectedNames[i] = strings.Clone(admission.Options.SelectedNames[i])
	}
	targets, ok := checkPlanningAdmission(route, admission)
	if !ok {
		return nil, ErrAdmission
	}
	owned, err := ownPlanningAdmission(admission)
	if err != nil {
		return nil, ErrAdmission
	}
	for i := range targets {
		targets[i].core.Name = strings.Clone(targets[i].core.Name)
	}
	private, cancel := context.WithCancel(ctx)
	c := &PlanningCustody{route: route, admission: owned, targets: targets, deadline: deadline, originalDone: ctx.Done(), ctx: private, cancel: cancel, done: make(chan struct{})}
	go c.observe()
	return c, nil
}

func checkPlanningAdmission(route KeyDecryptor, a contract.PlanningAdmission) ([]planningTarget, bool) {
	for _, id := range []contract.ID{a.RequestID, a.SessionID, a.DomainID, a.HEADDigest, a.HEADRevision, a.SnapshotID, a.AccessRoot, a.CredentialRoute} {
		if id.IsZero() {
			return nil, false
		}
	}
	if !a.Sources.Trusted.Valid() || !a.Sources.Proposed.Valid() || !a.Options.Valid() || !planningPurposeValid(a) ||
		len(a.Targets) > contract.CryptoMaxValueEntries || a.Control.DomainID != a.DomainID || a.Control.CompatibilityID != contract.CompatibilityID() ||
		a.Control.CryptoSupportID != contract.CryptoSupportID() || route.Family() != a.Control.Provider || route.CredentialRoute() != a.CredentialRoute ||
		!a.Root.ValidFor(contract.CanonicalSchema) || a.Root.Kind != contract.RootKind || a.Root.Domain != a.DomainID || a.Root.Object != a.SnapshotID ||
		!a.HEADToken.Valid() || a.HEADToken.Family != a.Control.Provider || a.Authority.SubjectKind != contract.OrdinaryWrapSubject ||
		a.Authority.SubjectID != a.Control.AuthorityRecipientID || !sameApplyBinding(a.Authority.Binding, a.Control.AuthorityKMSBinding) {
		return nil, false
	}
	if _, err := contract.ControlCoreLength(a.Control); err != nil {
		return nil, false
	}
	targets := make([]planningTarget, len(a.Targets))
	var proposedRaw, currentRaw uint64
	var memberships, currentMemberships int
	slots := make(map[uint16]bool)
	sources := make(map[contract.ID]bool)
	for i, target := range a.Targets {
		input := target.Input
		if len(input.Name) > contract.CryptoMaxName || !utf8.ValidString(input.Name) || i > 0 && a.Targets[i-1].Input.Name >= input.Name ||
			!planningRecipients(target.ProposedRecipients, a.Authority.SubjectID) {
			return nil, false
		}
		memberships += len(target.ProposedRecipients)
		if memberships > contract.CryptoMaxMemberships {
			return nil, false
		}
		if !target.CurrentPresent {
			if target.Current != nil || target.CurrentValueSource != 0 || target.CurrentConfidentialityClass != 0 {
				return nil, false
			}
		} else {
			if target.CurrentValueSource != contract.Supplied && target.CurrentValueSource != contract.Generated || target.CurrentConfidentialityClass != contract.Plain && target.CurrentConfidentialityClass != contract.Secret {
				return nil, false
			}
			comparable := target.CurrentValueSource == contract.Supplied && target.CurrentConfidentialityClass == contract.Secret
			if comparable != (target.Current != nil) {
				return nil, false
			}
		}
		if target.Current != nil {
			s := *target.Current
			index, packet, ok := checkConsumerSelection(s, a.Control.Provider)
			if !ok || s.Entry.Name != input.Name || s.Entry.ValueSource != contract.Supplied || s.DomainID != a.DomainID || s.HEADDigest != a.HEADDigest ||
				s.HEADRevision != a.HEADRevision || s.HEADToken != a.HEADToken || s.Root != a.Root || s.SnapshotID != a.SnapshotID || s.AccessRoot != a.AccessRoot ||
				s.Binding.SubjectKind != a.Authority.SubjectKind || s.Binding.SubjectID != a.Authority.SubjectID || !sameApplyBinding(s.Binding.Binding, a.Authority.Binding) ||
				s.Slot >= contract.CryptoMaxValueEntries || slots[s.Slot] || !planningRecoveryWrap(s, a.Control.Recovery) {
				return nil, false
			}
			slots[s.Slot] = true
			currentRaw += uint64(s.Core.ContentLength)
			currentMemberships += len(s.Entry.Recipients)
			if currentRaw > contract.CryptoMaxRawSet || currentMemberships > contract.CryptoMaxMemberships {
				return nil, false
			}
			targets[i].wrapIndex, targets[i].packetContext = index, packet
		}
		switch input.Form {
		case contract.PlanningSealed:
			if len(input.SealedInput) > contract.CryptoMaxSealedInputLength || input.Retained != (contract.RetainedSecretInput{}) {
				return nil, false
			}
			view, err := contract.InspectSealedInputEnvelope(input.SealedInput)
			if err != nil || string(view.Core.Name) != input.Name || view.Core.DomainID != a.DomainID || view.Core.FileIdentity != a.Sources.Proposed.FileIdentity ||
				view.Core.CompatibilityID != a.Control.CompatibilityID || view.Core.CryptoSupportID != a.Control.CryptoSupportID || sources[view.Core.SourceID] {
				return nil, false
			}
			core, err := view.Core.Own()
			if err != nil {
				return nil, false
			}
			wrap, err := custody.SealedInputWrapCore(core, a.Authority)
			if err != nil || !applyWrapMatches(contract.WrapRow(view.AuthorityWrap), wrap) {
				return nil, false
			}
			targets[i].core = core
			sources[core.SourceID] = true
			proposedRaw += uint64(core.ContentLength)
		case contract.PlanningRetained:
			if len(input.SealedInput) != 0 || input.Retained.Incarnation.IsZero() || input.Retained.Material.IsZero() || target.Current == nil ||
				input.Retained.Incarnation != target.Current.Entry.Incarnation || input.Retained.Material != target.Current.Entry.ValueState {
				return nil, false
			}
			proposedRaw += uint64(target.Current.Core.ContentLength)
		default:
			return nil, false
		}
		if proposedRaw > contract.CryptoMaxRawSet {
			return nil, false
		}
	}
	for _, name := range a.Options.SelectedNames {
		if !slices.ContainsFunc(a.Targets, func(t contract.PlanningTarget) bool { return t.Input.Name == name }) {
			return nil, false
		}
	}
	return targets, true
}

func planningRecipients(ids []contract.ID, authority contract.ID) bool {
	if len(ids) == 0 || len(ids) > contract.CryptoMaxValueEntryRecipients || !slices.Contains(ids, authority) {
		return false
	}
	for i, id := range ids {
		if id.IsZero() || i > 0 && bytes.Compare(ids[i-1][:], id[:]) >= 0 {
			return false
		}
	}
	return true
}

func planningRecoveryWrap(s contract.ConsumerSelection, recovery *contract.RecoveryBindings) bool {
	found := false
	for _, row := range s.Access.Wraps {
		if row.SubjectKind != contract.RecoveryWrapSubject {
			continue
		}
		if recovery == nil || found {
			return false
		}
		binding := contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: recovery.RoleID, Binding: recovery.KMS}
		wrap, err := custody.ValueWrapCore(s.Core, binding)
		if err != nil || !applyWrapMatches(row, wrap) {
			return false
		}
		found = true
	}
	return found == (recovery != nil)
}

func ownPlanningAdmission(a contract.PlanningAdmission) (contract.PlanningAdmission, error) {
	control, err := contract.EncodeControlCore(a.Control)
	if err != nil {
		return contract.PlanningAdmission{}, err
	}
	defer clear(control[:cap(control)])
	a.Control, err = contract.DecodeControlCore(control)
	if err != nil {
		return contract.PlanningAdmission{}, err
	}
	a.Authority.Binding.SPKI = slices.Clone(a.Authority.Binding.SPKI)
	a.Authority.Binding.KeySelector = strings.Clone(a.Authority.Binding.KeySelector)
	a.HEADToken.Value = strings.Clone(a.HEADToken.Value)
	a.Options.SelectedNames = slices.Clone(a.Options.SelectedNames)
	for i := range a.Options.SelectedNames {
		a.Options.SelectedNames[i] = strings.Clone(a.Options.SelectedNames[i])
	}
	if a.Retirement != nil {
		retired := *a.Retirement
		a.Retirement = &retired
	}
	a.Targets = slices.Clone(a.Targets)
	for i := range a.Targets {
		t := &a.Targets[i]
		t.Input.Name = strings.Clone(t.Input.Name)
		t.Input.SealedInput = slices.Clone(t.Input.SealedInput)
		t.ProposedRecipients = slices.Clone(t.ProposedRecipients)
		if t.Current == nil {
			continue
		}
		s := *t.Current
		s.Entry.Name, s.Core.Name = strings.Clone(s.Entry.Name), strings.Clone(s.Core.Name)
		s.Entry.Recipients = slices.Clone(s.Entry.Recipients)
		s.Entry.ValueBytes = slices.Clone(s.Entry.ValueBytes)
		s.Payload.Ciphertext = slices.Clone(s.Payload.Ciphertext)
		s.Access.Wraps = slices.Clone(s.Access.Wraps)
		for j := range s.Access.Wraps {
			s.Access.Wraps[j].RSACiphertext = slices.Clone(s.Access.Wraps[j].RSACiphertext)
		}
		s.Binding.Binding.SPKI = slices.Clone(s.Binding.Binding.SPKI)
		s.Binding.Binding.KeySelector = strings.Clone(s.Binding.Binding.KeySelector)
		s.HEADToken.Value = strings.Clone(s.HEADToken.Value)
		t.Current = &s
	}
	return a, nil
}

func (c *PlanningCustody) Check(ctx context.Context) (result contract.PlanningCheckResult) {
	result.Code = contract.CryptoInvalidAdmission
	if c == nil || ctx == nil {
		return result
	}
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoPlanning)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	defer func() { finishCryptoCall(call, result.Code) }()
	c.mu.Lock()
	if c.closed {
		result.Code = c.cancellationCode()
		c.mu.Unlock()
		return result
	}
	if c.used {
		c.mu.Unlock()
		result.Code = contract.CryptoAlreadyUsed
		return result
	}
	c.used = true
	c.work.Add(1)
	for _, target := range c.admission.Targets {
		result.Rows = append(result.Rows, contract.PlanningRelation{Name: target.Input.Name, Form: target.Input.Form, Relation: contract.PlanningUnchecked})
	}
	c.mu.Unlock()
	defer c.work.Done()
	deadline, finite := ctx.Deadline()
	if !finite || deadline != c.deadline || ctx.Done() != c.originalDone {
		return result
	}
	private := telemetry.PrivateContext(c.ctx, telemetry.CallContext(ctx, call))
	for i := range c.admission.Targets {
		if code := c.cancellationCode(); code != contract.CryptoSuccess {
			result.Code = code
			return result
		}
		if c.route.Family() != c.admission.Control.Provider || c.route.CredentialRoute() != c.admission.CredentialRoute {
			result.Code = contract.CryptoInvalidAdmission
			result.Rows[i].Relation, result.Rows[i].Code = contract.PlanningFailed, result.Code
			return result
		}
		relation, code := c.checkTarget(private, i)
		if c.admission.Options.Purpose == contract.PlanningRetirementFeasibility {
			relation, code = planningRetirementRelation(relation, code)
		}
		if code == contract.CryptoCancelled {
			if cancelled := c.cancellationCode(); cancelled != contract.CryptoSuccess {
				code = cancelled
			}
			result.Code = code
			return result
		}
		result.Rows[i].Relation, result.Rows[i].Code = relation, code
		if code != contract.CryptoSuccess {
			result.Code = code
			return result
		}
	}
	c.mu.Lock()
	if code := c.cancellationCode(); code != contract.CryptoSuccess {
		c.mu.Unlock()
		result.Code = code
		return result
	}
	result.Code, result.Complete = contract.CryptoSuccess, true
	c.result = result
	c.result.Rows = slices.Clone(result.Rows)
	c.mu.Unlock()
	return result
}

func (c *PlanningCustody) checkTarget(ctx context.Context, index int) (contract.PlanningPrivateRelation, contract.CryptoResultCode) {
	target, admitted := c.admission.Targets[index], c.targets[index]
	var proposed []byte
	if target.Input.Form == contract.PlanningSealed {
		view, err := contract.InspectSealedInputEnvelope(target.Input.SealedInput)
		if err != nil {
			return contract.PlanningFailed, contract.CryptoSourceAuthenticationFailed
		}
		envelope := contract.SealedInputEnvelope{Core: admitted.core, Nonce: view.Nonce, Ciphertext: view.Ciphertext, AuthorityWrap: contract.WrapRow(view.AuthorityWrap)}
		plain, _, code := authenticatedSealedValue(ctx, c.route, c.admission.Authority, admitted.core, envelope)
		if plain != nil {
			defer clear(plain[:cap(plain)])
		}
		if code != contract.CryptoSuccess {
			return contract.PlanningFailed, code
		}
		proposed = plain
	}
	if target.Current == nil {
		if !target.CurrentPresent {
			return contract.PlanningNew, contract.CryptoSuccess
		}
		return contract.PlanningUnchecked, contract.CryptoSuccess
	}
	s := target.Current
	keys, _, code := authenticatedCurrentKeys(ctx, c.route, c.admission.Authority, s.Access.Wraps[admitted.wrapIndex].RSACiphertext, admitted.packetContext, s.Core, s.Payload)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		return contract.PlanningFailed, code
	}
	if target.Input.Form == contract.PlanningRetained {
		return contract.PlanningEqual, contract.CryptoSuccess
	}
	equal, err := custody.EqualValue(s.Core, s.Payload, keys, proposed)
	if err != nil {
		return contract.PlanningFailed, contract.CryptoStoredAuthenticationFailed
	}
	equal = equal && admitted.core.InputEncoding == s.Core.InputEncoding && admitted.core.ContentLength == s.Core.ContentLength && admitted.core.RetainedLength == s.Core.RetainedLength
	if equal {
		return contract.PlanningEqual, contract.CryptoSuccess
	}
	return contract.PlanningChanged, contract.CryptoSuccess
}

func (c *PlanningCustody) cancellationCode() contract.CryptoResultCode {
	if !time.Now().Before(c.deadline) {
		return contract.CryptoExpired
	}
	if c.ctx.Err() != nil {
		return contract.CryptoCancelled
	}
	return contract.CryptoSuccess
}

func (c *PlanningCustody) observe() {
	<-c.ctx.Done()
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.work.Wait()
	c.mu.Lock()
	for i := range c.admission.Targets {
		t := &c.admission.Targets[i]
		clear(t.Input.SealedInput[:cap(t.Input.SealedInput)])
		if s := t.Current; s != nil {
			clear(s.Entry.ValueBytes[:cap(s.Entry.ValueBytes)])
			clear(s.Payload.Ciphertext[:cap(s.Payload.Ciphertext)])
			for _, wrap := range s.Access.Wraps {
				clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
			}
		}
	}
	c.admission, c.targets, c.route = contract.PlanningAdmission{}, nil, nil
	c.mu.Unlock()
	close(c.done)
}

func (c *PlanningCustody) Close() {
	if c != nil {
		c.cancel()
		<-c.done
	}
}

func planningPurposeValid(a contract.PlanningAdmission) bool {
	switch a.Options.Purpose {
	case contract.PlanningEquality, contract.PlanningDisplay:
		return a.Retirement == nil
	case contract.PlanningRetirementFeasibility:
		return planningRetirementAdmission(a)
	}
	return false
}
