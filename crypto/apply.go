package crypto

import (
	"context"
	"slices"
	"strings"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

type applyReceiptExpectation struct{ support, candidate contract.DescriptorVector }

type applyAdmission struct {
	*session
	stage                                  contract.CryptoKind
	busy                                   bool
	request                                contract.CryptoCompareRequest
	requestDigest                          contract.ID
	requestLength                          int
	control                                contract.ControlCore
	operationKind                          uint16
	routeID                                contract.ID
	registryChanged                        bool
	recipientPublic                        map[contract.ID]PublicKeyQualifier
	authorityIndex                         int
	sealedInputCores                       []contract.SealedInputCore
	equalOnlySources                       []string
	plainBefore                            []contract.MembershipRow
	requiredSupport                        contract.DescriptorVector
	comparison                             []contract.CryptoComparisonRow
	operationRef, comparisonDigest         contract.ID
	plan                                   contract.IdentityPlan
	identityDescriptor, preparedDescriptor contract.DescriptorVector
	prepared                               []contract.CryptoPreparedSecret
	frozen                                 contract.CryptoClaimRequest
	receiptRequired                        bool
	receipt                                *applyReceiptExpectation
	supportTransition                      *contract.GeneratedSupportTransition
}

// admitApply is private parent entry for a complete ordinary transition. The parent
// authenticates complete predecessor/control/registry facts and independently
// authorizes each original source body and its original provenance. Neither a
// Compare body nor its source's self-described caller can install this state.
func (r *Runtime) admitApply(q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, public map[contract.ID]PublicKeyQualifier, routeID contract.ID, accepted map[contract.ID]contract.SealedInputCore, plainBefore []contract.MembershipRow, support contract.DescriptorVector, deadline time.Time, witnesses ...*contract.GeneratedSupportTransition) error {
	_, err := r.admitApplyOwned(q, control, current, public, routeID, accepted, plainBefore, support, deadline, false, witnesses...)
	return err
}

func (r *Runtime) admitApplyOwned(q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, public map[contract.ID]PublicKeyQualifier, routeID contract.ID, accepted map[contract.ID]contract.SealedInputCore, plainBefore []contract.MembershipRow, support contract.DescriptorVector, deadline time.Time, receiptRequired bool, witnesses ...*contract.GeneratedSupportTransition) (*applyAdmission, error) {
	return r.admitApplyOperationOwned(contract.OperationApplyDeclaration, nil, q, control, current, public, routeID, accepted, plainBefore, support, deadline, receiptRequired, witnesses...)
}

func (r *Runtime) admitApplyOperationOwned(operation uint16, retiredSlot *uint16, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, public map[contract.ID]PublicKeyQualifier, routeID contract.ID, accepted map[contract.ID]contract.SealedInputCore, plainBefore []contract.MembershipRow, support contract.DescriptorVector, deadline time.Time, receiptRequired bool, witnesses ...*contract.GeneratedSupportTransition) (*applyAdmission, error) {
	switch operation {
	case contract.OperationApplyDeclaration:
		if q.SecretAccess != nil || q.Retirement != nil || retiredSlot != nil {
			return nil, ErrAdmission
		}
	case contract.OperationRetireRecipientIdentity:
		if q.Retirement == nil || q.SecretAccess != nil || retiredSlot == nil || len(public) != 0 {
			return nil, ErrAdmission
		}
	case contract.OperationEnvelopeRekey:
		if q.SecretAccess == nil || q.SecretAccess.OperationKind != operation || q.Retirement != nil || retiredSlot != nil {
			return nil, ErrAdmission
		}
	default:
		return nil, ErrAdmission
	}
	if len(witnesses) > 1 {
		return nil, ErrAdmission
	}
	var witness *contract.GeneratedSupportTransition
	if len(witnesses) == 1 {
		witness = witnesses[0]
	}
	if witness != nil {
		ref, err := contract.DecodeRef(q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
		access, accessErr := contract.AccessRoot(witness.BeforeAccess)
		if err != nil || accessErr != nil || witness.DomainID != q.Context.DomainID || witness.BeforeRootDigest != ref.Digest || witness.BeforeSnapshot != ref.Object || witness.BeforeSupport != support || access != q.Context.CurrentAccessRoot || witness.IntentError(q.Intent) != nil {
			return nil, ErrAdmission
		}
		if err := witness.CurrentError(q.Current); err != nil {
			return nil, ErrAdmission
		}
	}
	if r == nil || routeID.IsZero() || !validDeadline(deadline) || q.Context.Expiry != uint64(deadline.UnixNano()) || q.Context.CompatibilityID != contract.CompatibilityID() || q.Context.CurrentAccessRoot.IsZero() || len(q.Current)+len(plainBefore) > contract.CryptoMaxValueEntries || len(q.SealedInputs) > contract.CryptoMaxValueEntries || len(accepted) != len(q.SealedInputs) {
		return nil, ErrAdmission
	}
	if _, err := contract.EncodeApplyContext(q.Context); err != nil {
		return nil, ErrAdmission
	}
	if _, err := contract.ControlCoreLength(control); err != nil || control.Provider != r.family || control.DomainID != q.Context.DomainID || control.CompatibilityID != q.Context.CompatibilityID || control.CryptoSupportID != contract.CryptoSupportID() {
		return nil, ErrAdmission
	}
	// The private parent fixes the unchanged receipt projection independently of
	// the Freeze body. Ordinary value work cannot add, alter or remove receipts.
	if support.Digest.IsZero() {
		return nil, ErrAdmission
	}
	if _, err := contract.PublicStateDescriptor(contract.PublicState{Domain: q.Context.DomainID, RequiredSupport: support}); err != nil {
		return nil, ErrAdmission
	}
	if support.Count == 0 {
		empty, err := contract.EmptyRequiredSupportDescriptor(q.Context.DomainID)
		if err != nil || support != empty {
			return nil, ErrAdmission
		}
	}
	descriptor, err := applyOperationIntentDescriptor(q)
	if err != nil || descriptor != q.Context.IntentDescriptor {
		return nil, ErrAdmission
	}
	if _, err := contract.BindingTableLength(q.Bindings); err != nil || len(q.Bindings) > contract.CryptoMaxRecipients+1 {
		return nil, ErrAdmission
	}
	var registryChanged, registryOK bool
	var recipientPublic map[contract.ID]PublicKeyQualifier
	if retiredSlot != nil {
		registryOK = recipientRetirementAdmission(q, current, *retiredSlot, control)
		registryChanged = registryOK
	} else {
		registryChanged, recipientPublic, registryOK = applyRecipientAdmission(q, current, public, control)
	}
	if !registryOK || len(q.Current)+len(q.SealedInputs) == 0 && !registryChanged {
		return nil, ErrAdmission
	}
	if _, err := contract.GrantDescriptor(q.Context.DomainID, plainBefore); err != nil {
		return nil, ErrAdmission
	}
	authority, recovery, ordinary := -1, -1, 0
	var previous contract.BindingTableRow
	for i, row := range q.Bindings {
		if row.Binding.Provider != r.family || i > 0 && row.SubjectKind == previous.SubjectKind && row.SubjectID == previous.SubjectID {
			return nil, ErrAdmission
		}
		for _, prior := range q.Bindings[:i] {
			if prior.Binding.BindingID == row.Binding.BindingID {
				return nil, ErrAdmission
			}
		}
		previous = row
		if row.SubjectKind == contract.OrdinaryWrapSubject {
			ordinary++
			if row.SubjectID == control.AuthorityRecipientID {
				authority = i
			}
		} else {
			if recovery >= 0 || control.Recovery == nil || row.SubjectID != control.Recovery.RoleID {
				return nil, ErrAdmission
			}
			recovery = i
		}
	}
	expectedOrdinary := len(q.Recipients)
	if q.Retirement != nil {
		expectedOrdinary = len(current)
	}
	if authority < 0 || ordinary != expectedOrdinary || ordinary > contract.CryptoMaxRecipients || !sameApplyBinding(q.Bindings[authority].Binding, control.AuthorityKMSBinding) {
		return nil, ErrAdmission
	}
	if control.Recovery != nil && (recovery < 0 || !sameApplyBinding(q.Bindings[recovery].Binding, control.Recovery.KMS) || !contract.IndependentKMSBindings(control.AuthorityKMSBinding, control.Recovery.KMS)) {
		return nil, ErrAdmission
	}
	for _, before := range plainBefore {
		if before.EntryDigest.IsZero() || !applyRecipientsAdmitted(before.Recipients, control.AuthorityRecipientID, q.Bindings) {
			return nil, ErrAdmission
		}
	}
	currentAdmission := &applyAdmission{request: q, control: control, operationKind: operation, authorityIndex: authority, plainBefore: plainBefore}
	beforeMemberships := 0
	for _, before := range plainBefore {
		beforeMemberships += len(before.Recipients)
	}
	for _, row := range q.Current {
		current, ok := currentAdmission.current(row)
		if !ok || current.entry.ValueSource == contract.Generated && witness == nil || slices.ContainsFunc(plainBefore, func(before contract.MembershipRow) bool {
			return before.Name == current.entry.Name || before.Slot == row.Slot
		}) {
			return nil, ErrAdmission
		}
		beforeMemberships += len(current.entry.Recipients)
		if beforeMemberships > contract.CryptoMaxMemberships {
			return nil, ErrAdmission
		}
		for _, intent := range q.Intent {
			if intent.Name == current.entry.Name && intent.ConfidentialityClass != contract.Secret {
				return nil, ErrAdmission
			}
		}
	}
	if q.SecretAccess != nil && !currentAdmission.secretAccessAdmission(current, registryChanged) {
		return nil, ErrAdmission
	}
	if q.Retirement != nil && !currentAdmission.recipientRetirementCensus() {
		return nil, ErrAdmission
	}
	if witness != nil && witness.Output != nil {
		before := slices.Clone(plainBefore)
		for _, row := range q.Current {
			current, ok := currentAdmission.current(row)
			if !ok {
				return nil, ErrAdmission
			}
			before = append(before, contract.MembershipRow{Name: current.entry.Name, Slot: row.Slot, Incarnation: current.entry.Incarnation, EntryDigest: current.entryDigest, Recipients: current.entry.Recipients})
		}
		slices.SortFunc(before, func(a, b contract.MembershipRow) int { return strings.Compare(a.Name, b.Name) })
		actual, err := contract.GrantDescriptor(q.Context.DomainID, before)
		expected, expectedErr := contract.GrantDescriptor(q.Context.DomainID, witness.Output.EntriesBefore)
		if err != nil || expectedErr != nil || actual != expected {
			return nil, ErrAdmission
		}
	}
	cores := make([]contract.SealedInputCore, 0, len(q.SealedInputs))
	var equalOnlySources []string
	inputIndex := 0
	for _, intent := range q.Intent {
		if !applyRecipientsAdmitted(intent.Recipients, control.AuthorityRecipientID, q.Bindings) {
			return nil, ErrAdmission
		}
		if intent.ConfidentialityClass != contract.Secret {
			continue
		}
		if intent.Retained != (contract.RetainedSecretInput{}) {
			if _, ok := currentAdmission.retainedCurrent(intent); !ok {
				return nil, ErrAdmission
			}
			continue
		}
		if intent.ValueSource == contract.Generated {
			if witness == nil {
				return nil, ErrAdmission
			}
			continue
		}
		if slices.ContainsFunc(plainBefore, func(before contract.MembershipRow) bool { return before.Name == intent.Name }) || inputIndex >= len(q.SealedInputs) {
			return nil, ErrAdmission
		}
		source := q.SealedInputs[inputIndex]
		view, err := contract.InspectSealedInputEnvelope(source.EnvelopeBytes)
		if err != nil {
			return nil, ErrAdmission
		}
		core, err := view.Core.Own()
		if err != nil || source.Name != intent.Name || core.Name != intent.Name || core.DomainID != q.Context.DomainID || core.CompatibilityID != q.Context.CompatibilityID || core.CryptoSupportID != control.CryptoSupportID || core.ContentLength != intent.ContentLength || core.InputEncoding != intent.InputEncoding || core.RetainedLength != intent.RetainedLength || len(source.EnvelopeBytes) != int(intent.PayloadLength) {
			return nil, ErrAdmission
		}
		expected, ok := accepted[contract.Hash(source.EnvelopeBytes)]
		if !ok || expected != core {
			return nil, ErrAdmission
		}
		refs := make([]contract.RecipientBindingReference, len(intent.Recipients))
		for i, recipient := range intent.Recipients {
			row := q.Bindings[applyBindingIndex(q.Bindings, recipient)]
			digest, err := contract.PublicBindingDigest(row.Binding)
			if err != nil {
				return nil, ErrAdmission
			}
			refs[i] = contract.RecipientBindingReference{RecipientID: recipient, PublicBindingDigest: digest}
		}
		bindingSet, err := contract.IntendedRecipientBindingSetDigest(q.Context.DomainID, control.AuthorityRecipientID, refs)
		if err != nil {
			return nil, ErrAdmission
		}
		if bindingSet != core.IntendedRecipientBindingSetDigest {
			currentIndex := slices.IndexFunc(q.Current, func(row contract.CryptoCurrentSecret) bool {
				entry, err := contract.InspectValueEntry(row.EntryBytes)
				return err == nil && string(entry.Name) == intent.Name
			})
			if currentIndex < 0 {
				return nil, ErrAdmission
			}
			before, ok := currentAdmission.current(q.Current[currentIndex])
			if !ok || before.entry.ValueSource != contract.Supplied || slices.ContainsFunc(intent.Recipients, func(id contract.ID) bool { return !slices.Contains(before.entry.Recipients, id) }) {
				return nil, ErrAdmission
			}
			equalOnlySources = append(equalOnlySources, intent.Name)
		}
		wrapCore, err := custody.SealedInputWrapCore(core, q.Bindings[authority])
		if err != nil || !applyWrapMatches(contract.WrapRow(view.AuthorityWrap), wrapCore) {
			return nil, ErrAdmission
		}
		cores = append(cores, core)
		inputIndex++
	}
	if inputIndex != len(q.SealedInputs) {
		return nil, ErrAdmission
	}
	// Shared complete validation checks all nested source/input digests and
	// aggregate limits before the canonical request allocation and retained copy.
	body, err := contract.EncodeCryptoCompareRequest(q)
	if err != nil {
		return nil, ErrAdmission
	}
	owned, err := contract.DecodeCryptoCompareRequest(body)
	if err != nil {
		return nil, ErrAdmission
	}
	controlBody, err := contract.EncodeControlCore(control)
	if err != nil {
		return nil, ErrAdmission
	}
	ownedControl, err := contract.DecodeControlCore(controlBody)
	if err != nil {
		return nil, ErrAdmission
	}
	beforeCopy := slices.Clone(plainBefore)
	for i := range beforeCopy {
		beforeCopy[i].Name = strings.Clone(beforeCopy[i].Name)
		beforeCopy[i].Recipients = slices.Clone(beforeCopy[i].Recipients)
	}
	var pinned *contract.GeneratedSupportTransition
	if witness != nil {
		pinned, err = witness.CopyMetadata()
		if err != nil {
			return nil, ErrAdmission
		}
	}
	a := &applyAdmission{stage: contract.CryptoCompare, request: owned, requestDigest: contract.Hash(body), requestLength: len(body), control: ownedControl, operationKind: operation, routeID: routeID, registryChanged: registryChanged, recipientPublic: recipientPublic, authorityIndex: authority, sealedInputCores: cores, equalOnlySources: equalOnlySources, plainBefore: beforeCopy, requiredSupport: support, receiptRequired: receiptRequired, supportTransition: pinned}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slot != nil {
		return nil, ErrAdmission
	}
	route := r.routes[routeID]
	if route == nil || route.Family() != r.family || route.CredentialRoute() != routeID {
		return nil, ErrAdmission
	}
	a.session = r.installSession(q.Context.AdmissionID, deadline, nil, func() {
		a.request = contract.CryptoCompareRequest{}
		a.control = contract.ControlCore{}
		a.sealedInputCores, a.plainBefore, a.prepared, a.comparison = nil, nil, nil, nil
		a.equalOnlySources = nil
		a.plan = contract.IdentityPlan{}
		a.frozen = contract.CryptoClaimRequest{}
		a.routeID, a.operationRef, a.comparisonDigest = contract.ID{}, contract.ID{}, contract.ID{}
		a.supportTransition = nil
		a.receipt = nil
		a.recipientPublic = nil
	})
	if a.session == nil {
		return nil, ErrAdmission
	}
	r.apply = a
	return a, nil
}

func sameApplyBinding(a, b contract.KMSBinding) bool {
	ad, err := contract.PublicBindingDigest(a)
	if err != nil {
		return false
	}
	bd, err := contract.PublicBindingDigest(b)
	return err == nil && ad == bd
}

func applyBindingIndex(rows []contract.BindingTableRow, recipient contract.ID) int {
	return slices.IndexFunc(rows, func(row contract.BindingTableRow) bool {
		return row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == recipient
	})
}

func applyRecipientsAdmitted(recipients []contract.ID, authority contract.ID, bindings []contract.BindingTableRow) bool {
	if !slices.Contains(recipients, authority) {
		return false
	}
	for _, recipient := range recipients {
		if applyBindingIndex(bindings, recipient) < 0 {
			return false
		}
	}
	return true
}

func applyWrapMatches(row contract.WrapRow, core contract.WrapCore) bool {
	return row.SubjectKind == core.SubjectKind && row.SubjectID == core.SubjectID && row.BindingID == core.BindingID && row.BindingSerial == core.BindingSerial && row.PublicBindingDigest == core.PublicBindingDigest
}

func (r *Runtime) applyExchange(ctx context.Context, q contract.CryptoRequest, reply contract.CryptoResponse) contract.CryptoResponse {
	return r.applyExchangeOwned(ctx, q, nil)
}

func (r *Runtime) applyExchangeOwned(ctx context.Context, q contract.CryptoRequest, expected *applyAdmission) (out contract.CryptoResponse) {
	out = contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: r.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	if r == nil || ctx == nil || q.CustodyInstanceID != r.id {
		return out
	}
	if q.Schema != contract.CryptoSchema || q.RequestID.IsZero() || q.Kind < contract.CryptoCompare || q.Kind > contract.CryptoDiscard || len(q.Body) > contract.CryptoRequestLimit-71 {
		out.ResultCode = contract.CryptoInvalidInput
		return out
	}
	callerDone := ctx.Done()
	r.mu.Lock()
	a := r.apply
	if r.closed || a == nil || expected != nil && (a != expected || r.slot != expected.session) {
		r.mu.Unlock()
		return out
	}
	if a.terminal {
		r.mu.Unlock()
		out.ResultCode = contract.CryptoAlreadyUsed
		return out
	}
	if a.ctx.Err() != nil || !time.Now().Before(a.deadline) {
		r.mu.Unlock()
		out.ResultCode = contract.CryptoExpired
		return out
	}
	if a.busy {
		r.mu.Unlock()
		out.ResultCode = contract.CryptoAlreadyUsed
		return out
	}
	if q.Kind != a.stage && (q.Kind != contract.CryptoDiscard || a.stage <= contract.CryptoCompare) {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		out.ResultCode = contract.CryptoAlreadyUsed
		return out
	}
	a.busy = true
	a.work.Add(1)
	route := r.routes[a.routeID]
	r.mu.Unlock()
	defer a.work.Done()
	defer func() { r.finishApplyStage(callerDone, a, q.Kind, &out) }()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	privateCtx := telemetry.PrivateContext(a.ctx, ctx)
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		out.ResultCode = code
		return out
	}
	switch q.Kind {
	case contract.CryptoCompare:
		if _, err := contract.InspectCryptoCompareRequest(q.Body); err != nil {
			out.ResultCode = contract.CryptoInvalidInput
			return out
		}
		if len(q.Body) != a.requestLength || contract.Hash(q.Body) != a.requestDigest {
			return out
		}
		out.ResultCode = a.qualifyRecipients(privateCtx, &out)
		if out.ResultCode == contract.CryptoSuccess {
			out.ResultCode = a.compare(privateCtx, route, &out)
		}
	case contract.CryptoPrepare:
		decoded, err := contract.DecodeCryptoPrepareRequest(q.Body)
		if err != nil {
			out.ResultCode = contract.CryptoInvalidInput
			return out
		}
		if decoded.Context != a.request.Context || decoded.OperationRef != a.operationRef {
			return out
		}
		out.ResultCode = a.prepare(privateCtx, route, decoded, &out)
	case contract.CryptoFreeze:
		decoded, err := contract.DecodeCryptoFreezeRequest(q.Body)
		if err != nil {
			out.ResultCode = contract.CryptoInvalidInput
			return out
		}
		if decoded.Context != a.request.Context || decoded.OperationRef != a.operationRef {
			return out
		}
		out.ResultCode = a.freeze(r.id, decoded, &out)
	case contract.CryptoClaim:
		decoded, err := contract.DecodeCryptoClaimRequest(q.Body)
		if err != nil {
			out.ResultCode = contract.CryptoInvalidInput
			return out
		}
		if decoded != a.frozen {
			return out
		}
		out.ResultCode = contract.CryptoSuccess
	case contract.CryptoDiscard:
		decoded, err := contract.DecodeCryptoDiscardRequest(q.Body)
		if err != nil {
			out.ResultCode = contract.CryptoInvalidInput
			return out
		}
		if decoded.Context != a.request.Context || decoded.OperationRef != a.operationRef {
			return out
		}
		out.ResultCode = contract.CryptoSuccess
	}
	return out
}

func (r *Runtime) finishApplyStage(callerDone <-chan struct{}, a *applyAdmission, kind contract.CryptoKind, reply *contract.CryptoResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		reply.ResultCode = code
	}
	a.busy = false
	if reply.ResultCode != contract.CryptoSuccess || kind == contract.CryptoClaim || kind == contract.CryptoDiscard {
		if reply.ResultCode != contract.CryptoSuccess {
			reply.Body = nil
		}
		a.terminal = true
		a.cancel()
		return
	}
	a.stage = kind + 1
}

func (r *Runtime) retireApply() {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.apply
	r.mu.Unlock()
	if a != nil {
		r.retireSession(a.session)
	}
}
