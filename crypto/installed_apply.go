package crypto

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
)

// ApplyCustody owns one installed value comparison and its preparation. The
// installed composition supplies the Authority route; Recovery has public
// protection only and receives no private route from this owner.
// The constructor fixes the operation and its finite deadline. Exchange advances
// Compare, Prepare, Freeze and Claim in order. BindReceipt must fix the complete
// receipt delta after Prepare and before Freeze; Claim consumes the frozen facts.
// Caller cancellation and the original deadline bound each stage. Close cancels
// and joins this operation before releasing its retained state.
type ApplyCustody struct {
	runtime             *Runtime
	admission           *applyAdmission
	closed              atomic.Bool
	closeOnce           sync.Once
	predecessorRevision contract.ID
	before              contract.MutationReceiptWindows
	warningBits         uint8
}

func NewApplyCustody(r *Runtime, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, public map[contract.ID]PublicKeyQualifier,
	route, fileID contract.ID, plainBefore []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, predecessorRevision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*ApplyCustody, error) {
	if r == nil || fileID.IsZero() || predecessorRevision.IsZero() || before.DomainID != q.Context.DomainID || witness == nil {
		return nil, ErrAdmission
	}
	if _, err := contract.EncodeReceiptWarningBits(contract.OperationApplyDeclaration, warningBits, 0); err != nil {
		return nil, ErrAdmission
	}
	if _, err := before.Descriptors(); err != nil {
		return nil, ErrAdmission
	}
	before.Successes = slices.Clone(before.Successes)
	before.Failures = slices.Clone(before.Failures)
	before.Order = slices.Clone(before.Order)
	accepted := make(map[contract.ID]contract.SealedInputCore, len(q.SealedInputs))
	for _, source := range q.SealedInputs {
		view, err := contract.InspectSealedInputEnvelope(source.EnvelopeBytes)
		if err != nil || view.Core.FileIdentity != fileID {
			return nil, ErrAdmission
		}
		core, err := view.Core.Own()
		if err != nil {
			return nil, ErrAdmission
		}
		accepted[contract.Hash(source.EnvelopeBytes)] = core
	}
	return newApplyCustody(r, predecessorRevision, before, warningBits, func() (*applyAdmission, error) {
		return r.admitApplyOwned(q, control, current, public, route, accepted, plainBefore, support, deadline, true, witness)
	})
}

// The constructor fixes this installer. The local argument permits exact
// replacement interleavings without a process-global scheduling hook.
func newApplyCustody(r *Runtime, predecessorRevision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, install func() (*applyAdmission, error)) (*ApplyCustody, error) {
	a, err := install()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	valid := !r.closed && a != nil && r.apply == a && r.slot == a.session && applyPredecessorReceiptsMatch(a, before)
	r.mu.Unlock()
	if !valid {
		if a != nil {
			r.retireSession(a.session)
		}
		return nil, ErrAdmission
	}
	return &ApplyCustody{runtime: r, admission: a, predecessorRevision: predecessorRevision, before: before, warningBits: warningBits}, nil
}

func (c *ApplyCustody) InstanceID() contract.ID {
	if c == nil || c.runtime == nil {
		return contract.ID{}
	}
	return c.runtime.InstanceID()
}

func (c *ApplyCustody) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	refusal := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: request.Kind, RequestID: request.RequestID,
		CustodyInstanceID: c.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	if c == nil || c.runtime == nil || c.admission == nil || c.closed.Load() || request.Kind < contract.CryptoCompare || request.Kind > contract.CryptoDiscard {
		return refusal
	}
	return c.runtime.exchangeWithApplyOwner(ctx, request, c.admission)
}

func (c *ApplyCustody) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.runtime != nil && c.admission != nil {
			c.runtime.retireSession(c.admission.session)
			c.before = contract.MutationReceiptWindows{}
		}
	})
}

// BindReceipt is reachable only through the static installation's private
// parent closure. It cannot be installed by any Crypto request or fact body.
// The context must retain the constructor's exact deadline. Invalid facts or a
// repeated binding terminate the current operation; success owns its window slices.
func (c *ApplyCustody) BindReceipt(ctx context.Context, q contract.CryptoApplyReceiptAdmission) error {
	if c == nil || c.runtime == nil || ctx == nil || c.closed.Load() {
		return ErrAdmission
	}
	done := ctx.Done()
	deadline, finite := ctx.Deadline()
	r := c.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	a := c.admission
	if r.closed || a == nil || r.apply != a || r.slot != a.session || a.terminal || c.closed.Load() {
		return ErrAdmission
	}
	reject := func() error { a.terminal = true; a.cancel(); return ErrAdmission }
	if sessionCancellationObserved(done, a.session) != contract.CryptoSuccess || !finite || deadline != a.deadline || a.busy || a.stage != contract.CryptoFreeze || a.receipt != nil || q.Context != a.request.Context || q.OperationRef != a.operationRef || q.IdentityPlanDescriptor != a.identityDescriptor {
		return reject()
	}
	q.Delta.Before.Successes = slices.Clone(q.Delta.Before.Successes)
	q.Delta.Before.Failures = slices.Clone(q.Delta.Before.Failures)
	q.Delta.Before.Order = slices.Clone(q.Delta.Before.Order)
	q.Delta.After.Successes = slices.Clone(q.Delta.After.Successes)
	q.Delta.After.Failures = slices.Clone(q.Delta.After.Failures)
	q.Delta.After.Order = slices.Clone(q.Delta.After.Order)
	if a.supportTransition == nil || q.OperationKind != a.operationKind || !q.ChangedSubjects.Valid() || q.Delta.DomainID != a.request.Context.DomainID || q.Delta.OperationKind != q.OperationKind || q.Delta.AddedCount != 1 || q.Delta.Before.DomainID != c.before.DomainID || !slices.Equal(q.Delta.Before.Successes, c.before.Successes) || !slices.Equal(q.Delta.Before.Failures, c.before.Failures) || !slices.Equal(q.Delta.Before.Order, c.before.Order) || len(q.Delta.After.Successes) == 0 {
		return reject()
	}
	if _, err := contract.MutationReceiptDeltaDigest(q.Delta); err != nil {
		return reject()
	}
	row := q.Delta.After.Successes[len(q.Delta.After.Successes)-1]
	expectedEffect := uint16(contract.ReceiptEffectNoChange)
	if a.request.SecretAccess != nil {
		subjects, err := a.secretAccessSubjects()
		if err != nil || subjects != q.ChangedSubjects {
			return reject()
		}
		expectedEffect = contract.ReceiptEffectNotApplicable
	}
	if a.request.Retirement != nil {
		subjects, err := a.recipientRetirementSubjects()
		if err != nil || subjects != q.ChangedSubjects {
			return reject()
		}
		expectedEffect = contract.ReceiptEffectNotApplicable
	}
	if row.DomainID != a.request.Context.DomainID || row.OperationKind != q.OperationKind || row.ChangedSubjects != q.ChangedSubjects || row.OperationID != a.plan.Operation || row.PredecessorRevisionID != c.predecessorRevision || row.RequestedRevisionID != a.plan.Revision || row.ObservedRevisionID != a.plan.Revision || row.CanonicalOutcome != contract.ReceiptCanonicalSelected || row.EffectSummary != expectedEffect || row.OutputSummary != contract.ReceiptOutputNotApplicable || row.EvidenceCeiling != contract.ReceiptEvidenceCanonical || row.SummaryCounts[contract.ReceiptEffectCount] != 0 {
		return reject()
	}
	after, err := a.supportTransition.SupportAfter(a.plan, a.request.Intent)
	if err != nil {
		return reject()
	}
	duties, err := contract.MutationResultRecordDescriptor(contract.MutationResultDuties, a.request.Context.DomainID, applyReceiptSupportRows(after.Records, contract.GeneratedDutySupportKind))
	if err != nil || q.LiveDuties != duties || row.SummaryCounts[contract.ReceiptDutyCount] != duties.Count {
		return reject()
	}
	hazards, err := contract.MutationResultRecordDescriptor(contract.MutationResultHazards, a.request.Context.DomainID, applyReceiptSupportRows(after.Records, contract.GeneratedHazardSupportKind))
	if err != nil || q.LiveHazards != hazards || row.SummaryCounts[contract.ReceiptHazardCount] != hazards.Count {
		return reject()
	}
	expectedState := uint16(contract.ReceiptStateSuccess)
	if q.OperationKind == contract.OperationApplyDeclaration && len(a.supportTransition.Handoffs) != 0 {
		expectedState = contract.ReceiptStateRetirementPending
	}
	var expectedWarnings uint64
	if hazards.Count != 0 {
		expectedWarnings = contract.ReceiptWarningPossibleLive
	}
	warnings, effects, err := contract.DecodeReceiptWarningBits(row.OperationKind, row.WarningBits)
	if err != nil || row.StateResult != expectedState || warnings != c.warningBits || effects != expectedWarnings {
		return reject()
	}
	if q.AfterSupport.Digest.IsZero() || q.CandidatePublicState.Digest.IsZero() || q.CandidatePublicState.Count != uint32(len(a.request.Intent)) {
		return reject()
	}
	if _, err := contract.PublicStateDescriptor(contract.PublicState{Domain: a.request.Context.DomainID, RequiredSupport: q.AfterSupport}); err != nil {
		return reject()
	}
	expectedSupport, err := applyReceiptSuccessorSupport(a.request.Context.DomainID, after, q.Delta)
	if err != nil || expectedSupport != q.AfterSupport {
		return reject()
	}
	a.receipt = &applyReceiptExpectation{support: q.AfterSupport, candidate: q.CandidatePublicState}
	return nil
}

func applyPredecessorReceiptsMatch(a *applyAdmission, before contract.MutationReceiptWindows) bool {
	if a.supportTransition == nil || before.DomainID != a.request.Context.DomainID {
		return false
	}
	expected, err := before.SupportRecords()
	if err != nil {
		return false
	}
	actual := applyReceiptSupportRows(a.supportTransition.Records, contract.MutationReceiptSupportKind)
	if len(actual) != len(expected) {
		return false
	}
	for i, row := range expected {
		if row.RecordID != actual[i].RecordID || !bytes.Equal(row.Body, actual[i].Body) {
			return false
		}
	}
	if len(expected) == 0 {
		return true
	}
	index, err := applyReceiptIndexRecord(before)
	if err != nil {
		return false
	}
	expectedFact, err := contract.InspectSupportRecordDigest(before.DomainID, index)
	if err != nil {
		return false
	}
	for i, row := range a.supportTransition.Records {
		if row.Kind == index.Kind && row.RecordID == index.RecordID {
			return a.supportTransition.RecordFacts[i] == expectedFact && (row.Body == nil || bytes.Equal(row.Body, index.Body))
		}
	}
	return false
}

func applyReceiptIndexRecord(windows contract.MutationReceiptWindows) (contract.SupportRecord, error) {
	indexes, err := windows.Indexes()
	if err != nil {
		return contract.SupportRecord{}, err
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		return contract.SupportRecord{}, err
	}
	blob, err := contract.MutationReceiptIndexBlobID(windows.DomainID, successes, failures, order)
	if err != nil {
		return contract.SupportRecord{}, err
	}
	body, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		return contract.SupportRecord{}, err
	}
	fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema, BlobID: blob, Count: 1,
		TotalLength: uint64(len(body)), WholeDigest: contract.Hash(body), Payload: body})
	if err != nil {
		return contract.SupportRecord{}, err
	}
	id, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		return contract.SupportRecord{}, err
	}
	return contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: fragment}, nil
}

// The accepted work transition owns all nonreceipt rows. The actual delta owns
// the complete receipt windows and their index; caller descriptors own neither.
func applyReceiptSuccessorSupport(domain contract.ID, accepted contract.GeneratedSupportRows, delta contract.MutationReceiptDelta) (contract.DescriptorVector, error) {
	if len(accepted.Records) != len(accepted.Facts) {
		return contract.DescriptorVector{}, contract.ErrRecord
	}
	before, err := delta.Before.Descriptors()
	if err != nil {
		return contract.DescriptorVector{}, err
	}
	var previousIndex contract.ID
	if before.Successes.Count != 0 || before.Failures.Count != 0 {
		blob, err := contract.MutationReceiptIndexBlobID(domain, before.Successes, before.Failures, before.Order)
		if err != nil {
			return contract.DescriptorVector{}, err
		}
		previousIndex, err = contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			return contract.DescriptorVector{}, err
		}
	}
	facts := make([]contract.SupportRecordDigest, 0, len(accepted.Facts))
	for i, row := range accepted.Records {
		if row.Kind == contract.MutationReceiptSupportKind || row.Kind == contract.GeneratedFragmentSupportKind && row.RecordID == previousIndex {
			continue
		}
		facts = append(facts, accepted.Facts[i])
	}
	rows, err := delta.After.SupportRecords()
	if err != nil {
		return contract.DescriptorVector{}, err
	}
	index, err := applyReceiptIndexRecord(delta.After)
	if err != nil {
		return contract.DescriptorVector{}, err
	}
	rows = append(rows, index)
	for _, row := range rows {
		fact, err := contract.InspectSupportRecordDigest(domain, row)
		if err != nil {
			return contract.DescriptorVector{}, err
		}
		facts = append(facts, fact)
	}
	slices.SortFunc(facts, func(a, b contract.SupportRecordDigest) int {
		if a.Kind() != b.Kind() {
			return int(a.Kind()) - int(b.Kind())
		}
		left, right := a.RecordID(), b.RecordID()
		return bytes.Compare(left[:], right[:])
	})
	return contract.RequiredSupportDescriptorFromDigests(domain, facts)
}

// Canonical support order places each record kind in one borrowed span.
func applyReceiptSupportRows(rows []contract.SupportRecord, kind contract.SupportRecordKind) []contract.SupportRecord {
	start := slices.IndexFunc(rows, func(row contract.SupportRecord) bool { return row.Kind == kind })
	if start < 0 {
		return nil
	}
	end := start + 1
	for end < len(rows) && rows[end].Kind == kind {
		end++
	}
	return rows[start:end]
}
