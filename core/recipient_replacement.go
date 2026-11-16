package core

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

// AdmittedRecipientReplacement comes only from the enclosing private parent.
// A public binding or request digest cannot create this admission.
type AdmittedRecipientReplacement struct {
	observation   *operationObservation
	session       *StateSession
	intent        contract.RecipientReplacementIntent
	plan          transitionPlan
	context       contract.ApplyContext
	requestDigest contract.ID
	requestLength int
	crypto        contract.Crypto
	instance      contract.ID
	deadline      time.Time
	used          bool
}

func (s *StateSession) currentBindings() ([]contract.BindingTableRow, error) {
	image := s.selectedImageView()
	return image.currentBindings()
}

func (s *selectedImage) currentBindings() ([]contract.BindingTableRow, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	rows := make([]contract.BindingTableRow, 0, s.root.RecipientCount+1)
	for _, record := range selectedRecipientRegistry(&s.recipients, s.root.RecipientCount) {
		if record.Status != format.Current || record.CurrentBinding == nil {
			return nil, contract.ErrRecord
		}
		rows = append(rows, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: record.RecipientID, Binding: *record.CurrentBinding})
	}
	if recovery := s.root.CurrentAccess.Core.Recovery; recovery != nil {
		rows = append(rows, contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: recovery.RoleID, Binding: recovery.KMS})
	}
	orderBindings(rows)
	_, err := contract.BindingTableLength(rows)
	return rows, err
}

func orderBindings(rows []contract.BindingTableRow) {
	slices.SortFunc(rows, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		if n := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); n != 0 {
			return n
		}
		if a.Binding.BindingSerial < b.Binding.BindingSerial {
			return -1
		}
		if a.Binding.BindingSerial > b.Binding.BindingSerial {
			return 1
		}
		return bytes.Compare(a.Binding.BindingID[:], b.Binding.BindingID[:])
	})
}

func (s *StateSession) replacementIntentValid(ctx context.Context, intent contract.RecipientReplacementIntent) error {
	if s != nil && s.installedReplacement != nil && !s.installedReplacement.matchesRecipient(s, intent) {
		return contract.ErrRecord
	}
	if s == nil || !s.admission.valid(s.store) || s.prepared || intent.Schema != contract.CanonicalSchema || intent.Profile != 2 || intent.CompatibilityID != contract.CompatibilityID() || intent.CryptoSupportID != contract.CryptoSupportID() || intent.DomainID != s.admission.domain || intent.BeforeAccessRoot != s.root.CurrentAccess.AccessRoot || intent.RecipientID == s.admission.recipient {
		return contract.ErrRecord
	}
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return err
	}
	r := s.recipientRecord(intent.RecipientID)
	if r == nil || r.Status != format.Current || r.CurrentBinding == nil || !contract.IncarnationCounterStep(intent.Before.BindingIncarnationID, intent.Before.BindingSerial, intent.Successor.BindingIncarnationID, intent.Successor.BindingSerial) || intent.Before.Provider != intent.Successor.Provider || intent.Successor.Provider != s.admission.store.Family || used[intent.Successor.BindingID] {
		return contract.ErrRecord
	}
	b, err := contract.EncodeKMSBinding(intent.Before)
	if err != nil {
		return err
	}
	current, err := contract.EncodeKMSBinding(*r.CurrentBinding)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, current) {
		return contract.ErrRecord
	}
	_, err = contract.EncodeRecipientReplacementIntent(intent)
	return err
}

func (s *StateSession) replacementRequest(ctx context.Context, intent contract.RecipientReplacementIntent, p transitionPlan, c contract.ApplyContext) (contract.CryptoAccessReplaceRequest, contract.RequestCore, []contract.CompactRow, error) {
	fail := func(err error) (contract.CryptoAccessReplaceRequest, contract.RequestCore, []contract.CompactRow, error) {
		return contract.CryptoAccessReplaceRequest{}, contract.RequestCore{}, nil, err
	}
	if err := s.replacementIntentValid(ctx, intent); err != nil {
		return fail(err)
	}
	plan := identityPlan(&Comparison{session: s}, p)
	identity, err := contract.IdentityPlanDescriptor(plan)
	if err != nil {
		return fail(err)
	}
	if s.installedReplacement != nil && identity != s.installedReplacement.planDescriptor {
		return fail(contract.ErrRecord)
	}
	if identity.Count != 0 {
		return fail(contract.ErrRecord)
	}
	ids, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return fail(err)
	}
	ids[intent.Successor.BindingID] = true
	for _, id := range []contract.ID{p.operation, p.transition, p.snapshot, p.revision} {
		if id.IsZero() || ids[id] {
			return fail(contract.ErrRecord)
		}
		ids[id] = true
	}
	for _, page := range plan.Pages {
		if ids[page.Object] {
			return fail(contract.ErrRecord)
		}
		ids[page.Object] = true
	}
	for i, page := range s.recipients {
		target := false
		if page != nil {
			for _, r := range page.Slots {
				target = target || r != nil && r.RecipientID == intent.RecipientID
			}
		}
		if target == p.recipientPages[i].IsZero() {
			return fail(contract.ErrRecord)
		}
	}
	if len(plan.Rows) != 0 {
		return fail(contract.ErrRecord)
	}
	for _, id := range p.pages {
		if !id.IsZero() {
			return fail(contract.ErrRecord)
		}
	}
	indexes, err := s.mutationReceiptPageIndexes(ctx)
	if err != nil {
		return fail(err)
	}
	for i, id := range p.supportPages {
		if slices.Contains(indexes, uint16(i)) == id.IsZero() {
			return fail(contract.ErrRecord)
		}
	}
	intentDescriptor, err := contract.RecipientReplacementIntentDescriptor(intent)
	if err != nil {
		return fail(err)
	}
	h := s.successorCore(p)
	request := contract.RequestCore{RequestCoreFields: contract.RequestCoreFields{Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation, Epoch: h.Epoch, PreviousRevision: h.PreviousRevision, PreviousDigest: h.PreviousDigest, Intent: contract.DigestLength{Digest: intentDescriptor.Digest, Length: intentDescriptor.Length}, IdentityPlan: contract.DigestLength{Digest: identity.Digest, Length: identity.Length}}, PreviousToken: s.token}
	requestBody, err := contract.EncodeRequestCore(request)
	if err != nil {
		return fail(err)
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		return fail(err)
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		return fail(err)
	}
	if c.OperationClass != contract.CryptoAccessReplacementClass || c.DomainID != s.admission.domain || c.CompatibilityID != contract.CompatibilityID() || c.PredecessorHEADDigest != contract.Hash(s.body) || c.OriginalConditionDigest != condition || !bytes.Equal(c.PredecessorRootRef[:], root) || c.CurrentAccessRoot != s.root.CurrentAccess.AccessRoot {
		return fail(contract.ErrRecord)
	}
	c.IntentDescriptor = contract.DescriptorVector{Digest: contract.Hash(requestBody), Length: uint64(len(requestBody)), Count: 1}
	bindings, err := s.currentBindings()
	if err != nil {
		return fail(err)
	}
	bindings = append(bindings, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: intent.RecipientID, Binding: intent.Successor})
	orderBindings(bindings)
	source, target := -1, -1
	for i, row := range bindings {
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == s.admission.recipient {
			source = i
		}
		if row.Binding.BindingID == intent.Successor.BindingID {
			target = i
		}
	}
	if source < 0 || target < 0 {
		return fail(contract.ErrRecord)
	}
	before, err := contract.PublicBindingDigest(intent.Before)
	if err != nil {
		return fail(err)
	}
	q := contract.CryptoAccessReplaceRequest{Context: c, BindingTable: bindings, Replacements: []contract.ReplacementRow{{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: intent.RecipientID, BeforeBindingDigest: before, SuccessorBindingIndex: uint16(target)}}}
	rows, err := s.replacementMaterialRows(ctx, uint16(source), uint16(target), bindings[target])
	if err != nil {
		return fail(err)
	}
	var needed [contract.MaxChildPages]bool
	for _, row := range rows {
		location, ok := s.accessLocations[materialIdentity{row.Coverage.MaterialKind, row.Coverage.MaterialID}]
		if !ok || location.page < 0 || location.page >= len(needed) {
			return fail(contract.ErrRecord)
		}
		needed[location.page] = true
	}
	for i, required := range needed {
		if required == p.accessPages[i].IsZero() {
			return fail(contract.ErrRecord)
		}
	}
	projection, err := replacementProjection(q, uint32(len(rows)))
	if err != nil {
		return fail(err)
	}
	for _, row := range rows {
		if err := projection.Add(row, contract.AccessOutputRow{MaterialKind: row.Coverage.MaterialKind, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord}); err != nil {
			return fail(err)
		}
	}
	q.ExpectedCoverageDescriptor, _, _, err = projection.Descriptors()
	if err != nil {
		return fail(err)
	}
	return q, request, rows, nil
}

func (s *StateSession) PrepareRecipientReplacement(ctx context.Context, permit *AdmittedRecipientReplacement, trust contract.Trust) (*Candidate, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePrepareRecipientReplacement)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	candidate, result := s.prepareRecipientReplacement(ctx, permit, trust, call)
	finishCore(call, result)
	return candidate, result
}

func (s *StateSession) prepareRecipientReplacement(ctx context.Context, permit *AdmittedRecipientReplacement, trust contract.Trust, call *telemetry.Call) (*Candidate, Result) {
	if ctx == nil || ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	ctx = telemetry.CallContext(ctx, call)
	if ctx == nil || ctx.Err() != nil || s == nil || permit == nil || permit.used || permit.session != s || !validPrivateDeadline(permit.deadline) || permit.crypto == nil || permit.crypto.InstanceID() != permit.instance || trust == nil || trust.Identity() != s.admission.trust || trust.Family() != s.admission.store.Family {
		return nil, refused(AdmissionInvalid)
	}
	q, request, rows, err := s.replacementRequest(ctx, permit.intent, permit.plan, permit.context)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	body, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil || contract.Hash(body) != permit.requestDigest || len(body) != permit.requestLength || q.Context != permit.context {
		return nil, refused(AdmissionInvalid)
	}
	subjects, err := s.recipientReplacementSubjects(ctx, permit.intent, rows)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	// The access output changes bytes within existing access pages. Its selected
	// child count is fixed by the public identity plan; rebind the snapshot and
	// shard the exact retained work index before any private Crypto call.
	if _, err := s.projectedRecipientReplacementRoot(ctx, permit.plan, subjects, q.Context.IntentDescriptor.Digest); err != nil {
		if errors.Is(err, contract.ErrRecordCapacity) {
			return nil, refused(CapacityExceeded)
		}
		if readFailure, ok := selectedReadResult(err); ok {
			return nil, readFailure
		}
		return nil, refused(AdmissionInvalid)
	}
	permit.used = true
	source := exchangeSource(q.Context)
	source.OperationID = permit.plan.operation
	op := &cryptoOperation{observation: permit.observation, source: source, adapter: permit.crypto, instance: permit.instance, context: q.Context, deadline: permit.deadline, bindings: q.BindingTable, authority: s.admission.recipient, sourceCount: uint32(len(rows)), wrapCounts: map[contract.ID]uint32{permit.intent.Successor.BindingID: 1}}
	reply, res := op.exchange(ctx, contract.CryptoAccessReplace, body)
	if res.Outcome != 0 {
		return nil, res
	}
	started, err := contract.DecodeCryptoAccessReplaceResult(reply.Body)
	if err != nil || len(started.Qualified) != 0 {
		return nil, refused(AdmissionInvalid)
	}
	op.operationRef = started.OperationRef
	prepared, res := prepareReplacementRows(ctx, op, q, rows, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: permit.intent.RecipientID, Binding: permit.intent.Successor})
	if res.Outcome != 0 {
		return nil, res
	}
	next, ok := s.replacementSuccessor(permit.intent, permit.plan, prepared.after)
	if !ok {
		return nil, refused(InvalidRelation)
	}
	candidate, res := s.encodeRecipientReplacement(ctx, permit.intent, permit.plan, request, next, subjects)
	if candidate == nil {
		return nil, res
	}
	candidate.bindObservation(permit.observation, source)
	c := &Comparison{session: s}
	identity, err := contract.IdentityPlanDescriptor(identityPlan(c, permit.plan))
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	public, err := next.publicProjection()
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	publicDescriptor, err := contract.PublicStateDescriptor(public)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	coverage, outputs, unchanged, err := prepared.projection.Descriptors()
	if err != nil || coverage != q.ExpectedCoverageDescriptor {
		return nil, refused(AdmissionInvalid)
	}
	frozen := contract.CryptoAccessFreezeRequest{OperationRef: op.operationRef, Context: q.Context, IdentityPlanDescriptor: identity, ExpectedCoverageDescriptor: coverage, AfterAccessRowsDescriptor: outputs, CandidatePublicStateDescriptor: publicDescriptor, CandidateAccessRoot: next.root.CurrentAccess.AccessRoot, UnchangedMaterialDescriptor: unchanged, FinalTranscriptDigest: prepared.transcript}
	body, err = contract.EncodeCryptoAccessFreezeRequest(frozen)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	s.prepared = true
	reply, res = op.exchange(ctx, contract.CryptoFreeze, body)
	if res.Outcome != 0 {
		return nil, res
	}
	fact, err := contract.DecodeCryptoFreezeResult(reply.Body)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	expected, err := contract.CryptoAccessFactDigest(op.instance, frozen)
	if err != nil || fact.FactDigest != expected {
		return nil, refused(AdmissionInvalid)
	}
	body, err = contract.EncodeCryptoAccessClaimRequest(contract.CryptoAccessClaimRequest{CryptoAccessFreezeRequest: frozen, FactDigest: expected})
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	_, res = op.exchange(ctx, contract.CryptoClaim, body)
	if res.Outcome != 0 {
		return nil, res
	}
	return s.persistCandidate(ctx, candidate, trust)
}

func preservesReplacementWraps(before, after contract.AccessRecord, target contract.BindingTableRow) bool {
	if before.MaterialKind != after.MaterialKind || before.MaterialID != after.MaterialID || before.MaterialContextDigest != after.MaterialContextDigest || before.PackageCheck != after.PackageCheck || len(before.Wraps) != len(after.Wraps) {
		return false
	}
	digest, err := contract.PublicBindingDigest(target.Binding)
	if err != nil {
		return false
	}
	changed := false
	for i, row := range before.Wraps {
		out := after.Wraps[i]
		if row.SubjectKind == target.SubjectKind && row.SubjectID == target.SubjectID {
			if out.SubjectKind != target.SubjectKind || out.SubjectID != target.SubjectID || out.BindingID != target.Binding.BindingID || out.BindingSerial != target.Binding.BindingSerial || out.PublicBindingDigest != digest {
				return false
			}
			changed = true
			continue
		}
		if row.SubjectKind != out.SubjectKind || row.SubjectID != out.SubjectID || row.BindingID != out.BindingID || row.BindingSerial != out.BindingSerial || row.PublicBindingDigest != out.PublicBindingDigest || !bytes.Equal(row.RSACiphertext, out.RSACiphertext) {
			return false
		}
	}
	return changed
}

func (s *StateSession) replacementSuccessor(intent contract.RecipientReplacementIntent, p transitionPlan, after map[materialIdentity]contract.AccessRecord) (*StateSession, bool) {
	next := *s
	next.head.AuthKind = format.LifecycleAuth
	next.root.Snapshot = p.snapshot
	next.root.Transition = p.transition
	for index, id := range p.recipientPages {
		if id.IsZero() {
			continue
		}
		b, err := format.EncodeRecipientPage(*s.recipients[index])
		if err != nil {
			return nil, false
		}
		page, err := format.DecodeRecipientPage(b)
		if err != nil {
			return nil, false
		}
		page.Object = id
		for _, row := range page.Slots {
			if row != nil && row.RecipientID == intent.RecipientID {
				binding := intent.Successor
				row.CurrentBinding = &binding
			}
		}
		next.recipients[index] = &page
		body, err := format.EncodeRecipientPage(page)
		if err != nil {
			return nil, false
		}
		ref, err := format.Reference(format.RecipientKind, s.admission.domain, id, uint16(index), body)
		if err != nil {
			return nil, false
		}
		next.root.Recipients[index] = &ref
	}
	var recipientRefs []contract.Ref
	for _, ref := range next.root.Recipients {
		if ref != nil {
			recipientRefs = append(recipientRefs, *ref)
		}
	}
	recipientDescriptor, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: s.admission.domain, Refs: recipientRefs})
	if err != nil {
		return nil, false
	}
	next.root.CurrentAccess.Core.RecipientRefsDescriptor = recipientDescriptor
	var records []contract.AccessRecord
	changed := 0
	next.root.CurrentAccess.Core.AccessPageRefs = nil
	for index, page := range s.access {
		if page == nil {
			continue
		}
		if !p.accessPages[index].IsZero() {
			pageCopy := *page
			pageCopy.Object = p.accessPages[index]
			pageCopy.Records = slices.Clone(page.Records)
			for i, record := range pageCopy.Records {
				if output, ok := after[materialIdentity{record.MaterialKind, record.MaterialID}]; ok {
					pageCopy.Records[i] = output
					changed++
				}
			}
			page = &pageCopy
			next.access[index] = page
		}
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			return nil, false
		}
		ref, err := format.Reference(format.AccessKind, s.admission.domain, page.Object, page.Index, body)
		if err != nil {
			return nil, false
		}
		next.root.CurrentAccess.Core.AccessPageRefs = append(next.root.CurrentAccess.Core.AccessPageRefs, ref)
		records = append(records, page.Records...)
	}
	if changed != len(after) {
		return nil, false
	}
	slices.SortFunc(records, func(a, b contract.AccessRecord) int {
		return compareMaterial(a.MaterialKind, a.MaterialID, b.MaterialKind, b.MaterialID)
	})
	descriptor, err := contract.AccessRecordsDescriptor(s.admission.domain, records)
	if err != nil {
		return nil, false
	}
	next.root.CurrentAccess.Core.AccessRecordsDescriptor = descriptor
	if err := contract.AdvanceAccessGeneration(&next.root.CurrentAccess.Core, p.transition); err != nil {
		return nil, false
	}
	next.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(next.root.CurrentAccess.Core)
	if err != nil {
		return nil, false
	}
	return &next, true
}
