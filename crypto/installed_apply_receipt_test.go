package crypto

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

type installedReceiptFixture struct {
	f        applyTestFixture
	runtime  *Runtime
	owner    *ApplyCustody
	witness  *contract.GeneratedSupportTransition
	before   contract.MutationReceiptWindows
	revision contract.ID
	retained []contract.SupportRecord
}

func receiptHistoryRow(domain contract.ID, label string, success bool) contract.CompactMutationReceipt {
	row := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationApplyDeclaration, StateResult: contract.ReceiptStateSuccess, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical,
		DomainID: domain, OperationID: consumerID(label + " operation"), RequestIdentityDigest: consumerID(label + " request"), PredecessorRevisionID: consumerID(label + " previous"), RequestedRevisionID: consumerID(label + " revision"), ObservedRevisionID: consumerID(label + " revision"), CanonicalOutcome: contract.ReceiptCanonicalSelected,
		ChangedSubjects: contract.GeneratorDescriptor{Digest: consumerID(label + " subjects"), Length: 42, Count: 1}, CompleteResult: contract.GeneratorDescriptor{Digest: consumerID(label + " complete"), Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
	if !success {
		row.StateResult = contract.ReceiptStateEffectUnknown
		row.EffectSummary = contract.ReceiptEffectUnknown
		row.EvidenceCeiling = contract.ReceiptEvidenceProviderFacts
		row.CanonicalOutcome = contract.ReceiptCanonicalNotSelected
		row.ObservedRevisionID = row.PredecessorRevisionID
		row.UnknownCount = 1
		row.WarningBits = contract.ReceiptWarningPossibleLive
		row.SummaryCounts[contract.ReceiptEffectCount] = 1
		row.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 1
	}
	return row
}

func newInstalledReceiptFixture(t *testing.T, base applyTestFixture) installedReceiptFixture {
	t.Helper()
	return newInstalledReceiptFixtureWithWarnings(t, base, 0)
}

func newInstalledReceiptFixtureWithWarnings(t *testing.T, base applyTestFixture, warningBits uint8) installedReceiptFixture {
	t.Helper()
	return newInstalledReceiptFixtureWithRetained(t, base, warningBits, nil)
}

func installedReceiptIndexRecord(t *testing.T, windows contract.MutationReceiptWindows) contract.SupportRecord {
	t.Helper()
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := contract.MutationReceiptIndexBlobID(windows.DomainID, successes, failures, order)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema, BlobID: blob, Count: 1,
		TotalLength: uint64(len(body)), WholeDigest: contract.Hash(body), Payload: body})
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	return contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: fragment}
}

func newInstalledReceiptFixtureWithRetained(t *testing.T, base applyTestFixture, warningBits uint8, retained []contract.SupportRecord) installedReceiptFixture {
	t.Helper()
	f := cloneApplyFixture(t, base)
	f.deadline = time.Now().Add(time.Minute)
	f.q.Context.Expiry = uint64(f.deadline.UnixNano())
	ctx, cancel := context.WithDeadline(t.Context(), f.deadline)
	t.Cleanup(cancel)
	f.ctx = ctx
	domain := f.q.Context.DomainID
	before := contract.MutationReceiptWindows{DomainID: domain, Successes: []contract.CompactMutationReceipt{receiptHistoryRow(domain, "old success", true)}, Failures: []contract.CompactMutationReceipt{receiptHistoryRow(domain, "old failure", false)}}
	before.Order = []contract.ID{before.Successes[0].OperationID, before.Failures[0].OperationID}
	rows, err := before.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, installedReceiptIndexRecord(t, before))
	rows = append(rows, retained...)
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	var facts []contract.SupportRecordDigest
	for _, row := range rows {
		fact, err := contract.InspectSupportRecordDigest(domain, row)
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, fact)
	}
	support, err := contract.RequiredSupportDescriptorFromDigests(domain, facts)
	if err != nil {
		t.Fatal(err)
	}
	f.support = support
	ref, err := contract.DecodeRef(f.q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: domain, Refs: []contract.Ref{{Kind: contract.RecipientKind, Format: contract.CanonicalSchema, Domain: domain, Object: consumerID("receipt parent recipient page"), Digest: consumerID("receipt parent recipient digest"), Length: 1024}}})
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.AccessRecordsDescriptor(domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &contract.GeneratedSupportTransition{Schema: 1, DomainID: domain, BeforeSnapshot: ref.Object, BeforeSliceSnapshot: ref.Object, BeforeRootDigest: ref.Digest, BeforeSupport: support, Records: rows, RecordFacts: facts,
		BeforeAccess: contract.CurrentAccessCore{CurrentControl: f.control.CurrentControl, RecipientRefsDescriptor: recipients, AccessRecordsDescriptor: access}}
	f.q.Context.CurrentAccessRoot, err = contract.AccessRoot(w.BeforeAccess)
	if err != nil {
		t.Fatal(err)
	}
	r := newConsumerRuntime(t, f.route)
	revision := before.Successes[0].ObservedRevisionID
	owner, err := NewApplyCustody(r, f.q, f.control, f.current, nil, f.route.CredentialRoute(), consumerID("source file"), nil, support, w, revision, before, warningBits, f.deadline)
	if err != nil {
		t.Fatal("production apply receipt custody", err)
	}
	t.Cleanup(owner.Close)
	return installedReceiptFixture{f: f, runtime: r, owner: owner, witness: w, before: before, revision: revision, retained: slices.Clone(retained)}
}

func (f installedReceiptFixture) prepared(t *testing.T) (contract.CryptoApplyReceiptAdmission, contract.CryptoFreezeRequest) {
	t.Helper()
	compared := applyCompare(t, f.runtime, f.f)
	plan := applyPlan(f.f)
	plan.Pages = []contract.IdentityPage{{Kind: contract.AccessKind, Index: 0, Object: consumerID("receipt candidate access page")}}
	prepared := applyPrepare(t, f.runtime, f.f, compared, plan)
	freeze := applyFreezeRequest(t, f.f, compared, plan, prepared)
	row := receiptHistoryRow(f.f.q.Context.DomainID, "new selected", true)
	row.WarningBits = uint64(f.owner.warningBits) << 2
	row.OperationID = plan.Operation
	row.PredecessorRevisionID = f.revision
	row.RequestedRevisionID = plan.Revision
	row.ObservedRevisionID = plan.Revision
	var duties, hazards []contract.SupportRecord
	for _, retained := range f.retained {
		switch retained.Kind {
		case contract.GeneratedDutySupportKind:
			duties = append(duties, retained)
		case contract.GeneratedHazardSupportKind:
			hazards = append(hazards, retained)
		}
	}
	liveDuties, err := contract.MutationResultRecordDescriptor(contract.MutationResultDuties, f.f.q.Context.DomainID, duties)
	if err != nil {
		t.Fatal(err)
	}
	liveHazards, err := contract.MutationResultRecordDescriptor(contract.MutationResultHazards, f.f.q.Context.DomainID, hazards)
	if err != nil {
		t.Fatal(err)
	}
	row.SummaryCounts[contract.ReceiptDutyCount] = uint32(len(duties))
	row.SummaryCounts[contract.ReceiptHazardCount] = uint32(len(hazards))
	if len(hazards) != 0 {
		row.WarningBits |= contract.ReceiptWarningPossibleLive
	}
	after, err := contract.AppendMutationReceipt(f.before, row)
	if err != nil {
		t.Fatal(err)
	}
	records, err := after.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, installedReceiptIndexRecord(t, after))
	records = append(slices.Clone(f.retained), records...)
	slices.SortFunc(records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	support, err := contract.RequiredSupportDescriptor(f.f.q.Context.DomainID, records)
	if err != nil {
		t.Fatal("successor receipt support", err)
	}
	view, err := contract.InspectPublicState(freeze.CandidatePublicState, f.f.q.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.witness.AccessAfter(f.f.q.Intent, f.f.q.Current, prepared.Rows)
	if err != nil {
		t.Fatal(err)
	}
	core, _, err := f.witness.AccessCoreAfter(access, plan)
	if err != nil {
		t.Fatal(err)
	}
	public.AccessRoot, err = contract.AccessRoot(core)
	if err != nil {
		t.Fatal(err)
	}
	public.RequiredSupport = support
	freeze.CandidatePublicState, err = contract.EncodePublicState(public)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := contract.PublicStateDescriptor(public)
	if err != nil {
		t.Fatal(err)
	}
	return contract.CryptoApplyReceiptAdmission{OperationKind: contract.OperationApplyDeclaration, ChangedSubjects: row.ChangedSubjects, LiveDuties: liveDuties, LiveHazards: liveHazards, Context: f.f.q.Context, OperationRef: compared.OperationRef, IdentityPlanDescriptor: freeze.IdentityPlanDescriptor,
		Delta: contract.MutationReceiptDelta{DomainID: f.f.q.Context.DomainID, OperationKind: contract.OperationApplyDeclaration, AddedCount: 1, Before: f.before, After: after}, AfterSupport: support, CandidatePublicState: candidate}, freeze
}

func freezeInstalledReceipt(t *testing.T, f installedReceiptFixture, q contract.CryptoFreezeRequest) contract.CryptoResponse {
	t.Helper()
	body, err := contract.EncodeCryptoFreezeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	return f.owner.Exchange(f.f.ctx, contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoFreeze, RequestID: consumerID("installed receipt freeze"), CustodyInstanceID: f.owner.InstanceID(), Body: body})
}

// full_only: false
func TestInstalledApplyReceiptRequiredBeforeFreeze(t *testing.T) {
	applyBase := applyFixture(t, false)
	accessBase := exactRetainedFixture(t)
	for _, operation := range []string{"apply", "recipient-retirement", "envelope-rekey"} {
		for _, exchange := range []string{"owner", "runtime"} {
			t.Run(operation+"/"+exchange, func(t *testing.T) {
				var r *Runtime
				var owner *ApplyCustody
				var ctx context.Context
				var freeze contract.CryptoFreezeRequest
				switch operation {
				case "apply":
					f := newInstalledReceiptFixture(t, applyBase)
					r, owner, ctx = f.runtime, f.owner, f.f.ctx
					_, freeze = f.prepared(t)
				case "recipient-retirement":
					v := retirementFixture(t, accessBase, "mixed")
					r, owner = retirementOwner(t, &v)
					ctx = v.f.ctx
					comparison := retirementCompare(t, r, v.f)
					plan := retirementPlan(t, v.f)
					prepared := retirementPrepare(t, r, v.f, comparison, plan)
					freeze = retirementFreeze(t, v, r.apply, comparison, plan, prepared)
				case "envelope-rekey":
					f := secretAccessFixture(t, accessBase, contract.OperationEnvelopeRekey)
					r, owner = secretAccessOwner(t, &f, nil)
					ctx = f.ctx
					comparison := secretAccessCompare(t, r, f)
					plan := secretAccessPlan(f)
					prepared := secretAccessPrepare(t, r, f, comparison, plan)
					freeze = secretAccessFreeze(t, f, r.apply, comparison, plan, prepared)
				}
				a := r.apply
				after, err := a.supportTransition.SupportAfter(a.plan, a.request.Intent)
				if err != nil {
					t.Fatal(err)
				}
				support, err := contract.RequiredSupportDescriptorFromDigests(freeze.Context.DomainID, after.Facts)
				if err != nil {
					t.Fatal(err)
				}
				view, err := contract.InspectPublicState(freeze.CandidatePublicState, freeze.Context.DomainID)
				if err != nil {
					t.Fatal(err)
				}
				public, err := view.Own()
				if err != nil {
					t.Fatal(err)
				}
				public.RequiredSupport = support
				freeze.CandidatePublicState, err = contract.EncodePublicState(public)
				if err != nil {
					t.Fatal(err)
				}
				candidate, err := contract.PublicStateDescriptor(public)
				if err != nil {
					t.Fatal(err)
				}
				exclusions, err := contract.InspectExclusions(freeze.Exclusions, freeze.Context.DomainID)
				if err != nil {
					t.Fatal(err)
				}
				facts := contract.CryptoFactsPreimage{CustodyInstanceID: r.InstanceID(), OperationRef: freeze.OperationRef, Context: freeze.Context, ComparisonOrCoverageDigest: a.comparisonDigest,
					IdentityPlanDescriptor: freeze.IdentityPlanDescriptor, CandidatePublicStateDescriptor: candidate, CanonicalRowsDescriptor: freeze.CanonicalRowsDescriptor, ExclusionDescriptor: exclusions.Descriptor}
				digest, err := contract.CryptoFactsDigest(facts)
				if err != nil {
					t.Fatal(err)
				}
				claim := contract.CryptoClaimRequest{OperationRef: freeze.OperationRef, Context: freeze.Context, IdentityPlanDescriptor: freeze.IdentityPlanDescriptor,
					CandidatePublicStateDescriptor: candidate, CanonicalRowsDescriptor: freeze.CanonicalRowsDescriptor, ExclusionDescriptor: exclusions.Descriptor, FactDigest: digest}
				body, err := contract.EncodeCryptoFreezeRequest(freeze)
				if err != nil {
					t.Fatal(err)
				}
				call := owner.Exchange
				if exchange == "runtime" {
					call = r.Exchange
				}
				request := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoFreeze, RequestID: consumerID("unbound receipt freeze"), CustodyInstanceID: r.InstanceID(), Body: body}
				if reply := call(ctx, request); reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
					t.Error("installed custody froze a candidate without receipt binding", reply.ResultCode)
				}
				request.Kind, request.RequestID = contract.CryptoClaim, consumerID("unbound receipt claim")
				request.Body, err = contract.EncodeCryptoClaimRequest(claim)
				if err != nil {
					t.Fatal(err)
				}
				if reply := call(ctx, request); reply.ResultCode != contract.CryptoAlreadyUsed || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
					t.Error("claim bypassed the refused receipt binding", reply.ResultCode)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledApplyReceiptPinsExactPreparedSupportAndCandidate(t *testing.T) {
	base := applyFixture(t, false)
	f := newInstalledReceiptFixture(t, base)
	admission, freeze := f.prepared(t)
	if err := f.owner.BindReceipt(f.f.ctx, admission); err != nil {
		t.Fatal("exact receipt binding", err)
	}
	admission.Delta.Before.Order[0], admission.Delta.Before.Order[1] = admission.Delta.Before.Order[1], admission.Delta.Before.Order[0]
	admission.Delta.After.Order[0], admission.Delta.After.Order[1] = admission.Delta.After.Order[1], admission.Delta.After.Order[0]
	admission.AfterSupport.Digest[0] ^= 1
	admission.CandidatePublicState.Digest[0] ^= 1
	admission.Delta.After.Successes[len(admission.Delta.After.Successes)-1].RequestIdentityDigest[0] ^= 1
	reply := freezeInstalledReceipt(t, f, freeze)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("caller mutation changed pinned final facts", reply.ResultCode)
	}
	fact, err := contract.DecodeCryptoFreezeResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	public, err := contract.InspectPublicState(freeze.CandidatePublicState, f.f.q.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := contract.InspectExclusions(freeze.Exclusions, f.f.q.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	claim := contract.CryptoClaimRequest{OperationRef: freeze.OperationRef, Context: freeze.Context, IdentityPlanDescriptor: freeze.IdentityPlanDescriptor, CandidatePublicStateDescriptor: public.Descriptor, CanonicalRowsDescriptor: freeze.CanonicalRowsDescriptor, ExclusionDescriptor: exclusions.Descriptor, FactDigest: fact.FactDigest}
	body, err := contract.EncodeCryptoClaimRequest(claim)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoClaim, RequestID: consumerID("installed receipt claim"), CustodyInstanceID: f.owner.InstanceID(), Body: body}
	if result := f.owner.Exchange(f.f.ctx, request); result.ResultCode != contract.CryptoSuccess {
		t.Fatal("exact receipt claim", result.ResultCode)
	}
}

// full_only: false
func TestInstalledApplyReceiptRejectsChangedPrivateParentFacts(t *testing.T) {
	base := applyFixture(t, false)
	for _, condition := range []string{"context", "operation reference", "identity plan", "before success", "before failure", "before order", "after order", "predecessor revision", "operation", "domain", "requested revision", "observed revision", "plan hole", "failure append", "two appends", "unearned possible live warning", "operation kind", "changed subjects", "live duties", "live hazards", "forged successor support", "busy"} {
		t.Run(condition, func(t *testing.T) {
			f := newInstalledReceiptFixture(t, base)
			q, _ := f.prepared(t)
			switch condition {
			case "forged successor support":
				// This remains a well-shaped descriptor; it is not the support
				// derived from the accepted work and actual receipt delta.
				q.AfterSupport.Digest[0] ^= 1
			case "operation kind":
				q.OperationKind = contract.OperationEnvelopeRekey
			case "changed subjects":
				q.ChangedSubjects.Digest[0] ^= 1
			case "live duties":
				q.LiveDuties.Digest[0] ^= 1
			case "live hazards":
				q.LiveHazards.Digest[0] ^= 1
			case "context":
				q.Context.SessionID = consumerID("other receipt session")
			case "operation reference":
				q.OperationRef = consumerID("other receipt reference")
			case "identity plan":
				q.IdentityPlanDescriptor.Digest[0] ^= 1
			case "before order":
				q.Delta.Before.Order = slices.Clone(q.Delta.Before.Order)
				q.Delta.Before.Order[0], q.Delta.Before.Order[1] = q.Delta.Before.Order[1], q.Delta.Before.Order[0]
				row := q.Delta.After.Successes[len(q.Delta.After.Successes)-1]
				var err error
				q.Delta.After, err = contract.AppendMutationReceipt(q.Delta.Before, row)
				if err != nil {
					t.Fatal("alternate valid order", err)
				}
				if _, err := contract.MutationReceiptDeltaDigest(q.Delta); err != nil {
					t.Fatal("alternate valid delta", err)
				}
			case "after order":
				q.Delta.After.Order = slices.Clone(q.Delta.After.Order)
				q.Delta.After.Order[0], q.Delta.After.Order[1] = q.Delta.After.Order[1], q.Delta.After.Order[0]
			case "before success":
				q.Delta.Before.Successes = slices.Clone(q.Delta.Before.Successes)
				q.Delta.Before.Successes[0].RequestIdentityDigest[0] ^= 1
			case "before failure":
				q.Delta.Before.Failures = slices.Clone(q.Delta.Before.Failures)
				q.Delta.Before.Failures[0].RequestIdentityDigest[0] ^= 1
			case "predecessor revision":
				q.Delta.After.Successes[len(q.Delta.After.Successes)-1].PredecessorRevisionID = consumerID("other receipt predecessor")
			case "operation":
				q.Delta.After.Successes[len(q.Delta.After.Successes)-1].OperationID = consumerID("other receipt operation")
			case "domain":
				q.Delta.DomainID = consumerID("other receipt domain")
			case "requested revision":
				q.Delta.After.Successes[len(q.Delta.After.Successes)-1].RequestedRevisionID = consumerID("other requested receipt revision")
			case "observed revision":
				q.Delta.After.Successes[len(q.Delta.After.Successes)-1].ObservedRevisionID = consumerID("other observed receipt revision")
			case "plan hole":
				q.Delta.After.Successes[len(q.Delta.After.Successes)-1].RequestIdentityDigest = contract.ID{}
			case "failure append":
				row := receiptHistoryRow(q.Delta.DomainID, "new failure", false)
				row.OperationID = f.runtime.apply.plan.Operation
				q.Delta.After, _ = contract.AppendMutationReceipt(q.Delta.Before, row)
			case "two appends":
				row := receiptHistoryRow(q.Delta.DomainID, "second selected", true)
				q.Delta.After, _ = contract.AppendMutationReceipt(q.Delta.After, row)
			case "unearned possible live warning":
				q.Delta.After.Successes[len(q.Delta.After.Successes)-1].WarningBits |= contract.ReceiptWarningPossibleLive
			case "busy":
				f.runtime.mu.Lock()
				f.runtime.apply.busy = true
				f.runtime.mu.Unlock()
			}
			if err := f.owner.BindReceipt(f.f.ctx, q); err == nil {
				t.Fatal("changed receipt parent facts admitted")
			}
		})
	}
}

// full_only: false
func TestInstalledApplyReceiptRejectsWrongLifetimeAndReuse(t *testing.T) {
	base := applyFixture(t, false)
	t.Run("before prepare", func(t *testing.T) {
		f := newInstalledReceiptFixture(t, base)
		if err := f.owner.BindReceipt(f.f.ctx, contract.CryptoApplyReceiptAdmission{}); err == nil {
			t.Fatal("unprepared receipt admitted")
		}
	})
	for _, condition := range []string{"second bind", "after freeze", "closed", "cancelled", "different deadline", "replacement"} {
		t.Run(condition, func(t *testing.T) {
			f := newInstalledReceiptFixture(t, base)
			q, freeze := f.prepared(t)
			ctx := f.f.ctx
			switch condition {
			case "second bind", "after freeze":
				if err := f.owner.BindReceipt(ctx, q); err != nil {
					t.Fatal(err)
				}
				if condition == "after freeze" {
					if reply := freezeInstalledReceipt(t, f, freeze); reply.ResultCode != contract.CryptoSuccess {
						t.Fatal(reply.ResultCode)
					}
				}
			case "closed":
				f.owner.Close()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "different deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, f.f.deadline.Add(-time.Second))
				defer cancel()
			case "replacement":
				f.runtime.retireApply()
				next := f.f.q
				next.Context.AdmissionID = consumerID("new installed receipt admission")
				next.Context.SessionID = consumerID("new installed receipt session")
				if err := f.runtime.admitApply(next, f.f.control, f.f.current, nil, f.f.route.CredentialRoute(), f.f.accepted, nil, f.f.support, f.f.deadline, f.witness); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.owner.BindReceipt(ctx, q); err == nil {
				t.Fatal("wrong lifetime or repeated binding admitted")
			}
		})
	}
	synctest.Test(t, func(t *testing.T) {
		f := newInstalledReceiptFixture(t, base)
		q, _ := f.prepared(t)
		time.Sleep(time.Minute + time.Second)
		if err := f.owner.BindReceipt(f.f.ctx, q); err == nil {
			t.Fatal("expired receipt parent admitted")
		}
	})
}

// full_only: false
func TestInstalledApplyReceiptFreezeRejectsSupportAndCandidateChanges(t *testing.T) {
	base := applyFixture(t, false)
	for _, condition := range []string{"support", "entry", "access"} {
		t.Run(condition, func(t *testing.T) {
			f := newInstalledReceiptFixture(t, base)
			q, freeze := f.prepared(t)
			if err := f.owner.BindReceipt(f.f.ctx, q); err != nil {
				t.Fatal(err)
			}
			view, err := contract.InspectPublicState(freeze.CandidatePublicState, f.f.q.Context.DomainID)
			if err != nil {
				t.Fatal(err)
			}
			public, err := view.Own()
			if err != nil {
				t.Fatal(err)
			}
			switch condition {
			case "support":
				public.RequiredSupport.Digest[0] ^= 1
			case "entry":
				public.Rows[0].EntryDigest[0] ^= 1
			case "access":
				public.AccessRoot[0] ^= 1
			}
			freeze.CandidatePublicState, err = contract.EncodePublicState(public)
			if err != nil {
				t.Fatal(err)
			}
			if result := freezeInstalledReceipt(t, f, freeze); result.ResultCode == contract.CryptoSuccess || len(result.Body) != 0 {
				t.Fatal("changed frozen receipt candidate accepted", result.ResultCode)
			}
		})
	}
}

// full_only: false
func TestInstalledApplyCustodyCopiesPredecessorWindowMetadata(t *testing.T) {
	f := newInstalledReceiptFixture(t, applyFixture(t, false))
	oldSuccess, oldFailure := f.before.Successes[0], f.before.Failures[0]
	f.before.Successes[0].RequestIdentityDigest[0] ^= 1
	f.before.Failures[0].RequestIdentityDigest[0] ^= 1
	if f.owner.before.Successes[0] != oldSuccess || f.owner.before.Failures[0] != oldFailure {
		t.Fatal("constructor retained mutable window metadata")
	}
	if !bytes.Equal(f.owner.admission.request.SealedInputs[0].EnvelopeBytes, f.f.q.SealedInputs[0].EnvelopeBytes) {
		t.Fatal("constructor changed admitted source")
	}
}

// full_only: false
func TestInstalledApplyReceiptPinsInheritedDomainWarnings(t *testing.T) {
	base := applyFixture(t, false)
	for _, condition := range []string{"exact", "erased summary", "added summary", "unearned effect warning"} {
		t.Run(condition, func(t *testing.T) {
			inherited := uint8(31)
			if condition == "added summary" {
				inherited = 1
			}
			f := newInstalledReceiptFixtureWithWarnings(t, base, inherited)
			q, freeze := f.prepared(t)
			row := &q.Delta.After.Successes[len(q.Delta.After.Successes)-1]
			switch condition {
			case "exact":
				if row.WarningBits != 124 {
					t.Fatal("fixture lost exact packed domain31 summary", row.WarningBits)
				}
			case "erased summary":
				row.WarningBits = 0
			case "added summary":
				row.WarningBits = 124
			case "unearned effect warning":
				row.WarningBits = 125
			}
			err := f.owner.BindReceipt(f.f.ctx, q)
			if condition != "exact" {
				if err == nil {
					t.Fatal("receipt warnings differed from admitted predecessor summary or invented effects")
				}
				return
			}
			if err != nil {
				t.Fatal("exact inherited warning summary refused", err)
			}
			if reply := freezeInstalledReceipt(t, f, freeze); reply.ResultCode != contract.CryptoSuccess {
				t.Fatal("packed inherited warnings changed frozen support", reply.ResultCode)
			}
		})
	}
}

// full_only: false
func TestInstalledApplyReceiptPinsNonemptyRetainedWork(t *testing.T) {
	base := applyFixture(t, false)
	duty, _ := generatedCanonicalFixture(t, uint8(contract.GeneratedDutySupportKind))
	hazard, _ := generatedCanonicalFixture(t, uint8(contract.GeneratedHazardSupportKind))
	for _, retained := range []struct {
		name            string
		rows            []contract.SupportRecord
		duties, hazards uint32
		conditions      []string
	}{
		{"duty-only", []contract.SupportRecord{duty.Owner}, 1, 0, []string{"exact", "same-count-duty", "forged-pending"}},
		{"hazard-only", []contract.SupportRecord{hazard.Owner}, 0, 1, []string{"exact", "same-count-hazard", "lost-possible-live"}},
		{"duty-and-hazard", []contract.SupportRecord{duty.Owner, hazard.Owner}, 1, 1, []string{"exact", "same-count-duty", "same-count-hazard", "forged-pending", "lost-possible-live"}},
	} {
		t.Run(retained.name, func(t *testing.T) {
			for _, condition := range retained.conditions {
				t.Run(condition, func(t *testing.T) {
					f := newInstalledReceiptFixtureWithRetained(t, base, 0, retained.rows)
					q, freeze := f.prepared(t)
					row := &q.Delta.After.Successes[len(q.Delta.After.Successes)-1]
					var warnings uint64
					if retained.hazards != 0 {
						warnings = contract.ReceiptWarningPossibleLive
					}
					if q.LiveDuties.Count != retained.duties || q.LiveHazards.Count != retained.hazards || row.StateResult != contract.ReceiptStateSuccess || row.WarningBits != warnings {
						t.Fatal("inherited work changed the completed operation result or its exact live facts")
					}
					switch condition {
					case "same-count-duty":
						q.LiveDuties.Digest[0] ^= 1
					case "same-count-hazard":
						q.LiveHazards.Digest[0] ^= 1
					case "forged-pending":
						row.StateResult = contract.ReceiptStateRetirementPending
					case "lost-possible-live":
						row.WarningBits &^= contract.ReceiptWarningPossibleLive
					}
					err := f.owner.BindReceipt(f.f.ctx, q)
					if condition != "exact" {
						if err != ErrAdmission {
							t.Fatal("substituted inherited receipt facts admitted", err)
						}
						return
					}
					if err != nil {
						t.Fatal("exact inherited receipt admission", err)
					}
					reply := freezeInstalledReceipt(t, f, freeze)
					if reply.ResultCode != contract.CryptoSuccess {
						t.Fatal("inherited receipt lost its exact support through Freeze", reply.ResultCode)
					}
					for _, original := range retained.rows {
						found := slices.IndexFunc(f.witness.Records, func(row contract.SupportRecord) bool {
							return row.Kind == original.Kind && row.RecordID == original.RecordID
						})
						if found < 0 || !bytes.Equal(f.witness.Records[found].Body, original.Body) {
							t.Fatal("receipt binding changed inherited work bytes")
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestInstalledApplyCustodyAuthenticatesCompletePredecessorReceiptWindows(t *testing.T) {
	base := applyFixture(t, false)
	for _, condition := range []string{"exact", "unavailable-index-body", "omit-success", "omit-failure", "substitute-success", "substitute-failure", "reorder-classes"} {
		t.Run(condition, func(t *testing.T) {
			f := newInstalledReceiptFixture(t, base)
			before := f.before
			before.Successes = slices.Clone(before.Successes)
			before.Failures = slices.Clone(before.Failures)
			before.Order = slices.Clone(before.Order)
			switch condition {
			case "omit-success":
				before.Successes = nil
				before.Order = before.Order[1:]
			case "omit-failure":
				before.Failures = nil
				before.Order = before.Order[:1]
			case "substitute-success":
				before.Successes[0].RequestIdentityDigest[0] ^= 1
			case "substitute-failure":
				before.Failures[0].RequestIdentityDigest[0] ^= 1
			case "reorder-classes":
				before.Order[0], before.Order[1] = before.Order[1], before.Order[0]
			}
			if _, err := before.Descriptors(); err != nil {
				t.Fatal("fixture did not preserve a complete well-formed caller window", err)
			}
			if condition == "unavailable-index-body" {
				f.witness.Records = slices.Clone(f.witness.Records)
				for i := range f.witness.Records {
					if f.witness.Records[i].Kind == contract.GeneratedFragmentSupportKind {
						f.witness.Records[i].Body = nil
					}
				}
			}
			runtime := newConsumerRuntime(t, f.f.route)
			owner, err := NewApplyCustody(runtime, f.f.q, f.f.control, f.f.current, nil, f.f.route.CredentialRoute(), consumerID("source file"), nil,
				f.f.support, f.witness, f.revision, before, 0, f.f.deadline)
			if owner != nil {
				defer owner.Close()
			}
			if condition == "exact" || condition == "unavailable-index-body" {
				if err != nil || owner == nil {
					t.Fatal("exact predecessor receipt windows refused", err)
				}
				return
			}
			if err != ErrAdmission || owner != nil {
				t.Fatal("caller receipt windows replaced authenticated predecessor history", err, owner != nil)
			}
			if runtime.apply != nil || runtime.slot != nil || f.f.route.privateCalls != 0 {
				t.Fatal("refused receipt constructor retained private admission or reached a private operation")
			}
		})
	}
}

func installedReceiptHistoryWitness(t *testing.T, f *applyTestFixture, witness *contract.GeneratedSupportTransition, windows contract.MutationReceiptWindows) {
	t.Helper()
	rows, err := windows.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, installedReceiptIndexRecord(t, windows))
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	facts := make([]contract.SupportRecordDigest, len(rows))
	for i, row := range rows {
		facts[i], err = contract.InspectSupportRecordDigest(windows.DomainID, row)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.support, err = contract.RequiredSupportDescriptorFromDigests(windows.DomainID, facts)
	if err != nil {
		t.Fatal(err)
	}
	witness.BeforeSupport, witness.Records, witness.RecordFacts = f.support, rows, facts
	if err := witness.Inspect(); err != nil {
		t.Fatal("receipt history fixture did not preserve admitted support", err)
	}
}

// full_only: false
func TestAccessMutationCustodyAuthenticatesPredecessorReceiptWindows(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, operation := range []string{"envelope-rekey", "recipient-retirement"} {
		for _, condition := range []string{"exact", "omit-success", "omit-failure", "substitute-row", "reorder-successes", "reorder-classes"} {
			t.Run(operation+"/"+condition, func(t *testing.T) {
				var f applyTestFixture
				var retired retirementTestFixture
				if operation == "envelope-rekey" {
					f = secretAccessFixture(t, base, contract.OperationEnvelopeRekey)
				} else {
					retired = retirementFixture(t, base, "mixed")
					f = retired.f
				}
				witness := secretAccessWitness(t, &f)
				domain := f.q.Context.DomainID
				actual := contract.MutationReceiptWindows{DomainID: domain,
					Successes: []contract.CompactMutationReceipt{receiptHistoryRow(domain, "first success", true), receiptHistoryRow(domain, "second success", true)},
					Failures:  []contract.CompactMutationReceipt{receiptHistoryRow(domain, "middle failure", false)}}
				actual.Order = []contract.ID{actual.Successes[0].OperationID, actual.Failures[0].OperationID, actual.Successes[1].OperationID}
				installedReceiptHistoryWitness(t, &f, witness, actual)
				before := contract.MutationReceiptWindows{DomainID: domain, Successes: slices.Clone(actual.Successes), Failures: slices.Clone(actual.Failures), Order: slices.Clone(actual.Order)}
				switch condition {
				case "omit-success":
					before.Successes = before.Successes[1:]
					before.Order = before.Order[1:]
				case "omit-failure":
					before.Failures = nil
					before.Order = []contract.ID{actual.Successes[0].OperationID, actual.Successes[1].OperationID}
				case "substitute-row":
					before.Failures[0].RequestIdentityDigest[0] ^= 1
				case "reorder-successes":
					before.Successes[0], before.Successes[1] = before.Successes[1], before.Successes[0]
					before.Order = []contract.ID{actual.Successes[1].OperationID, actual.Failures[0].OperationID, actual.Successes[0].OperationID}
				case "reorder-classes":
					before.Order = []contract.ID{actual.Successes[0].OperationID, actual.Successes[1].OperationID, actual.Failures[0].OperationID}
				}
				if _, err := before.Descriptors(); err != nil {
					t.Fatal("caller window damage broke shape before authenticated comparison", err)
				}
				runtime := newConsumerRuntime(t, f.route)
				var owner *ApplyCustody
				var err error
				if operation == "envelope-rekey" {
					owner, err = NewEnvelopeRekeyCustody(runtime, f.q, f.control, f.current, f.route.CredentialRoute(), nil, f.support, witness,
						consumerID("access mutation predecessor"), before, 0, f.deadline)
				} else {
					owner, err = NewRecipientRetirementCustody(runtime, f.q, f.control, f.current, retired.slot, f.route.CredentialRoute(), retired.before, f.support, witness,
						consumerID("access mutation predecessor"), before, 0, f.deadline)
				}
				if owner != nil {
					defer owner.Close()
				}
				if condition == "exact" {
					if err != nil || owner == nil {
						t.Fatal("exact access-mutation receipt history refused", err)
					}
					return
				}
				if err != ErrAdmission || owner != nil {
					t.Fatal("access mutation replaced authenticated receipt history", err, owner != nil)
				}
				if runtime.apply != nil || runtime.slot != nil || f.route.privateCalls != 0 {
					t.Fatal("refused access receipt constructor retained admission or reached a private operation")
				}
			})
		}
	}
}
