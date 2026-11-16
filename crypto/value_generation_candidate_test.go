package crypto

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/internal/custody"
)

func generatedReadyCandidate(t *testing.T, f generatedRuntimeFixture) (*Runtime, generatedCandidate, contract.CryptoGeneratedFreezeRequest) {
	t.Helper()
	r := f.reservationRuntime(t)
	operation := generatedCompare(t, r, f)
	generatedPlanParts(t, r, f, operation)
	result, uses := generatedFinishPlanWithUses(t, r, f, operation)
	candidate := generatedPlanCandidate(t, f, result)
	return r, candidate, generatedCandidateRequest(t, f, operation, candidate, nil, uses)
}

func generatedFreeze(t *testing.T, r *Runtime, q contract.CryptoGeneratedFreezeRequest) contract.CryptoResponse {
	t.Helper()
	body, err := contract.EncodeCryptoGeneratedFreezeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	return applyCall(r, context.Background(), contract.CryptoFreeze, body)
}

func generatedRewriteHead(t *testing.T, c *generatedCandidate, mutate func(*format.HeadCore)) {
	t.Helper()
	head, err := format.DecodeHeadCore(c.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&head)
	c.HeadCore, err = format.EncodeHeadCore(head)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := format.DecodeConditionalPlan(c.Conditional)
	if err != nil {
		t.Fatal(err)
	}
	conditional.HeadCore = contract.Hash(c.HeadCore)
	c.Conditional, err = format.EncodeConditionalPlan(conditional)
	if err != nil {
		t.Fatal(err)
	}
	c.Subject.HeadCoreDigest, c.Subject.ConditionalPlanDigest = contract.Hash(c.HeadCore), contract.Hash(c.Conditional)
}

// full_only: false
func TestGeneratedCandidateUsesSigningInterpretationNotTrustBasis(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	f.base.control.TrustInterpretationID = consumerID("separate current trust interpretation")
	f.reservation.Session.Control = f.base.control
	for _, signing := range []bool{true, false} {
		r, candidate, _ := generatedReadyCandidate(t, f)
		interpretation := f.base.control.TrustInterpretationID
		want := contract.CryptoInvalidAdmission
		if signing {
			interpretation = f.base.control.NormalSigning.Binding.Interpretation
			want = contract.CryptoSuccess
		}
		generatedRewriteHead(t, &candidate, func(head *format.HeadCore) { head.Interpretation = interpretation })
		if got := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); got != want {
			t.Fatalf("signing interpretation=%t: got %v, want %v", signing, got, want)
		}
	}
}

// full_only: false
func TestGeneratedDeleteCandidatePreservesItsFrozenOriginalTargetContract(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		base := generatedDeleteProducerFixture(t, recovery)
		for _, kind := range []uint8{contract.GeneratedDutyRetirement, contract.GeneratedDutyUnselectedCleanup} {
			f := generatedSelectDeleteProducer(t, base, kind)
			p := &f.producer.Producer
			x := p.Expected.Template
			f.compare.Purpose, f.compare.ParentPlan = 1, contract.GeneratedParentPlan(f.compare.Parent)
			f.compare.Parent, f.compare.ParentPlan.RequestIdentityDigest = contract.GeneratedParentRecord{}, contract.ID{}
			var err error
			f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			f.reservation = generatedReservationAdmissionInput{Session: f.producer.Session, Plan: f.producer.Plan,
				Phase: f.producer.Phase, Target: f.producer.Target, ControlledPredecessor: f.producer.ControlledPredecessor}
			r := f.reservationRuntime(t)
			frozen := *f.reservation.Target
			if r.generated.purpose.reservation.target == f.reservation.Target || *r.generated.purpose.reservation.target != frozen {
				t.Fatal("delete admission did not own the exact target")
			}
			f.reservation.Target.ResourceDigest = consumerID("changed caller target after admission")
			if *r.generated.purpose.reservation.target != frozen {
				t.Fatal("caller mutation changed the frozen target")
			}
			for _, change := range []string{"none", "delete contract", "replacement original contract", "changed target", "changed original attempt"} {
				duty := p.Duty
				target := frozen
				switch change {
				case "delete contract":
					duty.ResultContractID = x.ResultContractID
				case "replacement original contract":
					target.ResultContractID = consumerID("replacement original contract")
					duty.ResultContractID = target.ResultContractID
				case "changed target":
					target.ResourceDigest = consumerID("replacement candidate token")
				case "changed original attempt":
					duty.OriginalAttemptID = consumerID("replacement candidate original attempt")
				}
				targetBody, err := contract.EncodeGeneratorTarget(target)
				if err != nil {
					t.Fatal(err)
				}
				duty.Target, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{targetBody})
				if err != nil {
					t.Fatal(err)
				}
				attemptBody, err := contract.EncodeGeneratedAttemptRecord(p.Attempt)
				if err != nil {
					t.Fatal(err)
				}
				dutyBody, err := contract.EncodeGeneratedDutyRecord(duty)
				if err != nil {
					t.Fatal(err)
				}
				candidate := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{Purpose: f.reservation.Phase.TransitionKind,
					OwnerID: duty.DutyID, LineageID: x.LineageID, AttemptID: x.AttemptID, ResultID: x.ResultID,
					DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ResultContractID: x.ResultContractID,
					ResultVector: f.reservation.Phase.Evidence, CapacityReservation: duty.CapacityReservation},
					SupportRecords: []contract.SupportRecord{{Kind: 9, RecordID: x.AttemptID, Body: attemptBody},
						{Kind: 10, RecordID: duty.DutyID, Body: dutyBody}}}
				want := change == "none" || change == "delete contract" && kind == contract.GeneratedDutyRetirement
				if got := r.generated.candidateDeleteReservationMatches(candidate); got != want {
					t.Fatalf("candidate kind=%d recovery=%t change=%s: got %t, want %t", kind, recovery, change, got, want)
				}
			}
			r.retireGenerated()
		}
	}
}

// full_only: false
func TestGeneratedCandidateRejectsChangedPrivateFacts(t *testing.T) {
	f := generatedRuntimePlanFixture(t, true)
	for _, test := range []struct {
		name   string
		mutate func(*generatedCandidate)
	}{
		{"phase", func(c *generatedCandidate) { c.Subject.PhaseID = consumerID("another phase") }},
		{"request identity", func(c *generatedCandidate) { c.Subject.RequestIdentityDigest = consumerID("another request") }},
		{"head control", func(c *generatedCandidate) {
			generatedRewriteHead(t, c, func(h *format.HeadCore) { h.Trust = consumerID("another trust") })
		}},
		{"head revision", func(c *generatedCandidate) {
			generatedRewriteHead(t, c, func(h *format.HeadCore) { h.Revision = consumerID("another revision") })
		}},
		{"head snapshot", func(c *generatedCandidate) {
			generatedRewriteHead(t, c, func(h *format.HeadCore) { h.Root.Object = consumerID("another snapshot") })
		}},
		{"exact condition", func(c *generatedCandidate) {
			generatedRewriteHead(t, c, func(h *format.HeadCore) { h.PreviousToken.Value = "2" })
		}},
		{"before access", func(c *generatedCandidate) { c.Subject.BeforeAccessDigest = consumerID("another current access") }},
		{"before root", func(c *generatedCandidate) { c.Subject.BeforeRootDigest = consumerID("another root") }},
		{"material", func(c *generatedCandidate) {
			v, err := contract.DecodeOperationMaterialRecord(c.SupportRecords[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			v.SeedCheck[0] ^= 1
			c.SupportRecords[0].Body, err = contract.EncodeOperationMaterialRecord(v)
			if err != nil {
				t.Fatal(err)
			}
			c.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(c.PublicState.Domain, c.SupportRecords)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"seed ciphertext", func(c *generatedCandidate) {
			c.AccessRecords[0].Wraps[0].RSACiphertext[0] ^= 1
			var err error
			c.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(c.PublicState.Domain, c.AccessRecords)
			if err != nil {
				t.Fatal(err)
			}
			c.PublicState.AccessRoot, err = contract.AccessRoot(c.CurrentAccess)
			if err != nil {
				t.Fatal(err)
			}
			c.Subject.AfterAccessDigest = c.PublicState.AccessRoot
		}},
		{"access generation", func(c *generatedCandidate) {
			c.CurrentAccess.AccessGeneration++
			var err error
			c.PublicState.AccessRoot, err = contract.AccessRoot(c.CurrentAccess)
			if err != nil {
				t.Fatal(err)
			}
			c.Subject.AfterAccessDigest = c.PublicState.AccessRoot
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, candidate, q := generatedReadyCandidate(t, f)
			test.mutate(&candidate)
			if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoInvalidAdmission {
				t.Fatal("candidate changed", code)
			}
			if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoAlreadyUsed || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("refused candidate left an operation", reply.ResultCode)
			}
		})
	}
}

// full_only: false
func TestGeneratedFreezeChecksEveryCapturedFact(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	for _, test := range []struct {
		name   string
		mutate func(*contract.CryptoGeneratedFreezeRequest)
	}{
		{"operation", func(q *contract.CryptoGeneratedFreezeRequest) { q.OperationRef = consumerID("another operation") }},
		{"phase", func(q *contract.CryptoGeneratedFreezeRequest) { q.PhaseID = consumerID("another phase") }},
		{"request", func(q *contract.CryptoGeneratedFreezeRequest) {
			q.RequestIdentityDigest = consumerID("another request")
		}},
		{"members", func(q *contract.CryptoGeneratedFreezeRequest) { q.CandidatePublicStateDescriptor.Digest[0] ^= 1 }},
		{"access", func(q *contract.CryptoGeneratedFreezeRequest) { q.CandidateAccess.Digest[0] ^= 1 }},
		{"support", func(q *contract.CryptoGeneratedFreezeRequest) { q.CandidateSupport.Digest[0] ^= 1 }},
		{"head", func(q *contract.CryptoGeneratedFreezeRequest) { q.HeadCoreDigest[0] ^= 1 }},
		{"condition", func(q *contract.CryptoGeneratedFreezeRequest) {
			q.ConditionDigest[0] ^= 1
			q.Context.OriginalConditionDigest = q.ConditionDigest
		}},
		{"results", func(q *contract.CryptoGeneratedFreezeRequest) {
			q.ActualResults.Digest[0] ^= 1
			q.ActualResults.Count, q.ActualResults.Length = 1, 78
		}},
		{"omitted wraps", func(q *contract.CryptoGeneratedFreezeRequest) {
			var err error
			q.KeyUses, err = contract.CryptoGeneratedKeyUseDescriptor(nil)
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, candidate, q := generatedReadyCandidate(t, f)
			if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
				t.Fatal(code)
			}
			test.mutate(&q)
			if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("changed freeze", reply.ResultCode)
			}
		})
	}
}

// full_only: false
func TestGeneratedCandidateBindsActualMembersAndOwnsFacts(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	m := contract.ValueEntry{Name: "plain", Incarnation: consumerID("plain incarnation"), ValueState: consumerID("plain state"),
		OriginSnapshot: consumerID("plain origin"), OriginTransition: consumerID("plain transition"), ValueSource: contract.Supplied,
		ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.base.control.AuthorityRecipientID}, ValueBytes: []byte("original"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("original"))), RetainedLength: uint32(len([]byte("original")))}
	digest, err := contract.PublicValueEntryDigest(f.compare.Context.DomainID, 0, m)
	if err != nil {
		t.Fatal(err)
	}
	f.entries = []generatedCandidateEntry{{Entry: m}}
	f.reservation.Session.BeforePublic.Rows = []contract.PublicStateRow{{Name: m.Name, EntryDigest: digest}}
	f.reservation.Session.Output = generatedEmptyOutputWitness(t, &f.reservation.Session.BeforePublic, f.entries, nil)
	t.Run("body substitution", func(t *testing.T) {
		r, candidate, _ := generatedReadyCandidate(t, f)
		candidate.Entries[0].Entry.ValueBytes = []byte("substitute")
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoInvalidAdmission {
			t.Fatal("member body was not checked", code)
		}
	})
	f.entries[0].Entry = m
	t.Run("owned admission and candidate", func(t *testing.T) {
		r, candidate, q := generatedReadyCandidate(t, f)
		f.reservation.Session.BeforePublic.Rows[0].EntryDigest[0] ^= 1
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
			t.Fatal("borrowed admission", code)
		}
		candidate.HeadCore[0] ^= 1
		candidate.AccessRecords[0].Wraps[0].RSACiphertext[0] ^= 1
		candidate.SupportRecords[0].Body[0] ^= 1
		candidate.Entries[0].Entry.ValueBytes[0] ^= 1
		if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("borrowed candidate", reply.ResultCode)
		}
	})
}

// full_only: false
func TestGeneratedCandidateRejectsDuplicateAndCancelledStage(t *testing.T) {
	f := generatedRuntimeOutputFixture(t, false)
	t.Run("no private candidate", func(t *testing.T) {
		r, _, q := generatedReadyCandidate(t, f)
		if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoInvalidAdmission {
			t.Fatal(reply.ResultCode)
		}
	})
	t.Run("duplicate binding", func(t *testing.T) {
		r, c, q := generatedReadyCandidate(t, f)
		a, witness := generatedOutputOwner(t, r, f.reservation.Session.Output, f.reservation.Session.BeforePublic)
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoSuccess {
			t.Fatal(code)
		}
		generatedOutputReleased(t, r, a, f.reservation.Session.Output, witness)
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoAlreadyUsed {
			t.Fatal(code)
		}
		if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoAlreadyUsed {
			t.Fatal(reply.ResultCode)
		}
		r.retireGenerated()
		generatedOutputReleased(t, r, a, f.reservation.Session.Output, witness)
	})
	t.Run("cancel and disposal", func(t *testing.T) {
		r, c, q := generatedReadyCandidate(t, f)
		a, witness := generatedOutputOwner(t, r, f.reservation.Session.Output, f.reservation.Session.BeforePublic)
		seed := a.seed
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if code := r.bindGeneratedCandidate(ctx, f.compare.Context.AdmissionID, c); code != contract.CryptoCancelled {
			t.Fatal(code)
		}
		select {
		case <-a.done:
		case <-time.After(time.Second):
			t.Fatal("cancel did not join")
		}
		generatedOutputReleased(t, r, a, f.reservation.Session.Output, witness)
		for _, b := range seed {
			if b != 0 {
				t.Fatal("seed was not cleared")
			}
		}
		if len(a.graph.ValueEntryPlans) != 0 || len(a.bindings) != 0 || a.candidate != nil {
			t.Fatal("owner was not disposed")
		}
		if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoAlreadyUsed {
			t.Fatal(reply.ResultCode)
		}
	})
	t.Run("cancel after binding work starts", func(t *testing.T) {
		r, candidate, _ := generatedReadyCandidate(t, f)
		a, witness := generatedOutputOwner(t, r, f.reservation.Session.Output, f.reservation.Session.BeforePublic)
		base, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx := &generatedBindingCancellationContext{Context: base, runtime: r, cancel: cancel}
		if code := r.bindGeneratedCandidate(ctx, f.compare.Context.AdmissionID, candidate); code != contract.CryptoCancelled {
			t.Fatal("binding cancellation", code)
		}
		if !ctx.workObserved.Load() {
			t.Fatal("cancellation did not reach binding work ownership")
		}
		r.retireGenerated()
		generatedOutputReleased(t, r, a, f.reservation.Session.Output, witness)
		if a.candidate != nil || len(a.graph.ValueEntryPlans) != 0 || len(a.seed) != 0 {
			t.Fatal("canceled binding owner was not disposed after join")
		}
	})
}

// full_only: false
func TestGeneratedClaimMatchesFrozenFacts(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	r, candidate, q := generatedReadyCandidate(t, f)
	if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	reply := generatedFreeze(t, r, q)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal(reply.ResultCode)
	}
	facts, err := contract.DecodeCryptoFreezeResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	want, err := contract.CryptoGeneratedFactDigest(r.InstanceID(), q)
	if err != nil || facts.FactDigest != want {
		t.Fatal("instance-bound fact", err)
	}
	q.CandidateSupport.Digest[0] ^= 1
	body, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
	if err != nil {
		t.Fatal(err)
	}
	if reply := applyCall(r, context.Background(), contract.CryptoClaim, body); reply.ResultCode != contract.CryptoInvalidAdmission {
		t.Fatal(reply.ResultCode)
	}
}

func generatedRuntimeOutputFixture(t *testing.T, retired bool) generatedRuntimeFixture {
	t.Helper()
	return generatedRuntimeOutputFixtureFrom(t, generatedRuntimePlanFixture(t, false), retired)
}

func generatedRuntimeOutputFixtureFrom(t *testing.T, f generatedRuntimeFixture, retired bool) generatedRuntimeFixture {
	t.Helper()
	domain := f.compare.Context.DomainID
	entry := contract.ValueEntry{Name: "plain", Incarnation: consumerID("output entry"), ValueState: consumerID("output value"),
		OriginSnapshot: consumerID("output origin"), OriginTransition: consumerID("output transition"), ValueSource: contract.Supplied,
		ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.base.control.AuthorityRecipientID}, ValueBytes: []byte("original"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("original"))), RetainedLength: uint32(len([]byte("original")))}
	digest, err := contract.PublicValueEntryDigest(domain, 0, entry)
	if err != nil {
		t.Fatal(err)
	}
	f.entries = []generatedCandidateEntry{{Entry: entry}}
	before := f.reservation.Session.BeforePublic
	before.Rows = []contract.PublicStateRow{{Name: entry.Name, EntryDigest: digest}}
	w := generatedEmptyOutputWitness(t, &before, f.entries, nil)
	binding := consumerID("output binding")
	target := contract.OutputTarget{EntryIncarnationID: entry.Incarnation, ServiceContractID: "provider", CanonicalTarget: "slot", ConsumerLocator: "locator",
		TargetContractID: "profile", PayloadEncoding: contract.OutputEncodingRaw}
	if !retired {
		w.Before.Bindings = []contract.OutputBinding{{DestinationID: "dest", IncarnationID: binding,
			Destination: contract.OutputDestination{ServiceContractID: "provider", ConfigContractID: "profile", CanonicalSettings: []byte(`{}`)},
			Targets:     []contract.OutputTarget{target}}}
	}
	coordinateID, err := contract.PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: domain, CoordinateID: coordinateID, ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget,
		BindingState: contract.PublicationBindingActive, ActiveBindingIncarnationID: binding, LastBindingIncarnationID: binding, LastEntryIncarnationID: entry.Incarnation,
		CurrentPublicationIncarnationID: consumerID("output publication incarnation")}
	if retired {
		coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	}
	body, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	w.Rows = contract.GeneratedSupportRows{Records: []contract.SupportRecord{{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinateID, Body: body}}}
	image, err := contract.EncodeOutputConfiguration(w.Before)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(domain, image)
	if err != nil {
		t.Fatal(err)
	}
	w.BeforeDescriptor = descriptor
	for _, part := range parts {
		body, err := contract.EncodeOutputConfigurationSlice(part)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.OutputConfigurationSliceID(domain, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Records = append(w.Rows.Records, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	for _, row := range w.Rows.Records {
		fact, err := contract.InspectSupportRecordDigest(domain, row)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Facts = append(w.Rows.Facts, fact)
	}
	before.RequiredSupport, err = contract.RequiredSupportDescriptorFromDigests(domain, w.Rows.Facts)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Session.BeforePublic = before
	f.reservation.Session.Output, err = w.Own(before)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Inspect the concrete owner before binding, including independent row backing.
func generatedOutputOwner(t *testing.T, r *Runtime, caller *contract.GeneratedOutputTransition, before contract.PublicState) (*generatedAdmission, *contract.GeneratedOutputTransition) {
	t.Helper()
	want, err := caller.Own(before)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.generated
	if a == nil || a.purpose.output == nil || a.purpose.output == caller || !reflect.DeepEqual(a.purpose.output, want) {
		t.Fatal("generated output witness has no independent owner")
	}
	for i, row := range caller.Rows.Records {
		if len(row.Body) != 0 && &row.Body[0] == &a.purpose.output.Rows.Records[i].Body[0] {
			t.Fatal("generated output witness borrows caller row backing")
		}
	}
	return a, want
}

func generatedOutputReleased(t *testing.T, r *Runtime, a *generatedAdmission, caller, want *contract.GeneratedOutputTransition) {
	t.Helper()
	r.mu.Lock()
	retained := a.purpose.output != nil
	r.mu.Unlock()
	if retained {
		t.Fatal("generated output witness retained after candidate binding")
	}
	if !reflect.DeepEqual(caller, want) {
		t.Fatal("generated output witness release changed caller state")
	}
}

// full_only: false
func TestGeneratedOutputWitnessRequiredAndOwned(t *testing.T) {
	for _, state := range []string{"empty", "active", "retired"} {
		t.Run(state, func(t *testing.T) {
			fixture := func(t *testing.T) generatedRuntimeFixture {
				if state == "empty" {
					return generatedRuntimePlanFixture(t, false)
				}
				return generatedRuntimeOutputFixture(t, state == "retired")
			}
			t.Run("witness and candidate rows omitted", func(t *testing.T) {
				f := fixture(t)
				admitted, candidate, _ := generatedReadyCandidate(t, f)
				admitted.retireGenerated()
				candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool {
					return row.Kind >= contract.PublicationCoordinateSupportKind && row.Kind <= contract.OutputConfigurationSliceSupportKind
				})
				var err error
				candidate.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(candidate.PublicState.Domain, candidate.SupportRecords)
				if err != nil {
					t.Fatal(err)
				}
				f.reservation.Session.Output = nil
				r := newConsumerRuntime(t, f.base.route)
				if err := r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline); err != ErrAdmission {
					t.Fatal("missing witness admitted", err)
				}
				if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoInvalidAdmission {
					t.Fatal("candidate accepted without owned predecessor", code)
				}
			})
			t.Run("configuration slice witness omitted", func(t *testing.T) {
				f := fixture(t)
				f.reservation.Session.Output.Rows.Records = slices.DeleteFunc(f.reservation.Session.Output.Rows.Records, func(row contract.SupportRecord) bool { return row.Kind == contract.OutputConfigurationSliceSupportKind })
				// Keep the authenticated complete predecessor commitment fixed.
				r := newConsumerRuntime(t, f.base.route)
				if err := r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline); err != ErrAdmission {
					t.Fatal("missing mandatory witness slice admitted", err)
				}
			})
			t.Run("configuration slice candidate omitted", func(t *testing.T) {
				f := fixture(t)
				r, candidate, _ := generatedReadyCandidate(t, f)
				a, witness := generatedOutputOwner(t, r, f.reservation.Session.Output, f.reservation.Session.BeforePublic)
				candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool { return row.Kind == contract.OutputConfigurationSliceSupportKind })
				var err error
				candidate.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(candidate.PublicState.Domain, candidate.SupportRecords)
				if err != nil {
					t.Fatal(err)
				}
				if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoInvalidAdmission {
					t.Fatal("missing mandatory candidate slice admitted", code)
				}
				r.retireGenerated()
				generatedOutputReleased(t, r, a, f.reservation.Session.Output, witness)
			})
			t.Run("owned predecessor", func(t *testing.T) {
				f := fixture(t)
				r, candidate, q := generatedReadyCandidate(t, f)
				a, _ := generatedOutputOwner(t, r, f.reservation.Session.Output, f.reservation.Session.BeforePublic)
				f.reservation.Session.Output.BeforeDescriptor.ConfigurationDigest[0] ^= 1
				if len(f.reservation.Session.Output.Rows.Records) != 0 {
					f.reservation.Session.Output.Rows.Records[0].Body[0] ^= 1
				}
				if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
					t.Fatal("borrowed output predecessor", code)
				}
				r.mu.Lock()
				retained := a.purpose.output != nil
				r.mu.Unlock()
				if retained {
					t.Fatal("generated output witness retained after candidate binding")
				}
				if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoSuccess {
					t.Fatal("owned output freeze", reply.ResultCode)
				}
			})
			if state == "empty" {
				return
			}
			t.Run("candidate coordinate omitted", func(t *testing.T) {
				f := fixture(t)
				r, candidate, _ := generatedReadyCandidate(t, f)
				candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool { return row.Kind == contract.PublicationCoordinateSupportKind })
				var err error
				candidate.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(candidate.PublicState.Domain, candidate.SupportRecords)
				if err != nil {
					t.Fatal(err)
				}
				if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoInvalidAdmission {
					t.Fatal("candidate lost selected coordinate", code)
				}
			})
			t.Run("wrong predecessor support", func(t *testing.T) {
				f := fixture(t)
				f.reservation.Session.Output.Rows.Facts = f.reservation.Session.Output.Rows.Facts[1:]
				r := newConsumerRuntime(t, f.base.route)
				if err := r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline); err != ErrAdmission {
					t.Fatal("wrong predecessor support admitted", err)
				}
			})
		})
	}
}

func refreshRuntimeOutputWitness(t *testing.T, f *generatedRuntimeFixture, configuration contract.OutputConfiguration, retained []contract.SupportRecord) {
	t.Helper()
	before := f.reservation.Session.BeforePublic
	before.Rows = nil
	for slot, entry := range f.entries {
		digest, err := contract.PublicValueEntryDigest(before.Domain, uint16(slot), entry.Entry)
		if err != nil {
			t.Fatal(err)
		}
		before.Rows = append(before.Rows, contract.PublicStateRow{Name: entry.Entry.Name, Slot: uint16(slot), EntryDigest: digest})
	}
	w := generatedEmptyOutputWitness(t, &before, f.entries, nil)
	w.Before = configuration
	// Keep current coordinates while checking the complete proposed entry set
	// against the declared default and exact entry replacements.
	nameFor := func(id contract.ID) string {
		for _, entry := range f.entries {
			if entry.Entry.Incarnation == id {
				return entry.Entry.Name
			}
		}
		t.Fatal("routing fixture refers to an absent selected entry", id)
		return ""
	}
	for _, binding := range configuration.Bindings {
		desired := contract.NormalOutputBinding{DestinationID: binding.DestinationID, Destination: binding.Destination}
		for _, target := range binding.Targets {
			name := nameFor(target.EntryIncarnationID)
			target.EntryIncarnationID = contract.ID{}
			desired.Targets = append(desired.Targets, contract.NormalOutputTarget{Name: name, Target: target})
		}
		w.Bindings = append(w.Bindings, desired)
	}
	w.Routes = append(w.Routes, contract.NormalOutputRoute{Default: true, Destinations: slices.Clone(configuration.DefaultDestinations)})
	for _, route := range configuration.Routes {
		w.Routes = append(w.Routes, contract.NormalOutputRoute{Name: nameFor(route.EntryIncarnationID), Destinations: slices.Clone(route.Destinations)})
	}
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(before.Domain, image)
	if err != nil {
		t.Fatal(err)
	}
	w.BeforeDescriptor = descriptor
	w.Rows = contract.GeneratedSupportRows{Records: slices.Clone(retained)}
	for _, part := range parts {
		body, err := contract.EncodeOutputConfigurationSlice(part)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.OutputConfigurationSliceID(before.Domain, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Records = append(w.Rows.Records, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	slices.SortFunc(w.Rows.Records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	for _, row := range w.Rows.Records {
		fact, err := contract.InspectSupportRecordDigest(before.Domain, row)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Facts = append(w.Rows.Facts, fact)
	}
	before.RequiredSupport, err = contract.RequiredSupportDescriptorFromDigests(before.Domain, w.Rows.Facts)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Session.BeforePublic = before
	f.reservation.Session.Output, err = w.Own(before)
	if err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestGeneratedOutputRoutingAdmission(t *testing.T) {
	t.Run("new entry default requires target", func(t *testing.T) {
		f := generatedRuntimeEffectFixture(t, false)
		graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
		if err != nil {
			t.Fatal(err)
		}
		graph.ValueEntryPlans[0].Slot = 1
		graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(graph.Header, graph.ValueEntryPlans, graph.Lineages, graph.Edges)
		if err != nil {
			t.Fatal(err)
		}
		f.graph, err = contract.EncodeGeneratorPlanBundle(graph)
		if err != nil {
			t.Fatal(err)
		}
		f = generatedRuntimeOutputFixtureFrom(t, f, false)
		configuration := f.reservation.Session.Output.Before
		configuration.DefaultDestinations = []string{"dest"}
		retained := slices.DeleteFunc(slices.Clone(f.reservation.Session.Output.Rows.Records), func(row contract.SupportRecord) bool { return row.Kind == contract.OutputConfigurationSliceSupportKind })
		refreshRuntimeOutputWitness(t, &f, configuration, retained)
		plain := f.entries[0].Entry
		generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: plain.Name, Recipients: plain.Recipients, Payload: plain.ValueBytes}, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 0, Name: plain.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, EntryIncarnationID: plain.Incarnation})
		r := newConsumerRuntime(t, f.base.route)
		err = r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline)
		if err != ErrAdmission {
			t.Errorf("new entry inherited an uncovered default: %v", err)
		}
		if f.base.route.privateCalls != 0 {
			t.Fatal("invalid successor started private work")
		}
		if r.generated != nil || r.slot != nil {
			t.Error("invalid successor retained admission or slot")
		}
		r.retireGenerated()
		configuration.DefaultDestinations = nil
		configuration.Routes = []contract.OutputRoute{{EntryIncarnationID: plain.Incarnation, Destinations: []string{"dest"}}}
		refreshRuntimeOutputWitness(t, &f, configuration, retained)
		control := newConsumerRuntime(t, f.base.route)
		if err := control.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline); err != nil {
			t.Fatal("valid sibling admission", err)
		}
		control.retireGenerated()
	})
	for _, grant := range []bool{false, true} {
		t.Run(fmt.Sprintf("membership addition=%t keeps shared routing", grant), func(t *testing.T) {
			f := generatedRuntimeOutputFixture(t, false)
			plain := f.entries[0].Entry
			other := plain
			other.Name, other.Incarnation, other.ValueState = "other", consumerID("other entry"), consumerID("other value")
			other.ValueBytes = []byte("other")
			// Keep canonical name order and independent physical targets.
			f.entries = []generatedCandidateEntry{{Slot: 0, Entry: other}, {Slot: 1, Entry: plain}}
			configuration := f.reservation.Session.Output.Before
			target := configuration.Bindings[0].Targets[0]
			target.EntryIncarnationID, target.CanonicalTarget = other.Incarnation, "other slot"
			configuration.Bindings = append(configuration.Bindings, contract.OutputBinding{DestinationID: "other", IncarnationID: consumerID("other binding"),
				Destination: contract.OutputDestination{ServiceContractID: "provider", ConfigContractID: "profile", CanonicalSettings: []byte(`{}`)},
				Targets:     []contract.OutputTarget{target}})
			configuration.DefaultDestinations = []string{"dest"}
			configuration.Routes = []contract.OutputRoute{{EntryIncarnationID: other.Incarnation, Destinations: []string{"other"}}}
			retained := slices.DeleteFunc(slices.Clone(f.reservation.Session.Output.Rows.Records), func(row contract.SupportRecord) bool { return row.Kind == contract.OutputConfigurationSliceSupportKind })
			coordinate, err := contract.InspectPublicationCoordinate(retained[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			coordinate.CoordinateID, err = contract.PublicationCoordinateID(coordinate.DomainID, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			coordinate.CanonicalTarget, coordinate.ActiveBindingIncarnationID = target.CanonicalTarget, configuration.Bindings[1].IncarnationID
			coordinate.LastBindingIncarnationID, coordinate.LastEntryIncarnationID = coordinate.ActiveBindingIncarnationID, other.Incarnation
			coordinate.CurrentPublicationIncarnationID = consumerID("other publication")
			body, err := contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal(err)
			}
			retained = append(retained, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: body})
			refreshRuntimeOutputWitness(t, &f, configuration, retained)
			recipients := slices.Clone(other.Recipients)
			var changeMask uint8
			if grant {
				recipients = append(recipients, consumerID("reader"))
				slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				changeMask = contract.GeneratorValueChangeMembership
			}
			generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: other.Name, Recipients: recipients, Payload: other.ValueBytes}, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 0, Name: other.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, EntryIncarnationID: other.Incarnation, ChangeMask: changeMask})
			generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: plain.Name, Recipients: plain.Recipients, Payload: plain.ValueBytes}, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 1, Name: plain.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, EntryIncarnationID: plain.Incarnation})
			r := newConsumerRuntime(t, f.base.route)
			if err := r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline); err != nil {
				t.Fatal("membership declaration changed shared routing admission", err)
			}
			if f.base.route.privateCalls != 0 {
				t.Fatal("routing admission started private work")
			}
			owned, _ := generatedOutputOwner(t, r, f.reservation.Session.Output, f.reservation.Session.BeforePublic)
			graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
			if err != nil {
				t.Fatal(err)
			}
			after, err := owned.purpose.output.ConfigurationAfter(graph.Header.OperationID, graph.ValueEntryPlans)
			if err != nil || !slices.Equal(after.DefaultDestinations, []string{"dest"}) || len(after.Routes) != 1 || after.Routes[0].EntryIncarnationID != other.Incarnation || !slices.Equal(after.Routes[0].Destinations, []string{"other"}) || !reflect.DeepEqual(after.Bindings, configuration.Bindings) {
				t.Fatal("membership declaration changed default, override or targets", err)
			}
			r.retireGenerated()
		})
	}
}

// full_only: false
func TestGeneratedDeleteCandidateMatchesCompleteOriginalFacts(t *testing.T) {
	base, prepared, _ := generatedProducerFixture(t, false)
	originalExpected := base.producer.Producer.Expected
	originalFacts := generatedProducerFacts(originalExpected)
	seed := generatedTestSeed(t, base, prepared)
	defer clear(seed)
	for _, kind := range []uint8{contract.GeneratedDutyRetirement, contract.GeneratedDutyUnselectedCleanup} {
		for _, source := range []string{"detached", "live"} {
			for _, damage := range []string{"exact", "provider facts", "target bytes", "missing"} {
				t.Run(fmt.Sprint(kind)+"/"+source+"/"+damage, func(t *testing.T) {
					f := generatedSelectDeleteProducer(t, base, kind)
					r := f.producerRuntime(t)
					defer r.retireGenerated()
					op, _ := generatedAdoptionCompare(t, r, f)
					generatedProducerPrepare(t, r, f, op)
					a := r.generated
					p := a.purpose.producer.producer
					x := p.expected.Template
					c := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{DomainID: f.compare.Context.DomainID,
						LineageID: x.LineageID, AttemptID: x.AttemptID, DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ResultContractID: x.ResultContractID}}
					attempt, err := contract.EncodeGeneratedAttemptRecord(p.attempt)
					if err != nil {
						t.Fatal(err)
					}
					c.SupportRecords = []contract.SupportRecord{{Kind: contract.GeneratedAttemptSupportKind, RecordID: p.attempt.AttemptID, Body: attempt}, p.ownerRecord}
					c.SupportRecords = append(c.SupportRecords, generatedVectorSupport(t, f.compare.Context.DomainID, p.ownerRecord.Kind, p.ownerRecord.RecordID, contract.GeneratorVectorConsumers, p.consumers)...)
					facts := originalFacts
					switch damage {
					case "provider facts":
						facts.ProviderFacts = []byte{1, 254}
					case "target bytes":
						facts.Target = []byte("another-service/target")
					}
					record, err := custody.SealGeneratedResult(originalExpected, prepared.Material, facts, seed, []byte("original private value"))
					if err != nil {
						t.Fatal(err)
					}
					packet, err := contract.EncodeGeneratedResultRecord(record)
					if err != nil {
						t.Fatal(err)
					}
					row := contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: record.Core.ResultID, Body: packet}
					if source == "detached" {
						core, err := contract.EncodeGeneratedResultCore(record.Core)
						if err != nil {
							t.Fatal(err)
						}
						body, err := contract.EncodeGeneratorSafeFacts(facts)
						if err != nil {
							t.Fatal(err)
						}
						evidence, err := contract.EncodeGeneratedCreateEvidence(contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema,
							LifecycleMode: originalExpected.Template.LifecycleMode, OriginalResultID: record.Core.ResultID, CredentialRouteID: originalExpected.Template.CredentialRouteID, ResultCore: core, SafeFacts: body,
							Intent: contract.GeneratorDescriptor{Digest: originalExpected.Template.IntentDigest, Length: uint64(len(base.producer.Producer.Intent)), Count: 1}, CompletionClass: originalExpected.Template.CompletionClass})
						if err != nil {
							t.Fatal(err)
						}
						row.Kind, row.Body = contract.GeneratedCreateEvidenceSupportKind, evidence
					}
					if damage != "missing" {
						c.SupportRecords = append(c.SupportRecords, row)
					}
					if got := a.candidateProducerMatches(c); got != (damage == "exact") {
						t.Fatalf("complete original facts binding: accepted=%t damage=%s", got, damage)
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedCarriedEntryOutputEncodingUsesExactPlan(t *testing.T) {
	for _, secret := range []bool{false, true} {
		t.Run(fmt.Sprint(secret), func(t *testing.T) {
			domain := consumerID("carried domain")
			entry := contract.ValueEntry{Name: "carried", Incarnation: consumerID("carried incarnation"), ValueState: consumerID("carried value"),
				OriginSnapshot: consumerID("carried origin"), OriginTransition: consumerID("carried transition"), ValueSource: contract.Supplied,
				ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw,
				ContentLength: 3, RetainedLength: 3, Recipients: []contract.ID{consumerID("carried recipient")}, ValueBytes: []byte("ABC")}
			if secret {
				selected, _ := consumerFixture(t)
				domain, entry = selected.DomainID, selected.Entry
			}
			body, err := contract.EncodeValueEntry(entry)
			if err != nil {
				t.Fatal(err)
			}
			before, err := contract.PublicValueEntryDigest(domain, 0, entry)
			if err != nil {
				t.Fatal(err)
			}
			plan := contract.GeneratorValueEntryPlan{Schema: contract.GeneratorValueEntryPlanSchema, Name: entry.Name, Slot: 0,
				EntryIncarnationID: entry.Incarnation, ValueSource: entry.ValueSource, ConfidentialityClass: entry.ConfidentialityClass,
				InputEncoding: entry.InputEncoding, OutputEncoding: contract.OutputEncodingBase64}
			admission := generatedAdmission{graph: contract.GeneratorPlanBundle{ValueEntryPlans: []contract.GeneratorValueEntryPlan{plan}},
				before:  contract.PublicState{Domain: domain, Rows: []contract.PublicStateRow{{Name: entry.Name, Slot: 0, EntryDigest: before}}},
				purpose: generatedPurposeState{output: &contract.GeneratedOutputTransition{EntryBodies: [][]byte{body}}, final: &generatedFinalPreparationState{suppliedFinal: true}}}
			expected := entry
			expected.OutputEncoding = contract.OutputEncodingBase64
			want, err := contract.PublicValueEntryDigest(domain, 0, expected)
			if err != nil {
				t.Fatal(err)
			}
			rows, ok := admission.preparedPublicStateRows(generatedCandidate{})
			if !ok || len(rows) != 1 || rows[0].EntryDigest != want || want == before {
				t.Fatal("carried entry lost selected output class", ok, rows)
			}
			unchanged, err := contract.DecodeValueEntry(body)
			if err != nil || unchanged.ValueState != entry.ValueState || !bytes.Equal(unchanged.ValueBytes, entry.ValueBytes) || unchanged.OutputEncoding != contract.OutputEncodingRaw {
				t.Fatal("output-only selection changed retained material", err)
			}
		})
	}
}
