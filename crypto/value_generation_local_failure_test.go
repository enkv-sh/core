package crypto

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This constructs new local input from the ordinary Crypto fixture's key and
// context setup. It does not reinterpret an accepted Cloudflare graph or row.
func generatedRuntimeLocalEffectFixture(t *testing.T) generatedRuntimeFixture {
	t.Helper()
	f := generatedRuntimePlanFixture(t, false)
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	id := consumerID
	intent := generatedFixtureIntent(id("local configuration contract"), contract.ID{}, contract.GeneratorLifecycleNone, `{}`)
	intentID, err := contract.GeneratorIntentDigest(intent)
	check(err)
	declared := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone,
		Epoch: 1, ConfigContractID: id("local configuration contract"), Intent: intent}
	payload, err := contract.EncodeGeneratorDeclaredGeneration(declared)
	check(err)
	recipients := []contract.ID{f.base.control.AuthorityRecipientID}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
		Entries: []contract.GeneratorDeclarationEntry{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationGenerated, Name: "local", Recipients: recipients, Payload: payload}}}
	f.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	check(err)
	g.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	check(err)
	lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: contract.GeneratorLineageCreate,
		DomainID: g.Header.DomainID, OperationID: g.Header.OperationID, Name: "local", EntryIncarnationID: id("local incarnation"), Epoch: 1, IntentDigest: intentID, TemplateCount: 1}
	lineage.LineageID, err = contract.GeneratorLineageID(lineage.DomainID, lineage.OperationID, lineage.Name, lineage.EntryIncarnationID, lineage.Epoch, intentID)
	check(err)
	x := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, LifecycleMode: contract.GeneratorLifecycleNone,
		Action: contract.GeneratorActionCreate, LineageID: lineage.LineageID, DescriptorID: id("local descriptor"), ConfigContractID: declared.ConfigContractID, CredentialRouteID: id("local route"),
		ExecutorID: id("local executor"), ResultContractID: id("local result contract"), IntentDigest: intentID,
		RequiredAuthoritySet: contract.GeneratorAuthorityNormal, ResultReaderID: contract.GeneratorResultReaderID()}
	x.AttemptID, err = contract.GeneratorAttemptID(x.LineageID, 0)
	check(err)
	x.ResourceIncarnationID, err = contract.GeneratorResourceID(lineage.DomainID, lineage.OperationID, x.AttemptID)
	check(err)
	x.PlannedValueSlotID, err = contract.GeneratorValueSlotID(lineage.DomainID, lineage.OperationID, x.AttemptID)
	check(err)
	x.DutyID, err = contract.GeneratorDutyID(lineage.DomainID, lineage.OperationID, x.AttemptID, contract.GeneratedDutyCreate)
	check(err)
	x.TransmissionID, err = contract.GeneratorTransmissionID(x.AttemptID, contract.GeneratorActionCreate)
	check(err)
	x.ResultID, err = contract.GeneratorResultID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.TransmissionID, contract.GeneratorActionCreate)
	check(err)
	x.InboxID, err = contract.GeneratorInboxID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.ResultID)
	check(err)
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	check(err)
	lineage.Templates[0] = x
	membership, err := contract.GeneratorIntendedMembershipDescriptor(recipients)
	check(err)
	g.ValueEntryPlans = []contract.GeneratorValueEntryPlan{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, LifecycleMode: contract.GeneratorLifecycleNone,
		Name: lineage.Name, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, EntryIncarnationID: lineage.EntryIncarnationID,
		Epoch: lineage.Epoch, IntentDigest: intentID, PlannedValueSlotID: x.PlannedValueSlotID, IntendedMembership: membership, LineageID: x.LineageID,
		ChangeMask: contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership}}
	g.Lineages = []contract.GeneratorLineageTemplate{lineage}
	g.Header.Schema, g.Header.ValueEntryPlanCount, g.Header.LineageCount, g.Header.TemplateCount = contract.GeneratorGraphHeaderSchema, 1, 1, 1
	g.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(g.Request)
	check(err)
	templateID, err := contract.GeneratorTemplateID(x)
	check(err)
	join, err := contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest)
	check(err)
	for _, guard := range []uint8{contract.GeneratorGuardQualifiedSuccess, contract.GeneratorGuardTerminalParent} {
		g.Edges = append(g.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: templateID, DestinationTemplateID: join, Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1})
	}
	g.ResultUses = []contract.GeneratorResultUse{{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID, InboxID: x.InboxID, ExecutorID: x.ExecutorID,
		ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID, MaterialID: g.Header.MaterialID, Purpose: contract.GeneratorUseGeneratedResult, MaxSecret: 65536, MaxFacts: 4096}}
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	check(err)
	g.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(g.ResultUses)
	check(err)
	g.UsePlan.ValueDerivationID = contract.GeneratorValueDerivationID()
	check(contract.ValidateGeneratorEffectGraph(g))
	return generatedRuntimeEffectGraphFixture(t, f, g)
}

func generatedLocalFailureCurrentFixture(t *testing.T, f generatedRuntimeFixture, c generatedCandidate) (generatedCandidate, contract.GeneratedPhaseRecord, []contract.Ref) {
	t.Helper()
	p := f.producer.Producer
	set := func(kind contract.GeneratorRecordSetKind, supportKind uint8) contract.GeneratorDescriptor {
		var rows []contract.SupportRecord
		for _, row := range c.SupportRecords {
			if row.Kind == supportKind {
				rows = append(rows, row)
			}
		}
		d, err := contract.GeneratorRecordSetDescriptor(kind, f.compare.Context.DomainID, rows)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: f.compare.Context.DomainID, OperationID: f.compare.Parent.OperationID,
		PlanGraphID: p.Expected.Plan.PlanGraphID, UsePlanDigest: f.compare.UsePlanDigest, OwnerID: f.compare.Parent.OperationID,
		PhaseID: c.Subject.PhaseID, Phase: 1, FrontierAttemptID: p.Attempt.AttemptID, Stage: contract.GeneratedStageRetainedResult,
		AcceptedResults: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseResults), Attempts: set(contract.GeneratorPhaseAttempts, contract.GeneratedAttemptSupportKind),
		Duties: set(contract.GeneratorPhaseDuties, contract.GeneratedDutySupportKind), Hazards: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards),
		PendingReleases: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases), Proofs: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs)}
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: contract.GeneratedPhaseSupportKind, RecordID: phase.OperationID, Body: body})
	c.ActiveOwner, c.ActivePhase, c.ActiveGraph = phase.OperationID, phase.PhaseID, phase.PlanGraphID
	generatedCanonicalizeCandidateSupport(t, &c)
	page := format.RecipientPage{Domain: phase.DomainID, Object: consumerID("local failure recipient page")}
	for i := range f.base.current {
		page.Slots[i] = &f.base.current[i]
	}
	pageBody, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(format.RecipientKind, phase.DomainID, page.Object, 0, pageBody)
	if err != nil {
		t.Fatal(err)
	}
	refs := []contract.Ref{ref}
	c.CurrentAccess.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: phase.DomainID, Refs: refs})
	if err != nil {
		t.Fatal(err)
	}
	c.PublicState.AccessRoot, err = contract.AccessRoot(c.CurrentAccess)
	if err != nil {
		t.Fatal(err)
	}
	c.Subject.AfterAccessDigest = c.PublicState.AccessRoot
	return c, phase, refs
}

func generatedLocalFailureContinuationFixture(t *testing.T, f generatedRuntimeFixture, prepared contract.CryptoGeneratedFinishPlanResult, current generatedCandidate, phase contract.GeneratedPhaseRecord, refs []contract.Ref, reason uint8) (contract.CryptoGeneratedCompareRequest, contract.ControlCore, GeneratedCustodyConstruction, contract.GeneratedLocalFailureInput) {
	t.Helper()
	q := f.compare
	q.Purpose = contract.CryptoGeneratedAdoptionPurpose
	q.Context.AdmissionID, q.Context.SessionID = consumerID("fresh failure admission"), consumerID("fresh failure session")
	q.Context.CurrentAccessRoot = current.PublicState.AccessRoot
	q.Context.PredecessorHEADDigest = contract.Hash(current.HeadCore)
	head, err := format.DecodeHeadCore(current.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	root, err := contract.AppendRef(nil, head.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(q.Context.PredecessorRootRef[:], root)
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		t.Fatal(err)
	}
	attempt := f.producer.Producer.Attempt
	attempt.State, attempt.Stage, attempt.FailureReason = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal, reason
	body, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.GeneratorPhaseIdentity{RequestIdentityDigest: q.Parent.RequestIdentityDigest, ObservedHEADDigest: q.Context.PredecessorHEADDigest,
		ConditionDigest: q.Context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityFailedTerminal, BeforePhase: 1, AfterPhase: 2,
		Evidence: contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: uint64(len(body)), Count: 1}}
	control := f.producer.Session.Control
	control.CurrentControl = current.CurrentAccess.CurrentControl
	input := contract.GeneratedLocalFailureInput{Session: contract.GeneratedSessionInput{Graph: f.graph, BeforePublic: current.PublicState,
		Output: generatedEmptyOutputWitness(t, &current.PublicState, current.Entries, current.SupportRecords), CurrentRecipients: f.base.current,
		CurrentRecipientRefs: refs, SelectionPhase: &phase, BeforeAccess: &current.CurrentAccess, BeforeAccessRecords: current.AccessRecords},
		Plan: contract.GeneratedPlanInput{Declaration: f.declaration}, Custody: contract.GeneratedCustodyInput{Material: prepared.Material, SeedAccess: prepared.SeedAccess},
		Phase: identity, Attempt: attempt, BeforeSliceSnapshot: head.Root.Object}
	return q, control, GeneratedCustodyConstruction{RouteID: f.producer.Session.RouteID}, input
}

// full_only: false
func TestGeneratedLocalFailureKeepsOriginalCallerAuthority(t *testing.T) {
	for _, name := range []string{"valid", "cancel before return", "cancel after join", "cancel after admit", "cancel after compare", "expired original", "caller deadline cannot extend", "caller expires after admit", "valid shorter caller", "valid child deadline"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, prepared, candidate := generatedProducerPlanFixture(t, generatedRuntimeLocalEffectFixture(t))
				if name == "valid child deadline" {
					f.base.deadline = time.Now().Add(5 * time.Minute)
					f.compare.Context.Expiry = uint64(f.base.deadline.UnixNano())
					var err error
					f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
					if err != nil {
						t.Fatal(err)
					}
				}
				candidate, phase, refs := generatedLocalFailureCurrentFixture(t, f, candidate)
				original, cancel := context.WithCancel(context.Background())
				originalDeadline := time.Now().Add(30 * time.Second)
				if name == "caller deadline cannot extend" || name == "caller expires after admit" || name == "valid shorter caller" {
					cancel()
					original, cancel = context.WithDeadline(context.Background(), originalDeadline)
				}
				defer cancel()
				calls := 0
				f.producer.Producer.Return = func(ctx context.Context, _ contract.GeneratedProducerCommand, _ []byte) generatedProducerReturn {
					calls++
					if name == "valid child deadline" {
						<-ctx.Done()
					}
					if name == "cancel before return" {
						cancel()
					}
					return generatedProducerReturn{}
				}
				r := f.producerRuntime(t)
				owner, err := newGeneratedCustody(r, func() (*generatedAdmission, error) { return r.generated, nil })
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				op, uses := generatedAdoptionCompare(t, r, f)
				locator := generatedProducerPrepare(t, r, f, op)
				authority := generatedProducerClaim(t, r, f, candidate, op, uses)
				returned := owner.InvokeProducer(original, locator, authority)
				code := returned.Code
				owner.Close()
				if calls != 1 || code == contract.CryptoSuccess {
					t.Fatal("fixture did not produce one actual failed return", calls, code)
				}
				reason := uint8(contract.GeneratorFailureInvalid)
				if name == "cancel before return" {
					reason = contract.GeneratorFailureCancelled
				}
				if name == "valid child deadline" {
					reason = contract.GeneratorFailureExpired
				}
				_, admit := owner.LocalFailureAdmission()
				if admit == nil {
					t.Fatal("fixture lost original receiver capability")
				}
				q, control, construction, input := generatedLocalFailureContinuationFixture(t, f, prepared, candidate, phase, refs, reason)
				deadline := f.base.deadline
				if name == "valid shorter caller" || name == "caller expires after admit" {
					deadline = originalDeadline
					q.Context.Expiry = uint64(deadline.UnixNano())
					q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
					if err != nil {
						t.Fatal(err)
					}
				}
				if name == "cancel after join" {
					cancel()
				}
				if name == "expired original" {
					time.Sleep(time.Until(f.base.deadline) + time.Nanosecond)
					deadline = time.Now().Add(time.Minute)
					q.Context.Expiry = uint64(deadline.UnixNano())
				}
				fresh := newConsumerRuntime(t, f.base.route)
				defer fresh.Close()
				public, private := f.base.route.publicCalls, f.base.route.privateCalls
				continued, err := admit(context.Background(), fresh, q, control, construction, input, deadline)
				if continued != nil {
					defer continued.Close()
				}
				if name == "cancel before return" || name == "cancel after join" || name == "expired original" || name == "caller deadline cannot extend" {
					if err == nil || continued != nil || f.base.route.publicCalls != public || f.base.route.privateCalls != private {
						t.Fatal("fresh context revived ended original authority", err)
					}
					return
				}
				if err != nil {
					t.Fatal("valid current failure admission refused", err)
				}
				if name == "cancel after admit" {
					cancel()
				}
				if name == "caller expires after admit" {
					time.Sleep(time.Until(originalDeadline) + time.Nanosecond)
				}
				body, err := contract.EncodeCryptoGeneratedCompareRequest(q)
				if err != nil {
					t.Fatal(err)
				}
				reply := continued.Exchange(context.Background(), contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare,
					RequestID: consumerID("continued compare"), CustodyInstanceID: continued.InstanceID(), Body: body})
				if name == "cancel after admit" || name == "caller expires after admit" {
					if reply.ResultCode == contract.CryptoSuccess || f.base.route.publicCalls != public || f.base.route.privateCalls != private {
						t.Fatal("new session reopened keys after original cancellation", reply.ResultCode)
					}
					return
				}
				if reply.ResultCode != contract.CryptoSuccess {
					t.Fatal("valid failure Compare refused", reply.ResultCode)
				}
				operation, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
				if err != nil {
					t.Fatal(err)
				}
				if name == "cancel after compare" {
					cancel()
				}
				body, err = contract.EncodeCryptoGeneratedLocalFailureRequest(contract.CryptoGeneratedLocalFailureRequest{OperationRef: operation.OperationRef, Context: q.Context, AttemptID: input.Attempt.AttemptID, Reason: reason})
				if err != nil {
					t.Fatal(err)
				}
				reply = continued.Exchange(context.Background(), contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoPrepare,
					RequestID: consumerID("continued failure Prepare"), CustodyInstanceID: continued.InstanceID(), Body: body})
				if name == "cancel after compare" {
					if reply.ResultCode == contract.CryptoSuccess {
						t.Fatal("new Prepare context revived ended original authority")
					}
				} else if reply.ResultCode != contract.CryptoSuccess || !bytes.Equal(reply.Body, []byte{9}) || len(reply.KeyUseRows) != 0 {
					t.Fatal("valid failure Prepare refused", reply.ResultCode)
				}
			})
		})
	}
}

// full_only: false
func TestGeneratedLocalProducerUsesFreshGraphAndJoinedReturn(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected return", true: "success"}[success], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, _, candidate := generatedProducerPlanFixture(t, generatedRuntimeLocalEffectFixture(t))
				p := f.producer.Producer
				if p.Expected.Template.Schema != contract.GeneratorAttemptTemplateSchema || p.Expected.Template.LifecycleMode != contract.GeneratorLifecycleNone ||
					p.Expected.Template.ResultReaderID != contract.GeneratorResultReaderID() || p.Expected.Use.MaxSecret != 65536 || p.Expected.Use.MaxFacts != 4096 ||
					p.Attempt.Schema != contract.GeneratedAttemptRecordSchema || p.Duty.Schema != contract.GeneratedDutyRecordSchema || p.Attempt.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || p.Duty.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || p.Duty.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) {
					t.Fatal("local fixture lost its exact fresh family framing")
				}
				entered, release := make(chan struct{}), make(chan struct{})
				finishReturn := sync.OnceFunc(func() { close(release) })
				allocation := bytes.Repeat([]byte{'S'}, 64)
				copy(allocation, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
				calls := 0
				f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
					calls++
					close(entered)
					<-release
					facts := contract.GeneratorSafeFacts{}
					if success {
						facts = contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate, LifecycleMode: contract.GeneratorLifecycleNone,
							Disposition: contract.GeneratorDispositionCompleteCreate, RequestDigest: f.producer.Producer.Expected.RequestDigest, IntentDigest: f.producer.Producer.Expected.Template.IntentDigest}
					}
					return generatedProducerReturn{Facts: facts, Secret: allocation[:43]}
				}
				r := f.producerRuntime(t)
				owner, err := newGeneratedCustody(r, func() (*generatedAdmission, error) { return r.generated, nil })
				if err != nil {
					t.Fatal(err)
				}
				failureReason, admitFailure := owner.LocalFailureAdmission()
				if failureReason == nil || admitFailure == nil {
					t.Fatal("local producer lost its receiver-bound failure path")
				}
				defer r.Close()
				defer finishReturn()
				op, uses := generatedAdoptionCompare(t, r, f)
				locator := generatedProducerPrepare(t, r, f, op)
				authority := generatedProducerClaim(t, r, f, candidate, op, uses)
				public, private := f.base.route.publicCalls, f.base.route.privateCalls
				done := make(chan struct{})
				var body []byte
				var code contract.CryptoResultCode
				go func() {
					returned := owner.InvokeProducer(context.Background(), locator, authority)
					body, code = returned.Record, returned.Code
					close(done)
				}()
				<-entered
				if failureReason() != 0 {
					t.Fatal("unjoined callback supplied failure eligibility")
				}
				r.mu.Lock()
				returnOwner := r.generated.purpose.producer.returnOwner
				ownedSeed, ownedIntent := returnOwner.seed[:cap(returnOwner.seed)], returnOwner.intent[:cap(returnOwner.intent)]
				r.mu.Unlock()
				closed := make(chan struct{})
				go func() { owner.Close(); close(closed) }()
				synctest.Wait()
				select {
				case <-closed:
					t.Fatal("Close returned before its local callback joined")
				default:
				}
				finishReturn()
				<-done
				<-closed
				defer clear(body)
				if calls != 1 || !bytes.Equal(allocation, make([]byte, len(allocation))) || !bytes.Equal(ownedSeed, make([]byte, len(ownedSeed))) ||
					!bytes.Equal(ownedIntent, make([]byte, len(ownedIntent))) || f.base.route.publicCalls != public || f.base.route.privateCalls != private {
					t.Fatal("local return did not join and dispose without reopening keys")
				}
				select {
				case <-returnOwner.done:
				default:
					t.Fatal("closed receiver did not join its original return owner")
				}
				if success {
					if failureReason() != 0 {
						t.Fatal("successful result export supplied failure eligibility")
					}
					result, err := contract.DecodeGeneratedResultRecord(body)
					if err != nil || code != contract.CryptoSuccess || result.Core.Schema != contract.GeneratedResultCoreSchema || result.SafeFacts.LifecycleMode != contract.GeneratorLifecycleNone {
						t.Fatal("fresh local result refused", code, err)
					}
				} else if code != contract.CryptoCustodyUnavailable || len(body) != 0 || failureReason() != contract.GeneratorFailureInvalid {
					t.Fatal("rejected local return lost its exact joined failure", code, failureReason())
				}
			})
		})
	}
}
