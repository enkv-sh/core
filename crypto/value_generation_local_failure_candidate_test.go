package crypto

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	protocol "enkv.sh/sdk/protocols/generator"
)

type generatedLocalFailureClaimFixture struct {
	f            generatedRuntimeFixture
	current      generatedCandidate
	phase        contract.GeneratedPhaseRecord
	refs         []contract.Ref
	q            contract.CryptoGeneratedCompareRequest
	control      contract.ControlCore
	construction GeneratedCustodyConstruction
	input        contract.GeneratedLocalFailureInput
	admit        GeneratedLocalFailureAdmitter
	cancel       context.CancelFunc
	deadline     time.Time
	calls        *int
}

func generatedLocalFailureClaimExchange(t *testing.T, owner *GeneratedCustody, kind contract.CryptoKind, body []byte) contract.CryptoResponse {
	t.Helper()
	return owner.Exchange(context.Background(), contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: kind,
		RequestID: consumerID("local failure candidate exchange " + strconv.Itoa(int(kind))), CustodyInstanceID: owner.InstanceID(), Body: body})
}

func generatedLocalFailureProcessPlan(t *testing.T, f generatedRuntimeFixture) (generatedRuntimeFixture, contract.GeneratorImplementation) {
	t.Helper()
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	x := g.Lineages[0].Templates[0]
	oldTemplate, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	route, routeID := generatedFixtureRoute(t)
	row := contract.GeneratorImplementation{Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind,
		DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID,
		ProtocolID: contract.ID(protocol.ProtocolID()), ArtifactContractID: consumerID("local process artifact contract"),
		DependencyManifestID: consumerID("local process dependencies"), ArtifactSHA256: consumerID("local process artifact"),
		CredentialRouteID: routeID, CredentialRoute: route,
		ArtifactLength: 1, Module: "local-process-fixture", Command: "cmd/local-process-fixture", Version: "0.0.0", GoVersion: "go1.27.3", NativeTuple: "darwin/arm64"}
	x.CredentialRouteID = routeID
	if err := row.Validate(); err != nil {
		t.Fatal(err)
	}
	x.ResultContractID, err = contract.GeneratedResultContractID(row, contract.GeneratorActionCreate, 0, contract.CryptoMaxRawValue, contract.GeneratorSafeFactsEnvelopeLength, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	if err != nil {
		t.Fatal(err)
	}
	newTemplate, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	g.Lineages[0].Templates[0] = x
	for i := range g.Edges {
		if g.Edges[i].SourceTemplateID == oldTemplate {
			g.Edges[i].SourceTemplateID = newTemplate
		}
		if g.Edges[i].DestinationTemplateID == oldTemplate {
			g.Edges[i].DestinationTemplateID = newTemplate
		}
	}
	g.ResultUses[0].ResultContractID = x.ResultContractID
	g.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(g.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	if err := contract.ValidateGeneratorEffectGraph(g); err != nil {
		t.Fatal("new Process graph does not bind its structural implementation", err)
	}
	return generatedRuntimeEffectGraphFixture(t, f, g), row
}

func generatedLocalFailureCandidateFixture(t *testing.T, otherReceiver, shortDeadline bool, processReason uint8) generatedLocalFailureClaimFixture {
	t.Helper()
	plan := generatedRuntimeLocalEffectFixture(t)
	var implementation contract.GeneratorImplementation
	if processReason != 0 {
		plan, implementation = generatedLocalFailureProcessPlan(t, plan)
	}
	f, prepared, current := generatedProducerPlanFixture(t, plan)
	if otherReceiver {
		f.compare.Parent.RequestIdentityDigest = consumerID("another original receiver request")
		f.producer.Producer.Preparation.RequestIdentityDigest = f.compare.Parent.RequestIdentityDigest
		var err error
		f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
		if err != nil {
			t.Fatal(err)
		}
		current.Subject.RequestIdentityDigest = f.compare.Parent.RequestIdentityDigest
		for i, row := range current.SupportRecords {
			if row.Kind == contract.GeneratedParentSupportKind && row.RecordID == f.compare.Parent.OperationID {
				current.SupportRecords[i].Body, err = contract.EncodeGeneratedParentRecord(f.compare.Parent)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	binding, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 1,
		ContractID: consumerID("failure retained support contract"), ImplementationID: consumerID("failure retained support implementation"), PublicBindingDigest: consumerID("failure retained support binding")})
	if err != nil {
		t.Fatal(err)
	}
	support, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSupport, [][]byte{binding})
	if err != nil {
		t.Fatal(err)
	}
	p := &f.producer.Producer
	p.Attempt.Support, p.Duty.Support = support, support
	history, err := contract.EncodeGeneratorHistory(contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: p.Attempt.AttemptID,
		OwnerID: p.Attempt.OwnerID, Outcome: contract.GeneratedEffectTransmitted})
	if err != nil {
		t.Fatal(err)
	}
	p.Attempt.History, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, [][]byte{history})
	if err != nil {
		t.Fatal(err)
	}
	p.Duty.History = p.Attempt.History
	for i, row := range current.SupportRecords {
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == p.Attempt.AttemptID {
			current.SupportRecords[i].Body, err = contract.EncodeGeneratedAttemptRecord(p.Attempt)
		}
		if row.Kind == contract.GeneratedDutySupportKind && row.RecordID == p.Duty.DutyID {
			current.SupportRecords[i].Body, err = contract.EncodeGeneratedDutyRecord(p.Duty)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, owner := range []struct {
		kind uint8
		id   contract.ID
	}{{contract.GeneratedAttemptSupportKind, p.Attempt.AttemptID}, {contract.GeneratedDutySupportKind, p.Duty.DutyID}} {
		current.SupportRecords = append(current.SupportRecords, generatedVectorSupport(t, f.compare.Context.DomainID, owner.kind, owner.id, contract.GeneratorVectorHistory, [][]byte{history})...)
	}
	current.SupportRecords = append(current.SupportRecords, generatedVectorSupport(t, f.compare.Context.DomainID, contract.GeneratedParentSupportKind, p.Attempt.OperationID, contract.GeneratorVectorSupport, [][]byte{binding})...)
	head, err := format.DecodeHeadCore(current.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	var locations [][]byte
	for _, content := range []struct {
		kind uint8
		id   contract.ID
		body []byte
	}{
		{contract.GeneratorContentIntent, p.Expected.Template.IntentDigest, p.Intent},
		{contract.GeneratorContentDeclaration, p.Attempt.OperationID, f.declaration},
		{contract.GeneratorContentGraph, p.Expected.Plan.PlanGraphID, f.graph},
	} {
		blob := contract.Hash(content.body)
		fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
			TotalLength: uint64(len(content.body)), WholeDigest: blob, Payload: content.body})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		current.SupportRecords = append(current.SupportRecords, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: fragment})
		location, err := contract.EncodeGeneratorSliceLocation(contract.GeneratorSliceLocation{Schema: 1, ContentKind: content.kind,
			ContentID: content.id, BlobID: blob, Length: uint32(len(content.body)), Digest: blob})
		if err != nil {
			t.Fatal(err)
		}
		locations = append(locations, location)
	}
	current.SupportRecords = append(current.SupportRecords, generatedVectorSupport(t, f.compare.Context.DomainID, contract.GeneratorSnapshotOwner,
		head.Root.Object, contract.GeneratorVectorSlices, locations)...)
	otherAccess := current.AccessRecords[0]
	otherAccess.MaterialID = consumerID("unrelated retained seed material")
	otherAccess.MaterialContextDigest = consumerID("unrelated retained seed context")
	otherAccess.PackageCheck = consumerID("unrelated retained seed check")
	otherAccess.Wraps = slices.Clone(otherAccess.Wraps)
	current.AccessRecords = append(current.AccessRecords, otherAccess)
	generatedFinalConservationDescriptors(t, &current)
	current, phase, refs := generatedLocalFailureCurrentFixture(t, f, current)
	original, cancel := context.WithCancel(context.Background())
	deadline := f.base.deadline
	if shortDeadline {
		cancel()
		deadline = time.Now().Add(10 * time.Second)
		original, cancel = context.WithDeadline(context.Background(), deadline)
	}
	t.Cleanup(cancel)
	calls := 0
	expectedReason := uint8(contract.GeneratorFailureInvalid)
	if processReason == 0 {
		f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
			calls++
			return generatedProducerReturn{}
		}
	} else {
		launcher := telemetryProcessLauncher{implementation: implementation,
			commandID: protocol.ID(consumerID("qualified local failure child")), waits: &calls}
		switch processReason {
		case contract.GeneratorFailureCancelled:
			launcher.omitResult, launcher.status = true, protocol.Status{Stage: protocol.StatusStageCommand, Category: protocol.StatusCancelled}
			launcher.waitErr = errors.New("joined expected child failure")
		case contract.GeneratorFailureProtocol:
			launcher.rawResult, launcher.status = []byte{1}, protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}
		default:
			t.Fatal("unsupported controlled local process failure fixture")
		}
		expectedReason = processReason
		f.producer.Producer.Return, f.producer.Producer.Process = nil, launcher
	}
	r := f.producerRuntime(t)
	t.Cleanup(r.Close)
	owner, err := newGeneratedCustody(r, func() (*generatedAdmission, error) { return r.generated, nil })
	if err != nil {
		t.Fatal(err)
	}
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	authority := generatedProducerClaim(t, r, f, current, op, uses)
	returned := owner.InvokeProducer(original, locator, authority)
	body, code := returned.Record, returned.Code
	owner.Close()
	if calls != 1 || len(body) != 0 || code == contract.CryptoSuccess {
		t.Fatal("fixture did not join one original failed producer", calls, code)
	}
	reason, admit := owner.LocalFailureAdmission()
	if reason == nil || admit == nil || reason() != expectedReason {
		t.Fatal("joined original receiver supplied no exact failure admission")
	}
	// An independent administrative slice owner can differ from the retained
	// active Phase and HEAD snapshot; the exact inherited facts authenticate it.
	beforeOwner := consumerID("independently rebound administrative slice owner")
	for i, row := range current.SupportRecords {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if carrier.OwnerKind != contract.GeneratorSnapshotOwner {
			continue
		}
		carrier.OwnerID = beforeOwner
		current.SupportRecords[i].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
		if err != nil {
			t.Fatal(err)
		}
		current.SupportRecords[i].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			t.Fatal(err)
		}
	}
	generatedCanonicalizeCandidateSupport(t, &current)
	q, control, construction, input := generatedLocalFailureContinuationFixture(t, f, prepared, current, phase, refs, expectedReason)
	input.BeforeSliceSnapshot = beforeOwner
	if shortDeadline {
		q.Context.Expiry = uint64(deadline.UnixNano())
		q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
		if err != nil {
			t.Fatal(err)
		}
	}
	return generatedLocalFailureClaimFixture{f: f, current: current, phase: phase, refs: refs, q: q, control: control,
		construction: construction, input: input, admit: admit, cancel: cancel, deadline: deadline, calls: &calls}
}

func (f generatedLocalFailureClaimFixture) prepared(t *testing.T) (*GeneratedCustody, contract.ID, []contract.KeyUseRow) {
	t.Helper()
	r := newConsumerRuntime(t, f.f.base.route)
	t.Cleanup(r.Close)
	owner, err := f.admit(context.Background(), r, f.q, f.control, f.construction, f.input, f.deadline)
	if err != nil {
		t.Fatal("fresh exact receiver admission", err)
	}
	t.Cleanup(owner.Close)
	body, err := contract.EncodeCryptoGeneratedCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := generatedLocalFailureClaimExchange(t, owner, contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("fresh receiver Compare", reply.ResultCode)
	}
	compared, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	uses := slices.Clone(reply.KeyUseRows)
	body, err = contract.EncodeCryptoGeneratedLocalFailureRequest(contract.CryptoGeneratedLocalFailureRequest{OperationRef: compared.OperationRef,
		Context: f.q.Context, AttemptID: f.input.Attempt.AttemptID, Reason: f.input.Attempt.FailureReason})
	if err != nil {
		t.Fatal(err)
	}
	reply = generatedLocalFailureClaimExchange(t, owner, contract.CryptoPrepare, body)
	if reply.ResultCode != contract.CryptoSuccess || !bytes.Equal(reply.Body, []byte{9}) || len(reply.KeyUseRows) != 0 {
		t.Fatal("fresh receiver Prepare9", reply.ResultCode)
	}
	return owner, compared.OperationRef, uses
}

func (f generatedLocalFailureClaimFixture) candidate(t *testing.T) generatedCandidate {
	t.Helper()
	c := f.current
	c.SupportRecords = slices.Clone(c.SupportRecords)
	for i := range c.SupportRecords {
		c.SupportRecords[i].Body = bytes.Clone(c.SupportRecords[i].Body)
	}
	phaseID, err := contract.GeneratorPhaseID(f.input.Phase)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	phase := f.phase
	phase.PhaseID, phase.Phase, phase.Stage = phaseID, f.input.Phase.AfterPhase, contract.GeneratedStageTerminal
	phase.AcceptedResultID, phase.ResultDigest = contract.ID{}, contract.ID{}
	for i, row := range c.SupportRecords {
		switch {
		case row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == f.input.Attempt.AttemptID:
			c.SupportRecords[i].Body, err = contract.EncodeGeneratedAttemptRecord(f.input.Attempt)
		case row.Kind == contract.GeneratedDutySupportKind && row.RecordID == f.input.Attempt.OwnerID:
			duty, inspectErr := contract.InspectGeneratedDutyRecord(row.Body)
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			duty.Status = contract.GeneratedEffectFailedTerminal
			c.SupportRecords[i].Body, err = contract.EncodeGeneratedDutyRecord(duty)
		case row.Kind == contract.GeneratorVectorSupportKind:
			carrier, inspectErr := contract.InspectGeneratorVectorCarrier(row.Body)
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if carrier.OwnerKind == contract.GeneratorSnapshotOwner {
				carrier.OwnerID = snapshot
				c.SupportRecords[i].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
				if err == nil {
					c.SupportRecords[i].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
				}
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, set := range []struct {
		kind   uint8
		family contract.GeneratorRecordSetKind
		out    *contract.GeneratorDescriptor
	}{{contract.GeneratedAttemptSupportKind, contract.GeneratorPhaseAttempts, &phase.Attempts}, {contract.GeneratedDutySupportKind, contract.GeneratorPhaseDuties, &phase.Duties}} {
		var rows []contract.SupportRecord
		for _, row := range c.SupportRecords {
			if row.Kind == set.kind {
				rows = append(rows, row)
			}
		}
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
		*set.out, err = contract.GeneratorRecordSetDescriptor(set.family, f.q.Context.DomainID, rows)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range c.SupportRecords {
		if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == f.input.Attempt.OperationID {
			c.SupportRecords[i].Body, err = contract.EncodeGeneratedPhaseRecord(phase)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	c.ActivePhase = phaseID
	c.Subject.Purpose, c.Subject.PhaseID = contract.GeneratorAuthorityFailedTerminal, phaseID
	c.Subject.PreviousHEADDigest = f.q.Context.PredecessorHEADDigest
	beforeHead, err := format.DecodeHeadCore(f.current.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	c.Subject.PreviousRevisionID, c.Subject.BeforeRootDigest = beforeHead.Revision, beforeHead.Root.Digest
	c.Subject.BeforeAccessDigest, c.Subject.AfterAccessDigest = f.current.PublicState.AccessRoot, f.current.PublicState.AccessRoot
	c.Subject.BeforePhase, c.Subject.AfterPhase = f.input.Phase.BeforePhase, f.input.Phase.AfterPhase
	a := f.input.Attempt
	c.Subject.OwnerID, c.Subject.LineageID, c.Subject.AttemptID = f.q.Parent.OperationID, a.LineageID, a.AttemptID
	c.Subject.PredecessorAttemptID, c.Subject.ResultID, c.Subject.ResultDigest = contract.ID{}, a.ResultID, contract.ID{}
	c.Subject.DescriptorID, c.Subject.ConfigContractID, c.Subject.ResultContractID = a.DescriptorID, a.ConfigContractID, a.ResultContractID
	c.Subject.Intent, c.Subject.CapacityReservation = f.q.Parent.Declaration, f.q.Parent.Capacity
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Subject.ResultVector = contract.GeneratorDescriptor(empty)
	c.Subject.BeforeWork, err = contract.GeneratorAuthorityWorkDescriptor(f.q.Context.DomainID, f.current.SupportRecords)
	if err != nil {
		t.Fatal(err)
	}
	generatedRewriteHead(t, &c, func(head *format.HeadCore) {
		head.PreviousDigest, head.PreviousRevision = f.q.Context.PredecessorHEADDigest, beforeHead.Revision
		head.Root.Object, head.Revision, head.Root.Digest = snapshot, revision, consumerID("failed local candidate root")
	})
	generatedLocalFailureRefreshCandidate(t, &c)
	return c
}

func generatedLocalFailureRefreshCandidate(t *testing.T, c *generatedCandidate) {
	t.Helper()
	generatedCanonicalizeCandidateSupport(t, c)
	var err error
	c.Subject.AfterWork, err = contract.GeneratorAuthorityWorkDescriptor(c.PublicState.Domain, c.SupportRecords)
	if err != nil {
		t.Fatal(err)
	}
	head, err := format.DecodeHeadCore(c.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	c.Subject.AfterRootDigest = head.Root.Digest
	c.Subject.HeadCoreDigest, c.Subject.HeadCoreLength = contract.Hash(c.HeadCore), uint32(len(c.HeadCore))
	c.Subject.ConditionalPlanDigest, c.Subject.ConditionalLength = contract.Hash(c.Conditional), uint32(len(c.Conditional))
}

func generatedLocalFailurePublicCandidate(c generatedCandidate) contract.GeneratedCandidateInput {
	out := contract.GeneratedCandidateInput{ActiveOwner: c.ActiveOwner, ActivePhase: c.ActivePhase, ActiveGraph: c.ActiveGraph,
		Subject: c.Subject, PublicState: c.PublicState, CurrentAccess: c.CurrentAccess, AccessRecords: c.AccessRecords, SupportRecords: c.SupportRecords,
		HeadCore: c.HeadCore, Conditional: c.Conditional, SourceProtections: c.SourceProtections, LiveSourceUses: c.LiveSourceUses, Registry: c.Registry}
	for _, row := range c.Entries {
		out.Entries = append(out.Entries, contract.GeneratedCandidateEntry(row))
	}
	return out
}

func generatedLocalFailureClaimRequest(t *testing.T, f generatedLocalFailureClaimFixture, operation contract.ID, c generatedCandidate, uses []contract.KeyUseRow) contract.CryptoGeneratedFreezeRequest {
	t.Helper()
	fixture := f.f
	fixture.compare = f.q
	return generatedCandidateRequest(t, fixture, operation, c, nil, uses)
}

func generatedLocalFailureClaimLater(t *testing.T, owner *GeneratedCustody, q contract.CryptoGeneratedFreezeRequest) (contract.CryptoResponse, contract.CryptoResponse) {
	t.Helper()
	body, err := contract.EncodeCryptoGeneratedFreezeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	freeze := generatedLocalFailureClaimExchange(t, owner, contract.CryptoFreeze, body)
	body, err = contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
	if err != nil {
		t.Fatal(err)
	}
	return freeze, generatedLocalFailureClaimExchange(t, owner, contract.CryptoClaim, body)
}

func generatedLocalFailureRewriteSliceCarriers(t *testing.T, c *generatedCandidate, mutate func(*[]contract.GeneratorVectorCarrier)) {
	t.Helper()
	var carriers []contract.GeneratorVectorCarrier
	other := slices.DeleteFunc(slices.Clone(c.SupportRecords), func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if carrier.OwnerKind != contract.GeneratorSnapshotOwner {
			return false
		}
		carriers = append(carriers, carrier)
		return true
	})
	slices.SortFunc(carriers, func(a, b contract.GeneratorVectorCarrier) int { return int(a.Ordinal) - int(b.Ordinal) })
	mutate(&carriers)
	bodies := make([][]byte, len(carriers))
	for i, carrier := range carriers {
		bodies[i] = carrier.Row
	}
	descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, bodies)
	if err != nil {
		t.Fatal(err)
	}
	for i, carrier := range carriers {
		carrier.Vector, carrier.Ordinal = descriptor, uint32(i)
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			t.Fatal(err)
		}
		other = append(other, contract.SupportRecord{Kind: contract.GeneratorVectorSupportKind, RecordID: id, Body: body})
	}
	c.SupportRecords = other
}

// full_only: false
func TestGeneratedLocalFailureCandidateConservesActualSelectedFacts(t *testing.T) {
	for _, damage := range []string{"exact", "reason", "duty-capacity", "phase-cursor", "accepted-results", "parent", "support", "history", "fragment-change", "fragment-remove", "carrier-owner", "carrier-location", "carrier-subset", "row-add", "unrelated-access", "before-owner", "before-work", "after-work"} {
		t.Run(damage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := generatedLocalFailureCandidateFixture(t, false, false, 0)
				if damage == "before-owner" {
					f.input.BeforeSliceSnapshot = consumerID("wrong inherited slice owner")
				}
				owner, op, uses := f.prepared(t)
				candidate := f.candidate(t)
				for i, row := range candidate.SupportRecords {
					var err error
					switch {
					case damage == "reason" && row.Kind == contract.GeneratedAttemptSupportKind:
						v, inspectErr := contract.InspectGeneratedAttemptRecord(row.Body)
						if inspectErr != nil {
							t.Fatal(inspectErr)
						}
						v.FailureReason = contract.GeneratorFailureProtocol
						candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedAttemptRecord(v)
					case damage == "duty-capacity" && row.Kind == contract.GeneratedDutySupportKind:
						v, inspectErr := contract.InspectGeneratedDutyRecord(row.Body)
						if inspectErr != nil {
							t.Fatal(inspectErr)
						}
						v.CapacityReservation.Digest = consumerID("changed exact create Duty capacity")
						candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedDutyRecord(v)
					case (damage == "phase-cursor" || damage == "accepted-results") && row.Kind == contract.GeneratedPhaseSupportKind:
						v, inspectErr := contract.InspectGeneratedPhaseRecord(row.Body)
						if inspectErr != nil {
							t.Fatal(inspectErr)
						}
						if damage == "phase-cursor" {
							v.FrontierAttemptID = consumerID("untransmitted cursor")
						} else {
							v.AcceptedResults.Digest = consumerID("changed earlier accepted results")
						}
						candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedPhaseRecord(v)
					case damage == "parent" && row.Kind == contract.GeneratedParentSupportKind:
						v, inspectErr := contract.InspectGeneratedParentRecord(row.Body)
						if inspectErr != nil {
							t.Fatal(inspectErr)
						}
						v.Capacity.Digest = consumerID("changed immutable Parent")
						candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedParentRecord(v)
					case (damage == "support" || damage == "history") && row.Kind == contract.GeneratorVectorSupportKind:
						v, inspectErr := contract.InspectGeneratorVectorCarrier(row.Body)
						if inspectErr != nil {
							t.Fatal(inspectErr)
						}
						if damage == "support" && v.VectorKind == contract.GeneratorVectorSupport {
							binding, inspectErr := contract.InspectGeneratorSupportBinding(v.Row)
							if inspectErr != nil {
								t.Fatal(inspectErr)
							}
							binding.ImplementationID = consumerID("changed retained sibling support")
							v.Row, err = contract.EncodeGeneratorSupportBinding(binding)
						} else if damage == "history" && v.VectorKind == contract.GeneratorVectorHistory {
							history, inspectErr := contract.InspectGeneratorHistory(v.Row)
							if inspectErr != nil {
								t.Fatal(inspectErr)
							}
							history.Outcome = contract.GeneratedEffectPossibleLive
							v.Row, err = contract.EncodeGeneratorHistory(history)
						}
						if err == nil {
							candidate.SupportRecords[i].Body, err = contract.EncodeGeneratorVectorCarrier(v)
						}
					case damage == "fragment-change" && row.Kind == contract.GeneratedFragmentSupportKind:
						v, inspectErr := contract.DecodeGeneratedFragment(row.Body)
						if inspectErr != nil {
							t.Fatal(inspectErr)
						}
						v.Payload[0] ^= 1
						v.WholeDigest = contract.Hash(v.Payload)
						candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedFragment(v)
					}
					if err != nil {
						t.Fatal("tamper must remain individually encodable", err)
					}
				}
				if damage == "fragment-remove" {
					index := slices.IndexFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool { return row.Kind == contract.GeneratedFragmentSupportKind })
					candidate.SupportRecords = slices.Delete(candidate.SupportRecords, index, index+1)
				}
				if damage == "carrier-owner" || damage == "carrier-location" || damage == "carrier-subset" {
					generatedLocalFailureRewriteSliceCarriers(t, &candidate, func(rows *[]contract.GeneratorVectorCarrier) {
						switch damage {
						case "carrier-owner":
							(*rows)[0].OwnerID = consumerID("foreign snapshot carrier owner")
						case "carrier-location":
							location, err := contract.InspectGeneratorSliceLocation((*rows)[0].Row)
							if err != nil {
								t.Fatal(err)
							}
							location.Offset++
							(*rows)[0].Row, err = contract.EncodeGeneratorSliceLocation(location)
							if err != nil {
								t.Fatal(err)
							}
						case "carrier-subset":
							*rows = (*rows)[:len(*rows)-1]
						}
					})
				}
				if damage == "row-add" {
					payload := []byte("an unowned fragment")
					blob := contract.Hash(payload)
					body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: blob, Payload: payload})
					if err != nil {
						t.Fatal(err)
					}
					id, err := contract.GeneratorFragmentID(blob, 0)
					if err != nil {
						t.Fatal(err)
					}
					candidate.SupportRecords = append(candidate.SupportRecords, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body})
				}
				if damage == "unrelated-access" {
					candidate.AccessRecords = slices.Clone(candidate.AccessRecords)
					index := slices.IndexFunc(candidate.AccessRecords, func(row contract.AccessRecord) bool {
						return row.MaterialID == consumerID("unrelated retained seed material")
					})
					candidate.AccessRecords[index].Wraps = slices.Clone(candidate.AccessRecords[index].Wraps)
					candidate.AccessRecords[index].Wraps[0].RSACiphertext = bytes.Clone(candidate.AccessRecords[index].Wraps[0].RSACiphertext)
					candidate.AccessRecords[index].Wraps[0].RSACiphertext[0] ^= 1
					candidate.CurrentAccess.AccessGeneration++
					candidate.CurrentAccess.AccessPageRefs = slices.Clone(candidate.CurrentAccess.AccessPageRefs)
					candidate.CurrentAccess.AccessPageRefs[0].Object = consumerID("new page for changed unrelated access")
					generatedFinalConservationDescriptors(t, &candidate)
					candidate.Subject.AfterAccessDigest = candidate.PublicState.AccessRoot
				}
				generatedLocalFailureRefreshCandidate(t, &candidate)
				if damage == "before-work" {
					candidate.Subject.BeforeWork.Digest = consumerID("false before work")
				}
				if damage == "after-work" {
					candidate.Subject.AfterWork.Digest = consumerID("false after work")
				}
				q := generatedLocalFailureClaimRequest(t, f, op, candidate, uses)
				public, private := f.f.base.route.publicCalls, f.f.base.route.privateCalls
				code := owner.BindCandidate(context.Background(), generatedLocalFailurePublicCandidate(candidate))
				freeze, claim := generatedLocalFailureClaimLater(t, owner, q)
				if damage == "exact" {
					if code != contract.CryptoSuccess || freeze.ResultCode != contract.CryptoSuccess || claim.ResultCode != contract.CryptoSuccess {
						t.Fatal("genuine joined failure did not Bind/Freeze/Claim", code, freeze.ResultCode, claim.ResultCode)
					}
				} else if code == contract.CryptoSuccess || freeze.ResultCode == contract.CryptoSuccess || claim.ResultCode == contract.CryptoSuccess || len(freeze.Body) != 0 || len(claim.Body) != 0 {
					t.Fatal("changed complete candidate retained signing rights", code, freeze.ResultCode, claim.ResultCode)
				}
				if *f.calls != 1 {
					t.Fatal("failure closure re-entered its consumed producer")
				}
				if damage != "exact" && (f.f.base.route.publicCalls != public || f.f.base.route.privateCalls != private) {
					t.Fatal("refused candidate reopened keys")
				}
			})
		})
	}
}

// full_only: false
func TestGeneratedLocalFailureRefusesForeignReceiverReasonAndTuple(t *testing.T) {
	for _, damage := range []string{"receiver", "unentered same tuple", "reason", "tuple"} {
		t.Run(damage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := generatedLocalFailureCandidateFixture(t, false, false, 0)
				if damage == "receiver" {
					other := generatedLocalFailureCandidateFixture(t, true, false, 0)
					f.admit = other.admit
				}
				if damage == "unentered same tuple" {
					// This is a separate genuinely admitted producer with the same public
					// Attempt. It never Compare/Prepare/Claims or invokes a return owner.
					otherRuntime := f.f.producerRuntime(t)
					t.Cleanup(otherRuntime.Close)
					other, err := newGeneratedCustody(otherRuntime, func() (*generatedAdmission, error) { return otherRuntime.generated, nil })
					if err != nil {
						t.Fatal(err)
					}
					other.Close()
					reason, admit := other.LocalFailureAdmission()
					if reason == nil || admit == nil || reason() != 0 || *f.calls != 1 {
						t.Fatal("closed nonentered receiver gained a joined failure")
					}
					f.admit = admit
				}
				if damage == "reason" {
					f.input.Attempt.FailureReason = contract.GeneratorFailureUnavailable
				}
				if damage == "tuple" {
					f.input.Attempt.RequestDigest = consumerID("another original command")
				}
				body, err := contract.EncodeGeneratedAttemptRecord(f.input.Attempt)
				if err != nil {
					t.Fatal(err)
				}
				f.input.Phase.Evidence = contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: uint64(len(body)), Count: 1}
				fresh := newConsumerRuntime(t, f.f.base.route)
				t.Cleanup(fresh.Close)
				public, private := f.f.base.route.publicCalls, f.f.base.route.privateCalls
				owner, err := f.admit(context.Background(), fresh, f.q, f.control, f.construction, f.input, f.deadline)
				if owner != nil {
					owner.Close()
				}
				if err == nil || owner != nil || f.f.base.route.publicCalls != public || f.f.base.route.privateCalls != private || *f.calls != 1 {
					t.Fatal("foreign failure proof reached fresh custody or reopened keys", err)
				}
			})
		})
	}
}

// full_only: false
func TestGeneratedLocalFailureAuthorityStaysLiveThroughClaim(t *testing.T) {
	for _, condition := range []string{"cancel-before-bind", "cancel-before-freeze", "cancel-before-claim", "expire-before-bind", "expire-before-freeze", "expire-before-claim"} {
		t.Run(condition, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				expires := condition[:6] == "expire"
				f := generatedLocalFailureCandidateFixture(t, false, expires, 0)
				owner, op, uses := f.prepared(t)
				candidate := f.candidate(t)
				q := generatedLocalFailureClaimRequest(t, f, op, candidate, uses)
				end := func() {
					if expires {
						time.Sleep(time.Until(f.deadline) + time.Nanosecond)
					} else {
						f.cancel()
					}
				}
				beforeBind := condition == "cancel-before-bind" || condition == "expire-before-bind"
				beforeFreeze := condition == "cancel-before-freeze" || condition == "expire-before-freeze"
				public, private := f.f.base.route.publicCalls, f.f.base.route.privateCalls
				if beforeBind {
					end()
				}
				bound := owner.BindCandidate(context.Background(), generatedLocalFailurePublicCandidate(candidate))
				if beforeBind && bound == contract.CryptoSuccess || !beforeBind && bound != contract.CryptoSuccess {
					t.Fatal("original liveness did not govern Background BindCandidate", bound)
				}
				if beforeFreeze {
					end()
				}
				body, err := contract.EncodeCryptoGeneratedFreezeRequest(q)
				if err != nil {
					t.Fatal(err)
				}
				freeze := generatedLocalFailureClaimExchange(t, owner, contract.CryptoFreeze, body)
				if beforeBind || beforeFreeze {
					if freeze.ResultCode == contract.CryptoSuccess || len(freeze.Body) != 0 {
						t.Fatal("Background Freeze extended original authority", freeze.ResultCode)
					}
				} else {
					if freeze.ResultCode != contract.CryptoSuccess {
						t.Fatal("live failure could not Freeze before cancellation", freeze.ResultCode)
					}
					end()
				}
				body, err = contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
				if err != nil {
					t.Fatal(err)
				}
				claim := generatedLocalFailureClaimExchange(t, owner, contract.CryptoClaim, body)
				if claim.ResultCode == contract.CryptoSuccess || len(claim.Body) != 0 || len(claim.KeyUseRows) != 0 ||
					f.f.base.route.publicCalls != public || f.f.base.route.privateCalls != private || *f.calls != 1 {
					t.Fatal("Background Claim extended original authority or reopened custody", claim.ResultCode)
				}
			})
		})
	}
}

// full_only: false
func TestGeneratedLocalFailureMalformedCarriersLoseLaterRights(t *testing.T) {
	for _, damage := range []string{"record-id", "duplicate-ordinal"} {
		t.Run(damage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := generatedLocalFailureCandidateFixture(t, false, false, 0)
				owner, op, uses := f.prepared(t)
				candidate := f.candidate(t)
				q := generatedLocalFailureClaimRequest(t, f, op, candidate, uses)
				first := -1
				for i, row := range candidate.SupportRecords {
					if row.Kind != contract.GeneratorVectorSupportKind {
						continue
					}
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if carrier.OwnerKind != contract.GeneratorSnapshotOwner {
						continue
					}
					if first < 0 {
						first = i
						if damage == "record-id" {
							candidate.SupportRecords[i].RecordID = consumerID("unbound snapshot carrier ID")
							break
						}
						continue
					}
					candidate.SupportRecords[i] = candidate.SupportRecords[first]
					break
				}
				bound := owner.BindCandidate(context.Background(), generatedLocalFailurePublicCandidate(candidate))
				freeze, claim := generatedLocalFailureClaimLater(t, owner, q)
				if bound == contract.CryptoSuccess || freeze.ResultCode == contract.CryptoSuccess || claim.ResultCode == contract.CryptoSuccess || len(freeze.Body) != 0 || len(claim.Body) != 0 {
					t.Fatal("malformed carrier retained later signing rights", bound, freeze.ResultCode, claim.ResultCode)
				}
			})
		})
	}
}

// full_only: false
func TestGeneratedLocalQualifiedProcessFailureReachesClaim(t *testing.T) {
	for _, reason := range []uint8{contract.GeneratorFailureCancelled, contract.GeneratorFailureProtocol} {
		t.Run(strconv.Itoa(int(reason)), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := generatedLocalFailureCandidateFixture(t, false, false, reason)
				if f.input.Attempt.FailureReason != reason || *f.calls != 1 {
					t.Fatal("original qualified child did not positively join with its exact reason")
				}
				owner, op, uses := f.prepared(t)
				candidate := f.candidate(t)
				q := generatedLocalFailureClaimRequest(t, f, op, candidate, uses)
				bound := owner.BindCandidate(context.Background(), generatedLocalFailurePublicCandidate(candidate))
				freeze, claim := generatedLocalFailureClaimLater(t, owner, q)
				if bound != contract.CryptoSuccess || freeze.ResultCode != contract.CryptoSuccess || claim.ResultCode != contract.CryptoSuccess || *f.calls != 1 {
					t.Fatal("qualified child failure lost its original receiver before claim", bound, freeze.ResultCode, claim.ResultCode)
				}
			})
		})
	}
}
