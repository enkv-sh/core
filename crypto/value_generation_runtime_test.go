package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/sdk/artifact/credentialroute"
)

func generatedFixtureRoute(t testing.TB) ([]byte, contract.ID) {
	t.Helper()
	route := credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment}
	body, err := credentialroute.Encode(route)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := credentialroute.Identity(route)
	if err != nil {
		t.Fatal(err)
	}
	return body, contract.ID(identity)
}

func generatedFixtureIntent(config, resource contract.ID, mode contract.GeneratorLifecycleMode, settings string) []byte {
	body := binary.BigEndian.AppendUint16(nil, 1)
	body = append(body, config[:]...)
	body = append(body, byte(mode))
	body = append(body, resource[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(settings)))
	return append(body, settings...)
}

type generatedRuntimeFixture struct {
	base         applyTestFixture
	compare      contract.CryptoGeneratedCompareRequest
	reservation  generatedReservationAdmissionInput
	adoption     generatedAdoptionAdmissionInput
	final        generatedFinalAdmissionInput
	producer     generatedProducerPreparationAdmissionInput
	verification generatedOriginalVerificationAdmissionInput
	declaration  []byte
	graph        []byte
	entries      []generatedCandidateEntry
}

type generatedLockProbeContext struct {
	base    context.Context
	runtime *Runtime
	locked  bool
}

func (c *generatedLockProbeContext) probe() {
	if !c.runtime.mu.TryLock() {
		c.locked = true
		return
	}
	c.runtime.mu.Unlock()
}

func (c *generatedLockProbeContext) Deadline() (time.Time, bool) {
	c.probe()
	return c.base.Deadline()
}

func (c *generatedLockProbeContext) Done() <-chan struct{} {
	c.probe()
	return c.base.Done()
}

func (c *generatedLockProbeContext) Err() error {
	c.probe()
	return c.base.Err()
}

func (c *generatedLockProbeContext) Value(key any) any {
	c.probe()
	return c.base.Value(key)
}

func (c *generatedLockProbeContext) AfterFunc(f func()) func() bool {
	c.probe()
	return context.AfterFunc(c.base, f)
}

// The second Done call is made by AfterFunc after binding registers its work.
// Cancel there to cover disposal with binding work already owned.
type generatedBindingCancellationContext struct {
	context.Context
	runtime      *Runtime
	cancel       context.CancelFunc
	calls        atomic.Int32
	workObserved atomic.Bool
}

func (c *generatedBindingCancellationContext) Done() <-chan struct{} {
	if c.calls.Add(1) == 2 {
		c.runtime.mu.Lock()
		a := c.runtime.generated
		c.workObserved.Store(a != nil && a.busy && a.candidate == nil && a.purpose.output != nil)
		c.runtime.mu.Unlock()
		c.cancel()
	}
	return c.Context.Done()
}

// full_only: false
func TestGeneratedCallerContextMethodsRunOutsideRuntimeLock(t *testing.T) {
	t.Run("exchange", func(t *testing.T) {
		f := generatedRuntimePlanFixture(t, false)
		r := f.reservationRuntime(t)
		ctx := &generatedLockProbeContext{base: context.Background(), runtime: r}
		body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
		if err != nil {
			t.Fatal(err)
		}
		if reply := applyCall(r, ctx, contract.CryptoCompare, body); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("compare", reply.ResultCode)
		}
		if ctx.locked {
			t.Fatal("exchange called a caller Context method under Runtime.mu")
		}
	})

	t.Run("candidate", func(t *testing.T) {
		f := generatedRuntimePlanFixture(t, false)
		r, candidate, _ := generatedReadyCandidate(t, f)
		ctx := &generatedLockProbeContext{base: context.Background(), runtime: r}
		if code := r.bindGeneratedCandidate(ctx, f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
			t.Fatal("candidate", code)
		}
		if ctx.locked {
			t.Fatal("candidate binding called a caller Context method under Runtime.mu")
		}
	})

	t.Run("source", func(t *testing.T) {
		f := generatedSealedFinalFixture(t, false)
		r := f.finalRuntime(t)
		generatedSourceCompare(t, r, f)
		ctx := &generatedLockProbeContext{base: context.Background(), runtime: r}
		a := r.generated
		if code := r.verifyGeneratedSource(ctx, a.id, a.purpose.final.plan.sources[0].core.SourceID, f.base.q.SealedInputs[0].EnvelopeBytes); code != contract.CryptoSuccess {
			t.Fatal("source", code)
		}
		if ctx.locked {
			t.Fatal("source verification called a caller Context method under Runtime.mu")
		}
	})

	t.Run("producer entry", func(t *testing.T) {
		f, _, candidate := generatedProducerFixture(t, false)
		r := f.producerRuntime(t)
		op, uses := generatedAdoptionCompare(t, r, f)
		locator := generatedProducerPrepare(t, r, f, op)
		authority := generatedProducerClaim(t, r, f, candidate, op, uses)
		ctx := &generatedLockProbeContext{base: context.Background(), runtime: r}
		if out := r.invokeGeneratedProducer(ctx, f.compare.Context.AdmissionID, locator, authority); out.code != contract.CryptoSuccess {
			t.Fatal("producer entry", out.code)
		}
		if ctx.locked {
			t.Fatal("producer entry called a caller Context method under Runtime.mu")
		}
	})
}

func generatedRuntimePlanFixture(t *testing.T, recovery bool) generatedRuntimeFixture {
	t.Helper()
	f := generatedRuntimeFixture{base: applyFixture(t, recovery)}
	id := consumerID
	condition, err := contract.MatchHeadCondition(contract.Token{Family: contract.GCP, Value: "1"})
	if err != nil {
		t.Fatal(err)
	}
	f.base.q.Context.OriginalConditionDigest, err = contract.CryptoConditionDigest(condition)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.GeneratorRequestCore{Schema: 2, OperationKind: 2, DomainID: f.base.control.DomainID,
		OperationID: id("generated operation"), PredecessorRevisionID: id("generated predecessor revision"), PredecessorHEADDigest: f.base.q.Context.PredecessorHEADDigest,
		ConditionDigest: f.base.q.Context.OriginalConditionDigest, CallerNonce: id("generated nonce"), CompatibilityID: contract.CompatibilityID(), RecoveryPolicyID: id("generated recovery policy"),
		Registry: contract.GeneratorDescriptor{Digest: id("generated registry"), Length: 4, Count: 0}}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: request.DomainID, OperationID: request.OperationID}
	f.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal(err)
	}
	material, err := contract.GeneratorMaterialID(request.DomainID, request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := contract.GeneratorRequestCoreDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	bundle := contract.GeneratorPlanBundle{Request: request, Header: contract.GeneratorGraphHeader{Schema: contract.GeneratorGraphHeaderSchema, DomainID: request.DomainID,
		OperationID: request.OperationID, MaterialID: material, RequestCoreDigest: requestDigest, RecoveryPolicyID: request.RecoveryPolicyID}}
	graphID, err := contract.GeneratorGraphID(bundle.Header, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	results, err := contract.GeneratorResultUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := contract.GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle.UsePlan = contract.GeneratorUsePlanCore{DomainID: request.DomainID, OperationID: request.OperationID, MaterialID: material,
		PlanGraphID: graphID, ResultUses: results, SourceUses: sources, ValueDerivationID: contract.GeneratorValueDerivationID()}
	f.graph, err = contract.EncodeGeneratorPlanBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := contract.GeneratorPlanBundleDescriptor(bundle)
	if err != nil {
		t.Fatal(err)
	}
	entryPlansDescriptor, err := contract.GeneratorValueEntryPlansDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	use, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	parent := contract.GeneratedParentPlan{Schema: 2, DomainID: request.DomainID, OperationID: request.OperationID,
		RequestCoreDigest: requestDigest, PlanGraphID: graphID, UsePlanDigest: use, MaterialID: material,
		RecoveryPolicyID: request.RecoveryPolicyID, Declaration: request.Declaration,
		Registry: request.Registry, Graph: graph, SourceUses: sources, IntendedEntryPlans: entryPlansDescriptor,
		Capacity:                 contract.GeneratorDescriptor{Digest: id("generated capacity"), Length: 4, Count: 0},
		InitialPredecessorDigest: request.PredecessorHEADDigest, ConditionDigest: request.ConditionDigest}
	c := f.base.q.Context
	c.OperationClass = contract.CryptoGeneratedClass
	f.compare = contract.CryptoGeneratedCompareRequest{Context: c, Purpose: 1, ParentPlan: parent, PlanGraph: graph, UsePlanDigest: use,
		MaterialID: material, AcceptedSources: sources, IntendedEntryPlans: entryPlansDescriptor}
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation = generatedReservationAdmissionInput{
		Session: generatedSessionAdmissionInput{Control: f.base.control, Bindings: f.base.q.Bindings, RouteID: f.base.route.CredentialRoute(),
			Graph: f.graph, BeforePublic: contract.PublicState{Domain: c.DomainID, AccessRoot: c.CurrentAccessRoot, RequiredSupport: f.base.support}},
		Plan: generatedPlanAdmissionInput{Declaration: f.declaration},
	}
	f.reservation.Session.Output = generatedEmptyOutputWitness(t, &f.reservation.Session.BeforePublic, f.entries, nil)
	return f
}

func generatedEmptyOutputWitness(t *testing.T, before *contract.PublicState, entries []generatedCandidateEntry, records []contract.SupportRecord) *contract.GeneratedOutputTransition {
	t.Helper()
	w := &contract.GeneratedOutputTransition{Before: contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: before.Domain}}
	image, err := contract.EncodeOutputConfiguration(w.Before)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(before.Domain, image)
	w.BeforeDescriptor = descriptor
	if err != nil {
		t.Fatal(err)
	}
	records = slices.Clone(records)
	if !slices.ContainsFunc(records, func(row contract.SupportRecord) bool { return row.Kind == contract.OutputConfigurationSliceSupportKind }) {
		for _, part := range parts {
			body, err := contract.EncodeOutputConfigurationSlice(part)
			if err != nil {
				t.Fatal(err)
			}
			id, err := contract.OutputConfigurationSliceID(before.Domain, descriptor.ConfigurationDigest, part.SliceIndex)
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
		}
	}
	slices.SortFunc(records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	before.RequiredSupport, err = contract.RequiredSupportDescriptor(before.Domain, records)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range records {
		fact, err := contract.InspectSupportRecordDigest(before.Domain, row)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Facts = append(w.Rows.Facts, fact)
		if row.Kind == contract.RetainedCanonicalSupportKind {
			w.Retained = append(w.Retained, row)
		}
		if row.Kind >= contract.PublicationCoordinateSupportKind && row.Kind <= contract.OutputConfigurationSliceSupportKind {
			w.Rows.Records = append(w.Rows.Records, row)
		}
	}
	for _, row := range entries {
		digest, err := contract.PublicValueEntryDigest(before.Domain, row.Slot, row.Entry)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeValueEntry(row.Entry)
		if err != nil {
			t.Fatal(err)
		}
		w.EntriesBefore = append(w.EntriesBefore, contract.MembershipRow{Name: row.Entry.Name, Slot: row.Slot, Incarnation: row.Entry.Incarnation, EntryDigest: digest, Recipients: row.Entry.Recipients})
		w.EntryBodies = append(w.EntryBodies, body)
	}
	owned, err := w.Own(*before)
	if err != nil {
		t.Fatal("synthetic selected output facts", err)
	}
	return owned
}

func generatedCanonicalizeCandidateSupport(t *testing.T, c *generatedCandidate) {
	t.Helper()
	slices.SortFunc(c.SupportRecords, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	var err error
	c.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(c.PublicState.Domain, c.SupportRecords)
	if err != nil {
		t.Fatal("candidate support", err)
	}
}

func generatedPlanCandidate(t *testing.T, f generatedRuntimeFixture, result contract.CryptoGeneratedFinishPlanResult) generatedCandidate {
	t.Helper()
	id := consumerID
	parent := contract.GeneratedParentRecord(f.compare.ParentPlan)
	parent.RequestIdentityDigest = id("final generated request")
	if f.reservation.Phase != nil {
		parent.RequestIdentityDigest = f.reservation.Phase.RequestIdentityDigest
	}
	materialBody, err := contract.EncodeOperationMaterialRecord(result.Material)
	if err != nil {
		t.Fatal(err)
	}
	parentBody, err := contract.EncodeGeneratedParentRecord(parent)
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.DecodeAccessRecord(result.SeedAccess)
	if err != nil {
		t.Fatal(err)
	}
	candidate := generatedCandidate{AccessRecords: []contract.AccessRecord{access}, Entries: f.entries,
		SupportRecords: []contract.SupportRecord{{Kind: 1, RecordID: parent.MaterialID, Body: materialBody}, {Kind: 2, RecordID: parent.OperationID, Body: parentBody}}}
	if f.reservation.Session.Output != nil {
		for _, row := range f.reservation.Session.Output.Rows.Records {
			row.Body = bytes.Clone(row.Body)
			candidate.SupportRecords = append(candidate.SupportRecords, row)
		}
	}
	candidate.PublicState = contract.PublicState{Domain: parent.DomainID, Rows: append([]contract.PublicStateRow(nil), f.reservation.Session.BeforePublic.Rows...)}
	generatedCanonicalizeCandidateSupport(t, &candidate)
	candidate.CurrentAccess.CurrentControl = f.base.control.CurrentControl
	candidate.CurrentAccess.AccessGeneration++
	candidate.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(parent.DomainID, candidate.AccessRecords)
	if err != nil {
		t.Fatal(err)
	}
	candidate.CurrentAccess.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: parent.DomainID,
		Refs: []contract.Ref{{Kind: contract.RecipientKind, Format: contract.CanonicalSchema, Domain: parent.DomainID, Object: id("generated recipient page"),
			Digest: id("generated recipient page digest"), Length: 200}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.CurrentAccess.AccessPageRefs = []contract.Ref{{Kind: contract.AccessKind, Format: contract.CanonicalSchema, Domain: parent.DomainID,
		Object: id("generated access page"), Digest: id("generated access page digest"), Length: uint32(75 + len(result.SeedAccess))}}
	candidate.PublicState.AccessRoot, err = contract.AccessRoot(candidate.CurrentAccess)
	if err != nil {
		t.Fatal(err)
	}
	phase, err := contract.GeneratorInitialPhaseID(parent.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := contract.GeneratorInitialRevisionID(parent.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := contract.GeneratorInitialSnapshotID(parent.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	head := format.HeadCore{Form: format.SuccessorHead, Domain: parent.DomainID, Revision: revision,
		PreviousRevision: id("generated predecessor revision"), PreviousDigest: f.compare.Context.PredecessorHEADDigest,
		PreviousToken: contract.Token{Family: contract.GCP, Value: "1"}, Root: contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema,
			Domain: parent.DomainID, Object: snapshot, Digest: id("generated root digest"), Length: 200}, Store: f.base.control.StoreID,
		Trust: f.base.control.NormalSigning.Binding.Trust, Coordinate: f.base.control.CoordinateID, NonBody: f.base.control.NonBodyID,
		Interpretation: f.base.control.NormalSigning.Binding.Interpretation, Epoch: f.base.control.NormalSigning.Binding.Epoch}
	candidate.HeadCore, err = format.EncodeHeadCore(head)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(head.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Conditional, err = format.EncodeConditionalPlan(format.ConditionalPlan{Family: contract.GCP, Store: head.Store, Coordinate: head.Coordinate,
		NonBody: head.NonBody, Condition: condition, HeadCore: contract.Hash(candidate.HeadCore), HeadCoreLength: uint32(len(candidate.HeadCore))})
	if err != nil {
		t.Fatal(err)
	}
	before, err := contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := contract.GeneratorDescriptor{Digest: id("closed phase descriptor"), Length: 4, Count: 0}
	candidate.Subject = contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityReservation, RequiredAuthoritySet: 1,
		DomainID: parent.DomainID, OperationID: parent.OperationID, RequestIdentityDigest: parent.RequestIdentityDigest, PlanGraphID: parent.PlanGraphID,
		UsePlanDigest: parent.UsePlanDigest, PhaseID: phase, PreviousHEADDigest: head.PreviousDigest, PreviousRevisionID: head.PreviousRevision,
		ConditionDigest: f.compare.Context.OriginalConditionDigest, BeforeRootDigest: before.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: f.compare.Context.CurrentAccessRoot, AfterAccessDigest: candidate.PublicState.AccessRoot, OwnerID: parent.OperationID,
		HeadCoreDigest: contract.Hash(candidate.HeadCore), ConditionalPlanDigest: contract.Hash(candidate.Conditional), Intent: parent.Declaration,
		IdentityPlan: descriptor, ValueEntryUnion: descriptor, MembershipChanges: descriptor, BeforeWork: descriptor, AfterWork: descriptor,
		ResultVector: descriptor, CapacityReservation: parent.Capacity, BeforePhase: 0, AfterPhase: 1,
		HeadCoreLength: uint32(len(candidate.HeadCore)), ConditionalLength: uint32(len(candidate.Conditional))}
	return candidate
}

func generatedCandidateRequest(t *testing.T, f generatedRuntimeFixture, operation contract.ID, c generatedCandidate, references []contract.GeneratorResultReference, uses []contract.KeyUseRow) contract.CryptoGeneratedFreezeRequest {
	t.Helper()
	candidatePublicStateDescriptor, err := contract.PublicStateDescriptor(c.PublicState)
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.AccessRecordsDescriptor(c.PublicState.Domain, c.AccessRecords)
	if err != nil {
		t.Fatal(err)
	}
	support, err := contract.RequiredSupportDescriptor(c.PublicState.Domain, c.SupportRecords)
	if err != nil {
		t.Fatal(err)
	}
	results, err := contract.GeneratorResultReferencesDescriptor(references)
	if err != nil {
		t.Fatal(err)
	}
	keyUses, err := contract.CryptoGeneratedKeyUseDescriptor(uses)
	if err != nil {
		t.Fatal(err)
	}
	return contract.CryptoGeneratedFreezeRequest{OperationRef: operation, Context: f.compare.Context, PhaseID: c.Subject.PhaseID,
		RequestIdentityDigest: c.Subject.RequestIdentityDigest, CandidatePublicStateDescriptor: candidatePublicStateDescriptor, CandidateAccess: access, CandidateSupport: support,
		HeadCoreDigest: contract.Hash(c.HeadCore), ConditionDigest: f.compare.Context.OriginalConditionDigest, ActualResults: results, KeyUses: keyUses}
}

// full_only: false
func TestGeneratedRuntimeFreezeUsesExactCandidateAndClaim(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	r := f.reservationRuntime(t)
	operation := generatedCompare(t, r, f)
	generatedPlanParts(t, r, f, operation)
	result, uses := generatedFinishPlanWithUses(t, r, f, operation)
	candidate := generatedPlanCandidate(t, f, result)
	if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
		t.Fatal("candidate", code)
	}
	q := generatedCandidateRequest(t, f, operation, candidate, nil, uses)
	body, err := contract.EncodeCryptoGeneratedFreezeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoFreeze, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("freeze", reply.ResultCode)
	}
	if _, err := contract.DecodeCryptoFreezeResult(reply.Body); err != nil {
		t.Fatal(err)
	}
	body, err = contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
	if err != nil {
		t.Fatal(err)
	}
	if reply := applyCall(r, context.Background(), contract.CryptoClaim, body); reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("claim", reply.ResultCode)
	}
	if reply := applyCall(r, context.Background(), contract.CryptoClaim, body); reply.ResultCode != contract.CryptoAlreadyUsed {
		t.Fatal("claim reused", reply.ResultCode)
	}
}

func (f generatedRuntimeFixture) reservationRuntime(t *testing.T) *Runtime {
	t.Helper()
	r := newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f generatedRuntimeFixture) adoptionRuntime(t *testing.T) *Runtime {
	t.Helper()
	r := newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedAdoption(f.compare, f.adoption, f.base.deadline); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f generatedRuntimeFixture) finalRuntime(t *testing.T) *Runtime {
	t.Helper()
	r := newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedFinal(f.compare, f.final, f.base.deadline); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f generatedRuntimeFixture) producerRuntime(t *testing.T) *Runtime {
	t.Helper()
	r := newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedProducer(f.compare, f.producer, f.base.deadline); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f generatedRuntimeFixture) verificationRuntime(t *testing.T) *Runtime {
	t.Helper()
	r := newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedOriginalVerification(f.compare, f.verification, f.base.deadline); err != nil {
		t.Fatal(err)
	}
	return r
}

func generatedCompare(t *testing.T, r *Runtime, f generatedRuntimeFixture) contract.ID {
	t.Helper()
	body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 0 {
		t.Fatal("compare", reply.ResultCode)
	}
	v, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	return v.OperationRef
}

func generatedPlanParts(t *testing.T, r *Runtime, f generatedRuntimeFixture, operation contract.ID) {
	t.Helper()
	for i, blob := range [][]byte{f.declaration, f.graph} {
		count := (len(blob) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
		for index := 0; index < count; index++ {
			offset := index * contract.GeneratedFragmentMaxPayload
			q := contract.CryptoGeneratedPlanPartRequest{OperationRef: operation, Context: f.compare.Context, BlobKind: uint8(i + 2),
				Index: uint16(index), Count: uint16(count), Total: uint64(len(blob)), WholeDigest: contract.Hash(blob), Offset: uint32(offset),
				Payload: blob[offset:min(offset+contract.GeneratedFragmentMaxPayload, len(blob))]}
			body, err := contract.EncodeCryptoGeneratedPlanPartRequest(q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), contract.CryptoPrepare, body)
			if reply.ResultCode != contract.CryptoSuccess {
				t.Fatal("plan part", i, index, reply.ResultCode)
			}
		}
	}
}

func generatedFinishPlan(t *testing.T, r *Runtime, f generatedRuntimeFixture, operation contract.ID) contract.CryptoGeneratedFinishPlanResult {
	t.Helper()
	result, _ := generatedFinishPlanWithUses(t, r, f, operation)
	return result
}

func generatedFinishPlanWithUses(t *testing.T, r *Runtime, f generatedRuntimeFixture, operation contract.ID) (contract.CryptoGeneratedFinishPlanResult, []contract.KeyUseRow) {
	t.Helper()
	q := contract.CryptoGeneratedFinishPlanRequest{OperationRef: operation, Context: f.compare.Context,
		Declaration: f.compare.ParentPlan.Declaration, Graph: f.compare.PlanGraph, SourceUses: f.compare.AcceptedSources}
	body, err := contract.EncodeCryptoGeneratedFinishPlanRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoPrepare, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("finish plan", reply.ResultCode)
	}
	view, err := contract.InspectCryptoGeneratedFinishPlanResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	result, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	return result, reply.KeyUseRows
}

// full_only: false
func TestGeneratedRuntimePlanProtectsSeedForExactCurrentSubjects(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := generatedRuntimePlanFixture(t, recovery)
		r := f.reservationRuntime(t)
		operation := generatedCompare(t, r, f)
		generatedPlanParts(t, r, f, operation)
		result := generatedFinishPlan(t, r, f, operation)
		access, err := contract.DecodeAccessRecord(result.SeedAccess)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if recovery {
			want++
		}
		if len(access.Wraps) != want || result.Material.Core.OperationMaterialID != f.compare.MaterialID {
			t.Fatal("seed protection context")
		}
		var previous []byte
		for _, wrap := range access.Wraps {
			var binding contract.BindingTableRow
			for _, row := range f.base.q.Bindings {
				if row.SubjectID == wrap.SubjectID {
					binding = row
				}
			}
			core, err := custody.SeedWrapCore(result.Material.Core, binding)
			if err != nil {
				t.Fatal(err)
			}
			private, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.base.keys[wrap.SubjectID], wrap.RSACiphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			context, err := contract.RSAPacketContextDigest(core)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := custody.PacketKeys(private, core.PacketKind, context)
			if err != nil {
				t.Fatal(err)
			}
			packet = bytes.Clone(packet)
			clear(private)
			check, err := custody.SeedCheck(result.Material.Core, packet)
			if err != nil || check != result.Material.SeedCheck || previous != nil && !bytes.Equal(previous, packet) {
				t.Fatal("different seed", err)
			}
			clear(previous)
			previous = packet
		}
		clear(previous)
		discard, err := contract.EncodeCryptoGeneratedDiscardRequest(contract.CryptoGeneratedDiscardRequest{OperationRef: operation, Context: f.compare.Context})
		if err != nil {
			t.Fatal(err)
		}
		if reply := applyCall(r, context.Background(), contract.CryptoDiscard, discard); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("discard", reply.ResultCode)
		}
		if reply := applyCall(r, context.Background(), contract.CryptoDiscard, discard); reply.ResultCode != contract.CryptoAlreadyUsed {
			t.Fatal("discard reused", reply.ResultCode)
		}
	}
}
