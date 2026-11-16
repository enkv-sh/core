package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
)

type installedAdministrativeTestReader struct {
	store                contract.Store
	reads, heads, closes atomic.Int32
	beforeRead           func(context.Context, string) (contract.ReadResult, bool)
	onClose              func()
}

func (r *installedAdministrativeTestReader) Descriptor() contract.Descriptor {
	return r.store.Descriptor()
}
func (*installedAdministrativeTestReader) StoreConfiguration() contract.StoreConfiguration {
	return contract.StoreConfiguration{}
}
func (r *installedAdministrativeTestReader) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	r.reads.Add(1)
	if key == r.Descriptor().HeadKey {
		r.heads.Add(1)
	}
	if r.beforeRead != nil {
		if result, handled := r.beforeRead(ctx, key); handled {
			return result
		}
	}
	return r.store.Read(ctx, key, limit)
}
func (r *installedAdministrativeTestReader) Close() {
	r.closes.Add(1)
	if r.onClose != nil {
		r.onClose()
	}
}

func installedAdministrativeTestPins() AdministrativeSourcePins {
	return AdministrativeSourcePins{FileID: generatedVectorID(201), Format: AdministrativeJSONFormat, EditableDigest: generatedVectorID(202), GeneratedDigest: generatedVectorID(203), EditableLength: 123, GeneratedLength: 456, HasGenerated: true}
}
func installedAdministrativeTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}
func installedAdministrativeReadInput(s *StateSession, reader PublicSelectedReader) AdministrativeReadInstallation {
	return AdministrativeReadInstallation{ExpectedDomain: s.admission.domain, ExpectedStore: s.admission.store, PublicBasis: s.admission.publicBasis(), CompositionID: generatedVectorID(204), SourcePins: installedAdministrativeTestPins(), Source: reader, CheckSource: func(context.Context) error { return nil }}
}

// This fixture derives, signs, persists and observes a generated reservation
// before the installed parent sees it. No replacement constructor or fake
// OpenContext stands in for the installed parent's public authority proof.
func installedAdministrativeWorkFixture(t *testing.T) (*StateSession, *observationSelectionStore, *testtrust.Signer) {
	t.Helper()
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	observationProtectFixture(t, s)
	s, initial := observationInitialProducerForSession(t, s, false, "alpha")
	signer := testtrust.New(t, s.admission.store.Family, s.admission.trust)
	store := observationPhysicalGeneratedStore(t, s)
	candidate := initial.reservation.candidate
	candidate.head.K1 = bytes.Clone(s.head.K1)
	candidate, result := s.persistCandidate(t.Context(), candidate, signer)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed reservation preparation", result)
	}
	selected, result := s.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent || len(selected.adminIndex.Groups) == 0 {
		t.Fatal("signed reservation selection", result)
	}
	return selected, store, signer
}

// full_only: false
func TestInstalledAdministrativeListOwnsSourceAndReadsFreshOnce(t *testing.T) {
	s, _, store := observationSelectedPredecessor(t)
	reader := &installedAdministrativeTestReader{store: store}
	input := installedAdministrativeReadInput(s, reader)
	basisDigest := contract.Hash(input.PublicBasis.Descriptor)
	ownedDescriptor := bytes.Clone(input.PublicBasis.Descriptor)
	checks := 0
	input.CheckSource = func(context.Context) error { checks++; return nil }
	session, err := NewInstalledAdministrativeReader(input, AdministrativeList)
	if err != nil {
		t.Fatal(err)
	}
	if reader.reads.Load() != 0 || checks != 0 {
		t.Fatal("constructor performed I/O")
	}
	input.PublicBasis.Descriptor[0] ^= 1
	out := session.List(installedAdministrativeTestContext(t), generatedVectorID(205))
	copy(input.PublicBasis.Descriptor, ownedDescriptor)
	if out.Operation != AdministrativeList || out.StateResult != AdministrativeSuccess || out.Result != s.observed(ObservedCurrent) || out.List == nil || out.Plan != nil || out.End != nil || out.Receipt != nil || out.Query == nil || out.Query.Observation == nil || out.Query.PublicBasisDigest != basisDigest || out.Query.Observation.Revision != s.head.Core.Revision || out.Query.Observation.Snapshot != s.root.Snapshot || out.RequestIdentity != out.Query.Digest || out.Query.Digest.IsZero() || reader.heads.Load() != 1 || checks != 2 {
		t.Fatal("fresh administrative projection", out.Result, reader.heads.Load(), checks)
	}
	reads := reader.reads.Load()
	if again := session.List(installedAdministrativeTestContext(t), generatedVectorID(206)); again.Result.Outcome != AdmissionRefused || again.List != nil || again.Query == nil || again.Query.Observation != nil || reader.reads.Load() != reads {
		t.Fatal("second nonce used cached or fresh image", again.Result)
	}
	if _, legacy := session.Inspect(t.Context()); legacy.Outcome != AdmissionRefused || reader.reads.Load() != reads {
		t.Fatal("legacy entry bypassed installed invocation", legacy)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil || reader.closes.Load() != 1 {
		t.Fatal("read owner close is not idempotent", err, reader.closes.Load())
	}
}

// full_only: false
func TestInstalledAdministrativeRefusalsRetainRequestedQuery(t *testing.T) {
	for _, scenario := range []string{"remote unavailable", "source before read", "source during read", "method mismatch", "missing receipt"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, store := observationSelectedPredecessor(t)
			reader := &installedAdministrativeTestReader{store: store}
			input := installedAdministrativeReadInput(s, reader)
			sourceErr := errors.New("captured source changed")
			changed := false
			input.CheckSource = func(context.Context) error {
				if changed {
					return sourceErr
				}
				return nil
			}
			if scenario == "source before read" {
				changed = true
			}
			if scenario == "remote unavailable" {
				reader.beforeRead = func(context.Context, string) (contract.ReadResult, bool) {
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
				}
			}
			if scenario == "source during read" {
				reader.beforeRead = func(context.Context, string) (contract.ReadResult, bool) {
					changed = true
					return contract.ReadResult{}, false
				}
			}
			operation := AdministrativeReceipt
			if scenario == "method mismatch" {
				operation = AdministrativeList
			}
			session, err := NewInstalledAdministrativeReader(input, operation)
			if err != nil {
				t.Fatal(err)
			}
			requested := generatedVectorID(207)
			out := session.Receipt(installedAdministrativeTestContext(t), generatedVectorID(208), requested)
			if out.Query == nil || out.Query.Operation != AdministrativeReceipt || out.Query.RequestedOperationID != requested || out.Query.RequiredStoredKind != contract.OperationEndSelectedWork || out.RequestIdentity != out.Query.Digest || out.Receipt != nil || out.List != nil || out.End != nil || out.Plan != nil {
				t.Fatal("refusal lost exact query selection", out)
			}
			switch scenario {
			case "remote unavailable":
				if out.StateResult != AdministrativeUnavailable || out.Query.Observation != nil || out.Result.StoreReason != contract.ReasonAccess {
					t.Fatal("unavailable read fabricated observation", out)
				}
			case "missing receipt":
				if out.StateResult != AdministrativeUnavailable || out.Query.Observation == nil || out.Result.Reason != MissingSelectedObject {
					t.Fatal("absence became historical outcome", out)
				}
			case "source during read":
				if out.StateResult != AdministrativeRefused || out.Query.Observation == nil {
					t.Fatal("source change lost whole-read refusal", out)
				}
			default:
				if out.StateResult != AdministrativeRefused || out.Query.Observation != nil || reader.reads.Load() != 0 {
					t.Fatal("local refusal reached Store", out, reader.reads.Load())
				}
			}
			closeErr := session.Close()
			if scenario == "source before read" || scenario == "source during read" {
				if !errors.Is(closeErr, sourceErr) || !errors.Is(session.Close(), sourceErr) {
					t.Fatal("source error was swallowed", closeErr)
				}
			} else if closeErr != nil {
				t.Fatal(closeErr)
			}
		})
	}
}

// full_only: false
func TestInstalledAdministrativeReceiptUsesOriginalSameImageBytes(t *testing.T) {
	// This bounded projection test uses the existing authenticated mandatory
	// support fixture; fresh-constructor proofs are covered separately above.
	state := administrativeHistoryFixture(t)
	session := &AuthoritySession{state: state}
	rows, err := state.retainedAdministrativeAbandonments()
	if err != nil || len(rows) != 3 {
		t.Fatal(err)
	}
	original := slices.Clone(rows[0].ReceiptBytes)
	got, result := session.installedReceipt(rows[0].Receipt.OperationID)
	if result != state.observed(ObservedCurrent) || !reflect.DeepEqual(got, rows[0]) || !bytes.Equal(got.ReceiptBytes, original) {
		t.Fatal("receipt changed selected raw bytes or stored state", result)
	}
	got.ReceiptBytes[0] ^= 1
	fresh, result := session.installedReceipt(rows[0].Receipt.OperationID)
	if result.Outcome != ObservedCurrent || !bytes.Equal(fresh.ReceiptBytes, original) {
		t.Fatal("receipt result borrowed authenticated bytes", result)
	}
	windows, err := state.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal(err)
	}
	if _, wrongKind := session.installedReceipt(windows.Successes[0].OperationID); wrongKind != refused(InvalidRelation) {
		t.Fatal("known wrong kind classified as absent", wrongKind)
	}
	if _, missing := session.installedReceipt(generatedVectorID(209)); missing != failure(EvidenceUnavailable, MissingSelectedObject) {
		t.Fatal("missing receipt claimed historical outcome", missing)
	}
}

// full_only: false
func TestInstalledAdministrativePlanBindingRejectsChangedOrForeignFacts(t *testing.T) {
	s, store, signer := installedAdministrativeWorkFixture(t)
	baselineCalls, baselineSends := signer.Calls(), store.sends
	ctx := installedAdministrativeTestContext(t)
	target := s.root.Generated.ActiveOwner
	if target.IsZero() {
		t.Fatal("fixture has no exact parent target")
	}
	newPlan := func() (*AuthoritySession, PublicAdministrativeResult) {
		reader := &installedAdministrativeTestReader{store: store}
		session, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativePlan)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := session.Close(); err != nil {
				t.Error(err)
			}
		})
		out := session.Plan(ctx, generatedVectorID(210), AdministrativePlanRequest{TargetGroupID: target, ArtifactPath: "/protected/plan.json"})
		if out.StateResult != AdministrativeSuccess || out.Plan == nil || out.Query == nil || out.Query.PlanIdentity != out.Plan.Preview.Identity || out.Query.Artifact != nil || out.Plan.Artifact != nil || reader.heads.Load() != 1 {
			t.Fatal("unbound plan", out.Result)
		}
		return session, out
	}
	session, out := newPlan()
	artifact := AdministrativeArtifact{Path: out.Plan.ArtifactPath, Digest: contract.Hash([]byte("strict composition-owned plan body")), Length: 34}
	for _, change := range []string{"state", "query", "scope", "capacity", "warnings", "path", "dependent commitment", "removed commitment", "preserved commitment"} {
		damaged := cloneAdministrativePlanResult(out)
		switch change {
		case "state":
			damaged.Result.ObservedRevision[0] ^= 1
		case "query":
			damaged.Query.SourcePins.EditableDigest[0] ^= 1
		case "scope":
			damaged.Plan.Preview.EndedGroupIDs[0][0] ^= 1
		case "capacity":
			damaged.Plan.Preview.AfterChildBytes++
		case "warnings":
			damaged.Plan.Preview.WarningBits ^= 1
		case "path":
			damaged.Plan.ArtifactPath = "/protected/other.json"
		case "dependent commitment":
			damaged.Plan.Preview.DependentGroups.Digest[0] ^= 1
		case "removed commitment":
			damaged.Plan.Preview.RemovedSupport.Digest[0] ^= 1
		case "preserved commitment":
			damaged.Plan.Preview.PreservedCurrent.Digest[0] ^= 1
		}
		if _, result := session.BindPlanArtifact(ctx, damaged, artifact); result.Outcome != AdmissionRefused {
			t.Fatal("changed plan facts accepted", change, result)
		}
	}
	foreign, foreignOut := newPlan()
	if !equalEndWorkPreview(out.Plan.Preview, foreignOut.Plan.Preview) {
		t.Fatal("same predecessor changed semantic preview")
	}
	if _, result := foreign.BindPlanArtifact(ctx, out, artifact); result.Outcome != AdmissionRefused {
		t.Fatal("foreign issued result accepted", result)
	}
	wrongArtifact := artifact
	wrongArtifact.Path = "/protected/elsewhere.json"
	if _, result := session.BindPlanArtifact(ctx, out, wrongArtifact); result.Outcome != AdmissionRefused {
		t.Fatal("artifact path changed", result)
	}
	for _, partial := range []AdministrativeArtifact{{Path: artifact.Path, Digest: artifact.Digest}, {Path: artifact.Path, Length: artifact.Length}} {
		if _, result := session.BindPlanArtifact(ctx, out, partial); result.Outcome != AdmissionRefused {
			t.Fatal("partial artifact commitment accepted", result)
		}
	}
	if _, result := session.BindPlanArtifact(context.Background(), out, artifact); result.Outcome != AdmissionRefused {
		t.Fatal("unbounded bind accepted", result)
	}
	bound, result := session.BindPlanArtifact(ctx, out, artifact)
	if result != out.Result || bound.Query.Artifact == nil || bound.Plan.Artifact == nil || *bound.Query.Artifact != artifact || *bound.Plan.Artifact != artifact || bound.RequestIdentity == out.RequestIdentity || bound.OperationID != out.OperationID || out.Plan.Artifact != nil || out.Query.Artifact != nil {
		t.Fatal("binding changed issued semantic facts or failed commitment", result)
	}
	changedArtifact := artifact
	changedArtifact.Digest[0] ^= 1
	if _, result := session.BindPlanArtifact(ctx, bound, changedArtifact); result.Outcome != AdmissionRefused {
		t.Fatal("plan rebound", result)
	}
	if signer.Calls() != baselineCalls || store.sends != baselineSends {
		t.Fatal("planning reached private signing or CAS")
	}
}

// full_only: false
func TestInstalledAdministrativeApplyAndFreshReceiptKeepSelectedFactAfterCloseError(t *testing.T) {
	s, store, signer := installedAdministrativeWorkFixture(t)
	ctx := installedAdministrativeTestContext(t)
	reader := &installedAdministrativeTestReader{store: store}
	planner, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativePlan)
	if err != nil {
		t.Fatal(err)
	}
	planned := planner.Plan(ctx, generatedVectorID(211), AdministrativePlanRequest{TargetGroupID: s.root.Generated.ActiveOwner, ArtifactPath: "/protected/apply.json"})
	if planned.Plan == nil {
		t.Fatal("plan", planned.Result)
	}
	if err := planner.Close(); err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("installed provider close failed")
	closes := 0
	authority, err := NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{ExpectedDomain: s.admission.domain, ExpectedStore: s.admission.store, PublicBasis: s.admission.publicBasis(), CompositionID: generatedVectorID(204), SourcePins: installedAdministrativeTestPins(), Store: store, Trust: signer, CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() error { closes++; return closeErr }})
	if err != nil {
		t.Fatal(err)
	}
	beforeSigns, beforeSends := signer.Calls(), store.sends
	applied := authority.Apply(ctx, generatedVectorID(212), planned.Plan.Preview)
	if applied.StateResult != AdministrativeWorkEnded || applied.Result.Outcome != ObservedCurrent || applied.End == nil || applied.Query != nil || applied.RequestIdentity.IsZero() || applied.End.Receipt.OperationID != applied.OperationID || applied.End.Preview.TargetGroupID != planned.Plan.Preview.TargetGroupID || !slices.Equal(applied.End.Preview.EndedGroupIDs, planned.Plan.Preview.EndedGroupIDs) || store.sends-beforeSends != 1 || signer.Calls()-beforeSigns != 1 {
		t.Fatal("installed exact ending", applied.Result)
	}
	snapshot := applied
	snapshotEnd := *applied.End
	snapshotEnd.Preview.EndedGroupIDs = slices.Clone(applied.End.Preview.EndedGroupIDs)
	snapshotEnd.ReceiptBytes = slices.Clone(applied.End.ReceiptBytes)
	snapshot.End = &snapshotEnd
	firstClose, secondClose := authority.Close(), authority.Close()
	if !errors.Is(firstClose, closeErr) || !errors.Is(secondClose, closeErr) || closes != 1 || !reflect.DeepEqual(applied, snapshot) {
		t.Fatal("cleanup lost known selected result or close error", closes)
	}
	laterReader := &installedAdministrativeTestReader{store: store}
	observer, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, laterReader), AdministrativeReceipt)
	if err != nil {
		t.Fatal(err)
	}
	observed := observer.Receipt(ctx, generatedVectorID(213), applied.OperationID)
	if observed.StateResult != AdministrativeSuccess || observed.Result.Outcome != ObservedCurrent || observed.Receipt == nil || observed.Receipt.Receipt.StateResult != contract.ReceiptStateWorkEnded || observed.Receipt.Receipt.RequestIdentityDigest != applied.RequestIdentity || !bytes.Equal(observed.Receipt.ReceiptBytes, applied.End.ReceiptBytes) || observed.Query == nil || observed.Query.RequiredStoredKind != contract.OperationEndSelectedWork || observed.Query.RequestedOperationID != applied.OperationID || laterReader.heads.Load() != 1 || signer.Calls()-beforeSigns != 1 || store.sends-beforeSends != 1 {
		t.Fatal("fresh GET-only receipt changed original outcome", observed.Result, laterReader.heads.Load())
	}
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestInstalledAdministrativeCloseCancelsAndJoinsRead(t *testing.T) {
	s, _, store := observationSelectedPredecessor(t)
	reader := &installedAdministrativeTestReader{store: store}
	entered, exited := make(chan struct{}), make(chan struct{})
	reader.beforeRead = func(ctx context.Context, _ string) (contract.ReadResult, bool) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}, true
	}
	reader.onClose = func() {
		select {
		case <-exited:
		default:
			t.Error("source closed before active read joined")
		}
	}
	session, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativeList)
	if err != nil {
		t.Fatal(err)
	}
	ctx := installedAdministrativeTestContext(t)
	result := make(chan PublicAdministrativeResult, 1)
	joined := false
	defer func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
		if !joined {
			<-result
		}
	}()
	go func() { result <- session.List(ctx, generatedVectorID(214)) }()
	select {
	case <-entered:
	case <-t.Context().Done():
		t.Fatal("read never entered")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	out := <-result
	joined = true
	if out.StateResult != AdministrativeRefused || out.List != nil || reader.closes.Load() != 1 {
		t.Fatal("cancelled read emitted semantic projection", out.Result)
	}
}

// full_only: false
func TestInstalledAdministrativeQueryBindsClosedSelections(t *testing.T) {
	q := AdministrativeQueryIdentity{Schema: "QueryRequestIdentity/v1", Operation: AdministrativeReceipt, SemanticOperation: 16, ExpectedDomain: generatedVectorID(1), StoreID: generatedVectorID(2), CoordinateID: generatedVectorID(3), NonBodyID: generatedVectorID(4), StoreDescriptorDigest: generatedVectorID(16), PublicBasisDigest: generatedVectorID(5), SourcePins: installedAdministrativeTestPins(), RequestNonce: generatedVectorID(6), RequestedOperationID: generatedVectorID(7), RequiredStoredKind: 43}
	absent, ok := q.digest()
	if !ok || absent.IsZero() {
		t.Fatal("closed absent observation query invalid")
	}
	q.Observation = &AdministrativeObservation{DomainID: q.ExpectedDomain, Revision: generatedVectorID(8), Snapshot: generatedVectorID(9)}
	observed, ok := q.digest()
	if !ok || observed == absent {
		t.Fatal("authenticated observation not bound")
	}
	for _, field := range []string{"nonce", "requested operation", "store descriptor", "basis", "source", "revision", "snapshot"} {
		changed := q
		observation := *q.Observation
		changed.Observation = &observation
		switch field {
		case "nonce":
			changed.RequestNonce[0] ^= 1
		case "requested operation":
			changed.RequestedOperationID[0] ^= 1
		case "store descriptor":
			changed.StoreDescriptorDigest[0] ^= 1
		case "basis":
			changed.PublicBasisDigest[0] ^= 1
		case "source":
			changed.SourcePins.EditableDigest[0] ^= 1
		case "revision":
			changed.Observation.Revision[0] ^= 1
		case "snapshot":
			changed.Observation.Snapshot[0] ^= 1
		}
		digest, ok := changed.digest()
		if !ok || digest == observed {
			t.Fatal("query input omitted", field)
		}
	}
	q.RequiredStoredKind = 36
	if _, ok := q.digest(); ok {
		t.Fatal("receipt query accepted alternate required kind")
	}
	q.RequiredStoredKind = 43
	q.Artifact = &AdministrativeArtifact{Path: "/protected/query", Digest: generatedVectorID(10), Length: 1}
	if _, ok := q.digest(); ok {
		t.Fatal("receipt query accepted plan fields")
	}
}

type installedAdministrativeStoreHook struct {
	contract.Store
	afterCreate func()
	afterCAS    func()
}

func (s *installedAdministrativeStoreHook) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	result := s.Store.Create(ctx, key, body)
	if s.afterCreate != nil {
		s.afterCreate()
	}
	return result
}
func (s *installedAdministrativeStoreHook) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	result := s.Store.CompareAndSwap(ctx, key, token, body)
	if s.afterCAS != nil {
		s.afterCAS()
	}
	return result
}

type installedAdministrativeSignHook struct {
	contract.Trust
	afterSign func()
}

func (t *installedAdministrativeSignHook) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	result := t.Trust.Sign(ctx, request)
	t.afterSign()
	return result
}

// full_only: false
func TestInstalledAdministrativeApplyChecksExactPlanAuthorityAndCASFacts(t *testing.T) {
	for _, scenario := range []string{"stale predecessor", "changed scope", "changed warning", "changed dependent", "changed removed", "changed preserved", "wrong signing key", "source changes during create", "source changes during sign", "source changes during CAS", "unknown predecessor", "not sent predecessor", "lost reply exact"} {
		t.Run(scenario, func(t *testing.T) {
			s, backend, normal := installedAdministrativeWorkFixture(t)
			ctx := installedAdministrativeTestContext(t)
			reader := &installedAdministrativeTestReader{store: backend}
			planner, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativePlan)
			if err != nil {
				t.Fatal(err)
			}
			planned := planner.Plan(ctx, generatedVectorID(215), AdministrativePlanRequest{TargetGroupID: s.root.Generated.ActiveOwner, ArtifactPath: "/protected/exact.json"})
			if planned.Plan == nil {
				t.Fatal("plan", planned.Result)
			}
			if err := planner.Close(); err != nil {
				t.Fatal(err)
			}
			expected := planned.Plan.Preview
			sourceErr := errors.New("source changed during immutable persistence")
			var changed bool
			var store contract.Store = backend
			signer := normal
			switch scenario {
			case "stale predecessor":
				expected.PredecessorRevision[0] ^= 1
			case "changed scope":
				expected.EndedGroupIDs = slices.Clone(expected.EndedGroupIDs)
				expected.EndedGroupIDs[0][0] ^= 1
			case "changed warning":
				expected.WarningBits ^= 1
			case "changed dependent":
				expected.DependentGroups.Digest[0] ^= 1
			case "changed removed":
				expected.RemovedSupport.Digest[0] ^= 1
			case "changed preserved":
				expected.PreservedCurrent.Digest[0] ^= 1
			case "wrong signing key":
				signer = testtrust.NewWithIdentity(t, s.admission.store.Family, generatedVectorID(240), s.admission.trust, contract.NormalSigningRole)
			case "source changes during create":
				store = &installedAdministrativeStoreHook{Store: backend, afterCreate: func() { changed = true }}
			case "source changes during CAS":
				store = &installedAdministrativeStoreHook{Store: backend, afterCAS: func() { changed = true }}
			case "unknown predecessor", "not sent predecessor", "lost reply exact":
				backend.commit = scenario == "lost reply exact"
				backend.write = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: scenario == "not sent predecessor"}
			}
			var actingTrust contract.Trust = signer
			if scenario == "source changes during sign" {
				actingTrust = &installedAdministrativeSignHook{Trust: signer, afterSign: func() { changed = true }}
			}
			authority, err := NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{ExpectedDomain: s.admission.domain, ExpectedStore: s.admission.store, PublicBasis: s.admission.publicBasis(), CompositionID: generatedVectorID(204), SourcePins: installedAdministrativeTestPins(), Store: store, Trust: actingTrust, CheckSource: func(context.Context) error {
				if changed {
					return sourceErr
				}
				return nil
			}, CloseInstalled: func() error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			beforeSigns, beforeSends := signer.Calls(), backend.sends
			out := authority.Apply(ctx, generatedVectorID(216), expected)
			sends, signs := backend.sends-beforeSends, signer.Calls()-beforeSigns
			switch scenario {
			case "stale predecessor", "changed scope", "changed warning", "changed dependent", "changed removed", "changed preserved":
				if out.Result != refused(StalePrecondition) || sends != 0 || signs != 0 || out.End != nil {
					t.Fatal("changed plan reached a private effect", out.Result, sends, signs)
				}
			case "wrong signing key":
				if out.Result != failure(IntegrityFailure, InvalidProof) || sends != 0 || signs != 1 || out.End != nil {
					t.Fatal("claimed route identity replaced current signing proof", out.Result, sends, signs)
				}
			case "source changes during sign":
				want := refused(ConstructionMismatch)
				want.RequestedRevision = out.Result.RequestedRevision
				if out.Result != want || out.Result.RequestedRevision.IsZero() || sends != 0 || signs != 1 || out.End != nil {
					t.Fatal("source change during Sign reached CAS", out.Result, sends, signs)
				}
			case "source changes during create":
				if out.Result != refused(ConstructionMismatch) || sends != 0 || signs != 0 || out.End != nil {
					t.Fatal("source change during persistence reached Sign/CAS", out.Result, sends, signs)
				}
			case "unknown predecessor":
				want := Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: out.Result.RequestedRevision, ObservedRevision: s.head.Core.Revision, ObservedSnapshotID: s.root.Snapshot, Evidence: AuthenticatedClosure, StoreReason: contract.ReasonTransport, CommitMayHaveOccurred: true}
				if out.Result != want || out.Result.RequestedRevision.IsZero() || out.StateResult != AdministrativeCommitUnknown || sends != 1 || signs != 1 || out.End != nil {
					t.Fatal("unknown CAS lost uncertainty or retried backend", out.Result, sends, signs)
				}
			case "not sent predecessor":
				want := Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, RequestedRevision: out.Result.RequestedRevision, StoreReason: contract.ReasonLimit}
				if out.Result != want || out.Result.RequestedRevision.IsZero() || out.StateResult != AdministrativeUnavailable || sends != 1 || signs != 1 || out.End != nil {
					t.Fatal("proven not-sent CAS fabricated commit uncertainty", out.Result, sends, signs)
				}
			case "lost reply exact", "source changes during CAS":
				if out.Result.Outcome != ObservedCurrent || out.Result.CommitMayHaveOccurred || out.StateResult != AdministrativeWorkEnded || sends != 1 || signs != 1 || out.End == nil {
					t.Fatal("exact readback failed to establish selected ending", out.Result, sends, signs)
				}
			}
			err = authority.Close()
			if scenario == "source changes during create" || scenario == "source changes during sign" || scenario == "source changes during CAS" {
				if !errors.Is(err, sourceErr) {
					t.Fatal("source failure lost", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func administrativeFixedID(t *testing.T, text string) contract.ID {
	t.Helper()
	body, err := hex.DecodeString(text)
	if err != nil || len(body) != 32 {
		t.Fatal("invalid fixed identity literal")
	}
	var id contract.ID
	copy(id[:], body)
	return id
}

// full_only: false
func TestInstalledAdministrativeDescriptorPreviewAndQueryFixedVectors(t *testing.T) {
	// The independent stdlib derivation had SHA-256
	// cf588214b7fcac3e8d2cc8b4ae09df69f7163696c69e10f80de96f91925c74aa.
	// It used no Go codec and recorded the 149-byte descriptor, prior 623-byte
	// preview and closed query frame lengths. See tests/shared/testdata/README.md
	// for the retained provenance limit.
	store := contract.Descriptor{Family: contract.GCP, Identity: generatedVectorID(2), Coordinate: generatedVectorID(3), NonBody: generatedVectorID(4), Prefix: "fixture", HeadKey: "fixture/HEAD"}
	storeWant := administrativeFixedID(t, "0be5588c8187b5e74fa7ea1af920d3d48c224c805ad2d92ba5360331fee1d6f8")
	if got := administrativeStoreDescriptorDigest(store); got != storeWant {
		t.Fatal("full descriptor vector changed", got)
	}
	for _, field := range []string{"family", "prefix", "identity", "coordinate", "nonbody"} {
		changed := store
		switch field {
		case "family":
			changed.Family = contract.AWS
		case "prefix":
			changed.Prefix = "other"
			changed.HeadKey = "other/HEAD"
		case "identity":
			changed.Identity[0] ^= 1
		case "coordinate":
			changed.Coordinate[0] ^= 1
		case "nonbody":
			changed.NonBody[0] ^= 1
		}
		if administrativeStoreDescriptorDigest(changed) == storeWant {
			t.Fatal("descriptor field omitted", field)
		}
	}
	subject := contract.EndWorkSubject{DomainID: generatedVectorID(1), PredecessorRevisionID: generatedVectorID(6), PredecessorFullHEADDigest: generatedVectorID(7), PredecessorToken: contract.Token{Family: contract.GCP, Value: "27"}, TargetGroupID: generatedVectorID(8), TargetOwnerID: generatedVectorID(9), TargetID: generatedVectorID(10), TargetKind: contract.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, DependentGroups: contract.GeneratorDescriptor{Digest: generatedVectorID(11), Length: 42, Count: 1}, RemovedSupport: contract.GeneratorDescriptor{Digest: generatedVectorID(12), Length: 42, Count: 1}, PreservedCurrent: contract.DigestLength{Digest: generatedVectorID(13), Length: 1200}, BeforeWarningBits: 1, AfterWarningBits: 3, BeforeAccessRoot: generatedVectorID(17), BeforeAccessIncarnationID: generatedVectorID(19), BeforeAccessGeneration: 2, AfterAccessGeneration: 3, BeforeChildCount: 32, AfterChildCount: 31, BeforeChildBytes: 140000, AfterChildBytes: 139000}
	previewWant := administrativeFixedID(t, "52cea4b8b0d832019bb25d432566553f91f212214890c75a81a62bc708ebdcf3")
	if got, ok := endWorkPreviewIdentity(subject, store, generatedVectorID(5)); !ok || got != previewWant {
		t.Fatal("existing preview v2 bytes changed", got, ok)
	}
	for _, vector := range []struct {
		name            string
		operation       AdministrativeOperation
		observed, bound bool
		want            string
	}{
		{"receipt absent", AdministrativeReceipt, false, false, "658004099ee79f60b49509915d40bbaa969835d0cdbc817402c024409d0a3936"},
		{"receipt observed", AdministrativeReceipt, true, false, "ce1d1bbbfcd9b4aada5f2f709e95a0b87015cf44cd529616336c9068dfe4d059"},
		{"list observed", AdministrativeList, true, false, "91b4048665fe150ca3b6e68cc7b6f9dd6ff3731ef632755aee1b4fd17cc724a4"},
		{"plan unobserved", AdministrativePlan, false, false, "3e8e7bbde67e5c602907de177dcd96adae13eeefb79cc319c3c5728b8bc1c728"},
		{"plan issued", AdministrativePlan, true, false, "9e05cec22eb080db86c09ee5a742162401dbdc39fd0821b3a255729ec4e7e5dc"},
		{"plan bound", AdministrativePlan, true, true, "1ecf5b501807e5d6a33c4504d18f014ca99f52aa96d1aef4ec1fc9229f44b10e"},
	} {
		q := AdministrativeQueryIdentity{Schema: "QueryRequestIdentity/v1", Operation: vector.operation, SemanticOperation: 15, ExpectedDomain: generatedVectorID(1), StoreID: store.Identity, CoordinateID: store.Coordinate, NonBodyID: store.NonBody, StoreDescriptorDigest: storeWant, PublicBasisDigest: generatedVectorID(5), SourcePins: installedAdministrativeTestPins(), RequestNonce: generatedVectorID(6)}
		if vector.observed {
			q.Observation = &AdministrativeObservation{DomainID: q.ExpectedDomain, Revision: generatedVectorID(8), Snapshot: generatedVectorID(9)}
		}
		if vector.operation == AdministrativeReceipt {
			q.SemanticOperation = 16
			q.RequestedOperationID = generatedVectorID(7)
			q.RequiredStoredKind = 43
		}
		if vector.operation == AdministrativePlan {
			q.TargetGroupID = generatedVectorID(8)
			q.ArtifactPath = "/protected/plan.json"
			if vector.observed {
				q.Observation.Revision = generatedVectorID(6)
				q.PlanIdentity = previewWant
			}
			if vector.bound {
				q.Artifact = &AdministrativeArtifact{Path: q.ArtifactPath, Digest: generatedVectorID(20), Length: 789}
			}
		}
		if got, ok := q.digest(); !ok || got != administrativeFixedID(t, vector.want) {
			t.Fatal("closed query vector changed", vector.name, got, ok)
		}
	}
}

// full_only: false
func TestInstalledAdministrativeQueriesKeepAllowedReadFailureFamilies(t *testing.T) {
	for _, operation := range []AdministrativeOperation{AdministrativeList, AdministrativePlan, AdministrativeReceipt} {
		for _, reason := range []Reason{DifferentSelection, StalePrecondition} {
			before := Result{Outcome: Contention, Reason: reason, StoreReason: contract.ReasonCondition, ObservedRevision: contract.ID{1}, ObservedSnapshotID: contract.ID{2}}
			got := administrativeReadResult(before)
			expected := before
			expected.Outcome = EvidenceUnavailable
			if got != expected || administrativeState(operation, got) != AdministrativeUnavailable {
				t.Fatal("GET-only result changed its failure cause or borrowed mutation contention", operation, before, got)
			}
		}
		capacity := Result{Outcome: AdmissionRefused, Reason: CapacityExceeded}
		if administrativeReadResult(capacity) != capacity || administrativeState(operation, capacity) != AdministrativeRefused {
			t.Fatal("bounded query admission borrowed a mutation size state", operation)
		}
		malformed := Result{Outcome: IntegrityFailure, Reason: InvalidFormat}
		if administrativeReadResult(malformed) != malformed || administrativeState(operation, malformed) != AdministrativePositiveDefect {
			t.Fatal("authenticated malformed input normalized to admission refusal", operation)
		}
	}
	if administrativeState(AdministrativeApply, Result{Outcome: Contention, Reason: StalePrecondition}) != AdministrativeContention || administrativeState(AdministrativeApply, Result{Outcome: AdmissionRefused, Reason: CapacityExceeded}) != AdministrativeSizeRefusal {
		t.Fatal("mutation disposition changed with query failure mapping")
	}
}

type administrativeLifetimeStore struct {
	contract.Store
	read func(context.Context, string, uint32) contract.ReadResult
}

func (s administrativeLifetimeStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return s.read(ctx, key, limit)
}

// full_only: false
func TestInstalledAdministrativeTelemetryPreservesCloseCancellation(t *testing.T) {
	for _, operation := range []AdministrativeOperation{AdministrativeList, AdministrativePlan, AdministrativeReceipt, AdministrativeApply} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/telemetry=%t", operation, enabled), func(t *testing.T) {
				state, store, signer := installedAdministrativeWorkFixture(t)
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					if enabled {
						ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, telemetry.NewRecorder()))
					}
					entered, exited := make(chan struct{}), make(chan struct{})
					var readCancellation error
					read := func(ctx context.Context, _ string, _ uint32) contract.ReadResult {
						close(entered)
						<-ctx.Done()
						readCancellation = ctx.Err()
						close(exited)
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
					}
					closedAfterJoin := func() {
						select {
						case <-exited:
						default:
							t.Error("installation disposed before its read joined")
						}
					}
					var session *AuthoritySession
					var err error
					if operation == AdministrativeApply {
						session, err = NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{
							ExpectedDomain: state.admission.domain, ExpectedStore: state.admission.store, PublicBasis: state.admission.publicBasis(),
							CompositionID: generatedVectorID(204), SourcePins: installedAdministrativeTestPins(),
							Store: administrativeLifetimeStore{Store: store, read: read}, Trust: signer, CheckSource: func(context.Context) error { return nil },
							CloseInstalled: func() error { closedAfterJoin(); return nil },
						})
					} else {
						reader := &installedAdministrativeTestReader{store: store, onClose: closedAfterJoin,
							beforeRead: func(ctx context.Context, key string) (contract.ReadResult, bool) { return read(ctx, key, 0), true }}
						session, err = NewInstalledAdministrativeReader(installedAdministrativeReadInput(state, reader), operation)
					}
					if err != nil {
						t.Fatal(err)
					}
					beforeSigns, beforeSends := signer.Calls(), store.sends
					result := make(chan PublicAdministrativeResult, 1)
					go func() {
						switch operation {
						case AdministrativeList:
							result <- session.List(ctx, generatedVectorID(215))
						case AdministrativePlan:
							result <- session.Plan(ctx, generatedVectorID(215), AdministrativePlanRequest{TargetGroupID: state.root.Generated.ActiveOwner, ArtifactPath: "/protected/plan.json"})
						case AdministrativeReceipt:
							result <- session.Receipt(ctx, generatedVectorID(215), generatedVectorID(216))
						case AdministrativeApply:
							result <- session.Apply(ctx, generatedVectorID(215), EndWorkPreview{Identity: generatedVectorID(217), TargetGroupID: state.root.Generated.ActiveOwner, EndedGroupIDs: []contract.ID{state.root.Generated.ActiveOwner}})
						}
					}()
					<-entered
					if err := session.Close(); err != nil {
						t.Error(err)
					}
					got := <-result
					if readCancellation != context.Canceled || ctx.Err() != nil || signer.Calls() != beforeSigns || store.sends != beforeSends || got.List != nil || got.Plan != nil || got.End != nil || got.Receipt != nil {
						t.Fatal("Close lost owned cancellation or admitted later effects", readCancellation, ctx.Err(), got.Result)
					}
				})
			})
		}
	}
}
