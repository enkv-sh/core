package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
)

type gcPublicFixtureStore struct {
	descriptor     contract.Descriptor
	configuration  contract.StoreConfiguration
	objects        map[string][]byte
	headGeneration uint64
	reads          map[string]int
	beforeRead     func(string)
}

func (s *gcPublicFixtureStore) Descriptor() contract.Descriptor { return s.descriptor }
func (s *gcPublicFixtureStore) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}
func (s *gcPublicFixtureStore) Read(_ context.Context, key string, limit uint32) contract.ReadResult {
	s.reads[key]++
	if s.beforeRead != nil {
		s.beforeRead(key)
	}
	body, ok := s.objects[key]
	if !ok {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	if len(body) == 0 || uint64(len(body)) > uint64(limit) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	token := "1"
	if key == s.descriptor.HeadKey {
		token = strconv.FormatUint(s.headGeneration, 10)
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(body), Token: contract.Token{Family: contract.GCP, Value: token}}
}
func (s *gcPublicFixtureStore) Create(_ context.Context, key string, body []byte) contract.WriteResult {
	if _, ok := s.objects[key]; ok {
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	s.objects[key] = bytes.Clone(body)
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}
func (s *gcPublicFixtureStore) CreateHead(ctx context.Context, request contract.HeadCreateRequest) contract.WriteResult {
	if !request.Valid() || request.Descriptor() != s.descriptor {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
	}
	result := s.Create(ctx, s.descriptor.HeadKey, request.Body())
	if result.Status == contract.WriteAcknowledged {
		s.headGeneration++
	}
	return result
}
func (s *gcPublicFixtureStore) CompareAndSwap(_ context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	if key != s.descriptor.HeadKey || token != (contract.Token{Family: contract.GCP, Value: strconv.FormatUint(s.headGeneration, 10)}) {
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	s.objects[key] = bytes.Clone(body)
	s.headGeneration++
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

type gcPublicFixtureCandidate struct{ store *gcPublicFixtureStore }

func (c gcPublicFixtureCandidate) CandidateLocation() contract.StoreLocation {
	s := c.store.configuration
	return contract.StoreLocation{Provider: s.Provider, Region: s.Region, Bucket: s.Bucket, PrefixBeforeHEAD: s.PrefixBeforeHEAD, ExpectedOwner: s.ExpectedOwner}
}
func (c gcPublicFixtureCandidate) ReadHEAD(ctx context.Context) contract.ReadResult {
	return c.store.Read(ctx, c.store.descriptor.HeadKey, contract.MaxHeadLength)
}
func (c gcPublicFixtureCandidate) ReadConfiguration(ctx context.Context, domain, id contract.ID) contract.ReadResult {
	key, err := contract.StoreConfigurationKeyForID(contract.GCP, c.store.descriptor.Prefix, domain, id)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return c.store.Read(ctx, key, contract.MaxStoreConfigurationLength)
}
func (c gcPublicFixtureCandidate) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	key, err := format.Key(c.store.descriptor.Prefix, ref)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return c.store.Read(ctx, key, ref.Length)
}

type gcPublicFixtureRead struct {
	store         *gcPublicFixtureStore
	page          contract.ListPageResult
	lists, closes *int
	beforeList    func()
}

func (r *gcPublicFixtureRead) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return r.store.Read(ctx, key, limit)
}
func (r *gcPublicFixtureRead) Descriptor() contract.Descriptor { return r.store.descriptor }
func (r *gcPublicFixtureRead) StoreConfiguration() contract.StoreConfiguration {
	return r.store.configuration
}
func (r *gcPublicFixtureRead) Close() { *r.closes++ }
func (r *gcPublicFixtureRead) ListPage(context.Context, string) contract.ListPageResult {
	*r.lists++
	if r.beforeList != nil {
		r.beforeList()
	}
	return r.page
}

// The fixture uses the existing admitted genesis producer, real signing and
// complete selected readback. Query construction receives separate read-only
// wrappers, not this fixture's mutation methods or its qualification custody.
func gcInstalledFixture(t *testing.T) (*StateSession, *gcPublicFixtureStore, PublicBasis) {
	t.Helper()
	admitted, source, signer, custody := observationGenesisFixture(t)
	store := &gcPublicFixtureStore{descriptor: source.Descriptor(), configuration: source.configuration, objects: map[string][]byte{}, reads: map[string]int{}}
	custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
		qualification := admitted.qualification
		c := qualification.Context
		result := contract.GenesisQualifiedKeysCore{InitID: c.InitID, DescriptorDigest: c.DescriptorDigest, RequestCoreDigest: c.RequestDescriptor.Digest, GenesisPlanDigest: c.GenesisPlanDigest}
		var rows []contract.KeyUseRow
		for _, probe := range qualification.Probes {
			public := contract.QualifiedBindingFields{SubjectKind: probe.SubjectKind, SubjectID: probe.SubjectID, BindingID: probe.BindingID, PublicBindingDigest: probe.PublicBindingDigest, Provider: contract.GCP, Qualified: 1}
			result.Public = append(result.Public, public)
			result.Private = append(result.Private, contract.QualifiedSuccessorRow{ProbeID: probe.ProbeID, QualifiedBindingFields: public})
			rows = append(rows, contract.KeyUseRow{BindingID: probe.BindingID, PublicBindingDigest: probe.PublicBindingDigest, SubjectKind: probe.SubjectKind, SubjectID: probe.SubjectID, Provider: contract.GCP, Purpose: contract.KeyUsePublicKeyRead, Outcome: contract.KeyUseCompleted, Count: 3}, contract.KeyUseRow{BindingID: probe.BindingID, PublicBindingDigest: probe.PublicBindingDigest, SubjectKind: probe.SubjectKind, SubjectID: probe.SubjectID, Provider: contract.GCP, Purpose: contract.KeyUsePrivateRoleProbe, Outcome: contract.KeyUseCompleted, Count: 1})
		}
		body, err := contract.EncodeCryptoQualifyInitKeysResult(result)
		if err != nil {
			t.Fatal(err)
		}
		return observationReply(q, contract.CryptoSuccess, rows, body)
	}
	selected, result := initialize(t.Context(), InitContext{admission: admitted}, store, signer, nil, custody)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("authentic public genesis fixture", result)
	}
	return selected, store, PublicBasis{Descriptor: bytes.Clone(admitted.prepared.descriptorBytes)}
}

func gcInstalledInput(s *StateSession, store *gcPublicFixtureStore, basis PublicBasis, page contract.ListPageResult, lists, closes *int) CapacityReadInstallation {
	return CapacityReadInstallation{Candidate: gcPublicFixtureCandidate{store}, Construct: func(context.Context, contract.StoreConfiguration) (PublicCapacityReader, Result) {
		return &gcPublicFixtureRead{store: store, page: page, lists: lists, closes: closes}, Result{}
	}, ExpectedDomain: s.root.Domain, ExpectedStore: store.descriptor, PublicBasis: basis, SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() {}}
}

type gcLaterDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c gcLaterDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

// full_only: false
func TestValidatedGCPlanKeepsOriginalSourceAndInvocationLifetime(t *testing.T) {
	for _, change := range []string{"engine close", "source changed", "cancelled", "replacement done", "later deadline", "expired"} {
		t.Run(change, func(t *testing.T) {
			s, store, basis := gcInstalledFixture(t)
			lists, closes, constructions, installedCloses := 0, 0, 0, 0
			sourceCurrent := true
			input := gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK}, &lists, &closes)
			construct := input.Construct
			input.Construct = func(ctx context.Context, configuration contract.StoreConfiguration) (PublicCapacityReader, Result) {
				constructions++
				return construct(ctx, configuration)
			}
			input.CheckSource = func(context.Context) error {
				if !sourceCurrent {
					return errors.New("source pins changed")
				}
				return nil
			}
			input.CloseInstalled = func() { installedCloses++ }
			reader, err := NewInstalledCapacityReader(input)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			duration := time.Minute
			if change == "expired" {
				duration = time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), duration)
			defer cancel()
			preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("lifetime-nonce"), OperationID: gcTestID("lifetime-operation")})
			if preview.Payload == nil {
				t.Fatal("lifetime preview", preview.Result)
			}
			proof, result := reader.ValidateGCPlan(ctx, preview.Payload.EncodedPlan)
			if proof == nil || result.Outcome != ObservedCurrent || closes != 2 || installedCloses != 0 || !proof.current(ctx) {
				t.Fatal("proof did not outlive its read invocation", result, closes, installedCloses)
			}
			readCounts := make(map[string]int, len(store.reads))
			for key, count := range store.reads {
				readCounts[key] = count
			}
			attemptContext := ctx
			switch change {
			case "engine close":
				reader.Close()
			case "source changed":
				sourceCurrent = false
			case "cancelled":
				cancel()
			case "replacement done":
				var stop context.CancelFunc
				attemptContext, stop = context.WithCancel(ctx)
				defer stop()
			case "later deadline":
				// Keep the original Done identity to isolate the deadline check.
				attemptContext = gcLaterDeadlineContext{Context: ctx, deadline: proof.deadline.Add(time.Minute)}
			case "expired":
				<-ctx.Done()
			}
			if proof.current(attemptContext) || proof.consume(attemptContext) || proof.used.Load() {
				t.Fatal("invalid lifetime consumed the proof", change)
			}
			if change == "replacement done" || change == "later deadline" {
				if !proof.consume(ctx) || proof.consume(ctx) {
					t.Fatal("refused replacement consumed the original proof")
				}
			}
			if constructions != 2 || lists != 1 || closes != 2 || !reflect.DeepEqual(readCounts, store.reads) {
				t.Fatal("proof lifetime check reacquired Store reach", constructions, lists, closes, store.reads)
			}
			if change == "engine close" && installedCloses != 1 {
				t.Fatal("engine close did not release its installation exactly once")
			}
		})
	}
}

func gcInstalledGeneratedFixture(t *testing.T) (*StateSession, *gcPublicFixtureStore, PublicBasis) {
	t.Helper()
	before, store, basis := gcInstalledFixture(t)
	reservation, err := before.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, before))
	if err != nil {
		t.Fatal("derive generated public fixture", err)
	}
	candidate := reservation.candidate
	candidate.head.K1 = bytes.Clone(before.head.K1)
	authority, err := contract.GeneratorAuthorityDigest(*candidate.head.Generator)
	if err != nil {
		t.Fatal(err)
	}
	// This is the same direct-Core readiness boundary as
	// generatedReflectionSelectAndColdOpen. Public selection still checks the
	// real signed successor and every stored fragment. It does not claim a
	// production private Crypto exchange for the fixture's synthetic wraps.
	candidate.generated = &generatedCandidateFacts{reservation: reservation, authority: authority, claimed: true}
	candidate, result := before.persistCandidate(t.Context(), candidate, testtrust.New(t, contract.GCP, before.admission.trust))
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("persist generated public fixture", result)
	}
	selected, result := before.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("select generated public fixture", result)
	}
	selected, result = Open(t.Context(), OpenContext{admission: &selected.admission}, store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold complete generated public fixture", result)
	}
	return selected, store, basis
}

type gcReusingReadSource struct {
	*gcPublicFixtureRead
	bodies       [][]byte
	reusedBodies *int
}

func (r *gcReusingReadSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	result := r.gcPublicFixtureRead.Read(ctx, key, limit)
	if result.Body != nil {
		r.bodies = append(r.bodies, result.Body)
	}
	return result
}

func (r *gcReusingReadSource) Close() {
	*r.reusedBodies += len(r.bodies)
	for _, body := range r.bodies {
		for i := range body {
			body[i] = 0xa5
		}
	}
	for i := range r.page.Keys {
		r.page.Keys[i] = "reused-source-key"
	}
	r.bodies = nil
	r.gcPublicFixtureRead.Close()
}

// full_only: false
func TestInstalledCapacityResultsOwnGeneratedFactsAfterSourceClose(t *testing.T) {
	s, store, basis := gcInstalledGeneratedFixture(t)
	g := mustSelectedGeneratedWork(t, s)
	if len(g.bundles) != 1 || len(g.image.fragmentFacts) == 0 {
		t.Fatal("fixture lost authenticated generated fragments")
	}
	var keys []string
	for _, lineage := range g.bundles[0].Lineages {
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			keys = append(keys, gcObjectTestKey(t, store.descriptor, s.root.Domain, contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: template.InboxID}))
		}
	}
	if len(keys) != 10 {
		t.Fatal("fixture lost five create and five cleanup coordinates", len(keys))
	}
	obsolete := *s.recipients[0]
	obsolete.Object = gcTestID("reuse-obsolete-recipient")
	body, err := format.EncodeRecipientPage(obsolete)
	if err != nil {
		t.Fatal(err)
	}
	key := gcObjectTestKey(t, store.descriptor, s.root.Domain, contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: obsolete.Object})
	store.objects[key] = body
	keys = append(keys, key, "foreign-only")
	page := contract.ListPageResult{Status: contract.ListPageOK, Keys: keys, NextCursor: "owned-next-page"}
	lists, closes := 0, 0
	input := gcInstalledInput(s, store, basis, page, &lists, &closes)
	healthy, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	ctx := gcReadContext(t)
	previewRequest := GCPreviewRequest{RequestNonce: gcTestID("reuse-preview"), OperationID: gcTestID("reuse-operation")}
	capacityRequest := CapacityInspectionRequest{RequestNonce: gcTestID("reuse-capacity")}
	wantPreview := healthy.PlanGC(ctx, previewRequest)
	wantCapacity := healthy.InspectCapacity(ctx, capacityRequest)
	if wantPreview.Payload == nil || wantCapacity.View == nil || wantPreview.Validate() != nil || wantCapacity.Validate() != nil {
		t.Fatal("healthy generated outputs refused", wantPreview.Result, wantCapacity.Result)
	}
	wantEncoded := bytes.Clone(wantPreview.Payload.EncodedPlan)
	if len(wantPreview.Payload.Plan.Targets) != 1 || wantPreview.Payload.Garbage.Candidates[10].Classification != contract.GCCandidateEligible {
		t.Fatal("healthy output lost the obsolete eligible object")
	}
	for i := range 10 {
		if wantPreview.Payload.Garbage.Candidates[i].Classification != contract.GCCandidateProtected || wantCapacity.View.Garbage.Candidates[i].Classification != contract.GCCandidateProtected {
			t.Fatal("absent generated coordinate lost selected protection", i)
		}
	}
	reusedBodies := 0
	input.Construct = func(context.Context, contract.StoreConfiguration) (PublicCapacityReader, Result) {
		ownedPage := page
		ownedPage.Keys = slices.Clone(page.Keys)
		return &gcReusingReadSource{gcPublicFixtureRead: &gcPublicFixtureRead{store: store, page: ownedPage, lists: &lists, closes: &closes}, reusedBodies: &reusedBodies}, Result{}
	}
	hostile, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer hostile.Close()
	gotPreview := hostile.PlanGC(ctx, previewRequest)
	gotCapacity := hostile.InspectCapacity(ctx, capacityRequest)
	if lists != 4 || closes != 4 || reusedBodies == 0 || gotPreview.Validate() != nil || gotCapacity.Validate() != nil ||
		!reflect.DeepEqual(gotPreview, wantPreview) || !reflect.DeepEqual(gotCapacity, wantCapacity) || gotPreview.Payload == nil || !bytes.Equal(gotPreview.Payload.EncodedPlan, wantEncoded) {
		t.Fatal("source Close changed owned generated outputs", gotPreview.Result, gotCapacity.Result, lists, closes)
	}
}

// full_only: false
func TestCapacityCaptureIsProvisionalUntilOuterReaderAdmission(t *testing.T) {
	for _, includeCapacity := range []bool{false, true} {
		t.Run(strconv.FormatBool(includeCapacity), func(t *testing.T) {
			s, store, basis := gcInstalledFixture(t)
			lists, closes := 0, 0
			reader, err := NewInstalledCapacityReader(gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK}, &lists, &closes))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			_, _, _, inv, failed := reader.begin(ctx, InspectCapacityOperation, gcTestID("late-capture"), contract.ID{}, "")
			if failed.Outcome != 0 {
				t.Fatal("admit late capture fixture", failed)
			}
			defer inv.Close()
			var captured gcSelectedObservation
			calls := 0
			selected, failed := inv.loadPublicSelection(ctx, inv.admission.operation, inv.admission.request, func(callbackContext context.Context, generated *generatedSelection) error {
				var err error
				captured, err = captureGCSelectedObservation(callbackContext, generated.image, generated, inv.admission.store, includeCapacity)
				if err != nil {
					return err
				}
				calls++
				cancel()
				return nil
			})
			if calls != 1 || len(captured.marks.objects) == 0 || includeCapacity && captured.capacity.RootDigest.IsZero() {
				t.Fatal("callback did not finish owned capture before cancellation", calls)
			}
			if !reflect.DeepEqual(selected, publicSelection{}) || failed.diagnostic != contract.ReasonCancelled {
				t.Fatal("outer admission accepted a completed provisional callback", failed)
			}
			// Exercise the installed wrapper's failure return as well: neither
			// a selected image nor its second-return facts may escape refusal.
			selected, facts, failed := reader.load(ctx, inv, includeCapacity)
			if !reflect.DeepEqual(selected, publicSelection{}) || !reflect.DeepEqual(facts, gcSelectedObservation{}) || failed.Outcome == 0 {
				t.Fatal("installed load retained facts on outer admission failure", failed)
			}
			inv.Close()
			if lists != 0 || closes != 1 {
				t.Fatal("cancelled provisional capture listed or lost custody", lists, closes)
			}
		})
	}
}

// full_only: false
func TestInstalledCapacityReaderKeepsPublicReachAndSourceCustody(t *testing.T) {
	s, store, basis := gcInstalledFixture(t)
	obsolete := *s.recipients[0]
	obsolete.Object = gcTestID("public-obsolete")
	body, err := format.EncodeRecipientPage(obsolete)
	if err != nil {
		t.Fatal(err)
	}
	object := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: obsolete.Object}
	key := gcObjectTestKey(t, store.descriptor, s.root.Domain, object)
	store.objects[key] = body
	page := contract.ListPageResult{Status: contract.ListPageOK, Keys: []string{key, "foreign/undisclosed"}, NextCursor: "next-page"}
	lists, closes := 0, 0
	input := gcInstalledInput(s, store, basis, page, &lists, &closes)
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx := gcReadContext(t)
	preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("public-preview-nonce"), OperationID: gcTestID("public-preview-operation")})
	if preview.StateResult != PublicQuerySuccess || preview.Payload == nil || preview.Validate() != nil || len(preview.Payload.Plan.Targets) != 1 || lists != 1 || closes != 1 {
		t.Fatal("public preview did not retain exact page", preview.Result, preview.FailureReason, lists, closes)
	}
	before := store.reads[key]
	proof, result := reader.ValidateGCPlan(ctx, preview.Payload.EncodedPlan)
	if proof == nil || result.Outcome != ObservedCurrent || !proof.targetsChecked || !proof.equalHeadRechecked || proof.emptyHeadRechecked || lists != 1 || closes != 2 || store.reads[key] != before+1 {
		t.Fatal("artifact validation relisted or lost sole preflight", result, lists, closes, store.reads[key]-before)
	}
	if !proof.consume(ctx) || proof.consume(ctx) {
		t.Fatal("public validation proof is not one-use")
	}
	capacity := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: gcTestID("public-capacity-nonce")})
	if capacity.StateResult != PublicQuerySuccess || capacity.View == nil || capacity.Validate() != nil || lists != 2 || closes != 3 {
		t.Fatal("public capacity view failed", capacity.Result, capacity.FailureReason, lists, closes)
	}
	checks := 0
	input.CheckSource = func(context.Context) error { checks++; return errors.New("source changed") }
	blocked, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	beforeHEAD := store.reads[store.descriptor.HeadKey]
	got := blocked.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("blocked-nonce"), OperationID: gcTestID("blocked-operation")})
	if got.StateResult != PublicQueryRefused || got.Payload != nil || checks != 1 || store.reads[store.descriptor.HeadKey] != beforeHEAD || lists != 2 {
		t.Fatal("source refusal reached public Store", got.Result, checks)
	}
}

// full_only: false
func TestGCPlanValidationEmptyProofRequiresEqualHEADWithoutListing(t *testing.T) {
	s, store, basis := gcInstalledFixture(t)
	lists, closes := 0, 0
	reader, err := NewInstalledCapacityReader(gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK, Keys: []string{"foreign-only"}, NextCursor: "more"}, &lists, &closes))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx := gcReadContext(t)
	preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("empty-nonce"), OperationID: gcTestID("empty-operation")})
	if preview.Payload == nil || len(preview.Payload.Plan.Targets) != 0 {
		t.Fatal("empty preview failed", preview.Result)
	}
	before := store.reads[store.descriptor.HeadKey]
	proof, result := reader.ValidateGCPlan(ctx, preview.Payload.EncodedPlan)
	if proof == nil || result.Outcome != ObservedCurrent || !proof.emptyHeadRechecked || lists != 1 || store.reads[store.descriptor.HeadKey] != before+3 {
		t.Fatal("empty proof omitted final equal HEAD or listed again", result, lists, store.reads[store.descriptor.HeadKey]-before)
	}
	// Candidate HEAD, guarded normal HEAD and final equal HEAD are distinct.
	reads := 0
	store.beforeRead = func(key string) {
		if key == store.descriptor.HeadKey {
			reads++
			if reads == 3 {
				store.headGeneration++
			}
		}
	}
	proof, result = reader.ValidateGCPlan(ctx, preview.Payload.EncodedPlan)
	if proof != nil || result.Outcome != Contention || lists != 1 {
		t.Fatal("changed final HEAD admitted empty no-op", result)
	}
}

// full_only: false
func TestGCPlanValidationFinalHEADPreservesMissingAndInvalidResults(t *testing.T) {
	for _, name := range []string{"missing", "invalid"} {
		t.Run(name, func(t *testing.T) {
			s, store, basis := gcInstalledFixture(t)
			lists, closes := 0, 0
			reader, err := NewInstalledCapacityReader(gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK}, &lists, &closes))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			ctx := gcReadContext(t)
			preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("final-head-failure-nonce"), OperationID: gcTestID("final-head-failure-operation")})
			if preview.Payload == nil || len(preview.Payload.Plan.Targets) != 0 || preview.Validate() != nil {
				t.Fatal("authentic empty preview unavailable", preview.Result)
			}
			before := store.reads[store.descriptor.HeadKey]
			reads := 0
			// The first two HEAD reads admit the complete selected image. Only
			// the final equal-HEAD observation loses the established root.
			store.beforeRead = func(key string) {
				if key == store.descriptor.HeadKey {
					reads++
					if reads == 3 {
						if name == "missing" {
							delete(store.objects, key)
							return
						}
						store.objects[key] = nil
					}
				}
			}
			proof, result := reader.ValidateGCPlan(ctx, preview.Payload.EncodedPlan)
			want := Result{Outcome: RootLossUnsupported, Reason: MissingSelectedObject}
			if name == "invalid" {
				want = Result{Outcome: IntegrityFailure, Reason: InvalidFormat}
			}
			if proof != nil || result != want {
				t.Error("final HEAD failure lost its established-domain classification", result, want)
			}
			if reads != 3 || store.reads[store.descriptor.HeadKey] != before+3 || lists != 1 || closes != 2 {
				t.Fatal("final HEAD failure retried admission, relisted or retained reader custody", reads, lists, closes)
			}
		})
	}
}

// full_only: false
func TestInstalledCapacityReaderRejectsCursorAndPlanScopeBeforeStoreConstruction(t *testing.T) {
	s, store, basis := gcInstalledFixture(t)
	lists, closes, constructions := 0, 0, 0
	input := gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK}, &lists, &closes)
	construct := input.Construct
	input.Construct = func(ctx context.Context, configuration contract.StoreConfiguration) (PublicCapacityReader, Result) {
		constructions++
		return construct(ctx, configuration)
	}
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx := gcReadContext(t)
	beforeHEAD := store.reads[store.descriptor.HeadKey]
	cursor, err := EncodeGCCursor("next", gcTestID("another-domain"), store.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	capacity := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: gcTestID("wrong-cursor-capacity"), Cursor: cursor})
	preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("wrong-cursor-preview"), OperationID: gcTestID("wrong-cursor-operation"), Cursor: cursor})
	if capacity.StateResult != PublicQueryRefused || preview.StateResult != PublicQueryRefused || constructions != 0 || store.reads[store.descriptor.HeadKey] != beforeHEAD || lists != 0 {
		t.Fatal("wrong-scope cursor reached Store construction")
	}
	preview = reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("scope-preview"), OperationID: gcTestID("scope-operation")})
	if preview.Payload == nil {
		t.Fatal("authentic scope preview refused", preview.Result)
	}
	beforeHEAD, beforeConstructions := store.reads[store.descriptor.HeadKey], constructions
	for _, field := range []string{"domain", "store", "public-basis", "source"} {
		t.Run(field, func(t *testing.T) {
			plan := preview.Payload.Plan
			switch field {
			case "domain":
				plan.DomainID = gcTestID("changed-domain")
			case "store":
				plan.StoreDescriptorDigest = gcTestID("changed-store")
			case "public-basis":
				plan.PublicBasisDigest = gcTestID("changed-public-basis")
			case "source":
				plan.SourcePinsDigest = gcTestID("changed-source")
			}
			encoded, err := contract.EncodeGCPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			proof, result := reader.ValidateGCPlan(ctx, encoded)
			if proof != nil || result.Outcome != AdmissionRefused || constructions != beforeConstructions || store.reads[store.descriptor.HeadKey] != beforeHEAD || lists != 1 {
				t.Fatal("wrong-scope artifact reached Store construction", result)
			}
		})
	}
}

// full_only: false
func TestInstalledCapacityReaderUnavailableListReasonRemainsClosed(t *testing.T) {
	for _, operation := range []string{InspectCapacityOperation, GCPlanOperation} {
		t.Run(operation, func(t *testing.T) {
			for _, item := range []struct {
				name         string
				reason, want contract.Reason
			}{
				{"none", contract.ReasonNone, contract.ReasonMalformed},
				{"unknown", contract.Reason(255), contract.ReasonMalformed},
				{"access", contract.ReasonAccess, contract.ReasonAccess},
			} {
				t.Run(item.name, func(t *testing.T) {
					s, store, basis := gcInstalledFixture(t)
					// This canonical, unmarked same-domain key would require an
					// exact GET if an unavailable page were processed as candidates.
					trap := gcObjectTestKey(t, store.descriptor, s.root.Domain, contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: gcTestID("unavailable-page-unmarked-recipient")})
					if _, exists := store.objects[trap]; exists {
						t.Fatal("candidate trap overlaps selected fixture")
					}
					objects := make(map[string][]byte, len(store.objects))
					reads := make(map[string]int, len(store.reads))
					for key, body := range store.objects {
						objects[key] = bytes.Clone(body)
					}
					for key, count := range store.reads {
						reads[key] = count
					}
					generation := store.headGeneration
					lists, closes := 0, 0
					page := contract.ListPageResult{Status: contract.ListPageUnavailable, Reason: item.reason, Keys: []string{trap}, NextCursor: "discarded-unavailable-cursor"}
					reader, err := NewInstalledCapacityReader(gcInstalledInput(s, store, basis, page, &lists, &closes))
					if err != nil {
						t.Fatal(err)
					}
					defer reader.Close()
					ctx := gcReadContext(t)
					var out PublicQueryResult
					var validation error
					if operation == InspectCapacityOperation {
						got := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: gcTestID("unavailable-list-capacity")})
						out, validation = got.PublicQueryResult, got.Validate()
						if got.View != nil || got.Query == nil {
							t.Fatal("capacity unavailable result lost bound identity or exposed payload", got)
						}
						if got.Query.Validate() != nil || got.Query.Digest != out.RequestIdentity || got.Query.Observation != nil || !got.Query.MarkDigest.IsZero() || !got.Query.EnumerationDigest.IsZero() || got.Query.Cursor != "" {
							t.Error("capacity unavailable result retained provisional page facts", got.Query)
						}
					} else {
						got := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("unavailable-list-preview"), OperationID: gcTestID("unavailable-list-operation")})
						out, validation = got.PublicQueryResult, got.Validate()
						if got.Payload != nil || got.Query == nil {
							t.Fatal("preview unavailable result lost bound identity or exposed payload", got)
						}
						if got.Query.Validate() != nil || got.Query.Digest != out.RequestIdentity || got.Query.Observation != nil || !got.Query.MarkDigest.IsZero() || !got.Query.EnumerationDigest.IsZero() || got.Query.Cursor != "" {
							t.Error("preview unavailable result retained provisional page facts", got.Query)
						}
					}
					want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: item.want}
					if validation != nil || out.Result != want || out.StateResult != PublicQueryUnavailable || out.FailureReason != contract.ReasonEvidenceUnavailable || out.RequestIdentity.IsZero() || out.OperationID.IsZero() {
						t.Error("unavailable LIST reason escaped closed failure owner", validation, out, want)
					}
					if lists != 1 || closes != 1 || store.reads[trap] != 0 || store.reads[store.descriptor.HeadKey]-reads[store.descriptor.HeadKey] != 2 {
						t.Error("unavailable page reached candidates, repeated admission or retained custody", lists, closes, store.reads)
					}
					for key, count := range store.reads {
						if count == reads[key] {
							continue
						}
						if _, selected := objects[key]; !selected || count-reads[key] > 3 {
							t.Error("query exceeded exact selected GET reach or physical read bound", key, count-reads[key])
						}
					}
					if store.headGeneration != generation || !reflect.DeepEqual(store.objects, objects) {
						t.Error("unavailable query changed physical selected state")
					}
				})
			}
		})
	}
}

// full_only: false
func TestInstalledCapacityReaderDiscardsFactsWhenFinalSourceCheckFails(t *testing.T) {
	for _, operation := range []string{InspectCapacityOperation, GCPlanOperation} {
		t.Run(operation, func(t *testing.T) {
			s, store, basis := gcInstalledFixture(t)
			lists, closes, checks := 0, 0, 0
			input := gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK, Keys: []string{"foreign-only"}}, &lists, &closes)
			input.CheckSource = func(context.Context) error {
				checks++
				if checks == 4 {
					return errors.New("source changed at result admission")
				}
				return nil
			}
			reader, err := NewInstalledCapacityReader(input)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			ctx := gcReadContext(t)
			if operation == InspectCapacityOperation {
				got := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: gcTestID("discard-capacity")})
				if got.StateResult != PublicQueryRefused || got.View != nil || got.Query == nil || got.Query.Observation != nil || !got.Query.MarkDigest.IsZero() || !got.Query.EnumerationDigest.IsZero() || got.Validate() != nil {
					t.Fatal("capacity refusal retained provisional facts", got)
				}
			} else {
				got := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("discard-preview"), OperationID: gcTestID("discard-operation")})
				if got.StateResult != PublicQueryRefused || got.Payload != nil || got.Query == nil || got.Query.Observation != nil || !got.Query.MarkDigest.IsZero() || !got.Query.EnumerationDigest.IsZero() || got.Validate() != nil {
					t.Fatal("preview refusal retained provisional facts", got)
				}
			}
			if checks != 4 || lists != 1 || closes != 1 {
				t.Fatal("final source refusal changed page or custody bounds", checks, lists, closes)
			}
		})
	}
}

// full_only: false
func TestInstalledCapacityRefusalTelemetryUsesOnlyPublicStages(t *testing.T) {
	var reader *InstalledCapacityReader
	for _, operation := range []telemetry.Operation{telemetry.OpCoreInspectCapacity, telemetry.OpCoreGCPlan, telemetry.OpCoreGCValidatePlan} {
		t.Run(string(operation), func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			switch operation {
			case telemetry.OpCoreInspectCapacity:
				got := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: contract.ID{1}})
				if got.Validate() != nil || got.View != nil {
					t.Fatal("unsafe capacity refusal")
				}
			case telemetry.OpCoreGCPlan:
				got := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: contract.ID{1}, OperationID: contract.ID{2}})
				if got.Validate() != nil || got.Payload != nil {
					t.Fatal("unsafe preview refusal")
				}
			case telemetry.OpCoreGCValidatePlan:
				if proof, result := reader.ValidateGCPlan(ctx, nil); proof != nil || result.Outcome != AdmissionRefused {
					t.Fatal("unsafe validation refusal")
				}
			}
			rows := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
			if len(rows) != 3 || rows[2].Result != telemetry.ResultAdmissionRefused {
				t.Fatal("public refusal lacks terminal telemetry", rows)
			}
			for _, row := range rows {
				if row.Validate() != nil {
					t.Fatal("invalid public diagnostic", row)
				}
			}
		})
	}
}
