package core

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func observationTestSession(t testing.TB) (*StateSession, contract.ApplyContext) {
	t.Helper()
	s := generatedEmptyPredecessor(t)
	s.admission.composition = generatedVectorID(97)
	s.admission.expires = time.Now().Add(time.Hour)
	s.admission.store.HeadKey = s.admission.store.Prefix + "/HEAD"
	s.store.(*generatedFixtureSupportStore).descriptor = s.admission.store
	c := generatedContinuationContext(t, s, 98, 99)
	if !s.admission.valid(s.store) {
		t.Fatal("observation fixture has no valid protected admission")
	}
	return s, c
}

func observationTestOwner(t testing.TB) *operationObservation {
	t.Helper()
	s, c := observationTestSession(t)
	var owner *operationObservation
	if !attachOperationObservation(&owner, s, c, true) {
		t.Fatal("observation owner admission refused")
	}
	return owner
}

func observationSmallComparison() changeObservation {
	return changeObservation{Source: observationSource{Stage: observationComparison}, Entries: []observationEntry{{AfterPresent: true, AfterSource: contract.Supplied, AfterConfidentiality: contract.Plain, ProposedName: "entry", Relation: observationEqual}}}
}

// full_only: false
func TestOperationObservationOwnershipAndAdmission(t *testing.T) {
	t.Run("retains admitted comparison", func(t *testing.T) {
		owner := observationTestOwner(t)
		v := observationSmallComparison()
		if !owner.offerChange(t.Context(), v) {
			t.Fatal("admitted owner did not retain a complete comparison fact")
		}
		facts, status := owner.read()
		if len(facts) != 1 || status.Accepted != 1 || facts[0].Change.Source != owner.sourceFor(v.Source) || facts[0].Change.Entries[0] != v.Entries[0] {
			t.Fatal("copied admitted fact missing", status)
		}
	})
	t.Run("rejects absent and mismatched admission", func(t *testing.T) {
		s, c := observationTestSession(t)
		for _, change := range []func(*contract.ApplyContext){func(c *contract.ApplyContext) { c.DomainID = generatedVectorID(20) }, func(c *contract.ApplyContext) { c.OperationClass = 0 }, func(c *contract.ApplyContext) { c.CompatibilityID = generatedVectorID(20) }, func(c *contract.ApplyContext) { c.AdmissionID = contract.ID{} }, func(c *contract.ApplyContext) { c.SessionID = contract.ID{} }, func(c *contract.ApplyContext) { c.Expiry = 1 }, func(c *contract.ApplyContext) { c.PredecessorHEADDigest = generatedVectorID(20) }, func(c *contract.ApplyContext) { c.OriginalConditionDigest = generatedVectorID(20) }, func(c *contract.ApplyContext) { c.PredecessorRootRef[0] ^= 1 }} {
			changed := c
			change(&changed)
			var owner *operationObservation
			if attachOperationObservation(&owner, s, changed, true) || owner != nil {
				t.Fatal("mismatched admission installed observation owner")
			}
		}
		var owner *operationObservation
		if attachOperationObservation(&owner, nil, c, true) || attachLocalObservation(&owner, &StateSession{}, true) || attachOperationObservation(nil, s, c, true) {
			t.Fatal("absent admission installed owner")
		}
		empty := &operationObservation{collector: &observationCollector{}}
		if empty.offerChange(t.Context(), observationSmallComparison()) {
			t.Fatal("empty owner disclosed a fact")
		}
		_, status := empty.read()
		if status.Rejected != 1 || status.Accepted != 0 {
			t.Fatal("absent owner rejection lost", status)
		}
		owner = observationTestOwner(t)
		v := observationSmallComparison()
		v.Source.DomainID = generatedVectorID(21)
		if owner.offerChange(t.Context(), v) {
			t.Fatal("fact from different domain accepted")
		}
		v = observationSmallComparison()
		v.Source.AdmissionID = generatedVectorID(21)
		if owner.offerChange(t.Context(), v) {
			t.Fatal("fact from different subadmission accepted without binding")
		}
	})
	t.Run("fixed owner and explicit child correlation", func(t *testing.T) {
		s, c := observationTestSession(t)
		var owner *operationObservation
		if !attachOperationObservation(&owner, s, c, true) {
			t.Fatal("initial admission refused")
		}
		captured := &Candidate{session: s, observation: owner}
		c.AdmissionID, c.SessionID = generatedVectorID(80), generatedVectorID(81)
		if attachOperationObservation(&owner, s, c, true) || captured.observation != owner {
			t.Fatal("later admission replaced candidate owner")
		}
		var other, child, disabled *operationObservation
		if !attachOperationObservation(&other, s, c, true) || !attachChildObservation(&child, owner, s, c) || !attachOperationObservation(&disabled, s, c, false) {
			t.Fatal("new or child admission refused")
		}
		if child.collector != owner.collector || child.source.AdmissionID != c.AdmissionID || child.source.SessionID != c.SessionID {
			t.Fatal("child lost checked source or fixed collector")
		}
		v := observationSmallComparison()
		if !child.offerChange(t.Context(), v) || !captured.observation.offerChange(t.Context(), v) {
			t.Fatal("captured owners failed")
		}
		facts, _ := owner.read()
		if len(facts) != 2 || facts[0].Change.Source.AdmissionID != c.AdmissionID || facts[1].Change.Source.AdmissionID != captured.observation.source.AdmissionID {
			t.Fatal("subadmission correlation was rewritten")
		}
		if disabled.offerChange(t.Context(), v) || attachOperationObservation(&disabled, s, c, true) {
			t.Fatal("disabled owner replaced or accepted")
		}
		if facts, status := other.read(); len(facts) != 0 || status != (observationStatus{}) {
			t.Fatal("session reuse inherited earlier collector")
		}
		if facts, status := disabled.read(); len(facts) != 0 || status != (observationStatus{}) {
			t.Fatal("disabled operation retained facts")
		}
	})
	t.Run("local correlation remains absent", func(t *testing.T) {
		s, _ := observationTestSession(t)
		var owner *operationObservation
		if !attachLocalObservation(&owner, s, true) || !owner.offerChange(t.Context(), observationSmallComparison()) {
			t.Fatal("protected local admission refused")
		}
		facts, _ := owner.read()
		source := facts[0].Change.Source
		if !source.AdmissionID.IsZero() || !source.SessionID.IsZero() || !source.InitID.IsZero() || !source.OperationID.IsZero() || !source.AttemptID.IsZero() {
			t.Fatal("local operation invented correlation")
		}
		if attachLocalObservation(&owner, s, false) {
			t.Fatal("local owner replaced")
		}
	})
}

// full_only: false
func TestOperationObservationCopiesClosedFacts(t *testing.T) {
	owner := observationTestOwner(t)
	backing := []byte("historical-name")
	name := unsafe.String(unsafe.SliceData(backing), len(backing))
	subjects := make([]observationSubject, 1, 16)
	subjects[0] = observationSubject{Row: contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectValueEntry, Change: contract.ChangedSubjectAdded, Identity: generatedVectorID(30)}, PrimaryID: generatedVectorID(31), Fields: observationFieldEncodedMaterial}
	v := changeObservation{Source: observationSource{Stage: observationCandidate, OperationID: generatedVectorID(32)},
		HasChangedSubjects: true, Subjects: subjects, Descriptor: contract.GeneratorDescriptor{Count: 1, Length: 42, Digest: generatedVectorID(35)},
		Names:          []observationName{{EntryIncarnationID: generatedVectorID(31), Name: name, Side: observationAfter}},
		Entries:        []observationEntry{{BeforePresent: true, AfterPresent: true, BeforeIncarnationID: generatedVectorID(31), AfterIncarnationID: generatedVectorID(31), BeforeSource: contract.Supplied, AfterSource: contract.Supplied, BeforeConfidentiality: contract.Secret, AfterConfidentiality: contract.Secret, Relation: observationEqual, Fields: observationFieldEncodedMaterial}},
		Memberships:    []observationMembership{{EntryIncarnationID: generatedVectorID(31), RecipientID: generatedVectorID(36), Change: contract.ChangedSubjectAdded}},
		Generations:    []observationGeneration{{EntryIncarnationID: generatedVectorID(31), GenerationID: generatedVectorID(37), PlanID: generatedVectorID(38), Side: observationAfter, PlannedMembership: true}},
		Succession:     []observationSuccession{{BeforeBindingID: generatedVectorID(39), AfterBindingID: generatedVectorID(40), Purpose: 1, Role: 1}},
		Administrative: &observationAdministrative{TargetGroupID: generatedVectorID(41), TargetOwnerID: generatedVectorID(42), TargetID: generatedVectorID(43), DispositionID: generatedVectorID(44), TargetKind: 1, EvidenceSummary: 1}}
	if !owner.offerChange(t.Context(), v) {
		t.Fatal("closed candidate not accepted")
	}
	exchange := exchangeObservation{Source: observationSource{Stage: observationExchange, AttemptID: generatedVectorID(45)}, RequestID: generatedVectorID(46), CustodyInstanceID: generatedVectorID(47), Kind: contract.CryptoCompare, ResultCode: contract.CryptoSuccess, Rows: []contract.KeyUseRow{{BindingID: generatedVectorID(48), PublicBindingDigest: generatedVectorID(49), SubjectKind: 1, SubjectID: generatedVectorID(50), Provider: contract.AWS, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 2}}}
	if !owner.offerExchange(t.Context(), exchange) {
		t.Fatal("checked exchange not accepted")
	}
	selected := changeObservation{Source: observationSource{Stage: observationSelection}, Candidate: observationCandidateIdentity{RevisionID: generatedVectorID(51), SnapshotID: generatedVectorID(52), PredecessorRevisionID: generatedVectorID(53), PredecessorDigest: generatedVectorID(54)}, Result: Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: generatedVectorID(51), ObservedRevision: generatedVectorID(53), ObservedSnapshotID: generatedVectorID(55), Evidence: AuthenticatedClosure, CommitMayHaveOccurred: true, StoreReason: contract.ReasonTransport}}
	if !owner.offerChange(t.Context(), selected) {
		t.Fatal("outcome not accepted")
	}
	facts, status := owner.read()
	expected := owner.sourceFor(v.Source)
	if len(facts) != 3 || status.Accepted != 3 || facts[0].Change.Source != expected || facts[2].Change.Result != selected.Result || facts[2].Change.Candidate != selected.Candidate || facts[1].Exchange.Rows[0] != exchange.Rows[0] {
		t.Fatal("closed facts changed during storage")
	}
	if cap(facts[0].Change.Subjects) != 1 || unsafe.StringData(facts[0].Change.Names[0].Name) == unsafe.StringData(name) {
		t.Fatal("source backing retained")
	}
	backing[0] = 'X'
	subjects[0].PrimaryID = contract.ID{}
	v.Entries[0].Relation = observationChanged
	v.Entries[0].Fields = 0
	v.Memberships[0].RecipientID = contract.ID{}
	v.Generations[0].PlanID = contract.ID{}
	v.Succession[0].Purpose = 6
	v.Administrative.TargetID = contract.ID{}
	exchange.Rows[0].Count = 9
	facts[0].Change.Subjects[0].Fields = 0
	facts[0].Change.Names[0].Name = "returned-mutation"
	facts[0].Change.Entries[0].Relation = observationChanged
	facts[0].Change.Entries[0].Fields = observationFieldMembership
	facts[0].Change.Memberships[0].Change = 0
	facts[0].Change.Generations[0].PlannedMembership = false
	facts[0].Change.Succession[0].Role = 3
	facts[0].Change.Administrative.EvidenceSummary = 0
	facts[1].Exchange.Rows[0].Count = 10
	facts[2].Change.Result.CommitMayHaveOccurred = false
	reread, _ := owner.read()
	if reread[0].Change.Names[0].Name != "historical-name" || reread[0].Change.Subjects[0].PrimaryID != generatedVectorID(31) || reread[0].Change.Subjects[0].Fields != observationFieldEncodedMaterial || reread[0].Change.Entries[0].Relation != observationEqual || reread[0].Change.Entries[0].Fields != observationFieldEncodedMaterial || reread[0].Change.Memberships[0].RecipientID != generatedVectorID(36) || reread[0].Change.Generations[0].PlanID != generatedVectorID(38) || !reread[0].Change.Generations[0].PlannedMembership || reread[0].Change.Succession[0].Purpose != 1 || reread[0].Change.Succession[0].Role != 1 || reread[0].Change.Administrative.TargetID != generatedVectorID(43) || reread[0].Change.Administrative.EvidenceSummary != 1 || reread[1].Exchange.Rows[0].Count != 2 || reread[2].Change.Result != selected.Result {
		t.Fatal("source or reader mutation changed retained facts")
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[changeObservation](), reflect.TypeFor[exchangeObservation]()} {
		observationAssertClosed(t, typ)
	}
}

func observationAssertClosed(t testing.TB, typ reflect.Type) {
	t.Helper()
	switch typ.Kind() {
	case reflect.Interface, reflect.Func, reflect.Map, reflect.Chan:
		t.Fatal("executable or arbitrary observation field", typ)
	case reflect.Pointer, reflect.Array:
		observationAssertClosed(t, typ.Elem())
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			t.Fatal("arbitrary byte payload", typ)
		}
		observationAssertClosed(t, typ.Elem())
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Type.Kind() == reflect.String && (typ != reflect.TypeFor[observationName]() || f.Name != "Name") && (typ != reflect.TypeFor[observationEntry]() || f.Name != "ProposedName") {
				t.Fatal("non-allowlisted string", typ, f.Name)
			}
			observationAssertClosed(t, f.Type)
		}
	}
}

// full_only: false
func TestOperationObservationNonblockingAtomicOffers(t *testing.T) {
	t.Run("controlled lock contention", func(t *testing.T) {
		owner := observationTestOwner(t)
		owner.collector.mu.Lock()
		// The same goroutine owns the lock, so a waiting offer cannot complete.
		accepted := owner.offerChange(t.Context(), observationSmallComparison())
		owner.collector.mu.Unlock()
		if accepted {
			t.Fatal("busy collector accepted")
		}
		facts, status := owner.read()
		if len(facts) != 0 || status.DroppedContention != 1 || status.Accepted != 0 {
			t.Fatal("busy offer not accounted", status)
		}
	})
	t.Run("exact remaining reservation", func(t *testing.T) {
		owner := observationTestOwner(t)
		v := observationSmallComparison()
		v.Entries = append(v.Entries, v.Entries[0], v.Entries[0])
		charge := observationChangeBytes(v)
		// Reserve the earlier capacity arithmetically; no large fixture is needed.
		owner.collector.storedBytes = observationRetainedLimit() - charge
		if !owner.offerChange(t.Context(), v) || owner.offerChange(t.Context(), v) {
			t.Fatal("whole exact-fit admission failed")
		}
		facts, status := owner.read()
		if len(facts) != 1 || len(facts[0].Change.Entries) != 3 || status.Accepted != 1 || status.DroppedFull != 1 || status.StoredBytes != observationRetainedLimit() {
			t.Fatal("full collector truncated or lost offer", status)
		}
	})
	t.Run("complete empty differs from absent", func(t *testing.T) {
		owner := observationTestOwner(t)
		absent := changeObservation{Source: observationSource{Stage: observationCandidate}}
		complete := absent
		complete.HasChangedSubjects = true
		complete.Descriptor = contract.GeneratorDescriptor{Length: 4, Digest: generatedVectorID(29)}
		complete.Subjects = []observationSubject{}
		if !owner.offerChange(t.Context(), absent) || !owner.offerChange(t.Context(), complete) {
			t.Fatal("empty facts refused")
		}
		facts, _ := owner.read()
		if facts[0].Change.HasChangedSubjects || !facts[1].Change.HasChangedSubjects || facts[1].Change.Descriptor != complete.Descriptor || facts[1].Change.Subjects == nil {
			t.Fatal("empty evidence conflated with absence")
		}
	})
	t.Run("oversize is whole rejected fact", func(t *testing.T) {
		owner := observationTestOwner(t)
		v := observationSmallComparison()
		v.Entries[0].ProposedName = strings.Repeat("a", contract.CryptoMaxName+1)
		if owner.offerChange(t.Context(), v) {
			t.Fatal("oversize name accepted")
		}
		facts, status := owner.read()
		if len(facts) != 0 || status.Rejected != 1 {
			t.Fatal("oversize projection partly retained")
		}
	})
	t.Run("unknown entry field is whole rejected fact", func(t *testing.T) {
		owner := observationTestOwner(t)
		v := observationSmallComparison()
		v.Entries[0].Fields = 1 << 15
		if owner.offerChange(t.Context(), v) {
			t.Fatal("unknown entry field accepted")
		}
		facts, status := owner.read()
		if len(facts) != 0 || status.Rejected != 1 {
			t.Fatal("invalid entry fields partly retained")
		}
	})
	t.Run("concurrent offers and copies", func(t *testing.T) {
		owner := observationTestOwner(t)
		const writers = 4
		const offers = 32
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for n := 0; n < offers; n++ {
					owner.offerChange(context.Background(), observationSmallComparison())
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < offers; n++ {
				facts, _ := owner.read()
				for _, f := range facts {
					f.Change.Entries[0].ProposedName = "reader mutation"
				}
			}
		}()
		close(start)
		wg.Wait()
		facts, status := owner.read()
		if status.Accepted+status.DroppedContention+status.DroppedFull+status.Rejected != writers*offers || len(facts) != int(status.Accepted) || status.Rejected != 0 || status.StoredBytes > observationRetainedLimit() {
			t.Fatal("joined process lost concurrent offers", status)
		}
		for _, f := range facts {
			if f.Change.Entries[0].ProposedName != "entry" {
				t.Fatal("concurrent read changed stored source")
			}
		}
	})
	t.Run("saturating drop evidence", func(t *testing.T) {
		owner := observationTestOwner(t)
		owner.collector.contention.Store(math.MaxUint64)
		owner.collector.mu.Lock()
		owner.offerChange(t.Context(), observationSmallComparison())
		owner.collector.mu.Unlock()
		_, status := owner.read()
		if status.DroppedContention != math.MaxUint64 {
			t.Fatal("drop count wrapped")
		}
	})
}

// full_only: false
func TestOperationObservationTelemetryExcludesDetail(t *testing.T) {
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	owner := observationTestOwner(t)
	v := observationSmallComparison()
	v.Entries[0].ProposedName = "historical-entry-observation-canary"
	if !owner.offerChange(ctx, v) {
		t.Fatal("telemetry changed accepted offer")
	}
	owner.collector.mu.Lock()
	owner.offerChange(ctx, v)
	owner.collector.mu.Unlock()
	owner.collector.storedBytes = observationRetainedLimit()
	owner.offerChange(ctx, v)
	v.Entries[0].ProposedName = strings.Repeat("a", contract.CryptoMaxName+1)
	owner.offerChange(ctx, v)
	disabled := newOperationObservation(owner.source, false)
	disabled.offerChange(ctx, v)
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8))
	want := []telemetry.Result{telemetry.ResultSuccess, telemetry.ResultContention, telemetry.ResultCapacityExceeded, telemetry.ResultInvalid}
	if len(records) != 8 {
		t.Fatal("missing or disabled telemetry offer", len(records))
	}
	for i, r := range records {
		if r.Validate() != nil || r.Operation != telemetry.OpCoreObservationOffer || r.Provider != telemetry.ProviderCore || i%2 == 1 && r.Result != want[i/2] {
			t.Fatal("incorrect closed offer signal", r)
		}
	}
	body, err := json.Marshal(records)
	if err != nil || strings.Contains(string(body), "canary") || strings.Contains(string(body), "input_bytes") || strings.Contains(string(body), "entry_name") {
		t.Fatal("observation detail entered diagnostic telemetry")
	}
	_, status := owner.read()
	if status.Accepted != 1 || status.DroppedContention != 1 || status.DroppedFull != 1 || status.Rejected != 1 {
		t.Fatal("telemetry changed local evidence", status)
	}
}

type observationInitCustody struct{ instance contract.ID }

func (c observationInitCustody) InstanceID() contract.ID { return c.instance }
func (c observationInitCustody) Exchange(context.Context, contract.CryptoRequest) contract.CryptoResponse {
	return contract.CryptoResponse{}
}

// full_only: false
func TestOperationObservationInitializationAdmission(t *testing.T) {
	s, _ := observationTestSession(t)
	prepared, err := planGenesis(s.admission)
	if err != nil {
		t.Fatal(err)
	}
	d := prepared.descriptor
	descriptor := artifactReceipt{fact: contract.GenesisArtifactFact{Kind: 1, ArtifactID: d.DescriptorArtifactID, BodyDigest: contract.Hash(prepared.descriptorBytes), BodyLength: uint64(len(prepared.descriptorBytes)), DurabilityProfile: 1, Outcome: 1}}
	manifest := artifactReceipt{fact: contract.GenesisArtifactFact{Kind: 2, ArtifactID: d.ManifestArtifactID, BodyDigest: contract.Hash(prepared.manifestBytes), BodyLength: uint64(len(prepared.manifestBytes)), DurabilityProfile: 1, Outcome: 1}}
	bindings, err := d.BindingTable()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	custody := observationInitCustody{instance: generatedVectorID(101)}
	a := &initAdmission{open: OpenContext{admission: &s.admission}, prepared: prepared, descriptor: descriptor, manifest: manifest, requestID: generatedVectorID(100), custodyID: custody.instance, custody: custody, deadline: deadline}
	a.qualification = contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: contract.GenesisProfile, AdmissionID: generatedVectorID(102), SessionID: generatedVectorID(103), DomainID: s.admission.domain, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), InitID: d.InitID, DescriptorDigest: contract.Hash(prepared.descriptorBytes), GenesisPlanDigest: contract.Hash(prepared.planBytes), RequestDescriptor: contract.DescriptorVector{Count: 1, Length: uint64(len(prepared.requestBytes)), Digest: contract.Hash(prepared.requestBytes)}}, Bindings: bindings, Probes: observationCopySlice(prepared.plan.Probes)}
	wrong := *a
	wrong.qualification.Context.DomainID = generatedVectorID(104)
	if attachInitObservation(nil, s.store, custody, true) || attachInitObservation(&wrong, s.store, custody, true) || wrong.observation != nil {
		t.Fatal("unadmitted initialization installed observer")
	}
	if !attachInitObservation(a, s.store, custody, true) || attachInitObservation(a, s.store, custody, false) {
		t.Fatal("init owner missing or replaceable")
	}
	v := exchangeObservation{Source: observationSource{Stage: observationExchange}, RequestID: a.requestID, CustodyInstanceID: custody.instance, Kind: contract.CryptoQualifyInitKeys, ResultCode: contract.CryptoSuccess, Rows: []contract.KeyUseRow{}}
	if !a.observation.offerExchange(t.Context(), v) {
		t.Fatal("init exchange refused")
	}
	facts, status := a.observation.read()
	source := facts[0].Exchange.Source
	if len(facts) != 1 || status.Accepted != 1 || source.InitID != d.InitID || source.AdmissionID != a.qualification.Context.AdmissionID || !source.OperationID.IsZero() || facts[0].Exchange.Rows == nil || len(facts[0].Exchange.Rows) != 0 {
		t.Fatal("init invented operation identity or lost exact zero use")
	}
}
