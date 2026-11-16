package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type gcReadProbe struct {
	store contract.Descriptor
	read  func(context.Context, string, uint32) contract.ReadResult
	keys  []string
}

func (s *gcReadProbe) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.keys = append(s.keys, key)
	if s.read != nil {
		return s.read(ctx, key, limit)
	}
	return contract.ReadResult{Status: contract.ReadMissing}
}
func (s *gcReadProbe) Descriptor() contract.Descriptor { return s.store }
func (*gcReadProbe) StoreConfiguration() contract.StoreConfiguration {
	return contract.StoreConfiguration{}
}
func (*gcReadProbe) Close() {}

func gcReadContext(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func gcObjectTestKey(t testing.TB, store contract.Descriptor, domain contract.ID, object contract.StoreObjectIdentity) string {
	t.Helper()
	key, err := contract.StoreObjectKey(store.Prefix, domain, object)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// full_only: false
func TestGCCandidatePageClassifiesExactWholeSet(t *testing.T) {
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	marks, err := gcMarkSelected(g.image, g, s.admission.store)
	if err != nil {
		t.Fatal(err)
	}
	obsolete := *s.recipients[0]
	obsolete.Object = gcTestID("eligible-recipient")
	body, err := format.EncodeRecipientPage(obsolete)
	if err != nil {
		t.Fatal(err)
	}
	eligibleObject := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: obsolete.Object}
	pendingObject := eligibleObject
	pendingObject.ObjectID = gcTestID("pending-recipient")
	missingObject := eligibleObject
	missingObject.ObjectID = gcTestID("absent-recipient")
	malformedObject := eligibleObject
	malformedObject.ObjectID = gcTestID("malformed-recipient")
	marks.pending[pendingObject] = struct{}{}
	live := gcObjectTestKey(t, s.admission.store, s.root.Domain, gcPageIdentity(*s.root.Recipients[0]))
	eligible := gcObjectTestKey(t, s.admission.store, s.root.Domain, eligibleObject)
	pending := gcObjectTestKey(t, s.admission.store, s.root.Domain, pendingObject)
	missing := gcObjectTestKey(t, s.admission.store, s.root.Domain, missingObject)
	malformed := gcObjectTestKey(t, s.admission.store, s.root.Domain, malformedObject)
	helper := s.admission.store.Prefix + "/" + hex.EncodeToString(s.root.Domain[:]) + "/configuration/" + hex.EncodeToString(s.head.Core.Store[:])
	probe := &gcReadProbe{store: s.admission.store, read: func(_ context.Context, key string, _ uint32) contract.ReadResult {
		switch key {
		case eligible:
			return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: s.token}
		case malformed:
			return contract.ReadResult{Status: contract.ReadOK, Body: []byte("unrecognized version"), Token: s.token}
		case missing:
			return contract.ReadResult{Status: contract.ReadMissing}
		default:
			t.Fatal("protected, pending or foreign key was read", key)
			return contract.ReadResult{}
		}
	}}
	ctx := gcReadContext(t)
	physical, err := newGCPhysicalReader(ctx, probe)
	if err != nil {
		t.Fatal(err)
	}
	page := contract.ListPageResult{Status: contract.ListPageOK, Keys: []string{live, eligible, pending, missing, "foreign/opaque", malformed, helper}, NextCursor: "more"}
	got, result := gcObservePage(ctx, physical, s.admission.store, s.root.Domain, contract.ID{9}, marks, "", page)
	if result.Outcome != 0 {
		t.Fatal(result)
	}
	want := []contract.GCCandidateClass{contract.GCCandidateProtected, contract.GCCandidateEligible, contract.GCCandidateAlreadyPending, contract.GCCandidateAbsent, contract.GCCandidateUnverifiable, contract.GCCandidateUnverifiable, contract.GCCandidateProtected}
	var classes []contract.GCCandidateClass
	for _, row := range got.candidates {
		classes = append(classes, row.Classification)
	}
	if !reflect.DeepEqual(classes, want) || len(got.targets) != 1 || got.targets[0] != (contract.GCTarget{Object: eligibleObject, Length: uint32(len(body)), Digest: contract.Hash(body), Token: s.token}) || got.candidates[1].TargetIndex != 0 || got.next != "more" || got.digest.IsZero() {
		t.Fatal("bounded page lost exact classifications", classes, result)
	}
	if !reflect.DeepEqual(probe.keys, []string{eligible, missing, malformed}) || !got.candidates[4].KeyDigest.IsZero() || got.candidates[4].Reason != contract.GCReasonForeign {
		t.Fatal("candidate reads or disclosure changed", probe.keys)
	}
	probe.keys = nil
	page.Keys = []string{eligible, eligible}
	if _, result := gcObservePage(ctx, physical, s.admission.store, s.root.Domain, contract.ID{9}, marks, "", page); result.Outcome != IntegrityFailure || len(probe.keys) != 0 {
		t.Fatal("duplicate page supplied partial evidence", result)
	}
}

// full_only: false
func TestGCEnumerationCommitmentUsesIndependentBytes(t *testing.T) {
	store := gcCursorTestStore()
	ctx := gcReadContext(t)
	probe := &gcReadProbe{store: store}
	physical, err := newGCPhysicalReader(ctx, probe)
	if err != nil {
		t.Fatal(err)
	}
	marks := gcMarkSet{objects: map[contract.StoreObjectIdentity]gcMarkFact{}, pending: map[contract.StoreObjectIdentity]struct{}{}}
	got, result := gcObservePage(ctx, physical, store, contract.ID{1}, contract.ID{9}, marks, "", contract.ListPageResult{Status: contract.ListPageOK, Keys: []string{"foreign-one", "foreign-two"}, NextCursor: "next"})
	// Python hashlib with BE B(key), count, classification6, indexffff,
	// reason1 and zero listed length; no production encoder was used.
	want, err := hex.DecodeString("412641044be1d093999141164e4f092228d12017e986f8ef259a49f4121d8d9a")
	if err != nil || result.Outcome != 0 || !bytes.Equal(got.digest[:], want) || len(probe.keys) != 0 {
		t.Fatal("independent enumeration commitment differs", err, result, got.digest)
	}
}

// full_only: false
func TestGCTargetPreflightRefusesChangedOrProtectedObjects(t *testing.T) {
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	page := *s.recipients[0]
	page.Object = gcTestID("target-preflight")
	body, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	target := contract.GCTarget{Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: page.Object}, Length: uint32(len(body)), Digest: contract.Hash(body), Token: s.token}
	plan := gcTestPlan(t, s, "target-preflight-plan")
	plan.Targets = []contract.GCTarget{target}
	descriptor, err := contract.GCTargetsDescriptor(plan.Targets)
	if err != nil {
		t.Fatal(err)
	}
	plan.TargetsDigest = descriptor.Digest
	key := gcObjectTestKey(t, s.admission.store, s.root.Domain, target.Object)
	plan.Candidates = []contract.GCCandidate{{KeyDigest: contract.Hash([]byte(key)), Classification: contract.GCCandidateEligible}}
	for _, scenario := range []string{"exact", "token changed", "bytes changed", "missing", "protected", "pending", "candidate mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			current := plan
			current.Candidates = append([]contract.GCCandidate(nil), plan.Candidates...)
			marks := gcMarkSet{objects: map[contract.StoreObjectIdentity]gcMarkFact{}, pending: map[contract.StoreObjectIdentity]struct{}{}}
			read := contract.ReadResult{Status: contract.ReadOK, Body: body, Token: s.token}
			switch scenario {
			case "token changed":
				read.Token.Value = "999"
			case "bytes changed":
				read.Body = append(bytes.Clone(body), 0)
			case "missing":
				read = contract.ReadResult{Status: contract.ReadMissing}
			case "protected":
				marks.objects[target.Object] = gcMarkFact{object: target.Object}
			case "pending":
				marks.pending[target.Object] = struct{}{}
			case "candidate mismatch":
				current.Candidates[0].KeyDigest = contract.ID{99}
			}
			probe := &gcReadProbe{store: s.admission.store, read: func(context.Context, string, uint32) contract.ReadResult { return read }}
			ctx := gcReadContext(t)
			physical, err := newGCPhysicalReader(ctx, probe)
			if err != nil {
				t.Fatal(err)
			}
			got := gcValidateTargets(ctx, physical, s.admission.store, current, marks)
			if scenario == "exact" {
				if got.Outcome != 0 || len(probe.keys) != 1 {
					t.Fatal("exact target refused", got, probe.keys)
				}
			} else if got.Outcome == 0 {
				t.Fatal("unproved target admitted", scenario)
			}
			if (scenario == "protected" || scenario == "pending" || scenario == "candidate mismatch") && len(probe.keys) != 0 {
				t.Fatal("invalid target reached Store")
			}
		})
	}
}

// full_only: false
func TestGCExactReadHasOneRecoveryOwnerAndOriginalDeadline(t *testing.T) {
	t.Run("three physical calls", func(t *testing.T) {
		ctx := gcReadContext(t)
		calls := 0
		deadline, _ := ctx.Deadline()
		probe := &gcReadProbe{read: func(callCtx context.Context, _ string, _ uint32) contract.ReadResult {
			calls++
			bound, ok := callCtx.Deadline()
			if !ok || bound.After(deadline) {
				t.Fatal("physical call extended original bound")
			}
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport, Body: []byte("partial"), Token: contract.Token{Family: contract.GCP, Value: "1"}}
		}}
		physical, err := newGCPhysicalReader(ctx, probe)
		if err != nil {
			t.Fatal(err)
		}
		got := gcReadExact(ctx, physical, "fixture/object", 10)
		if calls != 3 || got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonTransport || len(got.Body) != 0 || got.Token != (contract.Token{}) {
			t.Fatal("read recovery expanded or leaked partial bytes", calls, got)
		}
	})
	t.Run("original admission without caller deadline", func(t *testing.T) {
		ctx := context.Background()
		expiry := time.Now().Add(time.Second)
		calls := 0
		physical, err := newGCPhysicalRead(ctx, expiry, func(callCtx context.Context, _ string, _ uint32) contract.ReadResult {
			calls++
			bound, ok := callCtx.Deadline()
			if !ok || bound.After(expiry) {
				t.Fatal("first physical call lacks original expiry")
			}
			<-callCtx.Done()
			return contract.ReadResult{Status: contract.ReadOK, Body: []byte("late"), Token: contract.Token{Family: contract.GCP, Value: "1"}}
		})
		if err != nil {
			t.Fatal(err)
		}
		got := gcReadExact(ctx, physical, "fixture/object", 10)
		if calls != 1 || got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonLimit || len(got.Body) != 0 {
			t.Fatal("expired admission acquired another failure window", calls, got)
		}
	})
}
