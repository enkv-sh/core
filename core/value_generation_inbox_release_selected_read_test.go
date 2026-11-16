package core

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedInboxReleaseReadStore struct {
	*readFailureStore
	descriptor contract.Descriptor
	writes     int
}

func (s *generatedInboxReleaseReadStore) Descriptor() contract.Descriptor { return s.descriptor }
func (s *generatedInboxReleaseReadStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.writes++
	return contract.WriteResult{Status: contract.WriteRefused}
}
func (s *generatedInboxReleaseReadStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.writes++
	return contract.WriteResult{Status: contract.WriteRefused}
}
func (s *generatedInboxReleaseReadStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.writes++
	return contract.WriteResult{Status: contract.WriteRefused}
}

type generatedInboxReleaseReadTrust struct {
	identity contract.ID
	family   contract.Family
	signs    int
}

func (t *generatedInboxReleaseReadTrust) Identity() contract.ID   { return t.identity }
func (t *generatedInboxReleaseReadTrust) Family() contract.Family { return t.family }
func (t *generatedInboxReleaseReadTrust) Sign(context.Context, contract.SignRequest) contract.SignResult {
	t.signs++
	return contract.SignResult{Reason: contract.ReasonAccess}
}

// full_only: false
func TestGeneratedInboxReleaseSelectedReadResults(t *testing.T) {
	for _, releaseKind := range []string{"clean", "unknown"} {
		for _, fault := range []struct {
			name string
			want Result
		}{
			{"missing", failure(EvidenceUnavailable, MissingSelectedObject)},
			{"unavailable", Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}},
			{"canceled", failure(EvidenceUnavailable, ReadUnavailable)},
			{"changed", failure(IntegrityFailure, InvalidReference)},
			{"wrong-target", refused(InvalidRelation)},
			{"wrong-evidence", refused(InvalidRelation)},
		} {
			t.Run(releaseKind+"/"+fault.name, func(t *testing.T) {
				s, attempt, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
				admitted := generatedLifecycleFixture(t, s)
				s.admission.store.HeadKey = s.admission.store.Prefix + "/HEAD"
				s.admission.composition, s.admission.expires = generatedVectorID(244), time.Now().Add(time.Minute)
				backing := s.store.(*generatedFixtureSupportStore)
				inboxKey, err := format.GeneratedResultKey(s.admission.store.Prefix, release.DomainID, release.InboxID)
				if err != nil {
					t.Fatal("release inbox key", err)
				}
				store := &generatedInboxReleaseReadStore{readFailureStore: &readFailureStore{}, descriptor: s.admission.store}
				var faultKey string
				var faultLimit uint32
				var armed bool
				var cancelRead context.CancelFunc
				store.onReadCtx = func(ctx context.Context) (contract.ReadResult, bool) {
					last := len(store.keys) - 1
					key, limit := store.keys[last], store.limits[last]
					if armed && key == faultKey {
						if limit != faultLimit {
							t.Fatalf("selected graph read bound=%d want=%d", limit, faultLimit)
						}
						switch fault.name {
						case "missing":
							return contract.ReadResult{Status: contract.ReadMissing}, true
						case "unavailable":
							return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
						case "canceled":
							cancelRead()
							return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(backing.objects[key])}, true
						case "changed":
							body := bytes.Clone(backing.objects[key])
							body[len(body)-1] ^= 1
							return contract.ReadResult{Status: contract.ReadOK, Body: body}, true
						}
					}
					if key == inboxKey {
						if releaseKind == "clean" {
							return contract.ReadResult{Status: contract.ReadMissing}, true
						}
						return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(attempt.result),
							Token: contract.Token{Family: store.descriptor.Family, Value: "selected-inbox"}}, true
					}
					return backing.Read(ctx, key, limit), true
				}
				s.store = store
				if !s.admission.valid(store) {
					t.Fatal("release read fixture admission is invalid")
				}
				plan, err := s.generatedInboxReleasePlan(t.Context(), release.InboxID, admitted)
				if err != nil {
					t.Fatal("release plan before selected read damage", err)
				}
				wantKind := generatedLifecycleInboxRelease
				if releaseKind == "unknown" {
					wantKind = generatedLifecycleInboxReleaseUnknown
				}
				if plan.kind != wantKind {
					t.Fatalf("release plan kind=%d want=%d", plan.kind, wantKind)
				}
				permit, err := s.admitGeneratedLifecyclePlan(t.Context(), plan)
				if err != nil || permit == nil {
					t.Fatal("release admission before selected read damage", err)
				}
				if s.generatedWork != nil || len(s.generatedGraphs) != 0 {
					t.Fatal("release fixture unexpectedly published a predecessor graph cache")
				}
				selected, err := s.selectedGeneratedWork(t.Context())
				if err != nil {
					t.Fatal("selected release graph before damage", err)
				}
				graph := selected.content.locations[generatedContentKey{contract.GeneratorContentGraph, attempt.expected.Plan.PlanGraphID}]
				var released int
				for location, fact := range s.fragmentFacts {
					if location.BlobID != graph.BlobID {
						continue
					}
					if _, cached := s.cache[fact.ref]; cached {
						t.Fatal("release fixture retained the selected graph page in its byte cache")
					}
					faultKey, err = format.Key(s.admission.store.Prefix, fact.ref)
					if err != nil {
						t.Fatal("selected graph key", err)
					}
					faultLimit = fact.ref.Length
					for i := range s.support {
						if s.support[i].Index == location.SupportPageIndex {
							s.support[i].Records[location.RowSlot].Body = nil
							released++
						}
					}
				}
				if released != 1 || faultKey == "" || faultLimit == 0 {
					t.Fatalf("release fixture graph fragments=%d key present=%t bound=%d", released, faultKey != "", faultLimit)
				}
				generatedVerifySelectedFixtureSlices(t, s)
				healthyReads := len(store.keys)
				healthy, err := s.selectedGeneratedWork(t.Context())
				if len(store.keys) != healthyReads+1 || store.keys[healthyReads] != faultKey || store.limits[healthyReads] != faultLimit {
					t.Fatal("healthy bodyless graph did not use one exact selected read", store.keys[healthyReads:], store.limits[healthyReads:])
				}
				if err != nil || healthy == nil || healthy.content.locations[generatedContentKey{contract.GeneratorContentGraph, attempt.expected.Plan.PlanGraphID}] != graph {
					t.Fatal("healthy bodyless release graph selection", err)
				}
				if s.generatedWork != nil || len(s.generatedGraphs) != 0 {
					t.Fatal("healthy bodyless graph selection published a predecessor graph cache")
				}
				// Admission issued a real permit for the valid plan. Exercise the
				// closed-plan recheck with a healthy selected Store read.
				relationFailure := false
				switch fault.name {
				case "wrong-target":
					plan.target = generatedVectorID(231)
					relationFailure = true
					if plan.target == release.OriginalResultID {
						t.Fatal("relation fixture retained the valid target")
					}
				case "wrong-evidence":
					plan.evidence = generatedVectorID(232)
					relationFailure = true
					if plan.evidence == release.SelectedHandoffDigest {
						t.Fatal("relation fixture retained the valid evidence")
					}
				}
				before := generatedSuccessorPredecessorSnapshot(t, s)
				trust := &generatedInboxReleaseReadTrust{identity: s.admission.trust, family: s.admission.store.Family}
				armed = true
				for _, call := range []string{"derive", "prepare"} {
					t.Run(call, func(t *testing.T) {
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						cancelRead = cancel
						readsBefore := len(store.keys)
						var reservation *generatedReservation
						var candidate *Candidate
						var result Result
						var typed bool
						var err error
						if call == "derive" {
							if releaseKind == "clean" {
								reservation, err = s.deriveGeneratedInboxRelease(ctx, plan)
							} else {
								reservation, err = s.deriveGeneratedInboxReleaseUnknown(ctx, plan)
							}
							result, typed = selectedReadResult(err)
						} else {
							candidate, result = s.PrepareGeneratedLifecycle(ctx, permit, trust)
						}
						if len(store.keys) != readsBefore+1 || store.keys[readsBefore] != faultKey || store.limits[readsBefore] != faultLimit {
							t.Fatal("release failure did not use one exact selected graph read", store.keys[readsBefore:], store.limits[readsBefore:])
						}
						if trust.signs != 0 || store.writes != 0 || !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
							t.Fatal("selected release read failure reached signing or writes, or changed its predecessor", trust.signs, store.writes)
						}
						if call == "derive" {
							if relationFailure {
								if reservation != nil || typed || !errors.Is(err, contract.ErrRecord) {
									t.Fatalf("release relation derivation reservation=%t result=%+v typed=%t error=%v selected graph reads=1 bound=%d", reservation != nil, result, typed, err, faultLimit)
								}
							} else if reservation != nil || !typed || result != fault.want {
								t.Fatalf("release derivation reservation=%t result=%+v typed=%t error=%v selected graph reads=1 bound=%d", reservation != nil, result, typed, err, faultLimit)
							}
						}
						if call == "prepare" && (candidate != nil || result != fault.want) {
							t.Fatalf("release preparation candidate=%t result=%+v want=%+v selected graph reads=1 bound=%d", candidate != nil, result, fault.want, faultLimit)
						}
					})
				}
			})
		}
	}
}
