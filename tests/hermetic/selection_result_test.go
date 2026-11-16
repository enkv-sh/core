package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type recordingCASStore struct {
	contract.Store
	calls          int
	key            string
	token          contract.Token
	body           []byte
	requests       []selectionRequest
	write          func(context.Context, string, contract.Token, []byte) contract.WriteResult
	cancelledReads bool
	readCalls      int
}

type selectionRequest struct {
	key   string
	token contract.Token
	body  []byte
}

func (s *recordingCASStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s *recordingCASStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.calls++
	s.key, s.token, s.body = key, token, bytes.Clone(body)
	s.requests = append(s.requests, selectionRequest{key, token, bytes.Clone(body)})
	if s.write != nil {
		return s.write(ctx, key, token, body)
	}
	return s.Store.CompareAndSwap(ctx, key, token, body)
}

func (s *recordingCASStore) Read(ctx context.Context, key string, max uint32) contract.ReadResult {
	s.readCalls++
	if s.cancelledReads && ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	return s.Store.Read(ctx, key, max)
}

func assertExactSelectionRequest(t *testing.T, store *recordingCASStore, key string, token contract.Token, body []byte, expectedCalls ...int) {
	t.Helper()
	wantCalls := 1
	if len(expectedCalls) == 1 {
		wantCalls = expectedCalls[0]
	}
	if store.calls != wantCalls || len(store.requests) != wantCalls {
		t.Fatalf("selection sends = %d, want %d", store.calls, wantCalls)
	}
	for i, request := range store.requests {
		if request.key != key || request.token != token || !bytes.Equal(request.body, body) {
			t.Fatalf("selection send %d changed: key=%q token=%+v", i, request.key, request.token)
		}
	}
}

type selectionResultObservation struct {
	name     string
	reason   Reason
	observed string
}

// full_only: false
func TestSelectionResultEvidenceMatrix(t *testing.T) {
	testSelectionResultEvidenceMatrix(t, []selectionResultObservation{
		{"requested", NoReason, "requested"},
		{"proof-variation", NoReason, "requested"},
		{"predecessor", DifferentSelection, "predecessor"},
		{"other-selection", DifferentSelection, "other"},
		{"later-selection", DifferentSelection, "later"},
		{"missing-head", MissingSelectedObject, ""},
		{"unavailable-head", ReadUnavailable, ""},
		{"denied-head", ReadUnavailable, ""},
		{"invalid-head", InvalidFormat, ""},
		{"invalid-proof", InvalidProof, ""},
		{"invalid-closure", InvalidReference, ""},
		{"missing-closure", MissingSelectedObject, ""},
		{"defensive-missing-token", InvalidFormat, ""},
		{"defensive-wrong-token-family", InvalidFormat, ""},
		{"defensive-requested-body-predecessor-token", InvalidFormat, ""},
		{"defensive-predecessor-body-new-token", DifferentSelection, "predecessor"},
	})
}

// full_only: true
func TestSelectionResultMaximumObservedSelection(t *testing.T) {
	testSelectionResultEvidenceMatrix(t, []selectionResultObservation{
		{"larger-selection", DifferentSelection, "larger"},
	})
}

func testSelectionResultEvidenceMatrix(t *testing.T, observations []selectionResultObservation) {
	t.Helper()
	// Expected facts follow the state-path contract: an exact authenticated
	// observation proves currentness; all other possible-send cases retain doubt.
	for _, status := range []struct {
		name   string
		status contract.WriteStatus
	}{
		{"acknowledged", contract.WriteAcknowledged},
		{"conflict", contract.WriteConflict},
		{"unknown", contract.WriteUnknown},
	} {
		for _, observation := range observations {
			name := status.name + "/" + observation.name
			if status.status == contract.WriteAcknowledged && observation.name == "predecessor" {
				// This adapter ACK deliberately contradicts the stored predecessor.
				name = status.name + "/defensive-ack-without-effect"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				var memory *memoryAccounting
				if observation.observed == "larger" {
					memory = startMemoryAccounting()
				}
				f := newFixture(t, 1, false, 1)
				before := fixtureStateImage(t, f)
				oldHead := f.store.objects[f.store.desc.HeadKey]
				input := before.entryInputs()
				input[0].InputBytes = []byte("requested")
				comparison, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
				if comparison == nil {
					t.Fatal(result)
				}
				permit := admit(t, f.session, comparison)
				requested := expectedSuccessorImage(t, before, input, observeAllocatedTransitionInputs(permit))
				candidate, result := f.session.Prepare(ctx, comparison, permit, f.trust)
				if candidate == nil {
					t.Fatal(result)
				}
				frozenBody := bytes.Clone(candidate.body)
				observedImage := requested
				observedBody := bytes.Clone(candidate.body)
				if observation.observed == "other" || observation.observed == "later" || observation.observed == "larger" || observation.name == "invalid-closure" || observation.name == "missing-closure" {
					base := before
					if observation.observed == "later" {
						f.store.put(f.store.desc.HeadKey, candidate.body)
						base = requested
					}
					other, result := Open(ctx, f.admission, f.store)
					if other == nil {
						t.Fatal(result)
					}
					input := base.entryInputs()
					input[0].InputBytes = []byte("another selection")
					if observation.observed == "larger" {
						prototype := input[0]
						input = make([]ApplyEntryInput, 512)
						for i, name := range maximumLifecycleNames("observed") {
							input[i] = prototype
							input[i].Name, input[i].InputBytes = name, nil
							if i >= 384 {
								input[i].InputBytes = make([]byte, 65536)
							}
						}
					}
					comparison, result := other.Compare(context.Background(), input, admitSuppliedComparison(t, other, nil, input))
					if comparison == nil {
						t.Fatal(result)
					}
					permit := admit(t, other, comparison)
					observedImage = expectedSuccessorImage(t, base, input, observeAllocatedTransitionInputs(permit))
					otherCandidate, result := other.Prepare(ctx, comparison, permit, f.trust)
					if otherCandidate == nil {
						t.Fatal(result)
					}
					observedBody = bytes.Clone(otherCandidate.body)
					f.store.objects[f.store.desc.HeadKey] = oldHead
				}
				if observation.observed == "predecessor" {
					observedImage, observedBody = before, bytes.Clone(oldHead.Body)
				}
				if observation.name == "proof-variation" || observation.name == "invalid-proof" {
					head := candidate.head
					if observation.name == "proof-variation" {
						bindingRequest, err := contract.NewBindingRequest(binding(f.session.admission))
						if err != nil {
							t.Fatal(err)
						}
						lifecycleRequest, err := contract.NewLifecycleRequest(head.Subject)
						if err != nil {
							t.Fatal(err)
						}
						head.K1 = f.trust.Sign(ctx, bindingRequest).Signature
						head.AuthorizationSignature = f.trust.Sign(ctx, lifecycleRequest).Signature
						if bytes.Equal(head.K1, candidate.head.K1) || bytes.Equal(head.AuthorizationSignature, candidate.head.AuthorizationSignature) || head.Core != candidate.head.Core || head.Subject != candidate.head.Subject {
							t.Fatal("proof variation did not preserve all proof-free bindings and change both proofs")
						}
					} else {
						head.AuthorizationSignature = bytes.Clone(head.AuthorizationSignature)
						head.AuthorizationSignature[len(head.AuthorizationSignature)-1] ^= 1
					}
					var err error
					observedBody, err = format.EncodeHead(head)
					if err != nil {
						t.Fatal(err)
					}
				}
				want := Result{Outcome: UnresolvedCommit, Reason: observation.reason, RequestedRevision: requested.Revision, CommitMayHaveOccurred: true}
				if observation.observed != "" {
					want.ObservedRevision, want.ObservedSnapshotID, want.Evidence = observedImage.Revision, observedImage.Root.Snapshot, AuthenticatedClosure
				}
				if observation.observed == "requested" {
					want.Outcome, want.CommitMayHaveOccurred = ObservedCurrent, false
				}
				if observation.name == "predecessor" {
					want.Reason = WriteUncertain
				}
				switch observation.name {
				case "unavailable-head":
					want.StoreReason = contract.ReasonTransport
				case "denied-head":
					want.StoreReason = contract.ReasonAccess
				}
				store := &recordingCASStore{Store: f.store}
				store.write = func(_ context.Context, key string, _ contract.Token, body []byte) contract.WriteResult {
					f.store.put(key, body)
					if observation.name == "predecessor" {
						f.store.objects[key] = oldHead
					} else {
						f.store.put(key, observedBody)
					}
					return contract.WriteResult{Status: status.status}
				}
				f.session.store = store
				rootKey := mustKey(t, f.store.desc.Prefix, observedImage.RootRef)
				headReads, rootReads := 0, 0
				f.store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
					if key == rootKey {
						rootReads++
						switch observation.name {
						case "invalid-closure":
							r.Body[len(r.Body)-1] ^= 1
						case "missing-closure":
							return contract.ReadResult{Status: contract.ReadMissing}
						}
					}
					if key != f.store.desc.HeadKey {
						return r
					}
					headReads++
					switch observation.name {
					case "missing-head":
						return contract.ReadResult{Status: contract.ReadMissing}
					case "unavailable-head":
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
					case "denied-head":
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
					case "invalid-head":
						return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
					case "defensive-missing-token":
						r.Token = contract.Token{}
					case "defensive-wrong-token-family":
						r.Token = contract.Token{Family: contract.AWS, Value: `"unpaired-etag"`}
					case "defensive-requested-body-predecessor-token":
						r.Token = oldHead.Token
					}
					return r
				}
				creates, signs := f.store.creates, f.trust.signs
				if result := f.session.Select(ctx, candidate); result != want {
					t.Fatalf("Select = %+v, want %+v", result, want)
				}
				wantSends, wantHeadReads := 1, 1
				if observation.name == "unavailable-head" {
					wantHeadReads = 3
				}
				assertExactSelectionRequest(t, store, f.store.desc.HeadKey, oldHead.Token, frozenBody, wantSends)
				if headReads != wantHeadReads || f.store.creates != creates || f.trust.signs != signs || f.session.token != oldHead.Token || !candidate.used {
					t.Fatalf("selection observation or frozen request changed: HEAD reads=%d, want=%d", headReads, wantHeadReads)
				}
				if (observation.name == "invalid-closure" || observation.name == "missing-closure") && rootReads != 1 {
					t.Fatal("failed-closure case did not read the uncached selected root")
				}
				if memory != nil {
					memory.sample("larger-observation-returned", f.session, comparison, candidate, nil)
					observed, result := f.session.readCurrent(ctx)
					if observed == nil || result.ObservedRevision != observedImage.Revision || observed.root.RawBytes != 8<<20 || observed.root.RawBytes <= requested.Root.RawBytes {
						t.Fatalf("larger valid observation did not authenticate: %+v", result)
					}
					assertStateImage(t, observed, observedImage)
					memory.sample("retained-larger-observation", f.session, comparison, candidate, observed)
					for _, sample := range memory.samples {
						if sample.ByteCapacity > 77987224 || sample.GoHeapUpperBound < sample.ByteCapacity {
							t.Fatalf("larger observation exceeds memory ledger: %+v", sample)
						}
					}
					t.Logf("larger valid observation memory: %+v", memory.samples)
				}
			})
		}
	}
}

// full_only: false
func TestSelectionDefiniteWriteResults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  contract.WriteStatus
		outcome Outcome
		reason  Reason
	}{
		{"pre-send-refusal", contract.WriteRefused, AdmissionRefused, ConstructionMismatch},
		{"first-attempt-precondition", contract.WritePrecondition, Contention, StalePrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			before := fixtureStateImage(t, f)
			oldHead := f.store.objects[f.store.desc.HeadKey]
			comparison := changed(t, f.session, 0)
			permit := admit(t, f.session, comparison)
			candidate, result := f.session.Prepare(context.Background(), comparison, permit, f.trust)
			if candidate == nil {
				t.Fatal(result)
			}
			store := &recordingCASStore{Store: f.store, write: func(context.Context, string, contract.Token, []byte) contract.WriteResult {
				return contract.WriteResult{Status: tc.status}
			}}
			if tc.status == contract.WritePrecondition {
				f.store.put(f.store.desc.HeadKey, oldHead.Body)
				store.write = nil
			}
			selectedHead := f.store.objects[f.store.desc.HeadKey]
			f.session.store = store
			frozenBody := bytes.Clone(candidate.body)
			reads, creates, signs := f.store.reads, f.store.creates, f.trust.signs
			want := Result{Outcome: tc.outcome, Reason: tc.reason, RequestedRevision: permit.plan.revision, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure}
			if tc.status == contract.WriteRefused {
				// A refused send has no new authenticated current observation.
				want.ObservedRevision, want.ObservedSnapshotID, want.Evidence = contract.ID{}, contract.ID{}, NoEvidence
			}
			if result := f.session.Select(context.Background(), candidate); result != want {
				t.Fatalf("Select = %+v, want %+v", result, want)
			}
			assertExactSelectionRequest(t, store, f.store.desc.HeadKey, oldHead.Token, frozenBody)
			if f.store.reads != reads || f.store.creates != creates || f.trust.signs != signs || f.session.token != oldHead.Token {
				t.Fatal("definite write result performed observation, preparation, signing or token refresh")
			}
			after := f.store.objects[f.store.desc.HeadKey]
			if selectedHead.Token != after.Token || !bytes.Equal(selectedHead.Body, after.Body) {
				t.Fatal("refused write changed selected HEAD")
			}
		})
	}
}

// full_only: false
func TestSelectionCancellationEvidence(t *testing.T) {
	for _, mode := range []string{"before-send", "after-entry-with-effect", "after-entry-without-effect"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			before := fixtureStateImage(t, f)
			oldHead := f.store.objects[f.store.desc.HeadKey]
			input := before.entryInputs()
			input[0].InputBytes = []byte("requested")
			comparison, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
			if comparison == nil {
				t.Fatal(result)
			}
			permit := admit(t, f.session, comparison)
			requested := expectedSuccessorImage(t, before, input, observeAllocatedTransitionInputs(permit))
			candidate, result := f.session.Prepare(context.Background(), comparison, permit, f.trust)
			if candidate == nil {
				t.Fatal(result)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			frozenBody := bytes.Clone(candidate.body)
			store := &recordingCASStore{Store: f.store, cancelledReads: true}
			entered := 0
			store.write = func(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
				if ctx.Err() != nil {
					return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
				}
				entered++
				if mode == "after-entry-with-effect" {
					if result := f.store.CompareAndSwap(ctx, key, token, body); result.Status != contract.WriteAcknowledged {
						t.Fatal(result)
					}
				}
				cancel()
				return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			}
			f.session.store = store
			want := Result{Outcome: UnresolvedCommit, Reason: ReadUnavailable, RequestedRevision: requested.Revision, CommitMayHaveOccurred: true, StoreReason: contract.ReasonLimit}
			wantEntered := 1
			wantReads := 0
			if mode == "before-send" {
				cancel()
				want = refused(AdmissionInvalid)
				wantEntered = 0
				wantReads = 0
			}
			if result := f.session.Select(ctx, candidate); result != want {
				t.Fatalf("Select = %+v, want %+v", result, want)
			}
			if mode == "before-send" {
				if store.calls != 0 {
					t.Fatal("canceled Select reached the Store")
				}
			} else {
				assertExactSelectionRequest(t, store, f.store.desc.HeadKey, oldHead.Token, frozenBody)
			}
			if entered != wantEntered || store.readCalls != wantReads || ctx.Err() != context.Canceled {
				t.Fatalf("entry=%d want=%d reads=%d want=%d context=%v", entered, wantEntered, store.readCalls, wantReads, ctx.Err())
			}
			selected := before
			if mode == "after-entry-with-effect" {
				selected = requested
			}
			reader, result := Open(context.Background(), f.admission, f.store)
			if reader == nil {
				t.Fatal(result)
			}
			assertStateImage(t, reader, selected)
		})
	}
}
