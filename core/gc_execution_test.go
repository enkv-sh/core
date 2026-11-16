package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func gcOpenRuntime(t *testing.T, ctx context.Context, input CapacityReadInstallation, store contract.Store) *StateSession {
	t.Helper()
	admitted, result := admitPublicNormal(ctx, input.ExpectedDomain, input.ExpectedStore, input.PublicBasis, store, gcTestID("runtime-read-composition"), nil)
	if admitted.admission == nil {
		t.Fatal("runtime public normal admission", result)
	}
	state, result := open(ctx, admitted, store)
	if state == nil {
		t.Fatal("runtime current open", result)
	}
	return state
}
func gcRuntimeSelectOnly(t *testing.T, ctx context.Context, state *StateSession, input CapacityReadInstallation, plan contract.GCPlan, encoded []byte) (*StateSession, contract.GCProgress) {
	t.Helper()
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	proof, result := reader.ValidateGCPlan(ctx, encoded)
	if proof == nil || !proof.consume(ctx) {
		t.Fatal("real validation before selected runtime state", result)
	}
	progress, err := gcInitialProgress(plan)
	if err != nil {
		t.Fatal(err)
	}
	return gcSelectRuntimePhase(t, ctx, state, plan, progress, contract.GCSelect), progress
}

// full_only: false
func TestInstalledGCApplyUsesPublicValidationBeforeMutation(t *testing.T) {
	for _, name := range []string{"empty", "scope", "token", "digest", "stale", "oversized"} {
		t.Run(name, func(t *testing.T) {
			state, store, input, plan, encoded := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			if name == "empty" {
				var lists, closes atomic.Int32
				input.Construct = func(context.Context, contract.StoreConfiguration) (PublicCapacityReader, Result) {
					return &gcExecutionRead{store: store, page: contract.ListPageResult{Status: contract.ListPageOK}, lists: &lists, closes: &closes}, Result{}
				}
				reader, err := NewInstalledCapacityReader(input)
				if err != nil {
					t.Fatal(err)
				}
				preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("empty-runtime-preview"), OperationID: gcTestID("empty-runtime-operation")})
				reader.Close()
				if preview.Payload == nil {
					t.Fatal(preview.Result)
				}
				encoded = preview.Payload.EncodedPlan
			} else {
				switch name {
				case "scope":
					plan.SourcePinsDigest[0] ^= 1
				case "token":
					plan.Targets[0].Token.Value = "999"
				case "digest":
					plan.Targets[0].Digest = gcTestID("tampered-runtime-digest")
				case "stale":
					store.headGeneration++
				case "oversized":
					encoded = make([]byte, contract.GCPlanMaxLength+1)
				}
				if name == "token" || name == "digest" {
					descriptor, err := contract.GCTargetsDescriptor(plan.Targets)
					if err != nil {
						t.Fatal(err)
					}
					plan.TargetsDigest = descriptor.Digest
				}
				if name != "oversized" {
					var err error
					encoded, err = contract.EncodeGCPlan(plan)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			engine, factories := gcExecutionEngine(t, state, store, input)
			out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("validation-before-mutation"), EncodedPlan: encoded})
			if *factories != 0 || len(store.phases) != 0 || len(store.deletes) != 0 {
				t.Fatal("public validation or empty no-op constructed effects", name, *factories, store.phases, store.deletes)
			}
			if name == "empty" {
				if out.StateResult != "no-op" || out.EffectSummary != contract.ReceiptEffectNoChange || out.Payload == nil || out.Payload.SiblingResults.Count != 0 {
					t.Fatal("empty vector did not remain non-durable", out)
				}
			} else if out.StateResult == "success" || out.StateResult == "gc-partial-garbage" || out.StateResult == "no-op" {
				t.Fatal("invalid plan obtained completion", out)
			}
			if err := out.Validate(); err != nil {
				t.Fatal("public validation result invalid", name, err, out)
			}
		})
	}
	t.Run("missing delete capability", func(t *testing.T) {
		state, store, input, _, encoded := gcExecutionFixture(t)
		reader, err := NewInstalledCapacityReader(input)
		if err != nil {
			t.Fatal(err)
		}
		signer := testtrust.New(t, contract.GCP, state.admission.trust)
		closes := 0
		engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
			return GCMutationResources{Store: struct{ contract.Store }{store}, Trust: signer, Close: func() error { closes++; return nil }}, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		out := engine.ApplyPlan(gcReadContext(t), GCApplyPlanRequest{RequestNonce: gcTestID("no-delete-capability"), EncodedPlan: encoded})
		if out.Result.Outcome != AdmissionRefused || len(store.phases) != 0 || len(store.deletes) != 0 || signer.Calls() != 0 {
			t.Fatal("missing deletion capability admitted mutation", out, store.phases, store.deletes, signer.Calls())
		}
		if err := engine.Close(); err != nil || closes != 1 {
			t.Fatal("factory ownership did not join", err, closes)
		}
	})
}

// full_only: false
func TestGCSelectionRequiresOwnExactCandidate(t *testing.T) {
	for _, name := range []string{"acknowledged", "own unknown", "other candidate", "precondition", "conflict", "conflict unchanged", "conflict unreadable", "not-sent", "first-send"} {
		t.Run(name, func(t *testing.T) {
			state, store, input, plan, encoded := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			reader, err := NewInstalledCapacityReader(input)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			proof, result := reader.ValidateGCPlan(ctx, encoded)
			if proof == nil || !proof.consume(ctx) {
				t.Fatal("original selection validation", result)
			}
			progress, err := gcInitialProgress(plan)
			if err != nil {
				t.Fatal(err)
			}
			signer := testtrust.New(t, contract.GCP, state.admission.trust)
			candidate, result := state.prepareGCPhase(ctx, plan, gcTestID("selection-owner-a"), contract.GCSelect, &progress)
			if candidate == nil {
				t.Fatal(result)
			}
			candidate, result = state.persistCandidate(ctx, candidate, signer)
			if candidate == nil {
				t.Fatal(result)
			}
			var other *Candidate
			if name == "other candidate" {
				other, result = state.prepareGCPhase(ctx, plan, gcTestID("selection-owner-b"), contract.GCSelect, &progress)
				if other == nil {
					t.Fatal(result)
				}
				other, result = state.persistCandidate(ctx, other, signer)
				if other == nil {
					t.Fatal(result)
				}
				if other.head.Core.Revision == candidate.head.Core.Revision || other.head.GC.AdmissionID == candidate.head.GC.AdmissionID {
					t.Fatal("independent selection identities collapsed")
				}
			}
			store.onCAS = func(_ contract.GCPhase, body []byte) *contract.WriteResult {
				switch name {
				case "own unknown":
					store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, state.token, body)
					return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				case "other candidate":
					store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, state.token, other.body)
					return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				case "conflict unchanged", "conflict unreadable":
					if name == "conflict unreadable" {
						store.onRead = func(key string) *contract.ReadResult {
							if key == store.descriptor.HeadKey {
								return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
							}
							return nil
						}
					}
					return &contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
				case "precondition", "conflict", "not-sent":
					store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, state.token, body)
					if name == "not-sent" {
						return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
					}
					status := contract.WritePrecondition
					if name == "conflict" {
						status = contract.WriteConflict
					}
					return &contract.WriteResult{Status: status, Reason: contract.ReasonCondition}
				}
				return nil
			}
			if name == "first-send" {
				candidate.firstSend = &candidateFirstSend{}
			}
			selected := state.selectGCCandidate(ctx, candidate)
			want := name == "acknowledged" || name == "own unknown" || name == "conflict"
			if selected.confirmed != want {
				t.Fatal("selection admission did not require own exact possibly-entered candidate", name, selected.result)
			}
			if name == "conflict unchanged" || name == "conflict unreadable" || name == "other candidate" {
				if selected.result.Outcome != UnresolvedCommit || !selected.result.CommitMayHaveOccurred || selected.result.RequestedRevision != candidate.head.Core.Revision || selected.notSelected {
					t.Fatal("unconfirmed possible commit became clean contention", name, selected)
				}
			}
			if want && (selected.result.Outcome != ObservedCurrent || selected.result.CommitMayHaveOccurred || selected.result.RequestedRevision != candidate.head.Core.Revision || selected.result.ObservedRevision != candidate.head.Core.Revision) {
				t.Fatal("confirmed candidate lost exact authenticated selection facts", selected.result)
			}
			calls := 1
			if name == "first-send" {
				calls = 0
			}
			if len(store.phases) != calls || len(store.deletes) != 0 {
				t.Fatal("selection retried or dispatched", store.phases, store.deletes)
			}
		})
	}
}

// full_only: false
func TestGCSelectionRetainsPossibleCommitOnObservationFailure(t *testing.T) {
	for _, write := range []contract.WriteResult{{Status: contract.WriteAcknowledged}, {Status: contract.WriteUnknown, Reason: contract.ReasonTransport}} {
		for _, name := range []string{"malformed-head", "missing-head", "missing-root", "admission", "unavailable"} {
			t.Run(fmt.Sprintf("write-%d/%s", write.Status, name), func(t *testing.T) {
				state, store, input, plan, encoded := gcExecutionFixture(t)
				ctx := gcReadContext(t)
				state, progress := gcRuntimeSelectOnly(t, ctx, state, input, plan, encoded)
				progress.Ordinal++
				progress.Targets[0].Consumed = 1
				candidate, result := state.prepareGCPhase(ctx, plan, gcTestID("uncertain-reserve"), contract.GCReserve, &progress)
				if candidate == nil {
					t.Fatal("prepare reserve", result)
				}
				candidate, result = state.persistCandidate(ctx, candidate, testtrust.New(t, contract.GCP, state.admission.trust))
				if candidate == nil {
					t.Fatal("persist reserve", result)
				}
				rootKey, err := format.Key(store.descriptor.Prefix, candidate.head.Core.Root)
				if err != nil {
					t.Fatal(err)
				}
				if name == "missing-root" {
					delete(state.cache, candidate.head.Core.Root)
				}
				wantOutcome, wantReason, reads := IntegrityFailure, InvalidFormat, 1
				switch name {
				case "missing-head":
					wantOutcome, wantReason = RootLossUnsupported, MissingSelectedObject
				case "missing-root":
					wantOutcome, wantReason = UnresolvedCommit, MissingSelectedObject
				case "admission":
					wantOutcome, wantReason = AdmissionRefused, AdmissionInvalid
				case "unavailable":
					wantOutcome, wantReason, reads = UnresolvedCommit, ReadUnavailable, 3
				}
				if name == "malformed-head" && write.Status == contract.WriteUnknown {
					reads = 2
				}
				failedReads, rootReads := 0, 0
				store.onCAS = func(_ contract.GCPhase, body []byte) *contract.WriteResult {
					if got := store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, state.token, body); got.Status != contract.WriteAcknowledged {
						t.Fatal("fixture reserve did not commit", got)
					}
					if name == "admission" {
						state.admission.current, state.admission.observation, state.admission.descriptor = nil, nil, nil
					}
					store.onRead = func(key string) *contract.ReadResult {
						if name == "missing-root" && key == rootKey {
							rootReads++
							return &contract.ReadResult{Status: contract.ReadMissing}
						}
						if key != store.descriptor.HeadKey {
							return nil
						}
						failedReads++
						switch name {
						case "malformed-head":
							return &contract.ReadResult{Status: contract.ReadOK, Body: []byte("invalid HEAD"), Token: contract.Token{Family: contract.GCP, Value: "999"}}
						case "missing-head":
							return &contract.ReadResult{Status: contract.ReadMissing}
						case "unavailable":
							return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
						}
						return nil
					}
					return &write
				}
				offset := len(store.phases)
				selected := state.selectGCCandidate(ctx, candidate)
				if selected.confirmed || selected.notSelected || selected.state != nil || selected.result.Outcome != wantOutcome || selected.result.Reason != wantReason || !selected.result.CommitMayHaveOccurred || selected.result.RequestedRevision != candidate.head.Core.Revision || selected.write != write {
					t.Error("failed observation lost exact possible-commit facts", selected)
				}
				if name != "missing-root" && name != "admission" && failedReads != reads {
					t.Error("HEAD observation changed its original finite allowance", failedReads, reads)
				}
				if name == "missing-root" && rootReads != 1 {
					t.Error("missing selected root did not reach its exact read boundary", rootReads)
				}
				if len(store.phases)-offset != 1 || len(store.deletes) != 0 {
					t.Error("unconfirmed reserve resent CAS or acquired deletion authority", store.phases[offset:], store.deletes)
				}
			})
		}
	}
}

type selectionRejectionStore struct {
	contract.Store
	firstNotSent bool
	keys         []string
	tokens       []contract.Token
	bodies       [][]byte
}

func (s *selectionRejectionStore) CompareAndSwap(_ context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.keys = append(s.keys, key)
	s.tokens = append(s.tokens, token)
	s.bodies = append(s.bodies, bytes.Clone(body))
	if len(s.keys) == 1 {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: s.firstNotSent}
	}
	return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
}

// full_only: false
func TestSelectionPreconditionRetainsEarlierPossibleCommit(t *testing.T) {
	for _, notSent := range []bool{false, true} {
		t.Run(fmt.Sprintf("first-not-sent-%t", notSent), func(t *testing.T) {
			state, first, _, original, _ := observationPreparedSelectionForFamily(t, contract.AWS)
			ctx := gcReadContext(t)
			state, result := state.selectCandidate(ctx, first)
			if state == nil || result.Outcome != ObservedCurrent {
				t.Fatal("authenticated stored predecessor", result)
			}
			candidate, _, _ := observationPrepareNextSelection(t, state, 210000, "next value", "enabled")
			store := &selectionRejectionStore{Store: original, firstNotSent: notSent}
			state.store = store
			_, result = state.selectCandidate(ctx, candidate)
			wantOutcome, wantReason, wantStoreReason := UnresolvedCommit, WriteUncertain, contract.ReasonTransport
			if notSent {
				wantOutcome, wantReason, wantStoreReason = Contention, StalePrecondition, contract.ReasonNone
			}
			if result.Outcome != wantOutcome || result.Reason != wantReason || result.StoreReason != wantStoreReason || result.CommitMayHaveOccurred != !notSent || result.RequestedRevision != candidate.head.Core.Revision {
				t.Error("later exact rejection rewrote earlier send evidence", result)
			}
			if len(store.keys) != 2 {
				t.Fatal("recovery changed its exact send count", len(store.keys))
			}
			for i := range store.keys {
				if store.keys[i] != state.admission.store.HeadKey || store.tokens[i] != state.token || !bytes.Equal(store.bodies[i], candidate.body) {
					t.Error("conditional recovery changed frozen request", i)
				}
			}
		})
	}
}

// full_only: false
func TestGCExecutionKeepsOriginalVectorAndConditions(t *testing.T) {
	for _, name := range []string{"absence", "ack-present", "precondition", "changed"} {
		t.Run(name, func(t *testing.T) {
			state, store, input, plan, encoded := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			before, err := state.receiptWindows(ctx)
			if err != nil {
				t.Fatal(err)
			}
			key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
			reads := store.reads[key]
			if name == "ack-present" {
				store.onDelete = func(string, contract.Token) *contract.WriteResult {
					return &contract.WriteResult{Status: contract.WriteAcknowledged}
				}
			}
			if name == "precondition" || name == "changed" {
				store.onDelete = func(string, contract.Token) *contract.WriteResult {
					if name == "changed" {
						page, err := format.DecodeRecipientPage(store.objects[key])
						if err != nil {
							t.Fatal(err)
						}
						row := *page.Slots[0]
						row.DisplayName = "Changed"
						page.Slots[0] = &row
						store.objects[key], err = format.EncodeRecipientPage(page)
						if err != nil {
							t.Fatal(err)
						}
					}
					return &contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
				}
			}
			engine, _ := gcExecutionEngine(t, state, store, input)
			out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("runtime-vector"), EncodedPlan: encoded})
			if out.Payload == nil || !out.Payload.Closed || len(out.Payload.Targets) != 1 || len(store.deletes) != 1 || store.deletes[0] != (gcDeleteCall{key, plan.Targets[0].Token}) || store.reads[key]-reads != 2 {
				t.Fatal("bounded original effect inventory changed", out, store.deletes, store.reads[key]-reads)
			}
			if !reflect.DeepEqual(store.phases, []contract.GCPhase{contract.GCSelect, contract.GCReserve, contract.GCRecordProgress, contract.GCClose}) {
				t.Fatal("phase CAS inventory changed", store.phases)
			}
			token, err := GCTargetEffectToken(out.Payload.Targets[0])
			if err != nil {
				t.Fatal(err)
			}
			if name == "absence" {
				if out.StateResult != "success" || token != "succeeded" || out.Payload.RemainingCount != 0 {
					t.Fatal("qualified absence did not complete exact plan", out)
				}
			} else {
				if out.StateResult != "gc-partial-garbage" || out.Payload.RemainingCount != 1 {
					t.Fatal("ACK or condition became absence", out)
				}
				if name == "ack-present" && token != "unknown" || name != "ack-present" && token != "confirmed-no-effect" {
					t.Fatal("provider call evidence was rewritten", name, token)
				}
			}
			current := gcOpenRuntime(t, ctx, input, store)
			after, err := current.receiptWindows(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("GC created or changed receipt history", err)
			}
			if err := out.Validate(); err != nil {
				t.Fatal("complete GC result invalid", err, out)
			}
		})
	}
}

// full_only: false
func TestGCResumePreservesSpentPermissions(t *testing.T) {
	t.Run("transmitted unknown", func(t *testing.T) {
		state, store, input, plan, encoded := gcExecutionFixture(t)
		ctx := gcReadContext(t)
		store.onDelete = func(string, contract.Token) *contract.WriteResult {
			return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
		}
		engine, _ := gcExecutionEngine(t, state, store, input)
		first := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("unknown-first"), EncodedPlan: encoded})
		if first.Payload == nil || !first.Payload.Closed {
			t.Fatal(first)
		}
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
		store.onDelete = nil
		offset := len(store.phases)
		resume, _ := gcExecutionEngine(t, state, store, input)
		out := resume.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("unknown-resume"), OperationID: plan.OperationID})
		if out.Payload == nil || !out.Payload.Closed || out.Payload.Targets[0].Selected.Consumed != 1 || len(store.deletes) != 1 {
			t.Fatal("resume restored a lost transmission permission", out, store.deletes)
		}
		for _, phase := range store.phases[offset:] {
			if phase == contract.GCReserve {
				t.Fatal("matching GET invented retry witness")
			}
		}
	})
	t.Run("crash after reserve", func(t *testing.T) {
		state, store, input, plan, encoded := gcExecutionFixture(t)
		ctx := gcReadContext(t)
		state, progress := gcRuntimeSelectOnly(t, ctx, state, input, plan, encoded)
		progress.Ordinal++
		progress.Targets[0].Consumed = 1
		state = gcSelectRuntimePhase(t, ctx, state, plan, progress, contract.GCReserve)
		engine, _ := gcExecutionEngine(t, state, store, input)
		out := engine.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("lost-unentered-permission"), OperationID: plan.OperationID})
		if out.Payload == nil || !out.Payload.Closed || len(store.deletes) != 0 || out.Payload.Targets[0].Selected.Consumed != 1 || out.Payload.Targets[0].Selected.Disposition != contract.GCTargetUnknown {
			t.Fatal("crash restored or misclassified spent permission", out, store.deletes)
		}
	})
	t.Run("unused allowance after observation", func(t *testing.T) {
		state, store, input, plan, encoded := gcExecutionFixture(t)
		ctx := gcReadContext(t)
		state, _ = gcRuntimeSelectOnly(t, ctx, state, input, plan, encoded)
		key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
		store.onRead = func(actual string) *contract.ReadResult {
			if actual == key {
				return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
			}
			return nil
		}
		engine, _ := gcExecutionEngine(t, state, store, input)
		first := engine.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("unavailable-unused"), OperationID: plan.OperationID})
		if first.Payload == nil || first.Payload.Targets[0].Selected.Consumed != 0 || len(store.deletes) != 0 {
			t.Fatal(first)
		}
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
		store.onRead = nil
		next, _ := gcExecutionEngine(t, state, store, input)
		out := next.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("first-unused-later"), OperationID: plan.OperationID})
		if out.StateResult != "success" || len(store.deletes) != 1 {
			t.Fatal("unused first allowance was lost", out, store.deletes)
		}
	})
	t.Run("missing owner", func(t *testing.T) {
		state, store, input, plan, _ := gcExecutionFixture(t)
		engine, _ := gcExecutionEngine(t, state, store, input)
		out := engine.Continue(gcReadContext(t), GCContinueRequest{RequestNonce: gcTestID("missing-owner"), OperationID: plan.OperationID})
		if out.StateResult == "success" || out.StateResult == "exact-resume" || out.StateResult == "gc-partial-garbage" || out.Payload != nil || len(store.deletes) != 0 {
			t.Fatal("missing owner became historical completion", out)
		}
	})
}

// full_only: false
func TestGCRetryableNotSentRequiresLocalJoinedPermission(t *testing.T) {
	state, store, input, plan, encoded := gcExecutionFixture(t)
	ctx := gcReadContext(t)
	store.onDelete = func(string, contract.Token) *contract.WriteResult {
		return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	}
	for invocation := 1; invocation <= 4; invocation++ {
		engine, _ := gcExecutionEngine(t, state, store, input)
		var out PublicGCResult
		if invocation == 1 {
			out = engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("not-sent-first"), EncodedPlan: encoded})
		} else {
			out = engine.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID(fmt.Sprintf("not-sent-%d", invocation)), OperationID: plan.OperationID})
		}
		if out.Payload == nil || !out.Payload.Closed || out.Payload.Targets[0].Selected.Consumed != uint8(min(invocation, 3)) || len(store.deletes) != min(invocation, 3) {
			t.Fatal("cumulative allowance reset or expanded", invocation, out, store.deletes)
		}
		if invocation < 3 && (out.Payload.Targets[0].Selected.Disposition != contract.GCTargetRetryableNotSent || out.Payload.Targets[0].Selected.EvidenceDigest.IsZero()) {
			t.Fatal("joined unchanged NotSent did not retain witness", out)
		}
		if invocation >= 3 && out.Payload.Targets[0].Selected.Disposition == contract.GCTargetRetryableNotSent {
			t.Fatal("exhaustion restored repeat permission")
		}
		if err := out.Validate(); err != nil {
			t.Fatal(err, out)
		}
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// full_only: false
func TestGCConcurrentResumeCannotShareReservedPermission(t *testing.T) {
	state, store, input, plan, encoded := gcExecutionFixture(t)
	ctx := gcReadContext(t)
	state, _ = gcRuntimeSelectOnly(t, ctx, state, input, plan, encoded)
	var arrivals atomic.Int32
	release := make(chan struct{})
	store.beforeCAS = func(phase contract.GCPhase, _ []byte) {
		if phase == contract.GCReserve {
			if arrivals.Add(1) == 2 {
				close(release)
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}
	a, _ := gcExecutionEngine(t, state, store, input)
	b, _ := gcExecutionEngine(t, state, store, input)
	results := make(chan PublicGCResult, 2)
	go func() {
		results <- a.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("concurrent-a"), OperationID: plan.OperationID})
	}()
	go func() {
		results <- b.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("concurrent-b"), OperationID: plan.OperationID})
	}()
	first, second := <-results, <-results
	if len(store.deletes) != 1 || arrivals.Load() != 2 {
		t.Fatal("two resumptions shared selected allowance", store.deletes, arrivals.Load(), first, second)
	}
	successes := 0
	for _, out := range []PublicGCResult{first, second} {
		if out.StateResult == "success" {
			successes++
		}
		if err := out.Validate(); err != nil {
			t.Fatal("concurrent result invalid", err, out)
		}
	}
	if successes != 1 {
		t.Fatal("losing invocation claimed another's completion", first, second)
	}
}

// full_only: false
func TestGCClosePreservesSelectedProgressAndFailures(t *testing.T) {
	for _, failed := range []contract.GCPhase{contract.GCReserve, contract.GCRecordProgress, contract.GCClose} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			state, store, input, _, encoded := gcExecutionFixture(t)
			store.onCAS = func(phase contract.GCPhase, _ []byte) *contract.WriteResult {
				if phase == failed {
					return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
				}
				return nil
			}
			engine, _ := gcExecutionEngine(t, state, store, input)
			out := engine.ApplyPlan(gcReadContext(t), GCApplyPlanRequest{RequestNonce: gcTestID(fmt.Sprintf("close-failure-%d", failed)), EncodedPlan: encoded})
			if out.Payload == nil || len(out.Payload.Failures) != 1 || out.Payload.Failures[0].Phase != failed || out.Payload.Failures[0].Write != (contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}) {
				t.Fatal("later close lost earlier failure", out)
			}
			if failed == contract.GCClose {
				if out.Payload.Closed || out.StateResult == "success" || out.StateResult == "gc-partial-garbage" || out.EffectSummary != contract.ReceiptEffectComplete {
					t.Fatal("unselected close became completion", out)
				}
			} else {
				if !out.Payload.Closed || out.StateResult != "gc-partial-garbage" || out.Payload.RemainingCount != 1 {
					t.Fatal("known no-send phase did not close retained exact work", out)
				}
			}
			if failed == contract.GCRecordProgress && (out.Payload.Targets[0].Selected.Disposition != contract.GCTargetPending || out.Payload.Targets[0].Observed != contract.GCTargetAbsent || out.Payload.Targets[0].ObservedEvidence.IsZero()) {
				t.Fatal("volatile absence replaced selected progress", out)
			}
			if len(store.phases) > 4 {
				t.Fatal("close path expanded physical CAS budget", store.phases)
			}
			if err := out.Validate(); err != nil {
				t.Fatal(err, out)
			}
		})
	}
}

type gcBlockingDeleteStore struct {
	*gcExecutionStore
	entered, joined chan struct{}
}

func (s *gcBlockingDeleteStore) DeleteIfToken(ctx context.Context, _ string, _ contract.Token) contract.WriteResult {
	close(s.entered)
	<-ctx.Done()
	close(s.joined)
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
}

// full_only: false
func TestInstalledGCGuardChecksOriginalSourceAndLifetime(t *testing.T) {
	state, store, input, _, encoded := gcExecutionFixture(t)
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	blocked := &gcBlockingDeleteStore{gcExecutionStore: store, entered: make(chan struct{}), joined: make(chan struct{})}
	closed := make(chan struct{})
	engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
		return GCMutationResources{Store: blocked, Trust: testtrust.New(t, contract.GCP, state.admission.trust), Close: func() error {
			select {
			case <-blocked.joined:
			default:
				t.Error("resource close preceded entered-call join")
			}
			close(closed)
			return nil
		}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := gcReadContext(t)
	done := make(chan PublicGCResult, 1)
	go func() {
		done <- engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("cancel-and-join"), EncodedPlan: encoded})
	}()
	select {
	case <-blocked.entered:
	case <-ctx.Done():
		t.Fatal("GC never entered bounded delete")
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	out := <-done
	select {
	case <-closed:
	default:
		t.Fatal("installed resources did not close")
	}
	if out.StateResult == "success" || out.StateResult == "gc-partial-garbage" {
		t.Fatal("cancelled unclosed invocation claimed terminal GC", out)
	}
	if err := out.Validate(); err != nil {
		t.Fatal("cancelled joined result unrenderable", err, out)
	}
}

// full_only: false
func TestGCExecutionObservationAndEffectBounds(t *testing.T) {
	state, store, input, plan, encoded := gcExecutionFixture(t)
	key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
	calls := 0
	store.onRead = func(actual string) *contract.ReadResult {
		if actual != key {
			return nil
		}
		calls++
		if calls%3 != 0 {
			return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport, Body: []byte{1}, Token: contract.Token{Family: contract.GCP, Value: "999"}}
		}
		return nil
	}
	engine, _ := gcExecutionEngine(t, state, store, input)
	out := engine.ApplyPlan(gcReadContext(t), GCApplyPlanRequest{RequestNonce: gcTestID("physical-read-bounds"), EncodedPlan: encoded})
	if out.StateResult != "success" || calls != 6 || len(store.deletes) != 1 || len(store.phases) != 4 {
		t.Fatal("preflight/post-read owner or effect bounds expanded", calls, store.deletes, store.phases, out)
	}
	if err := out.Validate(); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestGCUnconfirmedSelectPreservesAdmissionFailureAndCommitState(t *testing.T) {
	for _, write := range []contract.WriteResult{{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, {Status: contract.WriteConflict, Reason: contract.ReasonCondition}} {
		t.Run(fmt.Sprintf("write-%d", write.Status), func(t *testing.T) {
			state, store, _, plan, _ := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			progress, err := gcInitialProgress(plan)
			if err != nil {
				t.Fatal(err)
			}
			out := gcResultForPlan(PublicGCResult{Operation: GCApplyOperation, RequestID: gcTestID("unconfirmed-select-request")}, plan, PublicObservation{DomainID: state.root.Domain, HeadRevisionID: state.head.Core.Revision, SnapshotID: state.root.Snapshot, RootDigest: state.head.Core.Root.Digest})
			signer := testtrust.New(t, contract.GCP, state.admission.trust)
			var requested contract.ID
			store.onCAS = func(phase contract.GCPhase, body []byte) *contract.WriteResult {
				if phase != contract.GCSelect {
					t.Fatal("unexpected phase", phase)
				}
				head, err := format.DecodeHead(body)
				if err != nil {
					t.Fatal(err)
				}
				requested = head.Core.Revision
				if got := store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, state.token, body); got.Status != contract.WriteAcknowledged {
					t.Fatal("fixture selection did not commit", got)
				}
				state.admission.current, state.admission.observation, state.admission.descriptor = nil, nil, nil
				return &write
			}
			step := gcAttemptPhase(ctx, state, plan, gcTestID("unconfirmed-select-admission"), contract.GCSelect, &progress, signer, &out)
			out = gcFailedPhase(out, step)
			want := Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid, RequestedRevision: requested, CommitMayHaveOccurred: true}
			if requested.IsZero() || step.confirmed || step.notSelected || step.state != nil || out.Result != want {
				t.Error("unconfirmed selection lost actual admission or commit facts", step, out.Result, want)
			}
			if err := RefreshGCResult(&out); err != nil || out.StateResult != "commit-outcome-unknown" || out.Result != want || out.Validate() != nil {
				t.Error("possible selection became a public refusal", out.StateResult, out.Result, err)
			}
			if out.Payload == nil || !out.Payload.SelectionUncertain || out.Payload.Active || out.Payload.Closed || out.Payload.ProgressOrdinal != 0 || len(out.Payload.Failures) != 1 || out.Payload.Failures[0] != (GCPhaseFailure{Phase: contract.GCSelect, Result: want, Write: write}) || out.Payload.Targets[0].PermissionOwned || out.Payload.Targets[0].DeleteAttempted {
				t.Error("unconfirmed selection changed retained phase or permission facts", out.Payload)
			}
			if len(store.phases) != 1 || len(store.deletes) != 0 {
				t.Error("unconfirmed selection retried or dispatched deletion", store.phases, store.deletes)
			}
		})
	}
}
