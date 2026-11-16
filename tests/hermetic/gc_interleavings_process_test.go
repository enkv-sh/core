package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type processGCFacts struct {
	EncodedPlan  []byte
	OperationID  contract.ID
	RequestNonce contract.ID
}

type processGCReader struct{ store *processStore }

func (*processGCReader) Close()                            {}
func (r *processGCReader) Descriptor() contract.Descriptor { return r.store.Descriptor() }
func (r *processGCReader) StoreConfiguration() contract.StoreConfiguration {
	return r.store.StoreConfiguration()
}
func (r *processGCReader) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	return r.store.Read(ctx, key, maximum)
}
func (r *processGCReader) ListPage(ctx context.Context, cursor string) contract.ListPageResult {
	return r.store.ListPage(ctx, cursor)
}

func processGCChild(t *testing.T, role string, store *processStore, facts processStoreFacts) {
	t.Helper()
	apply := strings.HasPrefix(role, "gc-apply-")
	continuation := strings.HasPrefix(role, "gc-continue-")
	if apply == continuation || facts.GC.OperationID.IsZero() || facts.GC.RequestNonce.IsZero() || apply != (len(facts.GC.EncodedPlan) != 0) {
		t.Fatal("process GC request does not match its exact role")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	admitted := processPublicAdmission(facts.Domain, facts.Trust, facts.Descriptor, facts.PublicKey, facts.DomainBasis)
	reader, err := NewInstalledCapacityReader(CapacityReadInstallation{
		Candidate: gcInterleavingCandidate{store: store},
		Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicCapacityReader, Result) {
			if configuration != facts.Configuration {
				return nil, refused(ConstructionMismatch)
			}
			return &processGCReader{store: store}, Result{}
		}, ExpectedDomain: facts.Domain, ExpectedStore: facts.Descriptor, PublicBasis: admitted.admission.publicBasis(),
		SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() {},
	})
	if err != nil {
		t.Fatal("process GC public reader", err)
	}
	engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: admitted.admission.composition,
		ConstructMutation: func(context.Context) (GCMutationResources, error) {
			return GCMutationResources{Store: store, Trust: testtrust.New(t, facts.Descriptor.Family, facts.Trust), Close: func() error { return nil }}, nil
		}})
	if err != nil {
		reader.Close()
		t.Fatal("process GC engine", err)
	}
	var result PublicGCResult
	if apply {
		result = engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: facts.GC.RequestNonce, EncodedPlan: facts.GC.EncodedPlan})
	} else {
		result = engine.Continue(ctx, GCContinueRequest{RequestNonce: facts.GC.RequestNonce, OperationID: facts.GC.OperationID})
	}
	if err := engine.Close(); err != nil {
		t.Fatal("process GC operation did not join", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatal("process GC returned invalid evidence", err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	store.call(processStoreRequest{Method: "gc-finished", Body: body})
}

func serveGCProcess(t *testing.T, child *processStoreChild, store *gcInterleavingStore, plan contract.GCPlan, cut string) (*PublicGCResult, error) {
	t.Helper()
	if len(plan.Targets) != 1 {
		return nil, errors.New("process GC requires one original target")
	}
	target := plan.Targets[0]
	targetKey, err := contract.StoreObjectKey(store.desc.Prefix, plan.DomainID, target.Object)
	if err != nil {
		return nil, err
	}
	for {
		request, err := child.next()
		if err != nil {
			return nil, err
		}
		if request.Method == "gc-finished" {
			if cut != "" || request.Key != "" || request.Maximum != 0 || request.Token != (contract.Token{}) || request.Cursor != "" || len(request.Body) == 0 {
				return nil, errors.New("process GC completed without its required cut")
			}
			var result PublicGCResult
			decoder := json.NewDecoder(bytes.NewReader(request.Body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&result); err != nil {
				return nil, err
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				return nil, errors.New("process GC result contains trailing data")
			}
			if err := result.Validate(); err != nil {
				return nil, err
			}
			if err := child.reply(processStoreReply{}); err != nil {
				return nil, err
			}
			return &result, nil
		}
		var phase contract.GCPhase
		switch request.Method {
		case "read", "create":
			if request.Key == store.desc.HeadKey {
				if request.Method != "read" || request.Maximum != contract.MaxHeadLength {
					return nil, errors.New("process GC used an invalid HEAD read")
				}
			} else {
				object, err := contract.ParseStoreObjectKey(store.desc.Prefix, plan.DomainID, request.Key)
				if err != nil || request.Method == "read" && request.Maximum > contract.StoreObjectLimit(object) ||
					request.Method == "create" && (!gcObjectBytesValid(plan.DomainID, store.desc, object, request.Body) || request.Key == targetKey) {
					return nil, errors.New("process GC left its exact typed object scope")
				}
			}
		case "cas":
			head, err := format.DecodeHead(request.Body)
			if err != nil || head.GC == nil || head.GC.OperationID != plan.OperationID || request.Key != store.desc.HeadKey {
				return nil, errors.New("process GC selected another operation or selector")
			}
			phase = head.GC.Phase
		case "delete":
			if request.Key != targetKey || request.Token != target.Token {
				return nil, errors.New("process GC changed its original delete condition")
			}
		default:
			return nil, errors.New("process GC relisted or used an unadmitted method")
		}
		reply, err := processStoreOperation(store, request, false)
		if err != nil {
			return nil, err
		}
		matched := cut == "delete" && request.Method == "delete" ||
			cut == "select" && phase == contract.GCSelect ||
			cut == "reserve" && phase == contract.GCReserve ||
			cut == "progress" && phase == contract.GCRecordProgress ||
			cut == "close" && phase == contract.GCClose
		if matched {
			if reply.Write.Status != contract.WriteAcknowledged {
				return nil, errors.New("process GC did not reach a confirmed physical cut")
			}
			child.trace = append(child.trace, "validated GC cut: "+cut)
			return nil, nil
		}
		if err := child.reply(reply); err != nil {
			return nil, err
		}
	}
}

// full_only: false
func TestGCProcessLossRetainsOriginalVectorAndConsumedAllowance(t *testing.T) {
	for _, cut := range []string{"select", "reserve", "delete", "progress", "close"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			env := memoryScenarioEnvironment(t)
			env.Context = ctx
			store := newGCInterleavingStore(env.Store.(*memoryStore))
			env.Store = store
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			before := sessionStateImage(t, f.session)
			comparison := changed(t, f.session, 0)
			candidate, result := f.session.Prepare(ctx, comparison, admit(t, f.session, comparison), env.Trust)
			if candidate == nil {
				t.Fatal("process GC obsolete candidate", result)
			}
			targetKey := gcInterleavingCandidateKey(t, store.desc, candidate, contract.ValueEntryPageKind)
			plan, encoded := gcInterleavingPreview(t, ctx, f.session, store, []string{targetKey}, "process "+cut)
			if len(plan.Targets) != 1 {
				t.Fatal("process GC has no exact original target")
			}
			facts := processStoreFacts{Domain: env.Domain, Trust: env.Trust.Identity(), Descriptor: store.desc, Configuration: store.configuration,
				PublicKey: bytes.Clone(env.PublicKey), DomainBasis: bytes.Clone(f.session.admission.descriptor), ExpectedImage: before,
				GC: &processGCFacts{EncodedPlan: encoded, OperationID: plan.OperationID, RequestNonce: fixtureID(env.Domain, cut+" child apply")}}
			directory := processStoreDiagnostics(t)
			child := startProcessStoreChild(t, directory, "gc-apply-"+cut, facts)
			if completed, err := serveGCProcess(t, child, store, plan, cut); err != nil || completed != nil {
				t.Fatal("process GC did not reach its declared physical cut", err)
			}
			if err := child.stop(); err != nil || !child.joined {
				t.Fatal("process GC kill did not positively join", err)
			}
			current := gcInterleavingCurrent(t, ctx, f.admission, store)
			wantConsumed, wantDeletes := uint8(1), 1
			switch cut {
			case "select":
				wantConsumed, wantDeletes = 0, 0
			case "reserve":
				wantDeletes = 0
			}
			if cut != "close" {
				retained, progress, err := current.selectedGCPlan(plan.OperationID)
				if err != nil || current.root.ActiveGC != plan.OperationID || progress.Targets[0].Consumed != wantConsumed || len(retained.Targets) != 1 || retained.Targets[0] != plan.Targets[0] {
					t.Fatal("process loss changed the original vector or spent allowance", err)
				}
				if cut == "progress" && progress.Targets[0].Disposition != contract.GCTargetAbsent || cut != "progress" && progress.Targets[0].Disposition != contract.GCTargetPending {
					t.Fatal("process loss invented selected progress")
				}
			} else if !current.root.ActiveGC.IsZero() || current.root.GCPlans.Count != 0 {
				t.Fatal("confirmed close did not remove its fully absent obligation")
			}
			if len(store.deleteCalls) != wantDeletes {
				t.Fatal("pre-restart physical delete count differs", len(store.deleteCalls), wantDeletes)
			}
			facts.ExpectedImage = sessionStateImage(t, current)
			facts.GC = &processGCFacts{OperationID: plan.OperationID, RequestNonce: fixtureID(env.Domain, cut+" child continue")}
			resumer := startProcessStoreChild(t, directory, "gc-continue-"+cut, facts)
			resumed, err := serveGCProcess(t, resumer, store, plan, "")
			if err != nil || resumed == nil {
				t.Fatal("fresh GC process did not return complete evidence", err)
			}
			if err := resumer.join(); err != nil || !resumer.joined {
				t.Fatal("fresh GC process did not positively join", err)
			}
			switch cut {
			case "reserve":
				if resumed.StateResult != "gc-partial-garbage" || resumed.Payload == nil || resumed.Payload.Active || !resumed.Payload.Closed ||
					resumed.Payload.Targets[0].Selected.Consumed != 1 || resumed.Payload.Targets[0].Selected.Disposition != contract.GCTargetUnknown || len(store.deleteCalls) != 0 {
					t.Fatal("restart restored a lost reserved permission", resumed.Result)
				}
			case "close":
				if resumed.StateResult == "success" || resumed.Payload != nil || len(store.deleteCalls) != 1 {
					t.Fatal("owner absence reconstructed historical success", resumed.Result)
				}
			default:
				if resumed.StateResult != "success" || resumed.Payload == nil || !resumed.Payload.Closed || resumed.Payload.RemainingCount != 0 ||
					resumed.Payload.Targets[0].Selected.Consumed != 1 || len(store.deleteCalls) != 1 {
					t.Fatal("fresh process did not settle the exact original obligation", resumed.Result)
				}
			}
			for _, call := range store.deleteCalls {
				if call.key != targetKey || call.token != plan.Targets[0].Token {
					t.Fatal("fresh process substituted a delete target or condition")
				}
			}
			current = gcInterleavingCurrent(t, ctx, f.admission, store)
			if !bytes.Equal(current.valueEntry(0).ValueBytes, before.Pages[0].Slots[0].ValueBytes) ||
				current.root.Generated.SuccessWindow != before.Root.Generated.SuccessWindow || current.root.Generated.FailureWindow != before.Root.Generated.FailureWindow || current.root.Generated.ReceiptOrder != before.Root.Generated.ReceiptOrder {
				t.Fatal("GC process loss changed current values or retained receipt commitments")
			}
			t.Logf("GC process cut=%s joined=true resumed_joined=true deletes=%d phases=%v", cut, len(store.deleteCalls), store.phases)
		})
	}
}
