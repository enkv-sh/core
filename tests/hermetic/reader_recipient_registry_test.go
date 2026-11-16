package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// Sign a complete current image without cold state admission. This isolates
// Reader authentication from the mutation owner's independent registry checks.
func readerChangedRegistryFixture(t *testing.T, ctx context.Context, env fixtureEnvironment, before *StateSession, signer contract.Trust, add bool, sparse ...bool) *StateSession {
	t.Helper()
	current := *before
	current.root.Snapshot = fixtureID(env.Domain, fmt.Sprint("registry snapshot ", add))
	current.root.Transition = fixtureID(env.Domain, fmt.Sprint("registry transition ", add))
	page := *before.recipients[0]
	page.Object = fixtureID(env.Domain, fmt.Sprint("registry page ", add))
	reader := fixtureID(env.Domain, "reader")
	found := false
	for index, row := range page.Slots {
		if row == nil || row.RecipientID != reader {
			continue
		}
		owned := *row
		owned.DisplayName = "current display metadata"
		page.Slots[index] = &owned
		found = true
	}
	if !found {
		t.Fatal("fixture reader absent")
	}
	if add {
		for index, row := range page.Slots {
			if row == nil {
				binding := *selectedRecipientRecord(&before.recipients, reader).CurrentBinding
				binding.BindingID = fixtureID(env.Domain, "new registry binding")
				binding.BindingIncarnationID = fixtureID(env.Domain, "new registry binding incarnation")
				page.Slots[index] = &contract.RecipientRecord{RecipientID: fixtureID(env.Domain, "new unassigned recipient"), Status: contract.CurrentRecipient, DisplayName: "unassigned recipient", CurrentBinding: &binding}
				current.root.RecipientCount++
				break
			}
		}
		// Physical slots are independent of enrollment declaration order.
		for i := range page.Slots {
			for j := i + 1; j < len(page.Slots); j++ {
				if page.Slots[j] != nil && (page.Slots[i] == nil || bytes.Compare(page.Slots[i].RecipientID[:], page.Slots[j].RecipientID[:]) > 0) {
					page.Slots[i], page.Slots[j] = page.Slots[j], page.Slots[i]
				}
			}
		}
	}
	if len(sparse) == 1 && sparse[0] {
		var rows []*contract.RecipientRecord
		for _, row := range page.Slots {
			if row != nil {
				rows = append(rows, row)
			}
		}
		if len(rows) != 2 {
			t.Fatal("sparse registry fixture requires two rows")
		}
		page.Slots = [format.RecipientSlots]*contract.RecipientRecord{5: rows[0], 7: rows[1]}
	}
	pageBody, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal("changed registry encoding", err)
	}
	ref, err := format.Reference(format.RecipientKind, env.Domain, page.Object, page.Index, pageBody)
	if err != nil {
		t.Fatal(err)
	}
	current.recipients[0], current.recipient = &page, page
	current.root.Recipients[0] = &ref
	refreshFixtureRecipientRefs(t, &current.root)
	current.recountChildren()
	store := env.Store.(*memoryStore)
	store.put(mustKey(t, store.desc.Prefix, ref), pageBody)
	rootBody, err := format.EncodeRoot(current.root)
	if err != nil {
		t.Fatal("changed registry root", err)
	}
	rootRef, err := format.Reference(format.RootKind, env.Domain, current.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	store.put(mustKey(t, store.desc.Prefix, rootRef), rootBody)
	head := before.head
	if head.AuthKind != format.LifecycleAuth {
		t.Fatal("changed registry requires an ordinary lifecycle fixture")
	}
	head.Core.Root = rootRef
	head.Core.Revision = fixtureID(env.Domain, fmt.Sprint("registry revision ", add))
	head.Core.PreviousRevision, head.Core.PreviousDigest, head.Core.PreviousToken = before.head.Core.Revision, contract.Hash(before.body), before.token
	head.Subject.Operation = fixtureID(env.Domain, fmt.Sprint("registry operation ", add))
	head.Subject.BeforeAccessRoot, head.Subject.AfterAccessRoot = before.root.CurrentAccess.AccessRoot, current.root.CurrentAccess.AccessRoot
	head.Subject.Normal.PublicState = current.publicState()
	if head.Subject.Normal.PublicState.Digest.IsZero() {
		t.Fatal("changed registry has no complete public-state commitment")
	}
	head.Subject.Request = requestCommitment(head.Core, head.Subject)
	core, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := format.EncodeConditionalPlan(conditional(head.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength, head.Subject.ConditionalPlan = contract.Hash(core), uint32(len(core)), contract.Hash(plan)
	request, err := contract.NewLifecycleRequest(head.Subject)
	if err != nil {
		t.Fatal(err)
	}
	proof := signer.Sign(ctx, request)
	if proof.Reason != contract.ReasonNone || len(proof.Signature) == 0 {
		t.Fatal("changed registry signing", proof.Reason)
	}
	head.AuthorizationSignature = proof.Signature
	current.body, err = format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store.put(store.desc.HeadKey, current.body)
	current.head, current.token = head, store.objects[store.desc.HeadKey].Token
	return &current
}

// full_only: false
func TestReaderHistoricalBasisPermitsAuthenticatedRegistryChanges(t *testing.T) {
	for _, successor := range []bool{false, true} {
		for _, add := range []bool{false, true} {
			t.Run(fmt.Sprintf("successor=%t/add=%t", successor, add), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				env, keys := genesisEnvironment(t, contract.GCP, true)
				f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
				before, basis := f.session, readerTypedBasisFixture(t, f.session)
				signer := env.Trust
				if successor {
					env = syntheticAuthorityScenarioEnvironment(t, env)
					selected, _ := selectReaderSuccessionFixture(t, ctx, env, before, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
					basis = readerTypedBasisFixture(t, selected)
					reader := fixtureID(env.Domain, "reader")
					binding := keys.RecipientSuccessor(t, reader)
					permit := admitReaderReplacement(t, selected, keys, reader, binding)
					signer = testtrust.NewCurrent(t, currentControlOf(selected).NormalSigning)
					candidate, result := selected.PrepareRecipientReplacement(ctx, permit, signer)
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("ordinary successor fixture", result)
					}
					before, result = selected.selectCandidate(ctx, candidate)
					if before == nil || result.Outcome != ObservedCurrent {
						t.Fatal("ordinary successor selection", result)
					}
				}
				current := readerChangedRegistryFixture(t, ctx, env, before, signer, add)
				engine, _, source := readerEngineWithPublicBasisFixture(t, env, current, basis)
				defer readerCapacityNoEffects(t, env)()
				inv := readerInvocationFixture(t, engine, ctx)
				selected, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
				if result.Outcome != 0 || !selected.complete {
					t.Fatal("historical public enrollment rejected authenticated current registry", result)
				}
				wantCount := 2
				if add {
					wantCount++
				}
				rows := selectedRecipientRegistry(&selected.image.recipients, selected.image.root.RecipientCount)
				if len(rows) != wantCount || selected.image.recipientRecord(fixtureID(env.Domain, "reader")).DisplayName != "current display metadata" {
					t.Fatal("selected registry lost exact current rows", rows)
				}
				inv.Close()
				if source.closes != 1 {
					t.Fatal("registry read owner did not close exactly once", source.closes)
				}
				registry := engine.ReadRecipientRegistry(ctx, contract.Hash([]byte("changed authenticated registry")))
				if registry.Registry == nil || registry.StateResult != contract.ReaderSuccess || registry.Registry.SnapshotID != current.root.Snapshot || !reflect.DeepEqual(registry.Registry.Recipients, selectedRecipientRegistry(&current.recipients, current.root.RecipientCount)) || source.closes != 2 {
					t.Fatal("registry operation did not expose the complete changed current registry", registry)
				}
			})
		}
	}
}

// full_only: false
func TestReaderRecipientRegistryOwnsCompleteSelectedRows(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	engine, _, source := readerEngineFixture(t, env, f.session)
	defer readerCapacityNoEffects(t, env)()
	want := selectedRecipientRegistry(&f.session.recipients, f.session.root.RecipientCount)
	request := contract.Hash([]byte("complete public recipient registry"))
	got := engine.ReadRecipientRegistry(ctx, request)
	if got.StateResult != contract.ReaderSuccess || got.Result.Outcome != ObservedCurrent || got.Result.Evidence != AuthenticatedClosure || got.FailureReason != "" || got.Registry == nil {
		t.Fatal("complete registry was not returned", got)
	}
	if got.Context.Operation != contract.ReaderRecipientsOperation || got.Context.RequestID != request || got.Context.ExpectedDomain != env.Domain || got.Context.OperationID.IsZero() || got.Registry.DomainID != env.Domain || got.Registry.SnapshotID != f.session.root.Snapshot || got.Registry.AuthorityRecipientID != f.session.root.CurrentAccess.Core.AuthorityRecipientID || !reflect.DeepEqual(got.Registry.Recipients, want) || cap(got.Registry.Recipients) != len(want) || source.closes != 1 {
		t.Fatal("registry lost exact selected identity, rows or ownership", got)
	}
	got.Registry.Recipients[0].CurrentBinding.SPKI[0] ^= 1
	got.Registry.Recipients[0].DisplayName = "caller mutation"
	again := engine.ReadRecipientRegistry(ctx, request)
	if again.Registry == nil || !reflect.DeepEqual(again.Registry.Recipients, want) || source.closes != 2 {
		t.Fatal("caller mutation changed a later authenticated registry", again)
	}
	engine.Close()
	if !reflect.DeepEqual(again.Registry.Recipients, want) {
		t.Fatal("Reader close changed caller-owned registry")
	}
}

// full_only: false
func TestReaderRecipientRegistryRefusesIncompleteSelection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	for _, name := range []string{"nil engine", "nil context", "zero request", "unbounded", "expired", "cancelled", "closed", "head", "root", "selected cancellation", "late child"} {
		t.Run(name, func(t *testing.T) {
			engine, candidate, source := readerEngineFixture(t, env, f.session)
			request, readctx := contract.ID{8}, ctx
			want := contract.ReasonInvalidInput
			wantState := contract.ReaderRefused
			reads := false
			switch name {
			case "nil engine":
				engine = nil
			case "nil context":
				readctx = nil
			case "zero request":
				request = contract.ID{}
			case "unbounded":
				readctx, want = context.Background(), contract.ReasonExpired
			case "expired":
				var stop context.CancelFunc
				readctx, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				want = contract.ReasonExpired
			case "cancelled":
				var stop context.CancelFunc
				readctx, stop = context.WithCancel(ctx)
				stop()
				want = contract.ReasonCancelled
			case "closed":
				engine.Close()
			case "head":
				candidate.head.Body = []byte("malformed HEAD")
				want, wantState, reads = contract.ReasonHeadInvalid, contract.ReaderPositiveDefect, true
			case "root":
				candidate.root.Body = bytes.Clone(candidate.root.Body)
				candidate.root.Body[len(candidate.root.Body)-1] ^= 1
				want, wantState, reads = contract.ReasonSelectedObjectInvalid, contract.ReaderPositiveDefect, true
			case "selected cancellation":
				var stop context.CancelFunc
				readctx, stop = context.WithCancel(ctx)
				defer stop()
				store := env.Store.(*memoryStore)
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					if key != store.desc.HeadKey {
						stop()
					}
					return read
				}
				defer func() { store.readHook = nil }()
				want, reads = contract.ReasonCancelled, true
			case "late child":
				source.missingKey = readerFixtureKey(t, source.descriptor.Prefix, f.session.root.RequiredSupport[len(f.session.root.RequiredSupport)-1])
				want, wantState, reads = contract.ReasonSelectedObjectUnavailable, contract.ReaderUnavailable, true
			}
			got := engine.ReadRecipientRegistry(readctx, request)
			if got.Registry != nil || got.StateResult != wantState || got.FailureReason != want {
				t.Fatal("incomplete selection returned registry or wrong failure", got)
			}
			if !reads && (len(candidate.calls) != 0 || source.reads != 0) {
				t.Fatal("invalid registry call reached Store")
			}
		})
	}
}
