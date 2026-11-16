package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCCandidateGuardRequiresExactOwnerBeforeHEADRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.AWS, false)
	env.Context = ctx
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	store := newGCInterleavingStore(env.Store.(*memoryStore))
	candidate := gcInterleavingCandidate{store: store}
	reads := store.reads
	for _, owner := range []string{"", "123456789013"} {
		read := candidate.ReadHEADGuarded(ctx, owner)
		if read.Status != contract.ReadInvalid || read.Reason != contract.ReasonConstruction || len(read.Body) != 0 || read.Token != (contract.Token{}) || store.reads != reads {
			t.Fatal("wrong candidate owner reached HEAD GET or returned selected bytes", read.Status, read.Reason)
		}
	}
	read := candidate.ReadHEADGuarded(ctx, store.configuration.ExpectedOwner)
	if read.Status != contract.ReadOK || read.Reason != contract.ReasonNone || read.Token != f.session.token || contract.Hash(read.Body) != contract.Hash(f.session.body) ||
		store.reads != reads+1 || store.readCounts[store.desc.HeadKey] != 1 || len(store.deleteCalls) != 0 {
		t.Fatal("exact candidate owner did not perform one physical HEAD GET", read.Status, read.Reason)
	}
}

// full_only: false
func TestGCStateOracleRequiresExplicitSelectedOperation(t *testing.T) {
	want := testID("selected GC oracle operation")
	head := format.Head{AuthKind: format.GCAuth, GC: &contract.GCSubject{OperationID: want}}
	if actual, present := observedHeadOperation(head); !present || actual != want {
		t.Fatal("state oracle lost its exact GC operation")
	}
	head.GC = nil
	if actual, present := observedHeadOperation(head); present || !actual.IsZero() {
		t.Fatal("state oracle manufactured a GC operation without its subject")
	}
}
