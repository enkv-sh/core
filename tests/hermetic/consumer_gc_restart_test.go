package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type consumerRestartReadStore struct {
	*memoryStore
	reads    []processStoreRequest
	statuses []contract.ReadStatus
	after    func(context.Context, string, contract.ReadResult)
}

func (s *consumerRestartReadStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	result := s.memoryStore.Read(ctx, key, maximum)
	s.reads = append(s.reads, processStoreRequest{Method: "read", Key: key, Maximum: maximum})
	s.statuses = append(s.statuses, result.Status)
	// The callback can perform another Store operation before this read returns.
	result.Body = bytes.Clone(result.Body)
	s.after(ctx, key, result)
	return result
}

// full_only: false
func TestConsumerSelectionRestartsAfterUnreadChildLossAndChangedHEAD(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	env.Context = ctx
	f := newEnvironmentFixture(t, ctx, env, []int{3}, false)
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	before := sessionStateImage(t, f.session)
	input := before.entryInputs()
	input[0].InputBytes = []byte("selected after the old root was read")
	comparison, result := f.session.Compare(ctx, input, admitSuppliedComparison(t, f.session, nil, input))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("changed consumer fixture comparison", result)
	}
	permit := admit(t, f.session, comparison)
	want := expectedSuccessorImage(t, before, input, observeAllocatedTransitionInputs(permit))
	candidate, result := f.session.Prepare(ctx, comparison, permit, trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("changed consumer fixture preparation", result)
	}
	wantHEAD := bytes.Clone(candidate.body)
	oldRoot := mustKey(t, store.desc.Prefix, before.RootRef)
	oldChild := mustKey(t, store.desc.Prefix, *before.Root.ValueEntryPages[0])
	newChild := mustKey(t, store.desc.Prefix, *want.Root.ValueEntryPages[0])
	if oldRoot == mustKey(t, store.desc.Prefix, want.RootRef) || oldChild == newChild ||
		before.Revision == want.Revision || bytes.Equal(f.session.body, wantHEAD) {
		t.Fatal("fixture has no distinct selected image and unread child")
	}
	configKey, err := contract.StoreConfigurationKeyForID(store.desc.Family, store.desc.Prefix, env.Domain, store.desc.Identity)
	if err != nil {
		t.Fatal(err)
	}
	wantReads := []processStoreRequest{
		{Method: "read", Key: store.desc.HeadKey, Maximum: contract.MaxHeadLength},
		{Method: "read", Key: configKey, Maximum: contract.MaxStoreConfigurationLength},
		{Method: "read", Key: oldRoot, Maximum: before.RootRef.Length},
		{Method: "read", Key: store.desc.HeadKey, Maximum: contract.MaxHeadLength},
		{Method: "read", Key: oldChild, Maximum: before.Root.ValueEntryPages[0].Length},
	}
	newReads := publicConsumerReadRequests(t, store.desc, want)
	wantReads = append(wantReads, newReads...)
	creates, cas, signs := store.creates, store.cas, trust.signs
	public, private := env.Custody.Calls()
	originalDeadline, _ := ctx.Deadline()
	advanceEntered, advanceReturned, removed := 0, 0, 0
	var selectedToken contract.Token
	source := &consumerRestartReadStore{memoryStore: store}
	source.after = func(readContext context.Context, key string, read contract.ReadResult) {
		deadline, finite := readContext.Deadline()
		if !finite || !deadline.Equal(originalDeadline) {
			t.Fatal("consumer read replaced the original deadline")
		}
		if !consumerLoadingImageCut(source, key, oldRoot, 2) {
			return
		}
		advanceEntered++
		if advanceEntered != 1 || read.Status != contract.ReadOK || !bytes.Equal(read.Body, f.session.body) || len(source.reads) != 4 {
			t.Fatal("writer did not enter after the exact old root read")
		}
		selected := f.session.Select(ctx, candidate)
		if selected.Outcome != ObservedCurrent || selected.Evidence != AuthenticatedClosure ||
			selected.ObservedRevision != want.Revision || selected.ObservedSnapshotID != want.Root.Snapshot {
			t.Fatal("competing writer did not select and authenticate its complete image", selected)
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		head := store.objects[store.desc.HeadKey]
		if !bytes.Equal(head.Body, wantHEAD) || head.Token == f.session.token || !head.Token.Valid() {
			t.Fatal("competing writer did not change the exact authenticated HEAD")
		}
		if _, present := store.objects[oldChild]; !present {
			t.Fatal("old unread child was absent before the declared removal")
		}
		if _, present := store.objects[newChild]; !present {
			t.Fatal("new selected child is absent")
		}
		selectedToken = head.Token
		delete(store.objects, oldChild)
		removed++
		advanceReturned++
	}
	t.Cleanup(func() {
		t.Logf("consumer restart inventory: reads=%d writer_entered=%d writer_returned=%d old_children_removed=%d creates=%d cas=%d signs=%d",
			len(source.reads), advanceEntered, advanceReturned, removed, store.creates-creates, store.cas-cas, trust.signs-signs)
		for i, read := range source.reads {
			t.Logf("consumer read: ordinal=%d key_digest=%x maximum=%d status=%d", i, contract.Hash([]byte(read.Key)), read.Maximum, source.statuses[i])
		}
		if advanceEntered != 1 || advanceReturned != 1 || removed != 1 || store.creates != creates || store.cas != cas+1 || trust.signs != signs {
			t.Error("consumer or competing writer did not retain its exact joined effect inventory")
		}
		if gotPublic, gotPrivate := env.Custody.Calls(); gotPublic != public || gotPrivate != private {
			t.Error("public consumer selection entered private custody")
		}
	})
	env.Store = source
	acting := f.session.admission.recipient
	selection := fixtureConsumerSelection(t, ctx, env, acting, input[0].Name)
	entry := *want.Pages[0].Slots[0]
	entryDigest, err := contract.PublicValueEntryDigest(env.Domain, 0, entry)
	if err != nil {
		t.Fatal("independent expected consumer entry", err)
	}
	wantSelection := contract.ConsumerSelection{
		DomainID: env.Domain, SnapshotID: want.Root.Snapshot, HEADDigest: contract.Hash(wantHEAD),
		AccessRoot: want.Root.CurrentAccess.AccessRoot, EntryDigest: entryDigest, Root: want.RootRef,
		HEADRevision: want.Revision, HEADToken: selectedToken, Slot: 0, Entry: entry,
		Binding: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: acting, Binding: *f.session.recipientRecord(acting).CurrentBinding},
	}
	if !reflect.DeepEqual(selection, wantSelection) {
		t.Fatal("consumer returned an old or mixed selection after unread child loss")
	}
	if !reflect.DeepEqual(source.reads, wantReads) || source.statuses[4] != contract.ReadMissing {
		t.Fatal("consumer did not reuse one changed-HEAD gate for one complete replacement image")
	}
}
