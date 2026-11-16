package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestInvalidReturnedProofCannotSelect(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	f.trust.corrupt = true
	c := changed(t, f.session, 0)
	if candidate, r := f.session.Prepare(context.Background(), c, admit(t, f.session, c), f.trust); candidate != nil || r.Outcome != IntegrityFailure || f.store.cas != 0 {
		t.Fatal(r)
	}
}

// full_only: false
func TestLaterValidSelectionDoesNotResolveLostReply(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	candidate := prepare(t, f, changed(t, f.session, 0))
	old := f.store.objects[f.store.desc.HeadKey]
	f.store.put(f.store.desc.HeadKey, candidate.body)
	laterSession, r := Open(context.Background(), f.admission, f.store)
	if laterSession == nil {
		t.Fatal(r)
	}
	c := changed(t, laterSession, 0)
	later, r := laterSession.Prepare(context.Background(), c, admit(t, laterSession, c), f.trust)
	if later == nil {
		t.Fatal(r)
	}
	f.store.objects[f.store.desc.HeadKey] = old
	f.store.casMode = "lost-after"
	f.store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
		if key == f.store.desc.HeadKey {
			f.store.put(key, later.body)
			v := f.store.objects[key]
			return contract.ReadResult{Status: contract.ReadOK, Body: v.Body, Token: v.Token}
		}
		return r
	}
	r = f.session.Select(context.Background(), candidate)
	if r.Outcome != UnresolvedCommit || !r.CommitMayHaveOccurred || r.ObservedRevision != later.head.Core.Revision || r.Evidence != AuthenticatedClosure {
		t.Fatal(r)
	}
}

// full_only: false
func TestRandomizedProofsKeepSemanticWinner(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	candidate := prepare(t, f, changed(t, f.session, 0))
	h := candidate.head
	k1, _ := contract.NewBindingRequest(binding(f.session.admission))
	k2, _ := contract.NewLifecycleRequest(h.Subject)
	h.K1 = f.trust.Sign(context.Background(), k1).Signature
	h.AuthorizationSignature = f.trust.Sign(context.Background(), k2).Signature
	body, err := format.EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	f.store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
		if key == f.store.desc.HeadKey {
			f.store.put(key, body)
			v := f.store.objects[key]
			r.Body, r.Token = v.Body, v.Token
		}
		return r
	}
	if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent || r.ObservedRevision != candidate.head.Core.Revision {
		t.Fatal(r)
	}
}
