package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) lifecycleAuthority(ctx context.Context, c *Comparison, p transitionPlan) (lifecycleAuthority, error) {
	next, err := s.deriveSuccessor(ctx, c, p)
	if err != nil {
		return lifecycleAuthority{}, err
	}
	return s.authorityFrom(next, c, p)
}

func (s *StateSession) buildSuccessor(ctx context.Context, c *Comparison, p transitionPlan) (*Candidate, Result) {
	next, err := s.deriveSuccessor(ctx, c, p)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	authority, err := s.authorityFrom(next, c, p)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	return s.encodeSuccessor(ctx, next, p, authority, c)
}

func mustKey(t testing.TB, prefix string, ref format.Ref) string {
	t.Helper()
	key, err := format.Key(prefix, ref)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func storeHead(t testing.TB, f *fixture, h format.Head, resign bool) {
	t.Helper()
	coreBytes, err := format.EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	planBytes, err := format.EncodeConditionalPlan(conditional(h.Core, coreBytes))
	if err != nil {
		t.Fatal(err)
	}
	h.Subject.HeadCore, h.Subject.HeadCoreLength = contract.Hash(coreBytes), uint32(len(coreBytes))
	h.Subject.ConditionalPlan = contract.Hash(planBytes)
	if resign {
		request, err := contract.NewLifecycleRequest(h.Subject)
		if err != nil {
			t.Fatalf("fixture lifecycle request: %v", err)
		}
		h.AuthorizationSignature = f.trust.Sign(context.Background(), request).Signature
	}
	body, err := format.EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	f.store.put(f.store.desc.HeadKey, body)
}

func historyIDs(original stateImage) map[contract.ID]bool {
	seen := map[contract.ID]bool{original.Revision: true, original.Operation: true, original.Root.Snapshot: true, original.Root.Transition: true}
	for _, page := range original.Pages {
		if page != nil {
			seen[page.Object] = true
			for _, entry := range page.Slots {
				if entry != nil {
					seen[entry.ValueState] = true
					seen[entry.Incarnation] = true
				}
			}
		}
	}
	return seen
}

func assertFreshAllocatedIDs(t testing.TB, seen map[contract.ID]bool, inputs allocatedTransitionInputs) {
	t.Helper()
	ids := []contract.ID{inputs.revision, inputs.operation, inputs.snapshot, inputs.transition}
	for _, id := range inputs.valueEntryPages {
		if !id.IsZero() {
			ids = append(ids, id)
		}
	}
	for _, pages := range [][contract.MaxChildPages]contract.ID{inputs.accessPages, inputs.supportPages} {
		for _, id := range pages {
			if !id.IsZero() {
				ids = append(ids, id)
			}
		}
	}
	for _, id := range inputs.recipientPages {
		if !id.IsZero() {
			ids = append(ids, id)
		}
	}
	for _, id := range inputs.values {
		ids = append(ids, id)
	}
	for _, id := range inputs.incarnations {
		ids = append(ids, id)
	}
	for _, id := range ids {
		if id.IsZero() || seen[id] {
			t.Fatal("new transition reused an identity from this history")
		}
		seen[id] = true
	}
}
