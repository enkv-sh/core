package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedProviderReleaseStore struct {
	*memoryStore
	provider contract.Store
	key      string
	reads    int
	deletes  int
}

func (s *generatedProviderReleaseStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if key != s.key {
		return s.memoryStore.Read(ctx, key, limit)
	}
	s.reads++
	return s.provider.Read(ctx, key, limit)
}

func (s *generatedProviderReleaseStore) DeleteIfToken(ctx context.Context, key string, token contract.Token) contract.WriteResult {
	s.deletes++
	return s.provider.(contract.ConditionalDeleteStore).DeleteIfToken(ctx, key, token)
}

// The selected canonical state stays in the memory Store. Only the obsolete
// inbox read and conditional delete use the actual provider adapter.
func checkGeneratedProviderRelease(t *testing.T, operationCtx context.Context, family contract.Family, clean bool,
	provider func(domain contract.ID, prefix, key string, body []byte) contract.Store) {
	t.Helper()
	s, attempt, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
	admitted := generatedLifecycleFixtureForFamily(t, s, family)
	base, trust := generatedLifecycleSelectionFixture(t, s)
	key, err := format.GeneratedResultKey(base.desc.Prefix, release.DomainID, release.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	adapter := provider(release.DomainID, base.desc.Prefix, key, attempt.result)
	if adapter == nil || adapter.Descriptor().Family != family {
		t.Fatal("provider adapter has the wrong family")
	}
	if _, ok := adapter.(contract.ConditionalDeleteStore); !ok {
		t.Fatal("provider adapter lacks conditional delete")
	}
	store := &generatedProviderReleaseStore{memoryStore: base, provider: adapter, key: key}
	s.store = store
	permit, err := s.admitGeneratedInboxRelease(context.Background(), release.InboxID, admitted)
	wantKind := generatedLifecycleInboxReleaseUnknown
	if clean {
		wantKind = generatedLifecycleInboxRelease
	}
	if err != nil || permit == nil || permit.plan.kind != wantKind || store.reads != 1 || store.deletes != 1 {
		t.Fatalf("provider fact did not reach Core: permit=%t err=%v reads=%d deletes=%d", permit != nil, err, store.reads, store.deletes)
	}
	candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent || trust.signs != 1 {
		t.Fatal("provider release preparation", prepared)
	}
	next, selected := s.selectCandidate(context.Background(), candidate)
	if next == nil || selected.Outcome != ObservedCurrent {
		t.Fatal("provider release selection", selected)
	}
	reopened := generatedLifecycleReopen(t, operationCtx, next, store)
	work, err := reopened.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("provider release cold reopen", err)
	}
	retained, present := work.releases[attempt.record.AttemptID]
	if clean {
		if present || work.hasRecord(generatedRecordKey{kind: 12, id: release.InboxID}) {
			t.Fatal("qualified provider completion retained the obsolete handoff")
		}
	} else if !present || retained.release.State != contract.GeneratedReleaseUnknown ||
		retained.release.InboxID != release.InboxID || retained.release.SelectedHandoffDigest != release.SelectedHandoffDigest {
		t.Fatal("unknown provider completion lost the exact release obligation")
	}
}
