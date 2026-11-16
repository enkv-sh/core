package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedInboxDeleteStore struct {
	descriptor  contract.Descriptor
	read        contract.ReadResult
	deleted     contract.WriteResult
	deleteKey   string
	deleteToken contract.Token
	readCalls   int
	deleteCalls int
	waitRead    bool
	selected    contract.Store
	inboxKey    string
}

func (s *generatedInboxDeleteStore) Descriptor() contract.Descriptor { return s.descriptor }
func (s *generatedInboxDeleteStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if s.selected != nil && key != s.inboxKey {
		// Selected closure reads must finish before the inbox effect read.
		return s.selected.Read(ctx, key, limit)
	}
	s.readCalls++
	if s.waitRead {
		<-ctx.Done()
	}
	return s.read
}
func (s *generatedInboxDeleteStore) Create(context.Context, string, []byte) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused}
}

// full_only: false
func TestGeneratedInboxReleaseDoesNotStartDeleteAfterAdmissionExpiry(t *testing.T) {
	s, attempt, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
	admitted := generatedLifecycleFixture(t, s)
	descriptor := s.admission.store
	descriptor.Prefix, descriptor.HeadKey = "fixture", "fixture/HEAD"
	s.admission.store = descriptor
	s.admission.composition, s.admission.expires = generatedVectorID(244), time.Now().Add(time.Minute)
	inboxKey, err := format.GeneratedResultKey(descriptor.Prefix, release.DomainID, release.InboxID)
	if err != nil {
		t.Fatal("exact inbox deadline coordinate", err)
	}
	token := contract.Token{Family: descriptor.Family, Value: `"inbox-etag"`}
	store := &generatedInboxDeleteStore{descriptor: descriptor, waitRead: true, selected: s.store, inboxKey: inboxKey,
		read:    contract.ReadResult{Status: contract.ReadOK, Body: attempt.result, Token: token},
		deleted: contract.WriteResult{Status: contract.WriteAcknowledged}}
	s.store = store
	if !s.admission.valid(store) {
		t.Fatal("release deadline fixture admission is invalid")
	}
	// Leave time for the required successor qualification, then let the
	// exact inbox read wait until the real admitted deadline has expired.
	admitted.Expiry = uint64(time.Now().Add(time.Second).UnixNano())
	if plan, err := s.generatedInboxReleasePlan(context.Background(), release.InboxID, admitted); err == nil || plan != nil || store.readCalls != 1 || store.deleteCalls != 0 {
		t.Fatal("expired release admission did not stop after the inbox read", err, store.readCalls, store.deleteCalls)
	}
}
func (s *generatedInboxDeleteStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused}
}
func (s *generatedInboxDeleteStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused}
}
func (s *generatedInboxDeleteStore) DeleteIfToken(_ context.Context, key string, token contract.Token) contract.WriteResult {
	s.deleteCalls++
	s.deleteKey, s.deleteToken = key, token
	return s.deleted
}

// full_only: false
func TestGeneratedInboxDeleteRequiresExactObservedHandoff(t *testing.T) {
	for _, state := range []uint8{contract.GeneratedReleasePending, contract.GeneratedReleaseUnknown} {
		for _, tc := range []struct {
			name      string
			read      func([]byte, contract.Token) contract.ReadResult
			deleted   contract.WriteResult
			want      generatedInboxDeleteOutcome
			wantCalls int
		}{
			{"missing", func(_ []byte, _ contract.Token) contract.ReadResult {
				return contract.ReadResult{Status: contract.ReadMissing}
			}, contract.WriteResult{}, generatedInboxDeleteClean, 0},
			{"exact", func(body []byte, token contract.Token) contract.ReadResult {
				return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: token}
			}, contract.WriteResult{Status: contract.WriteAcknowledged}, generatedInboxDeleteClean, 1},
			{"changed", func(body []byte, token contract.Token) contract.ReadResult {
				body = append([]byte(nil), body...)
				body[0] ^= 1
				return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: token}
			}, contract.WriteResult{Status: contract.WriteAcknowledged}, generatedInboxDeleteUnknown, 0},
			{"raced", func(body []byte, token contract.Token) contract.ReadResult {
				return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: token}
			}, contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}, generatedInboxDeletePending, 1},
			{"lost reply", func(body []byte, token contract.Token) contract.ReadResult {
				return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: token}
			}, contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, generatedInboxDeleteUnknown, 1},
		} {
			t.Run(map[uint8]string{contract.GeneratedReleasePending: "pending/", contract.GeneratedReleaseUnknown: "unknown/"}[state]+tc.name, func(t *testing.T) {
				s, a, release := generatedInboxReleaseState(t, 0, state)
				token := contract.Token{Family: contract.AWS, Value: `"inbox-etag"`}
				descriptor := contract.Descriptor{Family: contract.AWS, Prefix: "fixture"}
				store := &generatedInboxDeleteStore{descriptor: descriptor, read: tc.read(a.result, token), deleted: tc.deleted}
				s.store, s.admission.store = store, descriptor
				if got := s.deleteGeneratedInbox(context.Background(), release.InboxID); got != tc.want || store.deleteCalls != tc.wantCalls {
					t.Fatalf("outcome=%d calls=%d", got, store.deleteCalls)
				}
				if tc.wantCalls != 0 {
					key, err := format.GeneratedResultKey(descriptor.Prefix, release.DomainID, release.InboxID)
					if err != nil || store.deleteKey != key || store.deleteToken != token {
						t.Fatal("delete did not retain the exact read coordinate and token", err)
					}
				}
			})
		}
	}
}
