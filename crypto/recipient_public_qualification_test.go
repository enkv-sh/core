package crypto

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

type exactRecipientPublicQualifier struct {
	binding contract.KMSBinding
	calls   int
	denied  bool
}

func (q *exactRecipientPublicQualifier) Family() contract.Family { return contract.GCP }
func (q *exactRecipientPublicQualifier) CredentialRoute() contract.ID {
	return consumerID("separate successor public route")
}
func (q *exactRecipientPublicQualifier) Qualify(ctx context.Context, binding contract.KMSBinding) KeyResult {
	q.calls++
	want, err := contract.EncodeKMSBinding(q.binding)
	got, gotErr := contract.EncodeKMSBinding(binding)
	if err != nil || gotErr != nil || !bytes.Equal(got, want) {
		return KeyResult{Status: KeyInvalid}
	}
	if ctx.Err() != nil {
		return KeyResult{Status: KeyCancelled}
	}
	if q.denied {
		return KeyResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
	}
	return KeyResult{Status: KeyOK, Uses: KeyUses{Completed: 3}}
}

type recipientSourceLocationRoute struct{ *consumerTestRoute }

func (r *recipientSourceLocationRoute) Qualify(_ context.Context, binding contract.KMSBinding) KeyResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.publicCalls++
	if !strings.HasPrefix(binding.KeySelector, "projects/test-project/locations/us-central1/") {
		return KeyResult{Status: KeyInvalid}
	}
	return KeyResult{Status: KeyOK, Uses: KeyUses{Completed: 3}}
}

// full_only: false
func TestRecipientReplacementUsesExactSeparateSuccessorPublicQualifier(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "different-project-region", true: "denied-no-fallback"}[denied], func(t *testing.T) {
			f := newAccessCallerContextFixture(t)
			f.intent.Successor.KeySelector = "projects/other-project/locations/europe-west1/keyRings/test/cryptoKeys/reader/cryptoKeyVersions/2"
			index := f.q.Replacements[0].SuccessorBindingIndex
			f.q.BindingTable[index].Binding = f.intent.Successor
			intent, err := contract.RecipientReplacementIntentDescriptor(f.intent)
			if err != nil {
				t.Fatal(err)
			}
			f.request.Intent = contract.DigestLength{Digest: intent.Digest, Length: intent.Length}
			request, err := contract.EncodeRequestCore(f.request)
			if err != nil {
				t.Fatal(err)
			}
			f.q.Context.IntentDescriptor = contract.DescriptorVector{Digest: contract.Hash(request), Length: uint64(len(request)), Count: 1}
			plan, err := contract.AccessReplacementPlanDescriptor(f.q.Plan())
			if err != nil {
				t.Fatal(err)
			}
			projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: f.q.Context.DomainID,
				BeforeAccessRoot: f.q.Context.CurrentAccessRoot, RequestCoreDigest: f.q.Context.IntentDescriptor.Digest}, plan, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.q.ExpectedCoverageDescriptor, _, _, err = projection.Descriptors()
			if err != nil {
				t.Fatal(err)
			}
			public := &exactRecipientPublicQualifier{binding: f.intent.Successor, denied: denied}
			source := &recipientSourceLocationRoute{consumerTestRoute: f.sourceRoute}
			r, err := New(contract.GCP, []KeyAccess{source})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			if err := r.admitAccess(f.q, f.intent, f.request, f.control, nil, source.CredentialRoute(), public, f.deadline); err != nil {
				t.Fatal("separate public qualifier admission", err)
			}
			body, err := contract.EncodeCryptoAccessReplaceRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			reply := r.Exchange(t.Context(), contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoAccessReplace,
				RequestID: consumerID("separate successor qualification"), CustodyInstanceID: r.InstanceID(), Body: body})
			wantCode, wantOutcome, wantCount := contract.CryptoSuccess, uint8(contract.KeyUseCompleted), uint32(3)
			if denied {
				wantCode, wantOutcome, wantCount = contract.CryptoPrivateRouteUnavailable, contract.KeyUseDenied, 1
			}
			digest, err := contract.PublicBindingDigest(f.intent.Successor)
			wantUses := []contract.KeyUseRow{{BindingID: f.intent.Successor.BindingID, PublicBindingDigest: digest, SubjectKind: contract.OrdinaryWrapSubject,
				SubjectID: f.intent.RecipientID, Provider: contract.GCP, Purpose: contract.KeyUsePublicKeyRead, Outcome: wantOutcome, Count: wantCount}}
			if public.calls != 1 || f.sourceRoute.publicCalls != 0 || f.sourceRoute.privateCalls != 0 || f.route.publicCalls != 0 || f.route.privateCalls != 0 {
				t.Fatalf("successor qualification used the wrong route: successor_public=%d source_public=%d source_private=%d recipient_public=%d recipient_private=%d", public.calls, f.sourceRoute.publicCalls, f.sourceRoute.privateCalls, f.route.publicCalls, f.route.privateCalls)
			}
			if err != nil || reply.ResultCode != wantCode || len(reply.KeyUseRows) != 1 || reply.KeyUseRows[0] != wantUses[0] {
				t.Fatal("exact successor public use facts changed", reply.ResultCode, err)
			}
			if !sameApplyBinding(f.sourceRoute.binding, f.control.AuthorityKMSBinding) {
				t.Fatal("qualification changed the selected source binding")
			}
		})
	}
}
