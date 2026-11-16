package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

type accessCallerContextFixture struct {
	q           contract.CryptoAccessReplaceRequest
	intent      contract.RecipientReplacementIntent
	request     contract.RequestCore
	control     contract.ControlCore
	route       *consumerTestRoute
	sourceRoute *consumerTestRoute
	rows        []contract.CompactRow
	deadline    time.Time
	body        []byte
}

func newAccessCallerContextFixture(t *testing.T) accessCallerContextFixture {
	t.Helper()
	f := applyFixture(t, false)
	before := f.q.Bindings[slices.IndexFunc(f.q.Bindings, func(row contract.BindingTableRow) bool {
		return row.SubjectID != f.control.AuthorityRecipientID
	})]
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	successor := before
	successor.Binding.BindingID = consumerID("caller context successor binding")
	successor.Binding.BindingSerial++
	successor.Binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/reader/cryptoKeyVersions/2"
	successor.Binding.SPKI = spki
	successor.Binding.Fingerprint = contract.Hash(spki)
	intent := contract.RecipientReplacementIntent{
		RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{
			Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: f.q.Context.CompatibilityID,
			CryptoSupportID: contract.CryptoSupportID(), DomainID: f.q.Context.DomainID,
			BeforeAccessRoot: f.q.Context.CurrentAccessRoot, RecipientID: before.SubjectID,
		},
		Before: before.Binding, Successor: successor.Binding,
	}
	intentDescriptor, err := contract.RecipientReplacementIntentDescriptor(intent)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contract.IdentityPlanDescriptor(contract.IdentityPlan{
		Operation: consumerID("replacement operation"), Transition: consumerID("replacement transition"),
		Snapshot: consumerID("replacement snapshot"), Revision: consumerID("replacement revision"),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.RequestCore{
		RequestCoreFields: contract.RequestCoreFields{
			Domain: f.q.Context.DomainID, Store: f.control.StoreID, Trust: f.control.NormalSigning.Binding.Trust,
			Coordinate: f.control.CoordinateID, NonBody: f.control.NonBodyID, Interpretation: f.control.TrustInterpretationID,
			Epoch: f.control.NormalSigning.Binding.Epoch, PreviousRevision: consumerID("replacement predecessor revision"),
			PreviousDigest: f.q.Context.PredecessorHEADDigest, Intent: contract.DigestLength{Digest: intentDescriptor.Digest, Length: intentDescriptor.Length},
			IdentityPlan: contract.DigestLength{Digest: identity.Digest, Length: identity.Length},
		},
		PreviousToken: contract.Token{Family: contract.GCP, Value: "1"},
	}
	requestBody, err := contract.EncodeRequestCore(request)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(request.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	c := f.q.Context
	c.OperationClass = contract.CryptoAccessReplacementClass
	c.OriginalConditionDigest, err = contract.CryptoConditionDigest(condition)
	if err != nil {
		t.Fatal(err)
	}
	c.IntentDescriptor = contract.DescriptorVector{Digest: contract.Hash(requestBody), Length: uint64(len(requestBody)), Count: 1}
	bindings := append(slices.Clone(f.q.Bindings), successor)
	slices.SortFunc(bindings, func(a, b contract.BindingTableRow) int {
		if n := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); n != 0 {
			return n
		}
		if a.Binding.BindingSerial < b.Binding.BindingSerial {
			return -1
		}
		if a.Binding.BindingSerial > b.Binding.BindingSerial {
			return 1
		}
		return 0
	})
	beforeDigest, err := contract.PublicBindingDigest(before.Binding)
	if err != nil {
		t.Fatal(err)
	}
	q := contract.CryptoAccessReplaceRequest{
		Context: c, BindingTable: bindings,
		Replacements: []contract.ReplacementRow{{SubjectKind: 1, SubjectID: before.SubjectID, BeforeBindingDigest: beforeDigest,
			SuccessorBindingIndex: uint16(slices.IndexFunc(bindings, func(row contract.BindingTableRow) bool {
				return row.Binding.BindingID == successor.Binding.BindingID
			}))}},
	}
	plan, err := contract.AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{
		DomainID: c.DomainID, BeforeAccessRoot: c.CurrentAccessRoot, RequestCoreDigest: c.IntentDescriptor.Digest,
	}, plan, 0)
	if err != nil {
		t.Fatal(err)
	}
	q.ExpectedCoverageDescriptor, _, _, err = projection.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: key, binding: successor.Binding}}
	body, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	return accessCallerContextFixture{q: q, intent: intent, request: request, control: f.control, route: route, sourceRoute: f.route, deadline: f.deadline, body: body}
}

func (f accessCallerContextFixture) runtime(t *testing.T, route KeyAccess) *Runtime {
	t.Helper()
	r, err := New(contract.GCP, []KeyAccess{route})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if err := r.admitAccess(f.q, f.intent, f.request, f.control, f.rows, route.CredentialRoute(), route, f.deadline); err != nil {
		t.Fatal("access admission", err)
	}
	return r
}

type accessQualificationBarrierRoute struct {
	KeyAccess
	qualified chan struct{}
	release   <-chan struct{}
}

func (r *accessQualificationBarrierRoute) Qualify(ctx context.Context, binding contract.KMSBinding) KeyResult {
	result := r.KeyAccess.Qualify(ctx, binding)
	close(r.qualified)
	<-r.release
	return result
}

// full_only: false
func TestAccessCallerContextMethodsRunOutsideRuntimeLock(t *testing.T) {
	f := newAccessCallerContextFixture(t)
	t.Run("exchange", func(t *testing.T) {
		r := f.runtime(t, f.route)
		ctx := &generatedLockProbeContext{base: context.Background(), runtime: r}
		if reply := applyCall(r, ctx, contract.CryptoAccessReplace, f.body); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("access replacement", reply.ResultCode)
		}
		if ctx.locked {
			t.Fatal("access exchange called a caller Context method under Runtime.mu")
		}
	})
	for _, name := range []string{"caller-cancelled-completion", "concurrent-close"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				route := &accessQualificationBarrierRoute{KeyAccess: f.route, qualified: make(chan struct{}), release: release}
				r := f.runtime(t, route)
				released := false
				t.Cleanup(func() {
					if !released {
						close(release)
					}
				})
				r.mu.Lock()
				a := r.access
				clears := 0
				clearSession := a.clear
				a.clear = func() { clears++; clearSession() }
				r.mu.Unlock()
				f.route.mu.Lock()
				publicCalls := f.route.publicCalls
				f.route.mu.Unlock()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan contract.CryptoResponse, 1)
				go func() { result <- applyCall(r, ctx, contract.CryptoAccessReplace, f.body) }()
				<-route.qualified
				closed := make(chan struct{})
				if name == "concurrent-close" {
					go func() { r.Close(); close(closed) }()
				} else {
					cancel()
				}
				synctest.Wait()
				select {
				case <-closed:
					t.Fatal("Close did not join access qualification work")
				default:
				}
				r.mu.Lock()
				retained := a.used && a.busy && len(a.request.BindingTable) == 3 && a.clear != nil && clears == 0
				r.mu.Unlock()
				if !retained {
					t.Fatal("retirement did not retain the active access stage")
				}
				close(release)
				released = true
				reply := <-result
				if name == "concurrent-close" {
					<-closed
				} else {
					r.Close()
				}
				successor := f.q.BindingTable[f.q.Replacements[0].SuccessorBindingIndex]
				digest, err := contract.PublicBindingDigest(successor.Binding)
				if err != nil {
					t.Fatal(err)
				}
				wantUses := []contract.KeyUseRow{{BindingID: successor.Binding.BindingID, PublicBindingDigest: digest,
					SubjectKind: successor.SubjectKind, SubjectID: successor.SubjectID, Provider: contract.GCP,
					Purpose: contract.KeyUsePublicKeyRead, Outcome: contract.KeyUseCompleted, Count: 3}}
				if reply.ResultCode != contract.CryptoCancelled || len(reply.Body) != 0 || !slices.Equal(reply.KeyUseRows, wantUses) {
					t.Fatal("cancelled access stage lost completed qualification facts", reply.ResultCode, reply.KeyUseRows)
				}
				f.route.mu.Lock()
				callsCorrect := f.route.publicCalls == publicCalls+1 && f.route.privateCalls == 0
				f.route.mu.Unlock()
				if !callsCorrect {
					t.Fatal("access stage did not qualify the exact successor once")
				}
				r.Close()
				if clears != 1 || a.clear != nil || a.request.BindingTable != nil || a.projection != nil || a.busy {
					t.Fatal("retirement did not join and clear the access session exactly once")
				}
			})
		})
	}
}

// full_only: false
func TestApplyCallerContextMethodsRunOutsideRuntimeLock(t *testing.T) {
	f := applyFixture(t, false)
	r := f.runtime(t, nil)
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &generatedLockProbeContext{base: context.Background(), runtime: r}
	if reply := applyCall(r, ctx, contract.CryptoCompare, body); reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("apply comparison", reply.ResultCode)
	}
	if ctx.locked {
		t.Fatal("apply exchange called a caller Context method under Runtime.mu")
	}
}
