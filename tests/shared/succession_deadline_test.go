package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type lateSuccessionSuccess struct {
	contract.QualifyingTrust
	deadline       time.Time
	delayQualify   bool
	qualifications int
	signs          int
	lateSign       bool
}

func (s *lateSuccessionSuccess) waitUntilExpired() {
	timer := time.NewTimer(max(time.Until(s.deadline)+time.Millisecond, time.Millisecond))
	defer timer.Stop()
	<-timer.C
}

func (s *lateSuccessionSuccess) QualifySigningBinding(ctx context.Context, b contract.PublicSigningBinding) contract.SigningQualificationResult {
	s.qualifications++
	result := s.QualifyingTrust.QualifySigningBinding(ctx, b)
	if s.delayQualify {
		s.waitUntilExpired()
	}
	// Deliberately return a completed, valid reply after cancellation. The
	// caller must reject late evidence even when its adapter ignores the signal.
	return result
}

func (s *lateSuccessionSuccess) Sign(ctx context.Context, q contract.SignRequest) contract.SignResult {
	s.signs++
	s.lateSign = s.lateSign || !time.Now().Before(s.deadline)
	result := s.QualifyingTrust.Sign(ctx, q)
	if !s.delayQualify && q.Purpose() == contract.SuccessorSignerProbePurpose {
		s.waitUntilExpired()
	}
	return result
}

// full_only: false
func TestSuccessionDeadlineRefusesLateSignerOnlySuccessBeforeEffects(t *testing.T) {
	for _, qualification := range []bool{true, false} {
		name := "probe"
		if qualification {
			name = "qualification"
		}
		t.Run(name, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			admitted := fixtureAdmission(env)
			init, _ := fixtureInitAdmission(t, env, admitted)
			s, res := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), nil, env.Crypto)
			if s == nil || res.Outcome != ObservedCurrent {
				t.Fatal("deadline fixture initialization failed", res)
			}
			after, ok := s.selectedControl()
			if !ok {
				t.Fatal("deadline fixture current control missing")
			}
			successor, binding := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
			after.NormalSigning, after.AccessGeneration = binding, after.AccessGeneration+1
			permit := admitAuthorityReplacement(t, s, keys, after, 1, 1, 1, contract.BindingTableRow{})
			deadline := time.Now().Add(200 * time.Millisecond)
			permit.deadline, permit.context.Expiry = deadline, uint64(deadline.UnixNano())
			late := &lateSuccessionSuccess{QualifyingTrust: successor, deadline: deadline, delayQualify: qualification}
			store := env.Store.(*memoryStore)
			creates, cas, approvals := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
			public, private := keys.Calls()
			candidate, res := s.PrepareSuccession(context.Background(), permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: late})
			wantSigns := 1
			if qualification {
				wantSigns = 0
			}
			if candidate != nil || res.Outcome == ObservedCurrent || !permit.used || late.qualifications != 1 || late.signs != wantSigns || late.lateSign || s.prepared {
				t.Fatalf("late success survived expiry: result=%+v qualification=%d signs=%d lateSign=%t prepared=%t", res, late.qualifications, late.signs, late.lateSign, s.prepared)
			}
			if store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != approvals {
				t.Fatal("expired signer-only admission reached immutable writes or authority approval")
			}
			if p, k := keys.Calls(); p != public || k != private {
				t.Fatal("signer-only deadline check reached Crypto")
			}
			if !s.admission.valid(store) {
				t.Fatal("test expired the public admission instead of the private permit")
			}
		})
	}
}

// full_only: false
func TestSuccessionSigningCancellationAfterQualifiedReply(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	after := currentControlOf(f.session)
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
	after.NormalSigning, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, f.session, keys, after, 1, 1, 1, contract.BindingTableRow{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	route := cancelledQualificationTrust{QualifyingTrust: successor, cancel: cancel}
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	candidate, result := f.session.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: route})
	if candidate != nil || result != failure(EvidenceUnavailable, SigningUnavailable) || store.creates != creates || store.cas != cas || successor.Calls() != 0 {
		t.Fatalf("result=%+v effects=%d/%d signs=%d", result, store.creates-creates, store.cas-cas, successor.Calls())
	}
}
