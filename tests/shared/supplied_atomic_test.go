package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func (r *scenarioRun) suppliedCandidate(session *StateSession, input []ApplyEntryInput) *Candidate {
	r.t.Helper()
	parent := admitSuppliedComparison(r.t, session, r.env.Custody, input)
	count := int(session.root.SecretCount)
	for _, value := range input {
		if value.ConfidentialityClass == contract.Secret {
			count++
		}
	}
	if r.env.ReserveCustody != nil && !r.env.ReserveCustody("compare", count) {
		r.t.Fatal("comparison custody budget exhausted")
	}
	comparison, result := session.Compare(r.ctx, input, parent)
	if comparison == nil {
		r.t.Fatal("supplied comparison", result)
	}
	count = 0
	for i, value := range comparison.desiredEntries {
		if value.ConfidentialityClass == contract.Secret && slices.Contains(comparison.changed, comparison.slots[i]) {
			count++
		}
	}
	if count > 0 && r.env.ReserveCustody != nil && !r.env.ReserveCustody("prepare", count) {
		r.t.Fatal("preparation custody budget exhausted")
	}
	permit := admit(r.t, session, comparison)
	candidate, result := session.Prepare(r.ctx, comparison, permit, r.env.Trust)
	if candidate == nil {
		r.t.Fatal("supplied preparation", result)
	}
	r.env.Custody.RetireApply()
	return candidate
}

func runSuppliedAtomicScenario(t testing.TB, ctx context.Context, env fixtureEnvironment) {
	t.Helper()
	run := newScenarioRun(t, ctx, env)
	var f *environmentFixture
	var input []ApplyEntryInput
	run.phase("setup", func() {
		f = newEnvironmentFixture(t, ctx, run.env, []int{1, 1}, false)
	})
	run.phase("transition", func() {
		input = append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "atomic initial", custody.StandardValue), suppliedSecret(t, env, "zz-retained", "atomic retained", custody.EmptyValue))
		run.suppliedSelection(f, input)
	})
	var stale *StateSession
	var abandoned *Candidate
	run.phase("transition", func() {
		stale = f.session
		proposal := slices.Clone(input)
		proposal[0].InputBytes = []byte("abandoned plain")
		proposal[2] = suppliedSecret(t, env, "secret", "atomic abandoned", custody.EmptyValue)
		abandoned = run.suppliedCandidate(stale, proposal)
		if run.spy.StoreCAS != 0 || run.spy.TrustSign != 1 {
			t.Fatal("preparation selected an abandoned mixed candidate")
		}
		opened := run.open(f.admission)
		assertStateImage(t, opened, sessionStateImage(t, stale))
	})
	run.phase("transition", func() {
		f.session = run.open(f.admission)
		input[0].InputBytes = []byte("winning plain")
		input[2] = suppliedSecret(t, env, "secret", "atomic winning", custody.StandardValue)
		run.suppliedSelection(f, input)
		if result := stale.Select(ctx, abandoned); result.Outcome != Contention || result.Reason != StalePrecondition || result.CommitMayHaveOccurred || run.spy.StoreCAS != 2 || run.spy.PreconditionWrites != 1 {
			t.Fatal("stale supplied candidate did not keep its original condition", result)
		}
		before := run.spy.scenarioEffects
		if result := stale.Select(ctx, abandoned); result != refused(AdmissionInvalid) || run.spy.scenarioEffects != before {
			t.Fatal("abandoned supplied candidate was selected twice")
		}
	})
	var expected stateImage
	run.phase("transition", func() {
		before := f.session
		input[1].InputBytes = []byte("lost-reply plain")
		input[2] = suppliedSecret(t, env, "secret", "atomic final", custody.StandardValue)
		loss := &completedReplyLoss{Store: env.Store, head: true, spy: run.spy}
		before.store = scenarioStore{Store: loss, spy: run.spy}
		candidate := run.suppliedCandidate(before, input)
		if result := before.Select(ctx, candidate); result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure || result.CommitMayHaveOccurred || run.spy.InjectedLostReplies != 1 || run.spy.UnknownWrites != 1 || run.spy.StoreCAS != 1 {
			t.Fatal("injected lost reply did not resolve from complete selected evidence", result)
		}
		f.session = run.open(f.admission)
		if !bytes.Equal(f.session.valueEntry(0).ValueBytes, []byte("winning plain")) || !bytes.Equal(f.session.valueEntry(1).ValueBytes, []byte("lost-reply plain")) || f.session.root.SecretCount != 2 {
			t.Fatal("atomic supplied selection lost a member or kept an abandoned value")
		}
		expected = sessionStateImage(t, f.session)
	})
	run.verify(f.admission, expected)
}
