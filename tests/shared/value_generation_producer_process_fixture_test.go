package core

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func preparePrivateGeneratedProcessProducerWithConfig(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation, artifact string,
	configure func(testing.TB, string, contract.GeneratorResultExpectation) custody.GeneratedProcessConfig, lifetime ...time.Duration) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProcessProducerForAttempt(t, env, s, prior, env.Custody, contract.ID{}, artifact, configure, lifetime...)
}

func preparePrivateGeneratedProcessProducerForAttempt(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation,
	keys *custody.Fixture, attempt contract.ID, artifact string,
	configure func(testing.TB, string, contract.GeneratorResultExpectation) custody.GeneratedProcessConfig, lifetime ...time.Duration) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProcessProducerWithAdmission(t, env, s, prior, keys, attempt, artifact, configure,
		generatedProducerFixtureSteps{request: s.generatedProducerRequestForAttempt, prepare: s.PrepareGeneratedProducer,
			claim: func(ctx context.Context, p *generatedPreparation) (*Candidate, Result) {
				return s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust)
			}}, lifetime...)
}

func preparePrivateGeneratedOriginalProcessProducerForAttempt(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation,
	keys *custody.Fixture, attempt contract.ID, facts *generatedProducerFixtureFacts, artifact string,
	configure func(testing.TB, string, contract.GeneratorResultExpectation) custody.GeneratedProcessConfig, lifetime ...time.Duration) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProcessProducerWithAdmission(t, env, s, prior, keys, attempt, artifact, configure,
		generatedProducerFixtureSteps{request: s.generatedOriginalProducerRequest, prepare: s.PrepareGeneratedOriginalProducer,
			claim: s.ClaimGeneratedOriginalProducer, facts: facts}, lifetime...)
}

func preparePrivateGeneratedProcessProducerWithAdmission(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation,
	keys *custody.Fixture, attempt contract.ID, artifact string,
	configure func(testing.TB, string, contract.GeneratorResultExpectation) custody.GeneratedProcessConfig, steps generatedProducerFixtureSteps,
	lifetime ...time.Duration) (*generatedPreparation, contract.GeneratorResultExpectation) {
	t.Helper()
	ctx := env.operationContext()
	keys.RetireGenerated()
	admitted := prior.producerBaseContext
	if !prior.plannedSuccessor {
		admitted = prior.operation.context
	}
	label := fmt.Sprintf("%x", attempt)
	admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("native generated producer admission"+label), testID("native generated producer session"+label), contract.DescriptorVector{}
	if len(lifetime) > 0 {
		admitted.Expiry = uint64(time.Now().Add(lifetime[0]).UnixNano())
	}
	facts := steps.facts
	if facts == nil {
		facts = acquireGeneratedProducerFixtureFacts(t, env, s, prior)
	}
	if attempt.IsZero() {
		attempt = facts.selection.phase.FrontierAttemptID
	}
	input := generatedProducerFixtureAttemptInput(t, s, prior, facts, attempt)
	for i := range input.Plan.Canonical {
		source := &input.Plan.Canonical[i]
		selection := sessionConsumerSelection(t, s, s.admission.recipient, source.Record.Entry.Name)
		if selection.Slot != source.Record.OriginalSlot || !reflect.DeepEqual(selection.Entry, source.Record.Entry) {
			t.Fatal("process producer source differs from the selected predecessor")
		}
	}
	config := configure(t, artifact, input.Expected)
	q, preparation, err := steps.request(ctx, prior, attempt, admitted)
	if err != nil {
		t.Fatal("process producer public admission", err)
	}
	input.Preparation = preparation
	deadline := time.Unix(0, int64(q.Context.Expiry))
	if err := keys.AdmitGeneratedProcessProducer(ctx, q, currentControlOf(s), input, config, deadline); err != nil {
		t.Fatal("process producer private admission", err)
	}
	permit := &admittedGeneratedProducer{session: s, prior: prior, attempt: preparation.AttemptID, request: q, preparation: preparation,
		crypto: keys.Crypto(), instance: keys.Crypto().InstanceID(), deadline: deadline}
	p, res := steps.prepare(ctx, permit)
	if p == nil || res.Outcome != ObservedCurrent {
		t.Fatal("process producer preparation", res)
	}
	if code := keys.BindGeneratedCandidate(ctx, q.Context.AdmissionID, facts.candidate); code != contract.CryptoSuccess {
		t.Fatal("process producer candidate binding", code)
	}
	candidate, res := steps.claim(ctx, p)
	if candidate == nil || res.Outcome != ObservedCurrent {
		t.Fatal("process producer claim", res)
	}
	return p, input.Expected
}
