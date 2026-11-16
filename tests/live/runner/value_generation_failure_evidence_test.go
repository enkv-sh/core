package core

import (
	"sync"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
)

const maximumGeneratedOutcomes = 1024

type generatedOutcomeKey struct {
	id, locator, authority contract.ID
}

type generatedObservedOutcome struct {
	value     custody.GeneratedProducerOutcome
	duplicate bool
}

// generatedFailureTracker keeps private invocation IDs in memory. Only an
// exact matched return can become a closed assertion fact.
type generatedFailureTracker struct {
	mu       sync.Mutex
	failure  *records.FailureRecorder
	outcomes map[generatedOutcomeKey]generatedObservedOutcome
	overflow bool
}

func newGeneratedFailureTracker(failure *records.FailureRecorder) *generatedFailureTracker {
	return &generatedFailureTracker{failure: failure, outcomes: make(map[generatedOutcomeKey]generatedObservedOutcome)}
}

func (g *generatedFailureTracker) observe(value custody.GeneratedProducerOutcome) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := generatedOutcomeKey{value.ID, value.Locator, value.Authority}
	if prior, exists := g.outcomes[key]; exists {
		prior.duplicate = true
		g.outcomes[key] = prior
		return
	}
	if len(g.outcomes) >= maximumGeneratedOutcomes {
		g.overflow = true
		return
	}
	g.outcomes[key] = generatedObservedOutcome{value: value}
}

func (g *generatedFailureTracker) selectFailure(operation string, id, locator, authority contract.ID, code contract.CryptoResultCode, invoked bool) {
	if g == nil || g.failure == nil {
		return
	}
	facts := records.OperationFailureFacts{SchemaVersion: records.OperationFailureSchemaVersion, Operation: operation, Stage: "pre_invocation", Category: "unavailable",
		Effect: "no_send", FactsStatus: "facts_unavailable"}
	if invoked {
		key := generatedOutcomeKey{id, locator, authority}
		g.mu.Lock()
		observed, exists := g.outcomes[key]
		delete(g.outcomes, key)
		overflow := g.overflow
		g.mu.Unlock()
		if !exists || observed.duplicate || overflow || observed.value.Code != code {
			return
		}
		value := observed.value
		facts.Stage, facts.Category, facts.Code, facts.Effect = value.Stage, value.Category, value.Code, value.Effect
		if value.Qualified {
			facts.Stage, facts.Category, facts.FactsStatus = "completed", "none", "qualified"
			facts.SafeFacts = &records.QualifiedSafeFacts{Disposition: value.Disposition, Reason: value.Reason}
		}
	}
	ref, err := g.failure.CaptureOperationFailure(facts)
	if err == nil {
		_ = g.failure.SelectOperationFailure(ref)
	}
}
