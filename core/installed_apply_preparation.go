package core

import (
	"context"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

const generatedInvocationStepLimit = contract.GeneratorMaxCreateLineages*3*3 + contract.GeneratorMaxCreateLineages*3 + 2

// ApplyPreparationCountLimit covers the existing finite generated driver: two
// candidate preparations and two result records per step, two initial candidates
// and the original result set. A candidate prepares its children and root.
// Both the entry HEAD and the invocation's own granting HEAD can require
// materialization of already selected access pages before a successor.
const ApplyPreparationCountLimit uint64 = (2*generatedInvocationStepLimit+2)*(contract.MaxChildPages+1) + 2*generatedInvocationStepLimit + contract.GeneratorMaxCreateLineages + 2*format.MaxGrantPages

// ApplyPreparationFacts counts logical immutable persistence episodes in one
// invocation. Acknowledgement and exact-byte verification are independent; each
// episode contributes at most once to either count, including a later episode
// for the same key. PossibleUnacknowledgedCreate retains unknown possibly sent
// Create history even after later acknowledgement or verification. Omission or
// zero does not prove absence or zero writes and grants no recovery authority.
type ApplyPreparationFacts struct {
	AcknowledgedCreates, VerifiedPreparations uint64
	PossibleUnacknowledgedCreate              bool
}

type applyPreparationKey struct{}

type applyPreparationCollector struct {
	mu    sync.Mutex
	facts ApplyPreparationFacts
}

func beginApplyPreparation(ctx context.Context) (context.Context, *applyPreparationCollector) {
	if ctx == nil {
		return nil, nil
	}
	collector := new(applyPreparationCollector)
	return context.WithValue(ctx, applyPreparationKey{}, collector), collector
}

func applyPreparationFrom(ctx context.Context) *applyPreparationCollector {
	if ctx == nil {
		return nil
	}
	collector, _ := ctx.Value(applyPreparationKey{}).(*applyPreparationCollector)
	return collector
}

func (c *applyPreparationCollector) record(acknowledged, verified, possible bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if acknowledged {
		c.facts.AcknowledgedCreates++
	}
	if verified {
		c.facts.VerifiedPreparations++
	}
	c.facts.PossibleUnacknowledgedCreate = c.facts.PossibleUnacknowledgedCreate || possible
}

func (c *applyPreparationCollector) attach(out *PublicApplyResult) {
	if c == nil || out == nil {
		return
	}
	c.mu.Lock()
	facts := c.facts
	c.mu.Unlock()
	out.Preparation = &facts
}
