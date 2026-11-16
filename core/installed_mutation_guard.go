package core

import (
	"context"
	"errors"
	"sync"

	"enkv.sh/core/contract"
)

// installedMutationGuard belongs to one installed current-state invocation.
// The owning parent cancels and joins its calls before closing dependencies.
// Immutable-object recovery keeps its existing budget; only physical HEAD CAS
// calls share the one-call limit here.
type installedMutationGuard struct {
	mu          sync.Mutex
	checkSource func(context.Context) error
	sourceErr   error
	casUsed     bool
	store       contract.Store
}

func newInstalledMutationGuard(store contract.Store, checkSource func(context.Context) error) (*installedMutationGuard, error) {
	if store == nil || checkSource == nil {
		return nil, errors.New("installed mutation requires a store and source check")
	}
	g := &installedMutationGuard{checkSource: checkSource}
	base := &installedGuardStore{guard: g, backend: store}
	g.store = base
	if configuration, ok := store.(contract.StoreConfigurationSource); ok {
		g.store = &installedGuardConfiguredStore{installedGuardStore: base, configuration: configuration}
	}
	return g, nil
}

// Store always returns the same delegate. Admission and all opened images use
// this delegate, including observations after an uncertain CAS.
func (g *installedMutationGuard) Store() contract.Store { return g.store }

// SourceError retains the first local source error for the owning parent.
// Provider results expose only a bounded reason, never this error's text.
func (g *installedMutationGuard) SourceError() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sourceErr
}

func (g *installedMutationGuard) checkLocked(ctx context.Context) contract.Reason {
	if ctx == nil || ctx.Err() != nil {
		return contract.ReasonLimit
	}
	if g.sourceErr != nil {
		return contract.ReasonConstruction
	}
	if err := g.checkSource(ctx); err != nil {
		g.sourceErr = err
		return contract.ReasonConstruction
	}
	if ctx.Err() != nil {
		return contract.ReasonLimit
	}
	return contract.ReasonNone
}

func (g *installedMutationGuard) check(ctx context.Context) contract.Reason {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checkLocked(ctx)
}

func (g *installedMutationGuard) reserveCAS(ctx context.Context) contract.Reason {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.casUsed {
		return contract.ReasonLimit
	}
	if reason := g.checkLocked(ctx); reason != contract.ReasonNone {
		return reason
	}
	g.casUsed = true
	return contract.ReasonNone
}

type installedGuardStore struct {
	guard   *installedMutationGuard
	backend contract.Store
}

func (s *installedGuardStore) Descriptor() contract.Descriptor { return s.backend.Descriptor() }

// The parent checks sources before and after the complete authenticated read
// and result projection. Individual GETs need no repeated source-file reads.
func (s *installedGuardStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return s.backend.Read(ctx, key, limit)
}

func (s *installedGuardStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	if reason := s.guard.check(ctx); reason != contract.ReasonNone {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: reason, NotSent: true}
	}
	return s.backend.Create(ctx, key, body)
}

// Installed administrative and replacement operations cannot create HEAD.
func (*installedGuardStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
}

func (s *installedGuardStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	if reason := s.guard.reserveCAS(ctx); reason != contract.ReasonNone {
		// This call did not reach the backend, even if an earlier call was unknown.
		// selectCandidate owns the cumulative possible-prior-commit fact.
		return contract.WriteResult{Status: contract.WriteRefused, Reason: reason, NotSent: true}
	}
	return s.backend.CompareAndSwap(ctx, key, token, body)
}

type installedGuardConfiguredStore struct {
	*installedGuardStore
	configuration contract.StoreConfigurationSource
}

func (s *installedGuardConfiguredStore) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration.StoreConfiguration()
}

func (g *installedMutationGuard) Trust(trust contract.Trust) contract.Trust {
	if trust == nil {
		return nil
	}
	return &installedGuardTrust{guard: g, backend: trust}
}

func (g *installedMutationGuard) QualifyingTrust(trust contract.QualifyingTrust) contract.QualifyingTrust {
	if trust == nil {
		return nil
	}
	return &installedGuardQualifyingTrust{installedGuardTrust: &installedGuardTrust{guard: g, backend: trust}, qualifying: trust}
}

type installedGuardTrust struct {
	guard   *installedMutationGuard
	backend contract.Trust
}

func (t *installedGuardTrust) Identity() contract.ID   { return t.backend.Identity() }
func (t *installedGuardTrust) Family() contract.Family { return t.backend.Family() }
func (t *installedGuardTrust) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	if reason := t.guard.check(ctx); reason != contract.ReasonNone {
		return contract.SignResult{Reason: reason}
	}
	return t.backend.Sign(ctx, request)
}

type installedGuardQualifyingTrust struct {
	*installedGuardTrust
	qualifying contract.QualifyingTrust
}

func (t *installedGuardQualifyingTrust) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	return t.qualifying.QualifySigningBinding(ctx, binding)
}
