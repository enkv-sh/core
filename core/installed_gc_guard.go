package core

import (
	"context"
	"errors"
	"sync"

	"enkv.sh/core/contract"
)

type gcDeletePermission struct {
	key          string
	target       contract.GCTarget
	consumed     uint8
	used, joined bool
	result       contract.WriteResult
}

// The invocation owns every permission and joins its synchronous call before
// it can record a not-sent witness or close installed dependencies.
type installedGCGuard struct {
	mu               sync.Mutex
	ctx              context.Context
	checkSource      func(context.Context) error
	sourceErr        error
	cas              uint8
	store            contract.Store
	backend          contract.Store
	targets          map[string]bool
	creates, deletes uint32
	rawWrites        []gcRawWriteFact
}

type gcRawWriteFact struct {
	Kind      uint8
	KeyDigest contract.ID
	Result    contract.WriteResult
}

const gcCreateCallLimit = 4 * 3 * (contract.MaxChildPages + 1)

func gcNormalizeWriteResult(v contract.WriteResult) (contract.WriteResult, bool) {
	valid := false
	switch v.Status {
	case contract.WriteAcknowledged:
		valid = v.Reason == contract.ReasonNone && !v.NotSent
	case contract.WritePrecondition, contract.WriteConflict:
		valid = v.Reason == contract.ReasonCondition && !v.NotSent
	case contract.WriteUnknown:
		valid = v.Reason == contract.ReasonTransport || v.Reason == contract.ReasonAccess || (v.Reason == contract.ReasonMalformed || v.Reason == contract.ReasonConstruction) && !v.NotSent
	case contract.WriteRefused:
		valid = v.Reason > contract.ReasonNone && v.Reason <= contract.ReasonProof
	}
	if valid {
		return v, false
	}
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}, true
}
func (g *installedGCGuard) writeResult(kind uint8, key string, raw contract.WriteResult) contract.WriteResult {
	normalized, malformed := gcNormalizeWriteResult(raw)
	if malformed {
		g.mu.Lock()
		g.rawWrites = append(g.rawWrites, gcRawWriteFact{Kind: kind, KeyDigest: contract.Hash([]byte(key)), Result: raw})
		g.mu.Unlock()
	}
	return normalized
}

func newInstalledGCGuard(ctx context.Context, store contract.Store, check func(context.Context) error) (*installedGCGuard, error) {
	if ctx == nil || store == nil || check == nil {
		return nil, contract.ErrRecord
	}
	g := &installedGCGuard{ctx: ctx, checkSource: check, backend: store, targets: map[string]bool{}}
	base := &gcGuardStore{guard: g, backend: store}
	g.store = base
	if source, ok := store.(contract.StoreConfigurationSource); ok {
		g.store = &gcGuardConfiguredStore{gcGuardStore: base, source: source}
	}
	return g, nil
}
func (g *installedGCGuard) check(ctx context.Context) contract.Reason {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checkLocked(ctx)
}
func (g *installedGCGuard) checkLocked(ctx context.Context) contract.Reason {
	if ctx == nil || ctx.Err() != nil || g.ctx.Err() != nil {
		return contract.ReasonLimit
	}
	if g.sourceErr != nil {
		return contract.ReasonConstruction
	}
	if err := g.checkSource(g.ctx); err != nil {
		g.sourceErr = err
		return contract.ReasonConstruction
	}
	if ctx.Err() != nil || g.ctx.Err() != nil {
		return contract.ReasonLimit
	}
	return contract.ReasonNone
}
func (g *installedGCGuard) delete(ctx context.Context, p *gcDeletePermission) contract.WriteResult {
	g.mu.Lock()
	if p == nil || p.used || p.consumed == 0 || p.consumed > contract.GCTransmissionLimit {
		g.mu.Unlock()
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
	}
	p.used = true
	if reason := g.checkLocked(ctx); reason != contract.ReasonNone {
		p.result = contract.WriteResult{Status: contract.WriteRefused, Reason: reason, NotSent: true}
		p.joined = true
		g.mu.Unlock()
		return p.result
	}
	if g.deletes >= contract.GCTargetLimit {
		p.result = contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}
		p.joined = true
		g.mu.Unlock()
		return p.result
	}
	g.deletes++
	g.mu.Unlock()
	// The guarded Store deliberately exposes no arbitrary DeleteIfToken method.
	deleter, ok := g.backend.(contract.ConditionalDeleteStore)
	result := contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
	if ok {
		result = g.writeResult(3, p.key, deleter.DeleteIfToken(ctx, p.key, p.target.Token))
	}
	g.mu.Lock()
	p.result = result
	p.joined = true
	g.mu.Unlock()
	return result
}

type gcGuardStore struct {
	guard   *installedGCGuard
	backend contract.Store
}

func (s *gcGuardStore) Descriptor() contract.Descriptor { return s.backend.Descriptor() }
func (s *gcGuardStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if s.guard.targets[key] {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return s.backend.Read(ctx, key, limit)
}
func (g *installedGCGuard) readTarget(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if !g.targets[key] {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	if reason := g.check(ctx); reason != contract.ReasonNone {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: reason}
	}
	return g.backend.Read(ctx, key, limit)
}
func (s *gcGuardStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	if reason := s.guard.check(ctx); reason != contract.ReasonNone {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: reason, NotSent: true}
	}
	if s.guard.targets[key] {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
	}
	s.guard.mu.Lock()
	if s.guard.creates >= gcCreateCallLimit {
		s.guard.mu.Unlock()
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}
	}
	s.guard.creates++
	s.guard.mu.Unlock()
	return s.guard.writeResult(1, key, s.backend.Create(ctx, key, body))
}
func (*gcGuardStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
}
func (s *gcGuardStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.guard.mu.Lock()
	if s.guard.cas >= 4 || key != s.backend.Descriptor().HeadKey {
		s.guard.mu.Unlock()
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}
	}
	if reason := s.guard.checkLocked(ctx); reason != contract.ReasonNone {
		s.guard.mu.Unlock()
		return contract.WriteResult{Status: contract.WriteRefused, Reason: reason, NotSent: true}
	}
	s.guard.cas++
	s.guard.mu.Unlock()
	return s.guard.writeResult(2, key, s.backend.CompareAndSwap(ctx, key, token, body))
}

type gcGuardConfiguredStore struct {
	*gcGuardStore
	source contract.StoreConfigurationSource
}

func (s *gcGuardConfiguredStore) StoreConfiguration() contract.StoreConfiguration {
	return s.source.StoreConfiguration()
}

type gcGuardTrust struct {
	guard   *installedGCGuard
	backend contract.Trust
}

func (t gcGuardTrust) Identity() contract.ID   { return t.backend.Identity() }
func (t gcGuardTrust) Family() contract.Family { return t.backend.Family() }
func (t gcGuardTrust) Sign(ctx context.Context, q contract.SignRequest) contract.SignResult {
	if reason := t.guard.check(ctx); reason != contract.ReasonNone {
		return contract.SignResult{Reason: reason}
	}
	return t.backend.Sign(ctx, q)
}

var errGCSourceChanged = errors.New("GC source is no longer current")
