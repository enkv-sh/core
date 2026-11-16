package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
)

type gcpHeadWriteGate struct {
	busy chan struct{}
	next time.Time
}

func newGCPHeadWriteGate() *gcpHeadWriteGate {
	// Cleanup opens a new backend after the writer joins. Its first HEAD delete
	// must also leave one second after the previous process's last write.
	return &gcpHeadWriteGate{busy: make(chan struct{}, 1), next: time.Now().Add(time.Second)}
}

func (g *gcpHeadWriteGate) begin(ctx context.Context) bool {
	select {
	case g.busy <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	if ctx.Err() != nil {
		<-g.busy
		return false
	}
	if delay := time.Until(g.next); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			<-g.busy
			return false
		}
	}
	if ctx.Err() != nil {
		<-g.busy
		return false
	}
	return true
}

func (g *gcpHeadWriteGate) finish() {
	// Refused and uncertain attempts consume the same interval as success.
	g.next = time.Now().Add(time.Second)
	<-g.busy
}

func (s *gcpActorReadStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	if key == s.Store.Descriptor().HeadKey {
		if !s.headWrites.begin(ctx) {
			return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
		}
		defer s.headWrites.finish()
	}
	return s.Store.CompareAndSwap(ctx, key, token, body)
}

func (s *gcpActorReadStore) CreateHead(ctx context.Context, request contract.HeadCreateRequest) contract.WriteResult {
	if !request.Valid() || request.Descriptor() != s.Store.Descriptor() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	if !s.headWrites.begin(ctx) {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
	}
	defer s.headWrites.finish()
	return s.Store.CreateHead(ctx, request)
}
