package custody

import (
	"context"
	"crypto/subtle"
	"enkv.sh/core/contract"
	"sync"
)

// This responder exists only in the private test facade. Its scope is one
// local credential-use route; it cannot contact a provider or launch a process.
type ControlledRetirementResponder struct {
	mu                     sync.Mutex
	resource, token, scope contract.ID
	credential             []byte
	active                 bool
}

func NewControlledRetirementResponder(resource, token, scope contract.ID) *ControlledRetirementResponder {
	credential, _ := syntheticValue(StandardValue)
	return &ControlledRetirementResponder{resource: resource, token: token, scope: scope, credential: credential, active: true}
}

func (r *ControlledRetirementResponder) DeleteExact(token contract.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if token == r.token {
		r.active = false
	}
}

func (r *ControlledRetirementResponder) Probe(_ context.Context, _ contract.GeneratedProducerCommand) []byte {
	credential, _ := syntheticValue(StandardValue)
	defer clear(credential)
	return r.use(credential)
}

func (r *ControlledRetirementResponder) ProbeWithWrongCredential(_ context.Context, _ contract.GeneratedProducerCommand) []byte {
	return r.use([]byte("wrong credential"))
}

func (r *ControlledRetirementResponder) use(credential []byte) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if subtle.ConstantTimeCompare(credential, r.credential) != 1 {
		return []byte{3}
	}
	out := make([]byte, 97)
	out[0] = 2
	if r.active {
		out[0] = 1
	}
	copy(out[1:33], r.resource[:])
	copy(out[33:65], r.token[:])
	copy(out[65:97], r.scope[:])
	return out
}

func (r *ControlledRetirementResponder) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.credential)
	r.credential = nil
}
