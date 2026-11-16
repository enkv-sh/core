package crypto

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"enkv.sh/core/contract"
)

var ErrAdmission = errors.New("private admission refused")

type Runtime struct {
	mu              sync.Mutex
	id              contract.ID
	family          contract.Family
	routes          map[contract.ID]KeyAccess
	slot            *session
	init            *initAdmission
	inputSeal       *inputSealAdmission
	consumer        *consumerAdmission
	publication     *publicationAdmission
	apply           *applyAdmission
	access          *accessAdmission
	generated       *generatedAdmission
	generatedPlan   *validatedGeneratedPlan
	generatedInputs *generatedInputOwner
	retiredID       contract.ID
	closed          bool
}

var _ contract.Crypto = (*Runtime)(nil)

// New installs private provider routes. It grants no source, operation or
// consumer admission. Those require the separately admitted private parent.
func New(family contract.Family, routes []KeyAccess) (*Runtime, error) {
	if !family.Valid() || len(routes) > contract.CryptoMaxRecipients+1 {
		return nil, ErrAdmission
	}
	r := &Runtime{family: family, routes: make(map[contract.ID]KeyAccess, len(routes)), generatedInputs: new(generatedInputOwner)}
	for _, route := range routes {
		if route == nil || route.Family() != family || route.CredentialRoute().IsZero() {
			return nil, ErrAdmission
		}
		id := route.CredentialRoute()
		if _, exists := r.routes[id]; exists {
			return nil, ErrAdmission
		}
		r.routes[id] = route
	}
	if _, err := rand.Read(r.id[:]); err != nil {
		return nil, ErrAdmission
	}
	return r, nil
}

func (r *Runtime) InstanceID() contract.ID {
	if r == nil {
		return contract.ID{}
	}
	return r.id
}

// Fork creates an independent private operation slot over the same key routes.
// Callers close each fork after its admitted producer and return have joined.
func (r *Runtime) Fork() (*Runtime, error) {
	if r == nil {
		return nil, ErrAdmission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrAdmission
	}
	routes := make([]KeyAccess, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	fork, err := New(r.family, routes)
	if err != nil {
		return nil, err
	}
	if r.generatedInputs == nil {
		r.generatedInputs = new(generatedInputOwner)
	}
	// Forks share immutable public inputs before their first admission. Each
	// still owns its private session, validation facts and secret material.
	fork.generatedInputs = r.generatedInputs
	fork.generatedPlan = r.generatedPlan
	return fork, nil
}

// Close cancels the owned operation and waits for it to join before releasing
// the runtime's routes and shared input references. Closing one fork does not
// close another fork or the shared provider routes.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	a := r.slot
	if a != nil {
		a.cancel()
	}
	r.mu.Unlock()
	if a != nil {
		<-a.done
	}
	r.mu.Lock()
	r.routes = nil
	r.generatedPlan = nil
	r.generatedInputs = nil
	r.mu.Unlock()
}

func (r *Runtime) exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	reply := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: r.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	if r == nil || r.id.IsZero() || q.CustodyInstanceID != r.id || ctx == nil {
		return reply
	}
	if q.Schema != contract.CryptoSchema || q.RequestID.IsZero() {
		reply.ResultCode = contract.CryptoInvalidInput
		return reply
	}
	r.mu.Lock()
	access := r.access != nil
	generated := r.generated != nil
	r.mu.Unlock()
	if generated {
		return r.generatedExchange(ctx, q, reply)
	}
	if access {
		return r.accessExchange(ctx, q)
	}
	switch q.Kind {
	case contract.CryptoCompare, contract.CryptoPrepare, contract.CryptoFreeze, contract.CryptoClaim, contract.CryptoDiscard:
		return r.applyExchange(ctx, q, reply)
	case contract.CryptoQualifyInitKeys:
		return r.qualifyInit(ctx, q, nil)
	default:
		reply.ResultCode = contract.CryptoInvalidInput
		return reply
	}
}
