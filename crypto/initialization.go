package crypto

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
)

// InitializationCustody is installed by the trusted initialization composition.
// It admits only the exact fixed initialization qualification request and owns
// retirement of that private session, not the installed runtime or key routes.
type InitializationCustody struct {
	runtime   *Runtime
	admission *initAdmission
	closed    atomic.Bool
	closeOnce sync.Once
}

func NewInitializationCustody(r *Runtime, request contract.CryptoQualifyInitKeysRequest,
	publicRoutes, privateRoutes map[contract.ID]contract.ID, deadline time.Time) (*InitializationCustody, error) {
	if r == nil {
		return nil, ErrAdmission
	}
	return newInitializationCustody(r, request, publicRoutes, privateRoutes, deadline, r.installInit)
}

// The installer is fixed by the production constructor. The local function
// parameter permits deterministic ownership-interleaving checks without globals.
func newInitializationCustody(r *Runtime, request contract.CryptoQualifyInitKeysRequest,
	publicRoutes, privateRoutes map[contract.ID]contract.ID, deadline time.Time,
	install func(contract.CryptoQualifyInitKeysRequest, contract.ID, map[contract.ID]contract.ID, map[contract.ID]contract.ID, time.Time) (*initAdmission, error)) (*InitializationCustody, error) {
	a, err := install(request, contract.CryptoSupportID(), publicRoutes, privateRoutes, deadline)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	valid := !r.closed && a != nil && r.init == a && r.slot == a.session
	r.mu.Unlock()
	if !valid {
		if a != nil {
			r.retireSession(a.session)
		}
		return nil, ErrAdmission
	}
	return &InitializationCustody{runtime: r, admission: a}, nil
}

func (c *InitializationCustody) InstanceID() contract.ID {
	if c == nil || c.runtime == nil {
		return contract.ID{}
	}
	return c.runtime.InstanceID()
}

func (c *InitializationCustody) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	refusal := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: request.Kind, RequestID: request.RequestID,
		CustodyInstanceID: c.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	if c == nil || c.runtime == nil || c.admission == nil || c.closed.Load() || request.Kind != contract.CryptoQualifyInitKeys {
		return refusal
	}
	return c.runtime.exchangeWithInitOwner(ctx, request, c.admission)
}

func (c *InitializationCustody) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.runtime != nil && c.admission != nil {
			c.runtime.retireSession(c.admission.session)
		}
	})
}
