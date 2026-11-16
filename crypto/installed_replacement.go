package crypto

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
)

// ReplacementCustody owns exactly the access admission returned by its
// installer. Retirement never grants access to a later runtime session.
type ReplacementCustody struct {
	runtime   *Runtime
	admission *accessAdmission
	closed    atomic.Bool
	closeOnce sync.Once
}

func NewRecipientReplacementCustody(r *Runtime, q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, before contract.ControlCore, rows []contract.CompactRow, sourceRoute contract.ID, successorPublic PublicKeyQualifier, deadline time.Time) (*ReplacementCustody, error) {
	return newReplacementCustody(r, func() (*accessAdmission, error) {
		return r.admitAccessOwned(q, intent, request, before, rows, sourceRoute, successorPublic, deadline)
	})
}

func NewSuccessionReplacementCustody(r *Runtime, q contract.CryptoAccessReplaceRequest, request contract.SuccessionRequestCore, before contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore, rows []contract.CompactRow, sourceRoute, publicRoute, privateRoute contract.ID, deadline time.Time) (*ReplacementCustody, error) {
	return newReplacementCustody(r, func() (*accessAdmission, error) {
		return r.admitSuccessionAccessOwned(q, request, before, source, probe, rows, sourceRoute, publicRoute, privateRoute, deadline)
	})
}

func newReplacementCustody(r *Runtime, install func() (*accessAdmission, error)) (*ReplacementCustody, error) {
	if r == nil || install == nil {
		return nil, ErrAdmission
	}
	a, err := install()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	valid := !r.closed && a != nil && r.access == a && r.slot == a.session
	r.mu.Unlock()
	if !valid {
		if a != nil {
			r.retireSession(a.session)
		}
		return nil, ErrAdmission
	}
	return &ReplacementCustody{runtime: r, admission: a}, nil
}

func (c *ReplacementCustody) InstanceID() contract.ID {
	if c == nil || c.runtime == nil {
		return contract.ID{}
	}
	return c.runtime.InstanceID()
}

func (c *ReplacementCustody) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	refused := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: request.Kind, RequestID: request.RequestID,
		CustodyInstanceID: c.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	if c == nil || c.runtime == nil || c.admission == nil || c.closed.Load() {
		return refused
	}
	switch request.Kind {
	case contract.CryptoAccessReplace, contract.CryptoPrepare, contract.CryptoFreeze, contract.CryptoClaim, contract.CryptoDiscard:
	default:
		return refused
	}
	return c.runtime.accessExchangeOwned(ctx, request, c.admission)
}

func (c *ReplacementCustody) Close() {
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
