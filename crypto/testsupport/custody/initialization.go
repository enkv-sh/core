package custody

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// InitializationCustody keeps the fixture facade limited to typed Crypto
// messages and lifetime ownership. Private runtime types do not cross it.
type InitializationCustody struct {
	owner *privatecrypto.InitializationCustody
}

func (c *InitializationCustody) InstanceID() contract.ID {
	if c == nil || c.owner == nil {
		return contract.ID{}
	}
	return c.owner.InstanceID()
}

func (c *InitializationCustody) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	if c == nil || c.owner == nil {
		return contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: request.Kind, RequestID: request.RequestID,
			ResultCode: contract.CryptoInvalidAdmission}
	}
	return c.owner.Exchange(ctx, request)
}

func (c *InitializationCustody) Close() {
	if c != nil && c.owner != nil {
		c.owner.Close()
	}
}

// NewInitializationCustody uses the production purpose-specific constructor
// over the fixture's exact synthetic public and private routes.
func (f *Fixture) NewInitializationCustody(q contract.CryptoQualifyInitKeysRequest, deadline time.Time) (*InitializationCustody, error) {
	public, private, err := f.initializationRouteMaps(q)
	if err != nil {
		return nil, err
	}
	owner, err := privatecrypto.NewInitializationCustody(f.runtime, q, public, private, deadline)
	if err != nil {
		return nil, err
	}
	return &InitializationCustody{owner: owner}, nil
}

func (f *Fixture) initializationRouteMaps(q contract.CryptoQualifyInitKeysRequest) (map[contract.ID]contract.ID, map[contract.ID]contract.ID, error) {
	want, err := contract.EncodeBindingTable(f.Bindings())
	if err != nil {
		return nil, nil, err
	}
	got, err := contract.EncodeBindingTable(q.Bindings)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(got, want) || len(q.Probes) != 1+boolInt(!f.recovery.IsZero()) {
		return nil, nil, privatecrypto.ErrAdmission
	}
	public, private := make(map[contract.ID]contract.ID, len(q.Bindings)), make(map[contract.ID]contract.ID, len(q.Probes))
	f.mu.Lock()
	for _, row := range q.Bindings {
		public[row.Binding.BindingID] = f.publicRoutes[row.Binding.BindingID]
	}
	for i, row := range q.Probes {
		if i == 0 && row.SubjectID != f.authority || i == 1 && row.SubjectID != f.recovery {
			f.mu.Unlock()
			return nil, nil, privatecrypto.ErrAdmission
		}
		private[row.BindingID] = f.routes[row.BindingID]
	}
	f.mu.Unlock()
	return public, private, nil
}
