package custody

import (
	"context"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// InstalledApplyCustody exposes only typed production messages and retirement.
// Its constructor supplies the fixture's current Authority route directly.
type InstalledApplyCustody struct{ owner *privatecrypto.ApplyCustody }

func (c *InstalledApplyCustody) InstanceID() contract.ID {
	if c == nil || c.owner == nil {
		return contract.ID{}
	}
	return c.owner.InstanceID()
}
func (c *InstalledApplyCustody) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	if c == nil || c.owner == nil {
		return contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, ResultCode: contract.CryptoInvalidAdmission}
	}
	return c.owner.Exchange(ctx, q)
}
func (c *InstalledApplyCustody) BindReceipt(ctx context.Context, q contract.CryptoApplyReceiptAdmission) error {
	if c == nil || c.owner == nil {
		return privatecrypto.ErrAdmission
	}
	return c.owner.BindReceipt(ctx, q)
}
func (c *InstalledApplyCustody) Close() {
	if c != nil && c.owner != nil {
		c.owner.Close()
	}
}

func (f *Fixture) NewApplyCustody(q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, fileID contract.ID, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
	if f == nil || control.AuthorityRecipientID != f.authority || control.Provider != f.family || (control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return nil, privatecrypto.ErrAdmission
	}
	public, err := f.applyPublicQualifiers(q, current)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	route := f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	if route.IsZero() {
		return nil, privatecrypto.ErrAdmission
	}
	owner, err := privatecrypto.NewApplyCustody(f.runtime, q, control, current, public, route, fileID, plain, support, witness, revision, before, warningBits, deadline)
	if err != nil {
		return nil, err
	}
	return &InstalledApplyCustody{owner: owner}, nil
}

func (f *Fixture) NewEnvelopeRekeyCustody(q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
	route, err := f.secretAccessAuthorityRoute(control)
	if err != nil {
		return nil, err
	}
	owner, err := privatecrypto.NewEnvelopeRekeyCustody(f.runtime, q, control, current, route, plain, support, witness, revision, before, warningBits, deadline)
	if err != nil {
		return nil, err
	}
	return &InstalledApplyCustody{owner: owner}, nil
}

func (f *Fixture) NewRecipientRetirementCustody(q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, retiredSlot uint16, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
	route, err := f.secretAccessAuthorityRoute(control)
	if err != nil {
		return nil, err
	}
	owner, err := privatecrypto.NewRecipientRetirementCustody(f.runtime, q, control, current, retiredSlot, route, plain, support, witness, revision, before, warningBits, deadline)
	if err != nil {
		return nil, err
	}
	return &InstalledApplyCustody{owner: owner}, nil
}

func (f *Fixture) secretAccessAuthorityRoute(control contract.ControlCore) (contract.ID, error) {
	if f == nil || control.AuthorityRecipientID != f.authority || control.Provider != f.family || (control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return contract.ID{}, privatecrypto.ErrAdmission
	}
	f.mu.Lock()
	route := f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	if route.IsZero() {
		return contract.ID{}, privatecrypto.ErrAdmission
	}
	return route, nil
}
