package custody

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

type InstalledReplacementCustody struct {
	owner *privatecrypto.ReplacementCustody
}

func (c *InstalledReplacementCustody) InstanceID() contract.ID {
	if c == nil || c.owner == nil {
		return contract.ID{}
	}
	return c.owner.InstanceID()
}

func (c *InstalledReplacementCustody) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	if c == nil || c.owner == nil {
		return contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, ResultCode: contract.CryptoInvalidAdmission}
	}
	return c.owner.Exchange(ctx, q)
}

func (c *InstalledReplacementCustody) Close() {
	if c != nil && c.owner != nil {
		c.owner.Close()
	}
}

// bindInstalledSuccessor gives Core's fresh structural IDs to an already fixed
// synthetic public key. It neither chooses another key nor creates a route.
func (f *Fixture) bindInstalledSuccessor(row contract.BindingTableRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var current contract.BindingTableRow
	for _, candidate := range f.bindings {
		if candidate.SubjectKind == row.SubjectKind && candidate.SubjectID == row.SubjectID {
			current = candidate
			break
		}
	}
	if current.SubjectID.IsZero() || row.Binding.BindingID == current.Binding.BindingID || !contract.IncarnationCounterStep(current.Binding.BindingIncarnationID, current.Binding.BindingSerial, row.Binding.BindingIncarnationID, row.Binding.BindingSerial) {
		return privatecrypto.ErrAdmission
	}
	expected := f.successor
	if expected.SubjectID.IsZero() {
		expected = current
	}
	if expected.SubjectKind != row.SubjectKind || expected.SubjectID != row.SubjectID || expected.Binding.Provider != row.Binding.Provider || expected.Binding.KeySelector != row.Binding.KeySelector || !bytes.Equal(expected.Binding.SPKI, row.Binding.SPKI) || expected.Binding.Fingerprint != row.Binding.Fingerprint || expected.Binding.WrapProfile != row.Binding.WrapProfile || expected.Binding.ProtectionClass != row.Binding.ProtectionClass || f.keys[row.Binding.BindingID] != nil {
		return privatecrypto.ErrAdmission
	}
	if _, err := contract.EncodeKMSBinding(row.Binding); err != nil {
		return err
	}
	f.keys[row.Binding.BindingID] = f.keys[expected.Binding.BindingID]
	f.routes[row.Binding.BindingID] = f.routes[expected.Binding.BindingID]
	f.publicRoutes[row.Binding.BindingID] = f.publicRoutes[expected.Binding.BindingID]
	f.successor = row
	return nil
}

func (f *Fixture) AdmitInstalledRecipientReplacement(q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, before contract.ControlCore, rows []contract.CompactRow, deadline time.Time) (*InstalledReplacementCustody, error) {
	successor := q.BindingTable[q.Replacements[0].SuccessorBindingIndex]
	if err := f.bindInstalledSuccessor(successor); err != nil {
		return nil, err
	}
	f.mu.Lock()
	sourceRoute, publicRoute := f.routes[before.AuthorityKMSBinding.BindingID], f.publicRoutes[successor.Binding.BindingID]
	f.mu.Unlock()
	owner, err := privatecrypto.TestNewRecipientReplacementCustody(f.runtime, q, intent, request, before, rows, sourceRoute, publicRoute, deadline)
	if err != nil {
		return nil, err
	}
	return &InstalledReplacementCustody{owner: owner}, nil
}
func (f *Fixture) AdmitInstalledSuccessionReplacement(q contract.CryptoAccessReplaceRequest, request contract.SuccessionRequestCore, before contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore, rows []contract.CompactRow, deadline time.Time) (*InstalledReplacementCustody, error) {
	successor := q.BindingTable[q.Replacements[0].SuccessorBindingIndex]
	if err := f.bindInstalledSuccessor(successor); err != nil {
		return nil, err
	}
	f.mu.Lock()
	sourceRoute := f.routes[source.Binding.BindingID]
	publicRoute, privateRoute := f.publicRoutes[successor.Binding.BindingID], f.routes[successor.Binding.BindingID]
	f.mu.Unlock()
	owner, err := privatecrypto.NewSuccessionReplacementCustody(f.runtime, q, request, before, source, probe, rows, sourceRoute, publicRoute, privateRoute, deadline)
	if err != nil {
		return nil, err
	}
	return &InstalledReplacementCustody{owner: owner}, nil
}
