package custody

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

type applyPublicQualifier struct {
	owner *Fixture
	row   contract.BindingTableRow
}

func (q *applyPublicQualifier) Family() contract.Family { return q.owner.family }
func (q *applyPublicQualifier) CredentialRoute() contract.ID {
	return fixtureID(q.row.Binding.BindingID, "apply public qualification", q.row.SubjectID)
}
func (q *applyPublicQualifier) Qualify(ctx context.Context, binding contract.KMSBinding) privatecrypto.KeyResult {
	f := q.owner
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publicCalls++
	f.pendingQualifications++
	if ctx.Err() != nil {
		return privatecrypto.KeyResult{Status: privatecrypto.KeyCancelled}
	}
	want, err := contract.PublicBindingDigest(q.row.Binding)
	got, gotErr := contract.PublicBindingDigest(binding)
	if err != nil || gotErr != nil || want != got {
		return privatecrypto.KeyResult{Status: privatecrypto.KeyInvalid}
	}
	if f.unavailable {
		return privatecrypto.KeyResult{Status: privatecrypto.KeyUnavailable, Uses: privatecrypto.KeyUses{Unknown: 1}}
	}
	if f.denied[q.row.SubjectID] {
		return privatecrypto.KeyResult{Status: privatecrypto.KeyDenied, Uses: privatecrypto.KeyUses{Denied: 1}}
	}
	count := contract.PublicKeyQualificationUseCount(f.family)
	if f.qualificationUses != nil {
		count = *f.qualificationUses
	}
	return privatecrypto.KeyResult{Status: privatecrypto.KeyOK, Uses: privatecrypto.KeyUses{Completed: count}}
}

func sameApplyKeyResource(a, b contract.KMSBinding) bool {
	return a.Provider == b.Provider && a.WrapProfile == b.WrapProfile && a.ProtectionClass == b.ProtectionClass && a.KeySelector == b.KeySelector && a.Fingerprint == b.Fingerprint && bytes.Equal(a.SPKI, b.SPKI)
}

func (f *Fixture) applyPublicQualifiers(q contract.CryptoCompareRequest, current []contract.RecipientRecord) (map[contract.ID]privatecrypto.PublicKeyQualifier, error) {
	if _, err := contract.BindingTableLength(q.Bindings); err != nil {
		return nil, privatecrypto.ErrAdmission
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	public := make(map[contract.ID]privatecrypto.PublicKeyQualifier)
	for _, row := range q.Bindings {
		known := slices.IndexFunc(f.bindings, func(known contract.BindingTableRow) bool {
			return known.SubjectKind == row.SubjectKind && sameApplyKeyResource(known.Binding, row.Binding)
		})
		if known < 0 {
			return nil, privatecrypto.ErrAdmission
		}
		if row.SubjectKind != contract.OrdinaryWrapSubject {
			continue
		}
		if slices.ContainsFunc(current, func(before contract.RecipientRecord) bool { return before.RecipientID == row.SubjectID }) {
			continue
		}
		if f.keys == nil {
			return nil, privatecrypto.ErrAdmission
		}
		owned := row
		owned.Binding.SPKI = slices.Clone(row.Binding.SPKI)
		f.pendingRoutes++
		public[row.SubjectID] = &applyPublicQualifier{owner: f, row: owned}
	}
	return public, nil
}

// PendingKeyCalls counts route construction and qualification for proposed recipients.
func (f *Fixture) PendingKeyCalls() (routes, qualifications int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pendingRoutes, f.pendingQualifications
}
