package custody

import (
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// AdmitApply binds the trusted test parent's selected public state to source
// bodies already authorized by this fixture's independent producer.
func (f *Fixture) AdmitApply(q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plainBefore []contract.MembershipRow, support contract.DescriptorVector, deadline time.Time, witness ...*contract.GeneratedSupportTransition) error {
	if f == nil || control.AuthorityRecipientID != f.authority || control.Provider != f.family ||
		(control.Recovery == nil) != f.recovery.IsZero() || control.Recovery != nil && control.Recovery.RoleID != f.recovery {
		return privatecrypto.ErrAdmission
	}
	public, err := f.applyPublicQualifiers(q, current)
	if err != nil || len(q.SealedInputs) > contract.CryptoMaxValueEntries {
		return privatecrypto.ErrAdmission
	}
	f.mu.Lock()
	accepted := make(map[contract.ID]contract.SealedInputCore, len(q.SealedInputs))
	for _, source := range q.SealedInputs {
		if len(source.EnvelopeBytes) > contract.CryptoMaxSealedInputLength {
			f.mu.Unlock()
			return privatecrypto.ErrAdmission
		}
		digest := contract.Hash(source.EnvelopeBytes)
		core, ok := f.accepted[digest]
		if !ok {
			f.mu.Unlock()
			return privatecrypto.ErrAdmission
		}
		accepted[digest] = core
	}
	routeID := f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	return privatecrypto.TestAdmitApply(f.runtime, q, control, current, public, routeID, accepted, plainBefore, support, deadline, witness...)
}

func (f *Fixture) RetireApply() { privatecrypto.TestRetireApply(f.runtime) }
