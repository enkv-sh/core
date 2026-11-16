package crypto

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func (a *applyAdmission) prepareGrant(ctx context.Context, route KeyAccess, current applyCurrent, intent contract.CryptoIntentRow, reply *contract.CryptoResponse) (contract.CryptoPreparedSecret, contract.CryptoResultCode) {
	keys, code := a.openCurrent(ctx, route, current, reply)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		return contract.CryptoPreparedSecret{}, code
	}
	access := current.access
	access.Wraps = nil
	selected := current.access
	if a.supportTransition != nil {
		i := slices.IndexFunc(a.supportTransition.AccessRecords, func(row contract.AccessRecord) bool {
			return row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == current.entry.ValueState
		})
		if i < 0 {
			return contract.CryptoPreparedSecret{}, contract.CryptoInvalidAdmission
		}
		selected = a.supportTransition.AccessRecords[i]
	}
	for _, binding := range a.request.Bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(intent.Recipients, binding.SubjectID) {
			continue
		}
		if ctx.Err() != nil {
			return contract.CryptoPreparedSecret{}, contract.CryptoCancelled
		}
		index := slices.IndexFunc(selected.Wraps, func(wrap contract.WrapRow) bool {
			return wrap.SubjectKind == binding.SubjectKind && wrap.SubjectID == binding.SubjectID
		})
		if index >= 0 {
			access.Wraps = append(access.Wraps, selected.Wraps[index])
			continue
		}
		core, err := custody.ValueWrapCore(current.core, binding)
		if err != nil {
			return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
		}
		wrap, err := custody.Wrap(core, binding.Binding, keys)
		uses := KeyUses{Completed: 1}
		if err != nil {
			uses = KeyUses{Failed: 1}
		}
		if !appendKeyUses(reply, binding, contract.KeyUseMaterialWrap, uses, 1) {
			return contract.CryptoPreparedSecret{}, contract.CryptoResponseUnknown
		}
		if err != nil {
			return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
		}
		access.Wraps = append(access.Wraps, wrap)
	}
	entry := current.entry
	entry.Recipients = intent.Recipients
	entry.OutputEncoding = intent.OutputEncoding
	entryBytes, err := contract.EncodeValueEntry(entry)
	if err != nil {
		return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
	}
	accessBody, err := contract.EncodeAccessRecord(access)
	if err != nil {
		return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
	}
	return contract.CryptoPreparedSecret{Name: intent.Name, Slot: current.row.Slot, EntryBytes: entryBytes, AccessRecord: accessBody}, contract.CryptoSuccess
}
