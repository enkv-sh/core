package crypto

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// Callers fix the value identity and authority. Sealing grants only the current
// recipients and the admitted Recovery binding; retained sources stay separate.
func sealValueForRecipients(ctx context.Context, core contract.ValueCore, generated contract.GeneratedEntryMetadata,
	outputEncoding uint8, recipients []contract.ID, bindings []contract.BindingTableRow, plain []byte, out *contract.CryptoResponse) (contract.ValueEntry, contract.AccessRecord, contract.CryptoResultCode) {
	if ctx.Err() != nil {
		return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCancelled
	}
	payload, keys, err := custody.SealValue(core, plain)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if err != nil {
		return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCustodyUnavailable
	}
	defer clear(payload.Ciphertext[:cap(payload.Ciphertext)])
	material, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCustodyUnavailable
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID, MaterialContextDigest: material, PackageCheck: payload.PackageCheck}
	for _, binding := range bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(recipients, binding.SubjectID) {
			continue
		}
		if ctx.Err() != nil {
			return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCancelled
		}
		wrapCore, err := custody.ValueWrapCore(core, binding)
		if err != nil {
			return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCustodyUnavailable
		}
		wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
		uses := KeyUses{Completed: 1}
		if err != nil {
			uses = KeyUses{Failed: 1}
		}
		if !appendKeyUses(out, binding, contract.KeyUseMaterialWrap, uses, 1) {
			return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoResponseUnknown
		}
		if err != nil {
			return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCustodyUnavailable
		}
		access.Wraps = append(access.Wraps, wrap)
	}
	payloadBody, err := contract.EncodeCanonicalPayload(payload)
	if err != nil {
		return contract.ValueEntry{}, contract.AccessRecord{}, contract.CryptoCustodyUnavailable
	}
	entry := contract.ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID,
		OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: core.ValueSource,
		ConfidentialityClass: contract.Secret, InputEncoding: core.InputEncoding, ContentLength: core.ContentLength, RetainedLength: core.RetainedLength, OutputEncoding: outputEncoding, Recipients: slices.Clone(recipients), ValueBytes: payloadBody, Generated: generated}
	return entry, access, contract.CryptoSuccess
}
