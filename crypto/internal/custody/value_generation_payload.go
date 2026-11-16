package custody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"enkv.sh/core/contract"
)

// SealGeneratedValuePayload consumes the exact result selected by the private
// admission. The caller owns graph, membership and phase authority checks.
// Returned keys have one owner and must be cleared after wrapping.
func SealGeneratedValuePayload(expected contract.GeneratorResultExpectation, material contract.OperationMaterialRecord, phase contract.ID,
	selected contract.GeneratorResultReference, plan contract.CryptoGeneratedValueEntryPlan, seed []byte) (payload contract.CanonicalPayload, keys []byte, err error) {
	if len(plan.Result) > contract.GeneratedResultRecordMaxLength || selected.Schema != 1 ||
		selected.ResultID != expected.Use.ResultID || uint64(selected.ResultLength) != uint64(len(plan.Result)) ||
		selected.ResultBodyDigest != contract.Hash(plan.Result) {
		return payload, nil, ErrPayload
	}
	result, err := contract.DecodeGeneratedResultRecord(plan.Result)
	if err != nil || expected.Template.Action != contract.GeneratorActionCreate || result.SafeFacts.Disposition != contract.GeneratorDispositionCompleteCreate {
		return payload, nil, ErrPayload
	}
	core, meta, template := plan.ValueCore, plan.Generated, expected.Template
	encoded, err := contract.EncodeValueCore(core)
	if err != nil {
		return payload, nil, ErrPayload
	}
	var resourceDigest contract.ID
	if template.LifecycleMode == contract.GeneratorLifecycleManaged {
		resourceDigest, err = contract.GeneratorResourceDigest(result.SafeFacts)
		if err != nil {
			return payload, nil, ErrPayload
		}
	}
	binding, err := contract.GeneratedBindingDigest(meta)
	if err != nil || core.ValueSource != contract.Generated || core.GeneratedBindingDigest != binding ||
		core.DomainID != material.Core.DomainID || core.CompatibilityID != material.Core.CompatibilityID ||
		core.CryptoSupportID != material.Core.CryptoSupportID || core.Profile != material.Core.Profile ||
		core.InputEncoding != expected.InputEncoding || core.InputEncoding != result.Payload.InputEncoding || core.ContentLength != result.Payload.ContentLength || core.RetainedLength != result.Payload.RetainedLength || core.DataKeyEpoch != 1 || core.CommitmentKeyEpoch != 1 ||
		meta.ConfigContractID != template.ConfigContractID || meta.ResourceContractID != template.ResourceContractID || meta.IntentDigest != template.IntentDigest ||
		meta.SemanticLifecycleMode() != template.SemanticLifecycleMode() ||
		meta.ResourceIncarnationID != template.ResourceIncarnationID || meta.OriginOperationID != material.Core.OperationID ||
		meta.OriginAttemptID != template.AttemptID || meta.CreateResultID != result.Core.ResultID ||
		meta.ResourceDigest != resourceDigest || meta.CompletionClass != template.CompletionClass {
		return payload, nil, ErrPayload
	}
	identity, err := contract.DeriveGeneratedValueIdentity(expected.Use.PlannedValueSlotID, phase, expected.Use.ResultID, binding)
	if err != nil || core.ValueStateID != identity.ValueStateID || meta.GenerationID != identity.ValueStateID ||
		core.OriginSnapshotID != identity.OriginSnapshotID || core.OriginTransitionID != identity.OriginTransitionID ||
		core.DataKeyID != identity.DataKeyID || core.CommitmentKeyID != identity.CommitmentKeyID {
		return payload, nil, ErrPayload
	}
	plaintext, err := OpenGeneratedResult(expected, material, seed, result)
	if err != nil {
		return payload, nil, ErrPayload
	}
	defer clear(plaintext[:cap(plaintext)])
	resultCore, err := contract.EncodeGeneratedResultCore(result.Core)
	if err != nil {
		return payload, nil, ErrPayload
	}
	resultContext := binary.BigEndian.AppendUint32(nil, uint32(len(resultCore)))
	resultContext = append(resultContext, resultCore...)
	resultContext = append(resultContext, result.Payload.SemanticCommitment[:]...)
	resultDigest := sha256.Sum256(resultContext)
	context := binary.BigEndian.AppendUint32(nil, uint32(len(encoded)))
	context = append(context, encoded...)
	context = append(context, result.Core.ResultID[:]...)
	context = append(context, resultDigest[:]...)
	keys = make([]byte, 64)
	defer func() {
		if err != nil {
			clear(keys[:cap(keys)])
			keys = nil
			payload = contract.CanonicalPayload{}
		}
	}()
	var nonce [12]byte
	for _, output := range []struct {
		purpose string
		bytes   []byte
	}{
		{"generated-member-data", keys[:32]},
		{"generated-member-commitment", keys[32:]},
		{"generated-member-nonce", nonce[:]},
	} {
		info := append([]byte(retainedPurpose+output.purpose+"\x00"), context...)
		derived, e := hkdf.Key(sha256.New, seed, []byte(retainedPurpose+"generated-member-salt\x00"), string(info), len(output.bytes))
		if e != nil {
			return payload, keys, ErrPayload
		}
		copy(output.bytes, derived)
		clear(derived[:cap(derived)])
	}
	check, err := packageCheck(encoded, keys)
	if err != nil {
		return payload, keys, ErrPayload
	}
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		return payload, keys, ErrPayload
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return payload, keys, ErrPayload
	}
	// Only this derivation uses a deterministic nonce. The selected immutable
	// result and complete value context bind both its key and its nonce.
	ciphertext := aead.Seal(make([]byte, 0, len(plaintext)+aead.Overhead()), nonce[:], plaintext, valuePreimage(valueAADLabel, encoded))
	payload = contract.CanonicalPayload{Profile: core.Profile, CryptoSupportID: core.CryptoSupportID,
		DataKeyID: core.DataKeyID, DataKeyEpoch: core.DataKeyEpoch, CommitmentKeyID: core.CommitmentKeyID, CommitmentKeyEpoch: core.CommitmentKeyEpoch,
		InputEncoding: core.InputEncoding, ContentLength: core.ContentLength, RetainedLength: core.RetainedLength, Nonce: nonce, Ciphertext: ciphertext, PackageCheck: check, SemanticCommitment: semanticCommitment(encoded, plaintext, keys[32:])}
	return payload, keys, nil
}
