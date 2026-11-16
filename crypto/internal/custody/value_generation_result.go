package custody

import (
	"crypto/rand"
	"crypto/subtle"

	"enkv.sh/core/contract"
)

func generatedResultTransfer(material contract.OperationMaterialCore, core contract.GeneratedResultCore, digest contract.ID) contract.TransferCore {
	transfer := retainedTransfer(material)
	transfer.UseKind, transfer.PacketKind, transfer.PacketLength = 2, 6, contract.ResultTransferPacketLength
	transfer.AttemptID, transfer.ResultID, transfer.ResultCoreDigest = core.AttemptID, core.ResultID, digest
	return transfer
}

func SealGeneratedResult(expected contract.GeneratorResultExpectation, material contract.OperationMaterialRecord, facts contract.GeneratorSafeFacts, seed, plaintext []byte) (contract.GeneratedResultRecord, error) {
	core, err := contract.ExpectedGeneratedResultCore(expected, material, facts)
	content, contentErr := contract.InputContentLength(expected.InputEncoding, plaintext)
	if err != nil || contentErr != nil || content > expected.Use.MaxSecret ||
		(facts.Disposition == contract.GeneratorDispositionCompleteCreate) != (len(plaintext) != 0) {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	check, err := SeedCheck(material.Core, seed)
	if err != nil || subtle.ConstantTimeCompare(check[:], material.SeedCheck[:]) != 1 {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	body, err := contract.EncodeGeneratedResultCore(core)
	if err != nil {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	keys := make([]byte, 64)
	defer clear(keys[:cap(keys)])
	_, _ = rand.Read(keys[:32])
	_, _ = rand.Read(keys[32:])
	packageCheck, err := retainedCheck(body, keys, "result-package-hkdf-salt", "result-package-hkdf-info", "result-package-check")
	if err != nil {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	nonce, ciphertext, err := sealPayload(keys[:32], plaintext, valuePreimage(retainedPurpose+"result-aad\x00", body))
	if err != nil {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	data, commitment, err := contract.GeneratorResultKeyIDs(core.ResultID)
	if err != nil {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	payload := contract.CanonicalPayload{Profile: core.Profile, CryptoSupportID: material.Core.CryptoSupportID,
		DataKeyID: data, DataKeyEpoch: 1, CommitmentKeyID: commitment, CommitmentKeyEpoch: 1,
		InputEncoding: expected.InputEncoding, ContentLength: content, RetainedLength: uint32(len(plaintext)), Nonce: nonce, Ciphertext: ciphertext, PackageCheck: packageCheck,
		SemanticCommitment: resultSemantic(body, plaintext, keys[32:])}
	envelope, err := SealTransfer(generatedResultTransfer(material.Core, core, contract.Hash(body)), seed, keys)
	if err != nil {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	result := contract.GeneratedResultRecord{Core: core, SafeFacts: facts, Payload: payload, Transfer: envelope}
	if err := contract.ValidateGeneratedResult(expected, material, result); err != nil {
		return contract.GeneratedResultRecord{}, ErrPayload
	}
	return result, nil
}

func OpenGeneratedResult(expected contract.GeneratorResultExpectation, material contract.OperationMaterialRecord, seed []byte, record contract.GeneratedResultRecord) ([]byte, error) {
	if err := contract.ValidateGeneratedResult(expected, material, record); err != nil {
		return nil, ErrPayload
	}
	check, err := SeedCheck(material.Core, seed)
	if err != nil || subtle.ConstantTimeCompare(check[:], material.SeedCheck[:]) != 1 {
		return nil, ErrPayload
	}
	body, err := contract.EncodeGeneratedResultCore(record.Core)
	if err != nil {
		return nil, ErrPayload
	}
	transfer := generatedResultTransfer(material.Core, record.Core, contract.Hash(body))
	keys, err := OpenTransfer(transfer, record.Transfer, seed)
	if err != nil {
		return nil, ErrPayload
	}
	defer clear(keys[:cap(keys)])
	packageCheck, err := retainedCheck(body, keys, "result-package-hkdf-salt", "result-package-hkdf-info", "result-package-check")
	if err != nil || subtle.ConstantTimeCompare(packageCheck[:], record.Payload.PackageCheck[:]) != 1 {
		return nil, ErrPayload
	}
	plaintext, err := openPayload(keys[:32], record.Payload.Nonce, record.Payload.Ciphertext, valuePreimage(retainedPurpose+"result-aad\x00", body))
	if err != nil {
		return nil, ErrPayload
	}
	semantic := resultSemantic(body, plaintext, keys[32:])
	content, contentErr := contract.InputContentLength(record.Payload.InputEncoding, plaintext)
	if contentErr != nil || uint32(len(plaintext)) != record.Payload.RetainedLength || content != record.Payload.ContentLength || subtle.ConstantTimeCompare(semantic[:], record.Payload.SemanticCommitment[:]) != 1 {
		clear(plaintext[:cap(plaintext)])
		return nil, ErrPayload
	}
	return plaintext, nil
}
