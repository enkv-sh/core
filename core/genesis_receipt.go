package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func genesisPlanDigest(p format.GenesisPlanCore) contract.ID {
	body, err := format.EncodeGenesisPlanCore(p)
	if err != nil {
		return contract.ID{}
	}
	return contract.Hash(body)
}

func genesisReceipt(request contract.GenesisRequestCore, revision contract.ID) (contract.CompactMutationReceipt, error) {
	body, err := contract.EncodeGenesisRequestCore(request)
	if err != nil {
		return contract.CompactMutationReceipt{}, err
	}
	receipt, err := contract.GenesisReceiptFields(request.DomainID, request.InitID, revision)
	if err != nil {
		return contract.CompactMutationReceipt{}, err
	}
	empty := contract.EmptyMutationResultDescriptors()
	receipt.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{
		Receipt: contract.CompactMutationReceiptPlan(receipt), RequestCoreDigest: contract.Hash(body),
		ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil {
		return contract.CompactMutationReceipt{}, err
	}
	receipt.RequestIdentityDigest = contract.Hash(body)
	if !contract.CompactMutationReceiptValid(receipt) {
		return contract.CompactMutationReceipt{}, contract.ErrRecord
	}
	return receipt, nil
}
