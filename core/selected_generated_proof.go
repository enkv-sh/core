package core

import (
	"context"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type selectedGeneratedProof struct {
	*selectedImage
	head      format.Head
	validated *generatedImageValidation
}

func (p *selectedGeneratedProof) receiptWindows(ctx context.Context) (contract.MutationReceiptWindows, error) {
	if ctx == nil || ctx.Err() != nil {
		return contract.MutationReceiptWindows{}, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	return selectedCompleteReceiptWindows(p.selectedImage)
}
func (p *selectedGeneratedProof) generatedSelectionRoot() (contract.ID, bool) {
	body, err := format.EncodeRoot(p.root)
	if err != nil {
		return contract.ID{}, false
	}
	return contract.Hash(body), true
}
