package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedReceiptWindowsWithReader reads the bounded receipt index through
// exact selected fragment facts. The image retains decoded window order only
// after the whole index and all selected receipt rows validate.
func selectedReceiptWindowsWithReader(ctx context.Context, image *selectedImage,
	reader selectedObjectReader) (contract.MutationReceiptWindows, error) {
	if image == nil || ctx == nil || image.fragmentFacts == nil {
		return contract.MutationReceiptWindows{}, contract.ErrRecord
	}
	windows, err := selectedReceiptWindows(image.root.Domain, image.root, image.support,
		func(id contract.ID, limit uint64) ([]byte, error) {
			return selectedReceiptBlobWithReader(ctx, image, reader, id, limit)
		})
	if err != nil {
		return contract.MutationReceiptWindows{}, err
	}
	image.receiptWindows = contract.MutationReceiptWindows{DomainID: windows.DomainID,
		Successes: slices.Clone(windows.Successes), Failures: slices.Clone(windows.Failures), Order: slices.Clone(windows.Order)}
	image.receiptsValidated = true
	return windows, nil
}

func selectedReceiptBlobWithReader(ctx context.Context, image *selectedImage, reader selectedObjectReader,
	id contract.ID, limit uint64) ([]byte, error) {
	return selectedSupportBlobWithReader(ctx, image,
		func(ctx context.Context, location format.FragmentLocation, consume func([]byte) error) (Result, error) {
			return withSelectedFragmentFromImage(ctx, image, reader, location, consume)
		}, id, limit)
}
