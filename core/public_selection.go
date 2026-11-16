package core

import (
	"bytes"
	"context"
	"errors"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// PublicSelectedReader gives Core only exact selected GET reach. Close
// ends its one-attempt ownership; it has no write, CAS or signing method.
type PublicSelectedReader interface {
	Read(context.Context, string, uint32) contract.ReadResult
	Descriptor() contract.Descriptor
	StoreConfiguration() contract.StoreConfiguration
	Close()
}

// publicSelection is a complete, read-only current image. Its reader
// can GET exact selected objects, but it has no ordinary admission or Store
// mutation method. Public candidate facts alone cannot construct this value.
type publicSelection struct {
	basis       publicReadBasis
	image       selectedImage
	materials   selectedMaterialFacts
	authorityID contract.ID
	windows     contract.MutationReceiptWindows
	complete    bool
}

// completePublicSelection authenticates the full selected closure
// after the independently qualified anchor and guarded normal HEAD reread.
// It keeps the ordinary enrollment and predecessor-pin checks in ordinary Open.
// visitGenerated borrows authenticated facts synchronously. Its projection is
// provisional until the complete outer read admission also succeeds.
func completePublicSelection(ctx context.Context, basis publicReadBasis, visitGenerated func(context.Context, *generatedSelection) error) (publicSelection, Result) {
	var empty publicSelection
	if ctx == nil || basis.reader.source == nil || basis.anchor.headBody == nil ||
		basis.anchor.headToken.Family != basis.reader.descriptor.Family ||
		basis.anchor.head.Core.Domain != basis.reader.domain ||
		format.CheckReference(basis.anchor.head.Core.Root, basis.anchor.rootBody) != nil {
		return empty, refused(AdmissionInvalid)
	}
	encodedHead, err := format.EncodeHead(basis.anchor.head)
	if err != nil || !bytes.Equal(encodedHead, basis.anchor.headBody) {
		return empty, refused(AdmissionInvalid)
	}
	if !publicReadInvocationCurrent(ctx, basis.anchor) {
		return empty, failure(EvidenceUnavailable, ReadUnavailable)
	}
	head, root := basis.anchor.head, basis.anchor.root
	if !validAggregate(root) {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	if head.AuthKind == format.SuccessionAuth && !selectionAcceptanceValid(head, root) {
		return empty, failure(IntegrityFailure, InvalidProof)
	}
	image, result := readCompleteSelectedImage(ctx, basis.reader, root, false)
	if result.Outcome != 0 {
		return empty, result
	}
	if !publicReadInvocationCurrent(ctx, basis.anchor) {
		return empty, failure(EvidenceUnavailable, ReadUnavailable)
	}
	authorityID := image.root.CurrentAccess.Core.AuthorityRecipientID
	control, ok := selectedControlFrom(image.root, &image.recipients, authorityID)
	if !ok {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	var genesis *contract.GenesisDescriptorCore
	if head.AuthKind == format.GenesisAuth {
		d, _, valid := selectedGenesisDescriptor(head, &image)
		if !valid {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
		genesis = &d
	}
	if !selectedHeadProofs(head, control, genesis) {
		return empty, failure(IntegrityFailure, InvalidProof)
	}
	gc, err := selectedGCState(&image, true)
	if err != nil {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	if err := selectedGCStore(gc, basis.reader.descriptor); err != nil {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	evidence, err := administrativeSelectedEvidence(image.adminIndex, image.support, image.publicationFacts)
	if err != nil || len(evidence) != len(image.adminIndex.Groups) {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	for i, group := range image.adminIndex.Groups {
		if group.SelectedEvidenceSummary != evidence[i] {
			return empty, failure(IntegrityFailure, InvalidRelation)
		}
	}
	materials, ok := indexSelectedMaterialFacts(image.root, &image.pages, &image.access, image.support)
	if !ok {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	access, ok := selectedCompleteRelations(head, &image, authorityID, materials)
	if !ok {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	readFragment := func(ctx context.Context, location format.FragmentLocation, consume func([]byte) error) (Result, error) {
		return withSelectedFragmentFromImage(ctx, &image, basis.reader, location, consume)
	}
	if _, err := selectedReceiptWindowsWithReader(ctx, &image, basis.reader); err != nil {
		if result, ok := selectedReadResult(err); ok {
			return empty, result
		}
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	generated, err := selectedGeneratedWorkFromImageWithReader(ctx, &image, materials, nil, readFragment)
	if result, ok := selectedReadResult(err); ok {
		return empty, result
	}
	if err != nil || !generated.covers(access) {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}

	if err := validateAdministrativeExposure(image.adminIndex, image.support, generated.facts, image.publicationFacts); err != nil {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}

	switch head.AuthKind {
	case format.GenesisAuth:
		selected, ok := selectedGenesisClosure(head, &image, basis.anchor.configuration)
		if !ok || genesis == nil {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
		selectedBytes, selectedErr := contract.EncodeGenesisDescriptorCore(selected)
		genesisBytes, genesisErr := contract.EncodeGenesisDescriptorCore(*genesis)
		if selectedErr != nil || genesisErr != nil || !bytes.Equal(selectedBytes, genesisBytes) {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
	case format.GeneratorAuth:
		_, ok := selectedGeneratedPreflight(head, &image)
		if !ok {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
		proof := selectedGeneratedProof{selectedImage: &image, head: head, validated: generated}
		if err := proof.validateGeneratedSelection(ctx); err != nil {
			if result, ok := selectedReadResult(err); ok {
				return empty, result
			}
			return empty, failure(IntegrityFailure, InvalidProof)
		}
	case format.SuccessionAuth:
		if !intrinsicSuccessionSelection(head, image.root, control) {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
	case format.GCAuth:
		if !selectedGCSelection(head, &image) {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
	case format.AdministrativeAuth:
		if !selectedEndWorkSelection(head, &image, authorityID) {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
	case format.OutputReserveAuth, format.OutputCloseAuth:
		if !selectedOutputSelection(head, &image) {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
	case format.LifecycleAuth:
		if !selectedLifecycleSelection(head, &image, authorityID) {
			return empty, failure(IntegrityFailure, InvalidProof)
		}
	default:
		return empty, failure(IntegrityFailure, InvalidProof)
	}
	windows, err := selectedCompleteReceiptWindows(&image)
	if err != nil {
		return empty, failure(IntegrityFailure, InvalidRelation)
	}
	if !selectedLifecycleReceiptKind(head, windows) {
		return empty, failure(IntegrityFailure, InvalidProof)
	}
	if visitGenerated != nil {
		if err := visitGenerated(ctx, generated.facts); err != nil {
			if result, ok := selectedReadResult(err); ok {
				return empty, result
			}
			if errors.Is(err, contract.ErrRecordCapacity) {
				return empty, refused(CapacityExceeded)
			}
			return empty, failure(IntegrityFailure, InvalidRelation)
		}
	}
	if !publicReadInvocationCurrent(ctx, basis.anchor) {
		return empty, failure(EvidenceUnavailable, ReadUnavailable)
	}
	return publicSelection{basis: basis, image: image, materials: materials,
		authorityID: authorityID, windows: windows, complete: true}, Result{}
}
