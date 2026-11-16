package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// CheckPublicBasis checks separately retained trust against this authenticated
// observation. It issues no admission and cannot construct missing trust proof.
func (p *ReconstructionProjection) CheckPublicBasis(ctx context.Context, offered PublicBasis) error {
	if p == nil || ctx == nil {
		return ErrLocalAuthorityAdmission
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.parts) < 3 || ctx.Err() != nil {
		return ErrLocalAuthorityAdmission
	}
	if p.parts[0].kind != reconstructionConfigurationPart || p.parts[1].kind != reconstructionHEADPart || p.parts[2].kind != reconstructionRootPart {
		return ErrLocalAuthorityAdmission
	}
	stored, err := contract.DecodeStoreConfiguration(p.parts[0].body)
	if err != nil {
		return err
	}
	head, err := format.DecodeHead(p.parts[1].body)
	if err != nil {
		return err
	}
	root, err := format.DecodeRoot(p.parts[2].body)
	if err != nil {
		return err
	}
	if root.Domain != p.provenance.domain || root.Snapshot != p.provenance.snapshot || stored.DomainID != root.Domain || head.Core.Domain != root.Domain || head.Core.Root != p.parts[2].ref {
		return ErrLocalAuthorityAdmission
	}
	descriptor := contract.Descriptor{Family: stored.Provider, Identity: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Prefix: stored.PrefixBeforeHEAD, HeadKey: stored.PrefixBeforeHEAD + "/HEAD"}
	basis, reason := qualifyBorrowedReaderPublicBasis(offered, root.Domain, descriptor)
	if reason != "" {
		return ErrLocalAuthorityAdmission
	}
	current := contract.ControlCore{CurrentControl: root.CurrentAccess.Core.CurrentControl}
	found := false
	for _, part := range p.parts {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if part.kind != reconstructionRecipientPagePart {
			continue
		}
		page, err := format.DecodeRecipientPage(part.body)
		if err != nil {
			return err
		}
		for _, row := range page.Slots {
			if row == nil || row.RecipientID != current.AuthorityRecipientID {
				continue
			}
			if found || row.CurrentBinding == nil {
				return ErrLocalAuthorityAdmission
			}
			current.AuthorityKMSBinding, found = *row.CurrentBinding, true
		}
	}
	if !found || !CurrentControlMatches(current, basis.control) {
		return ErrLocalAuthorityAdmission
	}
	if head.AuthKind == format.SuccessionAuth && !basis.successionSelected(head) {
		return ErrLocalAuthorityAdmission
	}
	if head.AuthKind == format.GenesisAuth && !basis.genesisSelected(head) {
		return ErrLocalAuthorityAdmission
	}
	return ctx.Err()
}

// CopyPublicBasis returns public evidence only after complete reconstruction.
// The caller owns every returned byte independently of the projection.
func (p *ReconstructionProjection) CopyPublicBasis(ctx context.Context) (PublicBasis, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return PublicBasis{}, ErrLocalAuthorityAdmission
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.parts) < 3 || len(p.signingAnchor) == 0 || p.parts[0].kind != reconstructionConfigurationPart || p.parts[1].kind != reconstructionHEADPart || p.parts[2].kind != reconstructionRootPart {
		return PublicBasis{}, ErrLocalAuthorityAdmission
	}
	basis := PublicBasis{SigningAnchor: p.signingAnchor, StoreConfiguration: p.parts[0].body, HEAD: p.parts[1].body, Root: p.parts[2].body}
	for _, part := range p.parts {
		if part.kind == reconstructionRecipientPagePart {
			basis.RecipientPages = append(basis.RecipientPages, part.body)
		}
	}
	owned, err := basis.own()
	if ctx.Err() != nil {
		owned.clear()
		return PublicBasis{}, ctx.Err()
	}
	return owned, err
}
