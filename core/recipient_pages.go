package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (next *StateSession) installApplyRecipientPages(c *Comparison, p transitionPlan) error {
	if len(c.recipientChanges) == 0 {
		return nil
	}
	pages, refs, err := format.ApplyRecipientPages(next.root.Domain, c.proposedRegistry(), identityPlan(c, p))
	if err != nil {
		return err
	}
	next.root.Recipients = [contract.MaxRecipientPages]*contract.Ref{}
	next.recipients = [contract.MaxRecipientPages]*format.RecipientPage{}
	for i := range pages {
		next.recipients[pages[i].Index] = &pages[i]
		next.root.Recipients[refs[i].Index] = &refs[i]
	}
	next.root.RecipientCount = uint16(len(c.recipients))
	if len(pages) != 0 {
		next.recipient = pages[0]
	}
	descriptor, err := recipientRefsDescriptor(next.root)
	if err != nil {
		return err
	}
	next.root.CurrentAccess.Core.RecipientRefsDescriptor = descriptor
	return nil
}

func recipientRefsDescriptor(root format.Root) (contract.DescriptorVector, error) {
	refs := make([]contract.Ref, 0, contract.MaxRecipientPages)
	for _, ref := range root.Recipients {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	return contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: root.Domain, Refs: refs})
}
